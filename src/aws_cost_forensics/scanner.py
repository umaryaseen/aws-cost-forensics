"""Full scan pipeline: COLLECT → DETECT → CORRELATE → SUPERSEDE → PRICE → REMEDIATE → REPORT."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from aws_cost_forensics import __version__
from aws_cost_forensics.aws.collectors.account import collect_account_id
from aws_cost_forensics.aws.collectors.amis import collect_amis
from aws_cost_forensics.aws.collectors.autoscaling import collect_asgs
from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.collectors.ebs import collect_instances, collect_volumes
from aws_cost_forensics.aws.collectors.launch_templates import (
    LaunchTemplateMetadata,
    collect_launch_template_metadata,
    collect_lt_versions,
)
from aws_cost_forensics.aws.collectors.snapshots import collect_snapshots
from aws_cost_forensics.aws.readonly_client import (
    ReadOnlyASGClient,
    ReadOnlyEC2Client,
    ReadOnlySTSClient,
)
from aws_cost_forensics.aws.session import create_session, resolve_region
from aws_cost_forensics.domain.enums import RecurrenceStatus
from aws_cost_forensics.domain.findings import CostEstimate, ForensicCase, Observation
from aws_cost_forensics.domain.inventory import Inventory, ScanError, ScanResult, ScanSummary
from aws_cost_forensics.domain.resources import (
    AMI,
    AutoScalingGroup,
    EBSSnapshot,
    EBSVolume,
    EC2Instance,
    LaunchTemplateVersion,
)
from aws_cost_forensics.graph.builder import RelationshipBuilder
from aws_cost_forensics.pricing.provider import PricingProvider
from aws_cost_forensics.pricing.static import StaticPricingProvider
from aws_cost_forensics.remediation.planner import RemediationPlanner
from aws_cost_forensics.rules.asg_ebs_orphan_chain import ASGEBSOrphanChainCorrelator
from aws_cost_forensics.rules.ebs_gp2_to_gp3 import EBSGP2ToGP3Detector
from aws_cost_forensics.rules.ebs_unattached_stale import EBSUnattachedStaleDetector
from aws_cost_forensics.rules.lt_delete_on_termination import LTDeleteOnTerminationDetector

_log = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Configuration for a single scan run.

    T017 will wrap this in AcfConfig with CLI flags, env vars, and config-file loading.
    """

    profile: str | None = None
    region: str | None = None
    stale_volume_days: int = 30
    pricing_source: str = "static"


class Scanner:
    """Orchestrates the full cost forensics pipeline for one AWS region scan."""

    def run(self, config: ScanConfig) -> ScanResult:
        """Execute a complete scan and return the assembled ScanResult."""
        generated_at = datetime.now(tz=UTC)
        scan_errors: list[ScanError] = []

        # ── Session + clients ─────────────────────────────────────────────────
        session = create_session(config.profile)
        region = resolve_region(session, config.region)

        ec2 = ReadOnlyEC2Client(session.client("ec2", region_name=region))
        asg_c = ReadOnlyASGClient(session.client("autoscaling", region_name=region))
        sts = ReadOnlySTSClient(session.client("sts", region_name=region))

        # ── Account ID ────────────────────────────────────────────────────────
        # Fatal — STS failure means we have no account context; let it propagate.
        account_id = collect_account_id(sts)

        # ── Collection (non-fatal) ────────────────────────────────────────────
        volumes: list[EBSVolume] = _collect_safe(
            "ebs",
            lambda: collect_volumes(ec2, region, account_id),
            scan_errors,
            [],
        )
        instances: list[EC2Instance] = _collect_safe(
            "instances",
            lambda: collect_instances(ec2, region, account_id),
            scan_errors,
            [],
        )
        snapshots: list[EBSSnapshot] = _collect_safe(
            "snapshots",
            lambda: collect_snapshots(ec2, region, account_id),
            scan_errors,
            [],
        )
        amis: list[AMI] = _collect_safe(
            "amis",
            lambda: collect_amis(ec2, region, account_id),
            scan_errors,
            [],
        )
        lt_metadata_by_id: dict[str, LaunchTemplateMetadata] = _collect_safe(
            "launch_templates",
            lambda: collect_launch_template_metadata(ec2),
            scan_errors,
            {},
        )

        lt_versions: list[LaunchTemplateVersion] = []
        for template_id, metadata in lt_metadata_by_id.items():
            batch: list[LaunchTemplateVersion] = _collect_safe(
                f"launch_template_versions:{template_id}",
                functools.partial(
                    collect_lt_versions, ec2, template_id, metadata, region, account_id
                ),
                scan_errors,
                [],
            )
            lt_versions.extend(batch)

        asgs: list[AutoScalingGroup] = _collect_safe(
            "autoscaling",
            lambda: collect_asgs(asg_c, lt_metadata_by_id, region, account_id),
            scan_errors,
            [],
        )

        # ── Inventory + graph ─────────────────────────────────────────────────
        inventory = Inventory(
            account_id=account_id,
            region=region,
            scanned_at=datetime.now(tz=UTC),
            volumes=volumes,
            snapshots=snapshots,
            amis=amis,
            instances=instances,
            launch_template_versions=lt_versions,
            auto_scaling_groups=asgs,
        )
        RelationshipBuilder(inventory.graph).build_all(inventory)

        # ── Pricing provider ──────────────────────────────────────────────────
        pricing: PricingProvider = StaticPricingProvider()

        # ── Detect ────────────────────────────────────────────────────────────
        observations: list[Observation] = []
        observations.extend(EBSUnattachedStaleDetector(config.stale_volume_days).detect(inventory))
        observations.extend(EBSGP2ToGP3Detector(pricing).detect(inventory))
        observations.extend(LTDeleteOnTerminationDetector().detect(inventory))

        # ── Correlate ─────────────────────────────────────────────────────────
        correlator = ASGEBSOrphanChainCorrelator()
        forensic_cases = correlator.correlate(inventory, observations)

        # ── Supersede ─────────────────────────────────────────────────────────
        observations = _apply_supersession(
            observations, forensic_cases, correlator.supersedes_rules
        )

        # ── Price ─────────────────────────────────────────────────────────────
        observations = _price_observations(observations, pricing, inventory)
        forensic_cases = _price_cases(forensic_cases, pricing, inventory)

        # ── Remediate ─────────────────────────────────────────────────────────
        planner = RemediationPlanner()
        observations = [
            obs.model_copy(update={"remediation_plan": planner.plan_for_observation(obs)})
            for obs in observations
        ]
        forensic_cases = [
            case.model_copy(update={"remediation_plan": planner.plan_for_case(case)})
            for case in forensic_cases
        ]

        return ScanResult(
            tool_version=__version__,
            generated_at=generated_at,
            account_id=account_id,
            region=region,
            pricing_source=pricing.pricing_source_name(),
            observations=observations,
            forensic_cases=forensic_cases,
            scan_errors=scan_errors,
            summary=_build_summary(observations, forensic_cases, scan_errors),
        )


# ---------------------------------------------------------------------------
# Module-level pipeline helpers — testable without Scanner
# ---------------------------------------------------------------------------


def _collect_safe(
    collector_name: str,
    fn: Callable[[], Any],
    scan_errors: list[ScanError],
    default: Any,
) -> Any:
    """Run a collector function; on failure record a ScanError and return the default."""
    try:
        return fn()
    except CollectionError as exc:
        _log.warning("Collector '%s' failed: %s", exc.collector, exc)
        scan_errors.append(
            ScanError(
                collector=exc.collector,
                error_code="PERMISSION_DENIED" if exc.is_permission_error else "COLLECTION_FAILED",
                message=str(exc),
                is_permission_error=exc.is_permission_error,
            )
        )
        return default
    except Exception as exc:
        _log.warning("Unexpected error from collector '%s': %s", collector_name, exc)
        scan_errors.append(
            ScanError(
                collector=collector_name,
                error_code="UNEXPECTED_ERROR",
                message=str(exc),
                is_permission_error=False,
            )
        )
        return default


def _apply_supersession(
    observations: list[Observation],
    forensic_cases: list[ForensicCase],
    supersedes_rules: list[str],
) -> list[Observation]:
    """Mark observations whose resources are claimed by a forensic case.

    Sets superseded_by = case_id on observations whose rule_id is in supersedes_rules
    AND whose resource is in the case's affected_resource_refs.
    """
    superseded_rule_ids = set(supersedes_rules)
    affected_by_case: dict[str, str] = {}
    for case in forensic_cases:
        for ref in case.affected_resource_refs:
            affected_by_case[ref.resource_id] = case.case_id

    result: list[Observation] = []
    for obs in observations:
        if obs.rule_id in superseded_rule_ids and obs.resource_ref.resource_id in affected_by_case:
            obs = obs.model_copy(
                update={"superseded_by": affected_by_case[obs.resource_ref.resource_id]}
            )
        result.append(obs)
    return result


def _price_observations(
    observations: list[Observation],
    pricing: PricingProvider,
    inventory: Inventory,
) -> list[Observation]:
    """Fill cost_estimate on EBS_UNATTACHED_STALE observations that are missing one."""
    result: list[Observation] = []
    for obs in observations:
        if obs.rule_id == "EBS_UNATTACHED_STALE" and obs.cost_estimate is None:
            vol = inventory.get_volume(obs.resource_ref.resource_id)
            if vol is not None:
                monthly = pricing.ebs_monthly_cost(vol.region, vol.volume_type, vol.size_gib)
                if monthly is not None:
                    obs = obs.model_copy(
                        update={
                            "cost_estimate": CostEstimate(
                                monthly_cost_usd=monthly,
                                potential_saving_usd=monthly,
                                pricing_source=pricing.pricing_source_name(),
                                note="Volume is unattached and stale — ongoing waste.",
                            )
                        }
                    )
        result.append(obs)
    return result


def _price_cases(
    cases: list[ForensicCase],
    pricing: PricingProvider,
    inventory: Inventory,
) -> list[ForensicCase]:
    """Compute aggregate cost_estimate for each forensic case from its affected volumes."""
    result: list[ForensicCase] = []
    for case in cases:
        if case.cost_estimate is not None:
            result.append(case)
            continue

        total = Decimal("0")
        has_any = False
        all_priced = True

        for ref in case.affected_resource_refs:
            vol = inventory.get_volume(ref.resource_id)
            if vol is None:
                all_priced = False
                continue
            cost = pricing.ebs_monthly_cost(vol.region, vol.volume_type, vol.size_gib)
            if cost is None:
                all_priced = False
                continue
            total += cost
            has_any = True

        if not has_any:
            result.append(case)
            continue

        note = None if all_priced else "Pricing unavailable for some volumes; total is partial."
        result.append(
            case.model_copy(
                update={
                    "cost_estimate": CostEstimate(
                        monthly_cost_usd=total,
                        potential_saving_usd=total,
                        pricing_source=pricing.pricing_source_name(),
                        note=note,
                    )
                }
            )
        )
    return result


def _build_summary(
    observations: list[Observation],
    forensic_cases: list[ForensicCase],
    scan_errors: list[ScanError],
) -> ScanSummary:
    """Assemble the ScanSummary from the final, remediated, priced pipeline output."""
    superseded = sum(1 for o in observations if o.superseded_by is not None)
    affected = sum(len(c.affected_resource_refs) for c in forensic_cases)

    waste: list[Decimal] = []
    for case in forensic_cases:
        if case.cost_estimate:
            waste.append(case.cost_estimate.monthly_cost_usd)
    for obs in observations:
        if obs.superseded_by is not None or obs.cost_estimate is None:
            continue
        if obs.rule_id == "EBS_UNATTACHED_STALE":
            waste.append(obs.cost_estimate.monthly_cost_usd)
        elif obs.rule_id == "EBS_GP2_TO_GP3" and obs.cost_estimate.potential_saving_usd:
            waste.append(obs.cost_estimate.potential_saving_usd)

    total_waste: Decimal | None = sum(waste, Decimal("0")) if waste else None
    has_active = any(c.recurrence == RecurrenceStatus.ACTIVE for c in forensic_cases)

    return ScanSummary(
        forensic_cases=len(forensic_cases),
        observations=len(observations),
        observations_superseded=superseded,
        affected_resources=affected,
        total_monthly_waste_usd=total_waste,
        has_active_recurrence=has_active,
        scan_errors=len(scan_errors),
    )
