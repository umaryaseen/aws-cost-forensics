"""EBS_ASG_ORPHAN_CHAIN — causal forensic correlator.

Traces orphan EBS volumes back to a Launch Template DeleteOnTermination=false
misconfiguration through confirmed snapshot→AMI→LT→ASG lineage. Requires at
least one exact ID match (vol.snapshot_id in ami.snapshot_ids AND
ami.image_id == lt_ver.image_id) before emitting a ForensicCase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    DeleteOnTerminationSource,
    EvidenceKind,
    EvidenceStrength,
    RecurrenceStatus,
    RelationshipType,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import ForensicCase, Observation
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resource_key import ResourceKey
from aws_cost_forensics.domain.resources import (
    AMI,
    AutoScalingGroup,
    EBSVolume,
    EffectiveRootDeviceConfig,
    LaunchTemplateVersion,
)
from aws_cost_forensics.graph.builder import resolve_effective_root_device

# ---------------------------------------------------------------------------
# Internal chain data structures — ephemeral, not serialized
# ---------------------------------------------------------------------------


@dataclass
class LTChain:
    """One confirmed link: volume → snapshot → AMI → LT version."""

    lt_ver: LaunchTemplateVersion
    ami: AMI
    root_cfg: EffectiveRootDeviceConfig


@dataclass
class VolumeChain:
    """A candidate volume paired with all its confirmed LT chains."""

    volume: EBSVolume
    lt_chains: list[LTChain] = field(default_factory=list)
    snapshot_in_inventory: bool = False  # True → full vol→snap→ami→lt path

    @property
    def template_ids(self) -> frozenset[str]:
        return frozenset(c.lt_ver.template_id for c in self.lt_chains)

    @property
    def has_confirmed_lineage(self) -> bool:
        return len(self.lt_chains) > 0


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------


class ASGEBSOrphanChainCorrelator:
    case_type: ClassVar[str] = "ASG_EBS_LEAK"
    supersedes_rules: ClassVar[list[str]] = ["EBS_UNATTACHED_STALE", "EBS_GP2_TO_GP3"]

    def correlate(
        self, inventory: Inventory, observations: list[Observation]
    ) -> list[ForensicCase]:
        # Phase 1: candidate volumes — available with a snapshot source
        candidates = [
            v for v in inventory.volumes if v.state == "available" and v.snapshot_id is not None
        ]
        if not candidates:
            return []

        # Index: image_id → [LT versions using it]
        lt_by_ami: dict[str, list[LaunchTemplateVersion]] = {}
        for lt_ver in inventory.launch_template_versions:
            if lt_ver.image_id:
                lt_by_ami.setdefault(lt_ver.image_id, []).append(lt_ver)

        # Phase 2: trace lineage for each candidate
        volume_chains = self._trace_lineage(candidates, inventory, lt_by_ami)

        # Phase 3: only confirmed chains proceed
        confirmed = [vc for vc in volume_chains if vc.has_confirmed_lineage]
        if not confirmed:
            return []

        # Phase 4: group by template_id, exclude ambiguous volumes
        groups: dict[str, list[VolumeChain]] = {}
        for vc in confirmed:
            tids = vc.template_ids
            if len(tids) == 1:
                tid = next(iter(tids))
                groups.setdefault(tid, []).append(vc)
            # len > 1: ambiguous → excluded from all groups (no ForensicCase)

        cases: list[ForensicCase] = []
        for template_id, group_chains in groups.items():
            case = self._build_case(template_id, group_chains, inventory)
            if case is not None:
                cases.append(case)
        return cases

    # ------------------------------------------------------------------
    # Lineage tracing
    # ------------------------------------------------------------------

    def _trace_lineage(
        self,
        candidates: list[EBSVolume],
        inventory: Inventory,
        lt_by_ami: dict[str, list[LaunchTemplateVersion]],
    ) -> list[VolumeChain]:
        result: list[VolumeChain] = []
        for vol in candidates:
            snap_id = vol.snapshot_id
            assert snap_id is not None  # guaranteed by caller filter

            vc = VolumeChain(volume=vol)
            snap = inventory.get_snapshot(snap_id)
            if snap is not None:
                vc.snapshot_in_inventory = True

            # Confirmed lineage: direct ID check (works even without snapshot in inventory)
            # vol.snapshot_id in ami.snapshot_ids  AND  ami.image_id == lt_ver.image_id
            for ami in inventory.amis:
                if snap_id not in ami.snapshot_ids:
                    continue
                for lt_ver in lt_by_ami.get(ami.image_id, []):
                    ami_for_ver = inventory.get_ami(lt_ver.image_id) if lt_ver.image_id else None
                    root_cfg = resolve_effective_root_device(lt_ver, ami_for_ver)
                    vc.lt_chains.append(LTChain(lt_ver=lt_ver, ami=ami, root_cfg=root_cfg))

            if vc.has_confirmed_lineage:
                result.append(vc)
        return result

    # ------------------------------------------------------------------
    # Case building
    # ------------------------------------------------------------------

    def _build_case(
        self,
        template_id: str,
        group_chains: list[VolumeChain],
        inventory: Inventory,
    ) -> ForensicCase | None:
        region = inventory.region
        account_id = inventory.account_id

        # Collect unique LT versions in this group for this template
        lt_versions_in_group: dict[int, tuple[LaunchTemplateVersion, AMI]] = {}
        for vc in group_chains:
            for chain in vc.lt_chains:
                if chain.lt_ver.template_id == template_id:
                    lt_versions_in_group[chain.lt_ver.version_number] = (
                        chain.lt_ver,
                        chain.ami,
                    )

        # Phase 5: recurrence — evaluate each ASG's effective version
        lt_key = ResourceKey("launch_template", template_id, region, account_id)
        asg_keys = inventory.graph.sources(lt_key, RelationshipType.ASG_USES_LAUNCH_TEMPLATE)

        defective_asgs: list[AutoScalingGroup] = []
        non_defective_asgs: list[AutoScalingGroup] = []
        has_incomplete = False
        live_corroboration: list[Evidence] = []

        for asg_key in asg_keys:
            asg = inventory.get_asg(asg_key.resource_id)
            if asg is None:
                continue
            eff = asg.effective_lt_ref
            if eff is None or eff.template_id != template_id:
                continue

            if asg.mixed_instances_policy and asg.mixed_instances_policy.has_override_specific_lt:
                has_incomplete = True  # override paths unresolved; still evaluate base

            ver_key = ResourceKey(
                "launch_template_version",
                template_id,
                region,
                account_id,
                qualifier=str(eff.resolved_version_number),
            )
            effective_ver = inventory.get_lt_version(ver_key)
            if effective_ver is None:
                has_incomplete = True
                continue

            ami = inventory.get_ami(effective_ver.image_id) if effective_ver.image_id else None
            root_cfg = resolve_effective_root_device(effective_ver, ami)

            if root_cfg.source == DeleteOnTerminationSource.UNRESOLVED:
                has_incomplete = True
                continue

            is_defective = (
                root_cfg.source == DeleteOnTerminationSource.LT_EXPLICIT
                and root_cfg.delete_on_termination is False
            )

            if is_defective:
                if asg.has_reachable_launch_path:
                    defective_asgs.append(asg)
                    # Phase 6: live instance corroboration
                    corr = self._check_live_instances(asg, effective_ver, inventory)
                    live_corroboration.extend(corr)
                else:
                    # Defect confirmed but ASG sealed (max_size=0) — intent ambiguous
                    has_incomplete = True
            else:
                non_defective_asgs.append(asg)

        # Recurrence: facts-first — proven ACTIVE holds even when incomplete paths exist
        if defective_asgs:
            recurrence = RecurrenceStatus.ACTIVE
        elif has_incomplete:
            recurrence = RecurrenceStatus.UNKNOWN
        elif non_defective_asgs:
            recurrence = RecurrenceStatus.HISTORICAL
        else:
            recurrence = RecurrenceStatus.UNKNOWN  # no ASG data → cannot claim HISTORICAL

        # Phase 7: evidence strength (scoped to this group)
        total = len(group_chains)
        fully_chained = sum(1 for vc in group_chains if vc.snapshot_in_inventory)
        ratio = fully_chained / total if total > 0 else 0.0

        defect_confirmed = any(
            chain.root_cfg.source == DeleteOnTerminationSource.LT_EXPLICIT
            and chain.root_cfg.delete_on_termination is False
            for vc in group_chains
            for chain in vc.lt_chains
            if chain.lt_ver.template_id == template_id
        )
        has_live_corr = len(live_corroboration) > 0

        if (
            ratio >= 0.8
            and defect_confirmed
            and (recurrence == RecurrenceStatus.ACTIVE or has_live_corr)
        ):
            strength = EvidenceStrength.HIGH
        elif ratio >= 0.4 and defect_confirmed:
            strength = EvidenceStrength.MEDIUM
        else:
            strength = EvidenceStrength.LOW

        severity = self._case_severity(recurrence)

        # Build evidence list
        evidence = self._build_evidence(
            template_id,
            group_chains,
            defective_asgs,
            non_defective_asgs,
            recurrence,
            has_incomplete,
            live_corroboration,
            lt_versions_in_group,
        )

        affected_refs = [
            ResourceRef(
                resource_id=vc.volume.volume_id,
                resource_type="ebs_volume",
                region=vc.volume.region,
                account_id=vc.volume.account_id,
            )
            for vc in group_chains
        ]
        root_cause_ref = ResourceRef(
            resource_id=template_id,
            resource_type="launch_template",
            region=region,
            account_id=account_id,
        )
        case_id = f"ASG_EBS_LEAK:{account_id}:{region}:{template_id}"
        return ForensicCase(
            case_id=case_id,
            case_type=self.case_type,
            title=f"{len(group_chains)} EBS volume(s) orphaned by Launch Template {template_id}",
            description=(
                f"EBS volumes became orphaned because Launch Template {template_id} "
                "has DeleteOnTermination=false on the root block device. "
                "When Auto Scaling terminates instances, the root EBS volume is "
                "preserved rather than deleted, accumulating as unattached waste."
            ),
            severity=severity,
            decision_class=DecisionClass.CONFIGURATION_DEFECT,
            recurrence=recurrence,
            evidence_strength=strength,
            root_cause_ref=root_cause_ref,
            affected_resource_refs=affected_refs,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Live instance corroboration
    # ------------------------------------------------------------------

    def _check_live_instances(
        self,
        asg: AutoScalingGroup,
        effective_ver: LaunchTemplateVersion,
        inventory: Inventory,
    ) -> list[Evidence]:
        result: list[Evidence] = []
        ami = inventory.get_ami(effective_ver.image_id) if effective_ver.image_id else None
        root_cfg = resolve_effective_root_device(effective_ver, ami)

        for asg_inst in asg.current_instances:
            instance = inventory.get_instance(asg_inst.instance_id)
            if instance is None:
                continue
            root_device = instance.root_device_name or root_cfg.device_name
            for bdm in instance.block_device_mappings:
                if bdm.device == root_device and bdm.delete_on_termination is False:
                    result.append(
                        Evidence(
                            code="LIVE_INSTANCE_ROOT_PRESERVES_VOLUME",
                            kind=EvidenceKind.SUPPORTING,
                            description=(
                                f"Running instance {instance.instance_id} in ASG "
                                f"'{asg.asg_name}' has root device '{root_device}' "
                                "with DeleteOnTermination=false — confirms the defect "
                                "is active on current instances."
                            ),
                            resource_ref=ResourceRef(
                                resource_id=instance.instance_id,
                                resource_type="ec2_instance",
                                region=instance.region,
                                account_id=instance.account_id,
                            ),
                            api_source="ec2:DescribeInstances",
                        )
                    )
        return result

    # ------------------------------------------------------------------
    # Evidence construction
    # ------------------------------------------------------------------

    def _build_evidence(
        self,
        template_id: str,
        group_chains: list[VolumeChain],
        defective_asgs: list[AutoScalingGroup],
        non_defective_asgs: list[AutoScalingGroup],
        recurrence: RecurrenceStatus,
        has_incomplete: bool,
        live_corroboration: list[Evidence],
        lt_versions_in_group: dict[int, tuple[LaunchTemplateVersion, AMI]],
    ) -> list[Evidence]:
        total = len(group_chains)
        fully_chained = sum(1 for vc in group_chains if vc.snapshot_in_inventory)
        evidence: list[Evidence] = [
            Evidence(
                code="ORPHAN_VOLUME_COUNT",
                kind=EvidenceKind.SUPPORTING,
                description=f"{total} orphan volume(s) with confirmed lineage to {template_id}.",
                api_source="ec2:DescribeVolumes",
                value=total,
            ),
            Evidence(
                code="CONFIRMED_LINEAGE_COUNT",
                kind=EvidenceKind.SUPPORTING,
                description=(
                    f"{fully_chained}/{total} volumes have a full "
                    "volume→snapshot→AMI→LT chain in inventory."
                ),
                api_source="ec2:DescribeVolumes",
                value=fully_chained,
            ),
        ]

        # Root cause: LT DeleteOnTermination evidence
        for ver_num, (lt_ver, ami) in sorted(lt_versions_in_group.items()):
            root_cfg = resolve_effective_root_device(lt_ver, ami)
            if (
                root_cfg.source == DeleteOnTerminationSource.LT_EXPLICIT
                and root_cfg.delete_on_termination is False
            ):
                evidence.append(
                    Evidence(
                        code="LT_DELETE_ON_TERMINATION_FALSE",
                        kind=EvidenceKind.SUPPORTING,
                        description=(
                            f"LT {template_id} v{ver_num}: root device "
                            f"'{root_cfg.device_name}' has DeleteOnTermination=false (LT_EXPLICIT)."
                        ),
                        api_source="ec2:DescribeLaunchTemplateVersions",
                        value=False,
                    )
                )

        # Recurrence evidence
        evidence.append(
            Evidence(
                code="RECURRENCE_STATUS",
                kind=EvidenceKind.SUPPORTING,
                description=self._recurrence_description(
                    recurrence, defective_asgs, non_defective_asgs, has_incomplete
                ),
                api_source="autoscaling:DescribeAutoScalingGroups",
                value=str(recurrence),
            )
        )

        for asg in defective_asgs:
            eff = asg.effective_lt_ref
            evidence.append(
                Evidence(
                    code="DEFECTIVE_ASG_LAUNCH_PATH",
                    kind=EvidenceKind.SUPPORTING,
                    description=(
                        f"ASG '{asg.asg_name}' uses defective LT version "
                        f"(selector={eff.version_selector if eff else '?'}, "
                        f"resolved={eff.resolved_version_number if eff else '?'}) "
                        f"with max_size={asg.max_size}."
                    ),
                    resource_ref=ResourceRef(
                        resource_id=asg.asg_name,
                        resource_type="asg",
                        region=asg.region,
                        account_id=asg.account_id,
                    ),
                    api_source="autoscaling:DescribeAutoScalingGroups",
                )
            )

        evidence.extend(live_corroboration)

        if has_incomplete:
            evidence.append(
                Evidence(
                    code="LAUNCH_PATH_PARTIALLY_UNRESOLVED",
                    kind=EvidenceKind.MISSING,
                    description=(
                        "Some ASG launch paths could not be fully evaluated "
                        "(missing LT version, UNRESOLVED root device config, "
                        "or MixedInstancesPolicy override-specific LTs)."
                    ),
                    api_source="autoscaling:DescribeAutoScalingGroups",
                )
            )

        return evidence

    @staticmethod
    def _recurrence_description(
        recurrence: RecurrenceStatus,
        defective_asgs: list[AutoScalingGroup],
        non_defective_asgs: list[AutoScalingGroup],
        has_incomplete: bool,
    ) -> str:
        if recurrence == RecurrenceStatus.ACTIVE:
            names = [a.asg_name for a in defective_asgs]
            return (
                f"ACTIVE — {len(defective_asgs)} ASG(s) with reachable launch path "
                f"use the defective LT version: {', '.join(names)}."
            )
        if recurrence == RecurrenceStatus.HISTORICAL:
            return (
                "HISTORICAL — all referencing ASGs now use a fixed LT version. "
                "Orphans predate the fix."
            )
        reasons: list[str] = []
        if has_incomplete:
            reasons.append("some ASG launch paths could not be fully evaluated")
        if not defective_asgs and not non_defective_asgs:
            reasons.append("no ASG data found for this template")
        return "UNKNOWN — " + ("; ".join(reasons) if reasons else "recurrence cannot be determined")

    @staticmethod
    def _case_severity(recurrence: RecurrenceStatus) -> Severity:
        if recurrence == RecurrenceStatus.ACTIVE:
            return Severity.HIGH
        if recurrence == RecurrenceStatus.UNKNOWN:
            return Severity.MEDIUM
        return Severity.LOW  # HISTORICAL
