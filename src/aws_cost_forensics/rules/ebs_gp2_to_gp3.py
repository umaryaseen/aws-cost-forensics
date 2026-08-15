from __future__ import annotations

from decimal import Decimal
from typing import ClassVar

from aws_cost_forensics.domain.enums import DecisionClass, EvidenceKind, EvidenceStrength, Severity
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import CostEstimate, Observation
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resources import EBSVolume
from aws_cost_forensics.pricing.provider import PricingProvider


class EBSGP2ToGP3Detector:
    rule_id: ClassVar[str] = "EBS_GP2_TO_GP3"

    def __init__(self, pricing: PricingProvider) -> None:
        self._pricing = pricing

    def detect(self, inventory: Inventory) -> list[Observation]:
        return [
            self._make_observation(vol) for vol in inventory.volumes if vol.volume_type == "gp2"
        ]

    def _make_observation(self, vol: EBSVolume) -> Observation:
        evidence: list[Evidence] = [
            Evidence(
                code="VOLUME_TYPE_GP2",
                kind=EvidenceKind.SUPPORTING,
                description="Volume is gp2; gp3 provides the same baseline at lower cost.",
                api_source="ec2:DescribeVolumes",
                value="gp2",
            ),
            Evidence(
                code="WORKLOAD_IOPS_UNKNOWN",
                kind=EvidenceKind.MISSING,
                description=(
                    "Actual workload IOPS are unknown (no CloudWatch). "
                    "gp3 cost model uses the gp2 IOPS baseline formula "
                    "(min(size_gib * 3, 16000)); provisioned IOPS above the "
                    "gp3 free tier of 3000 are priced accordingly."
                ),
                api_source="ec2:DescribeVolumes",
            ),
        ]

        cost_estimate = self._build_cost_estimate(vol)

        resource_ref = ResourceRef(
            resource_id=vol.volume_id,
            resource_type="ebs_volume",
            region=vol.region,
            account_id=vol.account_id,
        )
        observation_id = f"{self.rule_id}:{vol.account_id}:{vol.region}:ebs_volume:{vol.volume_id}"
        return Observation(
            observation_id=observation_id,
            rule_id=self.rule_id,
            resource_ref=resource_ref,
            severity=Severity.LOW,
            decision_class=DecisionClass.REMEDIATION_CANDIDATE,
            evidence=evidence,
            evidence_strength=EvidenceStrength.HIGH,
            cost_estimate=cost_estimate,
        )

    def _build_cost_estimate(self, vol: EBSVolume) -> CostEstimate | None:
        gp2_cost = self._pricing.ebs_monthly_cost(vol.region, "gp2", vol.size_gib)
        if gp2_cost is None:
            return None

        # Performance-preserving gp3 model: match gp2 IOPS baseline
        gp2_equiv_iops = min(vol.size_gib * 3, 16000)
        gp3_provisioned_iops = max(0, gp2_equiv_iops - 3000)
        gp3_cost = self._pricing.ebs_monthly_cost(
            vol.region, "gp3", vol.size_gib, iops=gp3_provisioned_iops
        )
        if gp3_cost is None:
            return None

        saving: Decimal | None = None
        if gp3_cost < gp2_cost:
            saving = gp2_cost - gp3_cost

        return CostEstimate(
            monthly_cost_usd=gp2_cost,
            potential_saving_usd=saving,
            pricing_source=self._pricing.pricing_source_name(),
            note=(
                "Cost model preserves gp2 IOPS baseline. "
                "Verify actual workload IOPS before migration."
            ),
        )
