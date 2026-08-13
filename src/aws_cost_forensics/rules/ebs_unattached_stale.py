from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import ClassVar

from aws_cost_forensics.domain.enums import DecisionClass, EvidenceKind, EvidenceStrength, Severity
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import Observation
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resources import EBSVolume


class EBSUnattachedStaleDetector:
    rule_id: ClassVar[str] = "EBS_UNATTACHED_STALE"

    def __init__(self, stale_days: int = 30) -> None:
        self._stale_days = stale_days

    def detect(self, inventory: Inventory, *, now: datetime | None = None) -> list[Observation]:
        _now = now if now is not None else datetime.now(tz=UTC)
        threshold = timedelta(days=self._stale_days)
        return [
            self._make_observation(vol, _now, inventory)
            for vol in inventory.volumes
            if vol.state == "available" and (_now - vol.create_time) >= threshold
        ]

    def _make_observation(self, vol: EBSVolume, now: datetime, inventory: Inventory) -> Observation:
        age_days = (now - vol.create_time).days
        evidence: list[Evidence] = [
            Evidence(
                code="VOLUME_UNATTACHED",
                kind=EvidenceKind.SUPPORTING,
                description="Volume has no EC2 attachments (state=available).",
                api_source="ec2:DescribeVolumes",
            ),
            Evidence(
                code="VOLUME_AGE_DAYS",
                kind=EvidenceKind.SUPPORTING,
                description=f"Volume is {age_days} days old (threshold: {self._stale_days} days).",
                api_source="ec2:DescribeVolumes",
                value=age_days,
            ),
        ]

        if not vol.tags:
            evidence.append(
                Evidence(
                    code="VOLUME_MISSING_TAGS",
                    kind=EvidenceKind.SUPPORTING,
                    description="Volume has no tags; ownership is difficult to determine.",
                    api_source="ec2:DescribeVolumes",
                    value=True,
                )
            )

        if vol.snapshot_id:
            snap = inventory.get_snapshot(vol.snapshot_id)
            if snap is not None:
                evidence.append(
                    Evidence(
                        code="SNAPSHOT_SOURCE_EXISTS",
                        kind=EvidenceKind.SUPPORTING,
                        description=f"Source snapshot {vol.snapshot_id} is present in inventory.",
                        api_source="ec2:DescribeVolumes",
                        value=vol.snapshot_id,
                    )
                )
            else:
                evidence.append(
                    Evidence(
                        code="SNAPSHOT_NOT_IN_INVENTORY",
                        kind=EvidenceKind.MISSING,
                        description=(
                            f"Source snapshot {vol.snapshot_id} not found — "
                            "may be deregistered or cross-account."
                        ),
                        api_source="ec2:DescribeVolumes",
                        value=vol.snapshot_id,
                    )
                )

        evidence.append(
            Evidence(
                code="ATTACHMENT_HISTORY_UNAVAILABLE",
                kind=EvidenceKind.MISSING,
                description=(
                    "No CloudTrail/CloudWatch data available to confirm prior attachment history."
                ),
                api_source="ec2:DescribeVolumes",
            )
        )

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
            severity=Severity.MEDIUM,
            decision_class=DecisionClass.REMEDIATION_CANDIDATE,
            evidence=evidence,
            evidence_strength=EvidenceStrength.HIGH,
        )
