from __future__ import annotations

from typing import ClassVar

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    DeleteOnTerminationSource,
    EvidenceKind,
    EvidenceStrength,
    RelationshipType,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import Observation
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resource_key import ResourceKey
from aws_cost_forensics.domain.resources import AutoScalingGroup, LaunchTemplateVersion
from aws_cost_forensics.graph.builder import resolve_effective_root_device


class LTDeleteOnTerminationDetector:
    rule_id: ClassVar[str] = "LT_DELETE_ON_TERMINATION_FALSE"

    def detect(self, inventory: Inventory) -> list[Observation]:
        observations: list[Observation] = []
        for lt_ver in inventory.launch_template_versions:
            ami = inventory.get_ami(lt_ver.image_id) if lt_ver.image_id else None
            root_cfg = resolve_effective_root_device(lt_ver, ami)

            if root_cfg.source != DeleteOnTerminationSource.LT_EXPLICIT:
                continue
            if root_cfg.delete_on_termination is not False:
                continue

            referencing_asgs = self._find_referencing_asgs(lt_ver, inventory)
            obs = self._make_observation(lt_ver, root_cfg.device_name, ami, referencing_asgs)
            observations.append(obs)
        return observations

    def _find_referencing_asgs(
        self, lt_ver: LaunchTemplateVersion, inventory: Inventory
    ) -> list[AutoScalingGroup]:
        lt_key = ResourceKey(
            "launch_template", lt_ver.template_id, lt_ver.region, lt_ver.account_id
        )
        asg_keys = inventory.graph.sources(lt_key, RelationshipType.ASG_USES_LAUNCH_TEMPLATE)
        result: list[AutoScalingGroup] = []
        for asg_key in asg_keys:
            asg = inventory.get_asg(asg_key.resource_id)
            if asg is None:
                continue
            eff = asg.effective_lt_ref
            if (
                eff
                and eff.template_id == lt_ver.template_id
                and eff.resolved_version_number == lt_ver.version_number
            ):
                result.append(asg)
        return result

    def _make_observation(
        self,
        lt_ver: LaunchTemplateVersion,
        device_name: str,
        ami: object,
        referencing_asgs: list[AutoScalingGroup],
    ) -> Observation:
        # ASGs with a reachable launch path (max_size > 0) → CRITICAL; others → HIGH if referenced
        reachable_asgs = [a for a in referencing_asgs if a.has_reachable_launch_path]
        is_prominent = lt_ver.is_default or lt_ver.is_latest

        evidence: list[Evidence] = [
            Evidence(
                code="LT_ROOT_DEVICE_DELETE_ON_TERMINATION_FALSE",
                kind=EvidenceKind.SUPPORTING,
                description=(
                    f"Root device '{device_name}' has DeleteOnTermination=false "
                    "explicitly set in the Launch Template BDM."
                ),
                api_source="ec2:DescribeLaunchTemplateVersions",
                value=False,
            ),
            Evidence(
                code="LT_VERSION_IS_DEFAULT",
                kind=EvidenceKind.SUPPORTING,
                description=f"Version {lt_ver.version_number} is the default version: {lt_ver.is_default}.",  # noqa: E501
                api_source="ec2:DescribeLaunchTemplates",
                value=lt_ver.is_default,
            ),
            Evidence(
                code="LT_VERSION_IS_LATEST",
                kind=EvidenceKind.SUPPORTING,
                description=f"Version {lt_ver.version_number} is the latest version: {lt_ver.is_latest}.",  # noqa: E501
                api_source="ec2:DescribeLaunchTemplates",
                value=lt_ver.is_latest,
            ),
        ]

        if referencing_asgs:
            for asg in referencing_asgs:
                eff = asg.effective_lt_ref
                evidence.append(
                    Evidence(
                        code="ASG_REFERENCES_LT_VERSION",
                        kind=EvidenceKind.SUPPORTING,
                        description=(
                            f"ASG '{asg.asg_name}' references this version "
                            f"(selector={eff.version_selector if eff else '?'}, "
                            f"resolved={lt_ver.version_number}, "
                            f"has_reachable_launch_path={asg.has_reachable_launch_path})."
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
        else:
            evidence.append(
                Evidence(
                    code="LT_VERSION_NOT_REFERENCED_BY_ACTIVE_ASG",
                    kind=EvidenceKind.CONTRADICTING,
                    description=(
                        "No active ASG currently uses this LT version as its "
                        "effective launch configuration."
                    ),
                    api_source="autoscaling:DescribeAutoScalingGroups",
                )
            )

        if ami is None:
            evidence.append(
                Evidence(
                    code="ROOT_DEVICE_RESOLUTION_INCOMPLETE",
                    kind=EvidenceKind.MISSING,
                    description=("AMI unavailable; root device identified by BDM heuristic only."),
                    api_source="ec2:DescribeImages",
                )
            )

        severity = self._severity(referencing_asgs, reachable_asgs)
        strength = self._strength(referencing_asgs, is_prominent)

        resource_ref = ResourceRef(
            resource_id=lt_ver.template_id,
            resource_type="launch_template_version",
            region=lt_ver.region,
            account_id=lt_ver.account_id,
            display_name=f"{lt_ver.template_id}:v{lt_ver.version_number}",
        )
        observation_id = (
            f"{self.rule_id}:{lt_ver.account_id}:{lt_ver.region}"
            f":launch_template_version:{lt_ver.template_id}:v{lt_ver.version_number}"
        )
        return Observation(
            observation_id=observation_id,
            rule_id=self.rule_id,
            resource_ref=resource_ref,
            severity=severity,
            decision_class=DecisionClass.CONFIGURATION_DEFECT,
            evidence=evidence,
            evidence_strength=strength,
        )

    @staticmethod
    def _severity(
        referencing_asgs: list[AutoScalingGroup],
        reachable_asgs: list[AutoScalingGroup],
    ) -> Severity:
        if reachable_asgs:
            return Severity.CRITICAL
        if referencing_asgs:
            # ASG references this version but has no reachable launch path (max_size=0)
            return Severity.HIGH
        return Severity.MEDIUM

    @staticmethod
    def _strength(referencing_asgs: list[AutoScalingGroup], is_prominent: bool) -> EvidenceStrength:
        if referencing_asgs and is_prominent:
            return EvidenceStrength.HIGH
        if referencing_asgs or is_prominent:
            return EvidenceStrength.MEDIUM
        return EvidenceStrength.LOW
