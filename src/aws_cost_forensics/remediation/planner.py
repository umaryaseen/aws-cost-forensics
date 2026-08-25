"""Context-aware remediation planner.

Produces RemediationPlan instances by reading actual case/observation context —
specifically the ASG version selector — rather than dispatching on type alone.
The correct fix for a pinned ASG differs from one using $Default or $Latest.
"""

from __future__ import annotations

from aws_cost_forensics.domain.evidence import Evidence
from aws_cost_forensics.domain.findings import (
    ForensicCase,
    Observation,
    RemediationPlan,
    RemediationStep,
)


def _step(order: int, title: str, description: str, hint: str | None = None) -> RemediationStep:
    return RemediationStep(order=order, title=title, description=description, aws_cli_hint=hint)


class RemediationPlanner:
    """Produce RemediationPlan for a ForensicCase or Observation."""

    def plan_for_case(self, case: ForensicCase) -> RemediationPlan:
        if case.case_type == "ASG_EBS_LEAK":
            return self._plan_asg_ebs_leak(case)
        # Default — shouldn't be reached in v0.1 but keeps the interface closed
        return RemediationPlan(
            priority="FIX_SOURCE_FIRST",
            steps=[
                _step(1, "Investigate root cause", case.description),
            ],
            blockers=[],
        )

    def plan_for_observation(self, obs: Observation) -> RemediationPlan:
        if obs.rule_id == "EBS_UNATTACHED_STALE":
            return self._plan_ebs_unattached_stale(obs)
        if obs.rule_id == "EBS_GP2_TO_GP3":
            return self._plan_gp2_to_gp3(obs)
        if obs.rule_id == "LT_DELETE_ON_TERMINATION_FALSE":
            return self._plan_lt_dot_false(obs)
        return RemediationPlan(
            priority="CLEAN_RESIDUE",
            steps=[_step(1, "Review finding", obs.observation_id)],
            blockers=[],
        )

    # ------------------------------------------------------------------
    # ASG_EBS_LEAK — reads evidence to derive correct ASG fix sequence
    # ------------------------------------------------------------------

    def _plan_asg_ebs_leak(self, case: ForensicCase) -> RemediationPlan:
        template_id = case.root_cause_ref.resource_id
        region = case.root_cause_ref.region

        # Collect defective ASG names and their version selectors from evidence
        defective_asg_evidence = [e for e in case.evidence if e.code == "DEFECTIVE_ASG_LAUNCH_PATH"]

        steps: list[RemediationStep] = []
        blockers: list[str] = []

        # Step 1: create a fixed LT version
        steps.append(
            _step(
                1,
                "Create a fixed Launch Template version",
                f"Create a new version of Launch Template '{template_id}' with "
                "DeleteOnTermination=true on the root block device. "
                "Do not modify the existing version — preserving history aids audit.",
                f"aws ec2 create-launch-template-version "
                f"--launch-template-id {template_id} "
                f"--region {region} "
                f"--source-version '$Latest' "
                "--launch-template-data '"
                '{"BlockDeviceMappings":[{"DeviceName":"/dev/xvda",'
                '"Ebs":{"DeleteOnTermination":true}}]}'
                "'",
            )
        )

        if defective_asg_evidence:
            # Determine which version selectors are in use from evidence descriptions
            pinned_asgs = self._extract_pinned_asgs(defective_asg_evidence)
            dynamic_asgs = self._extract_dynamic_asgs(defective_asg_evidence)

            order = 2

            if dynamic_asgs:
                # $Default or $Latest users: set the new version as default
                steps.append(
                    _step(
                        order,
                        "Set the fixed version as the new default",
                        f"Update the default version of Launch Template '{template_id}' "
                        "to the newly created fixed version. ASGs using "
                        "version_selector='$Default' or '$Latest' will automatically "
                        "pick it up on next launch.",
                        f"aws ec2 modify-launch-template "
                        f"--launch-template-id {template_id} "
                        f"--region {region} "
                        "--default-version <new-version-number>",
                    )
                )
                order += 1

            if pinned_asgs:
                # Pinned ASGs will NOT pick up a new default — must be updated explicitly
                asg_list = ", ".join(f"'{a}'" for a in pinned_asgs)
                steps.append(
                    _step(
                        order,
                        "Update pinned ASGs to the fixed version",
                        f"The following ASG(s) are pinned to an explicit version number "
                        f"and will NOT be updated by changing the default: {asg_list}. "
                        "Update each ASG's Launch Template version explicitly.",
                        f"aws autoscaling update-auto-scaling-group "
                        f"--region {region} "
                        "--auto-scaling-group-name <asg-name> "
                        "--launch-template "
                        f"LaunchTemplateId={template_id},Version=<new-version-number>",
                    )
                )
                order += 1
                blockers.append(
                    f"Pinned ASG(s) {asg_list} require explicit version update — "
                    "setting a new default is not sufficient."
                )

            steps.append(
                _step(
                    order,
                    "Initiate a rolling instance refresh",
                    "Trigger an instance refresh on affected ASG(s) so new instances "
                    "are launched with the fixed LT version. "
                    "Existing instances already running with the old template will not be affected "
                    "until the refresh completes.",
                    f"aws autoscaling start-instance-refresh "
                    f"--region {region} "
                    "--auto-scaling-group-name <asg-name>",
                )
            )
            order += 1

        steps.append(
            _step(
                len(steps) + 1,
                "Confirm no new volumes are orphaned post-refresh",
                "After the instance refresh completes, run 'acf scan' again to verify "
                "no new unattached volumes have appeared. The fix is confirmed when "
                f"no new EBS_ASG_ORPHAN_CHAIN case is emitted for template '{template_id}'.",
            )
        )

        steps.append(
            _step(
                len(steps) + 1,
                "Delete confirmed orphan volumes",
                f"Delete the {len(case.affected_resource_refs)} orphan volume(s) identified "
                "in this case after confirming they are safe to remove "
                "(no manual snapshots needed, no reattachment planned). "
                "Create a final snapshot of each before deletion if data retention is required.",
                f"aws ec2 delete-volume --region {region} --volume-id <volume-id>",
            )
        )

        return RemediationPlan(
            priority="FIX_SOURCE_FIRST",
            steps=steps,
            blockers=blockers,
        )

    # ------------------------------------------------------------------
    # EBS_UNATTACHED_STALE
    # ------------------------------------------------------------------

    def _plan_ebs_unattached_stale(self, obs: Observation) -> RemediationPlan:
        volume_id = obs.resource_ref.resource_id
        region = obs.resource_ref.region
        return RemediationPlan(
            priority="CLEAN_RESIDUE",
            steps=[
                _step(
                    1,
                    "Confirm the volume is no longer needed",
                    f"Verify that volume '{volume_id}' is not expected to be reattached "
                    "to any current or planned instance. Check tags, owner, and any "
                    "application inventory or CMDB records.",
                ),
                _step(
                    2,
                    "Create a final snapshot if data retention is required",
                    "If the volume may contain data you need to retain, "
                    "snapshot it before deletion.",
                    f"aws ec2 create-snapshot --region {region} "
                    f"--volume-id {volume_id} "
                    '--description "Pre-deletion backup"',
                ),
                _step(
                    3,
                    "Delete the volume",
                    f"Delete volume '{volume_id}' once confirmed safe.",
                    f"aws ec2 delete-volume --region {region} --volume-id {volume_id}",
                ),
            ],
            blockers=[],
        )

    # ------------------------------------------------------------------
    # EBS_GP2_TO_GP3
    # ------------------------------------------------------------------

    def _plan_gp2_to_gp3(self, obs: Observation) -> RemediationPlan:
        volume_id = obs.resource_ref.resource_id
        region = obs.resource_ref.region
        return RemediationPlan(
            priority="OPTIMIZE",
            steps=[
                _step(
                    1,
                    "Verify workload IOPS requirements",
                    f"Before migrating volume '{volume_id}', confirm the actual IOPS "
                    "consumed by the workload (via CloudWatch VolumeReadOps/VolumeWriteOps). "
                    "The cost model uses the gp2 IOPS baseline formula — actual needs may differ.",
                    f"aws cloudwatch get-metric-statistics --region {region} "
                    "--namespace AWS/EBS --metric-name VolumeReadOps "
                    f"--dimensions Name=VolumeId,Value={volume_id} "
                    "--start-time <start> --end-time <end> --period 3600 --statistics Average",
                ),
                _step(
                    2,
                    "Modify volume type to gp3",
                    f"Modify '{volume_id}' to gp3 with appropriate IOPS and throughput settings. "
                    "gp3 provides 3000 IOPS and 125 MB/s baseline at no extra cost; "
                    "provision above baseline only if your workload requires it.",
                    f"aws ec2 modify-volume --region {region} "
                    f"--volume-id {volume_id} "
                    "--volume-type gp3 "
                    "--iops 3000 --throughput 125",
                ),
                _step(
                    3,
                    "Monitor performance after migration",
                    "Watch CloudWatch metrics for 24-48 hours post-migration to confirm "
                    "the workload performs as expected on gp3.",
                ),
            ],
            blockers=[],
        )

    # ------------------------------------------------------------------
    # LT_DELETE_ON_TERMINATION_FALSE
    # ------------------------------------------------------------------

    def _plan_lt_dot_false(self, obs: Observation) -> RemediationPlan:
        # Historical versions (not default, not latest, no ASG reference) have already
        # been superseded by a corrected version — no source action needed.
        if any(e.code == "LT_VERSION_HISTORICALLY_DEFECTIVE" for e in obs.evidence):
            return RemediationPlan(
                priority="HISTORICAL",
                steps=[
                    _step(
                        1,
                        "No source remediation required",
                        "This Launch Template version is no longer the default or latest, "
                        "and no ASG currently uses it as its effective launch configuration. "
                        "The defect is preserved as forensic history only. "
                        "Verify the current active LT version has DeleteOnTermination=true.",
                    )
                ],
                blockers=[],
            )

        # Currently reachable defect — source must be fixed.
        resource_id = obs.resource_ref.resource_id
        region = obs.resource_ref.region
        return RemediationPlan(
            priority="FIX_SOURCE_FIRST",
            steps=[
                _step(
                    1,
                    "Create a new Launch Template version with DeleteOnTermination=true",
                    f"Create a new version of Launch Template '{resource_id}' "
                    "with the root block device's DeleteOnTermination set to true. "
                    "Do not edit the existing version.",
                    f"aws ec2 create-launch-template-version "
                    f"--launch-template-id {resource_id} "
                    f"--region {region} "
                    "--source-version '$Latest' "
                    "--launch-template-data '"
                    '{"BlockDeviceMappings":[{"DeviceName":"/dev/xvda",'
                    '"Ebs":{"DeleteOnTermination":true}}]}'
                    "'",
                ),
                _step(
                    2,
                    "Set the new version as default (if ASGs use $Default)",
                    "If any Auto Scaling Group references this template with '$Default', "
                    "update the default version to the newly created fixed version.",
                    f"aws ec2 modify-launch-template "
                    f"--launch-template-id {resource_id} "
                    f"--region {region} "
                    "--default-version <new-version-number>",
                ),
                _step(
                    3,
                    "Update pinned ASGs explicitly",
                    "For any ASG pinned to an explicit version number, update it directly — "
                    "changing the default version will not affect pinned ASGs.",
                    f"aws autoscaling update-auto-scaling-group "
                    f"--region {region} "
                    "--auto-scaling-group-name <asg-name> "
                    "--launch-template "
                    f"LaunchTemplateId={resource_id},Version=<new-version-number>",
                ),
                _step(
                    4,
                    "Initiate a rolling instance refresh",
                    "Trigger an instance refresh to replace running instances with "
                    "new ones launched from the fixed LT version.",
                    f"aws autoscaling start-instance-refresh "
                    f"--region {region} "
                    "--auto-scaling-group-name <asg-name>",
                ),
            ],
            blockers=[],
        )

    # ------------------------------------------------------------------
    # Helpers: parse version selector from evidence description text
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_pinned_asgs(defective_evidence: list[Evidence]) -> list[str]:
        """Return ASG names where version_selector is an explicit number."""
        pinned: list[str] = []
        for ev in defective_evidence:
            desc = ev.description
            # Evidence description format:
            # "ASG '<name>' uses defective LT version (selector=<sel>, resolved=<n>) ..."
            if "selector=$Default" in desc or "selector=$Latest" in desc:
                continue
            # Anything else is an explicit pin
            name = _extract_asg_name(desc)
            if name:
                pinned.append(name)
        return pinned

    @staticmethod
    def _extract_dynamic_asgs(defective_evidence: list[Evidence]) -> list[str]:
        """Return ASG names where version_selector is $Default or $Latest."""
        dynamic: list[str] = []
        for ev in defective_evidence:
            desc = ev.description
            if "selector=$Default" in desc or "selector=$Latest" in desc:
                name = _extract_asg_name(desc)
                if name:
                    dynamic.append(name)
        return dynamic


def _extract_asg_name(desc: str) -> str | None:
    """Parse ASG name from evidence description: "ASG '<name>' uses ..."."""
    prefix = "ASG '"
    if prefix not in desc:
        return None
    start = desc.index(prefix) + len(prefix)
    end = desc.index("'", start)
    return desc[start:end]
