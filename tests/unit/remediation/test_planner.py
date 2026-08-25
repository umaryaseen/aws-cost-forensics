"""Tests for the context-aware RemediationPlanner (T013).

Covers:
- ASG_EBS_LEAK case with $Default ASG → set-new-default step included
- ASG_EBS_LEAK case with $Latest ASG → set-new-default step included
- ASG_EBS_LEAK case with pinned ASG → update-pinned step included; blocker recorded
- ASG_EBS_LEAK with mixed selectors (pinned + dynamic) → both steps present
- ASG_EBS_LEAK with no defective ASGs (HISTORICAL) → no update-ASG steps; still fix+delete
- EBS_UNATTACHED_STALE observation → 3 steps, CLEAN_RESIDUE priority
- EBS_GP2_TO_GP3 observation → 3 steps, OPTIMIZE priority
- LT_DELETE_ON_TERMINATION_FALSE observation → 4 steps, FIX_SOURCE_FIRST priority
- Step ordering is monotonically increasing
- aws_cli_hint present for actionable steps
- priority values correct per case type
"""

from __future__ import annotations

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    RecurrenceStatus,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import ForensicCase, Observation
from aws_cost_forensics.remediation.planner import RemediationPlanner

REGION = "us-east-1"
ACCOUNT = "123456789012"
TEMPLATE_ID = "lt-aabbccdd11223344"

planner = RemediationPlanner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _root_ref(
    resource_id: str = TEMPLATE_ID, resource_type: str = "launch_template"
) -> ResourceRef:
    return ResourceRef(
        resource_id=resource_id,
        resource_type=resource_type,
        region=REGION,
        account_id=ACCOUNT,
    )


def _asg_evidence(asg_name: str, selector: str, resolved: int = 1) -> Evidence:
    return Evidence(
        code="DEFECTIVE_ASG_LAUNCH_PATH",
        kind=EvidenceKind.SUPPORTING,
        description=(
            f"ASG '{asg_name}' uses defective LT version "
            f"(selector={selector}, resolved={resolved}) with max_size=5."
        ),
        api_source="autoscaling:DescribeAutoScalingGroups",
    )


def _make_case(
    recurrence: RecurrenceStatus = RecurrenceStatus.ACTIVE,
    defective_asg_evidence: list[Evidence] | None = None,
    n_affected: int = 3,
) -> ForensicCase:
    base_evidence: list[Evidence] = [
        Evidence(
            code="ORPHAN_VOLUME_COUNT",
            kind=EvidenceKind.SUPPORTING,
            description=f"{n_affected} orphan volume(s) with confirmed lineage.",
            api_source="ec2:DescribeVolumes",
            value=n_affected,
        ),
        Evidence(
            code="RECURRENCE_STATUS",
            kind=EvidenceKind.SUPPORTING,
            description=f"{recurrence} recurrence.",
            api_source="autoscaling:DescribeAutoScalingGroups",
            value=str(recurrence),
        ),
    ]
    if defective_asg_evidence:
        base_evidence.extend(defective_asg_evidence)

    affected = [
        ResourceRef(
            resource_id=f"vol-{i:03d}",
            resource_type="ebs_volume",
            region=REGION,
            account_id=ACCOUNT,
        )
        for i in range(n_affected)
    ]
    return ForensicCase(
        case_id=f"ASG_EBS_LEAK:{ACCOUNT}:{REGION}:{TEMPLATE_ID}",
        case_type="ASG_EBS_LEAK",
        title="Test case",
        description="Test description",
        severity=Severity.HIGH,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        recurrence=recurrence,
        evidence_strength=EvidenceStrength.HIGH,
        root_cause_ref=_root_ref(),
        affected_resource_refs=affected,
        evidence=base_evidence,
    )


def _make_obs(
    rule_id: str, resource_id: str = "vol-001", resource_type: str = "ebs_volume"
) -> Observation:
    return Observation(
        observation_id=f"{rule_id}:{ACCOUNT}:{REGION}:{resource_type}:{resource_id}",
        rule_id=rule_id,
        resource_ref=ResourceRef(
            resource_id=resource_id,
            resource_type=resource_type,
            region=REGION,
            account_id=ACCOUNT,
        ),
        severity=Severity.MEDIUM,
        decision_class=DecisionClass.REMEDIATION_CANDIDATE,
        evidence=[],
        evidence_strength=EvidenceStrength.HIGH,
    )


def _step_titles(plan) -> list[str]:
    return [s.title for s in plan.steps]


def _step_orders(plan) -> list[int]:
    return [s.order for s in plan.steps]


# ---------------------------------------------------------------------------
# ASG_EBS_LEAK — FIX_SOURCE_FIRST priority
# ---------------------------------------------------------------------------


def test_asg_ebs_leak_priority_fix_source_first() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    assert plan.priority == "FIX_SOURCE_FIRST"


def test_asg_ebs_leak_first_step_create_fixed_lt_version() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    assert plan.steps[0].order == 1
    assert "fixed" in plan.steps[0].title.lower() or "create" in plan.steps[0].title.lower()
    assert TEMPLATE_ID in plan.steps[0].description
    assert plan.steps[0].aws_cli_hint is not None
    assert "create-launch-template-version" in plan.steps[0].aws_cli_hint


def test_asg_ebs_leak_last_step_delete_volumes() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    last = plan.steps[-1]
    assert "delete" in last.title.lower() or "orphan" in last.description.lower()
    assert "3" in last.description  # n_affected=3


def test_asg_ebs_leak_confirm_step_present() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    titles = _step_titles(plan)
    assert any("confirm" in t.lower() or "verify" in t.lower() for t in titles)


def test_asg_ebs_leak_step_orders_monotonic() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    orders = _step_orders(plan)
    assert orders == sorted(orders)
    assert orders[0] == 1


# ---------------------------------------------------------------------------
# $Default selector → set-new-default step
# ---------------------------------------------------------------------------


def test_dollar_default_asg_includes_set_default_step() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    descs = " ".join(s.description for s in plan.steps)
    assert "default" in descs.lower()
    assert "modify-launch-template" in " ".join(s.aws_cli_hint or "" for s in plan.steps)


def test_dollar_default_asg_no_pinned_blocker() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    assert plan.blockers == []


# ---------------------------------------------------------------------------
# $Latest selector → set-new-default step
# ---------------------------------------------------------------------------


def test_dollar_latest_asg_includes_set_default_step() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-latest", "$Latest")])
    plan = planner.plan_for_case(case)
    descs = " ".join(s.description for s in plan.steps)
    assert "default" in descs.lower()


def test_dollar_latest_asg_no_pinned_blocker() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-latest", "$Latest")])
    plan = planner.plan_for_case(case)
    assert plan.blockers == []


# ---------------------------------------------------------------------------
# Pinned ASG → explicit update step + blocker
# ---------------------------------------------------------------------------


def test_pinned_asg_includes_update_asg_step() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-pinned", "3", resolved=3)])
    plan = planner.plan_for_case(case)
    descs = " ".join(s.description + (s.aws_cli_hint or "") for s in plan.steps)
    assert "pinned" in descs.lower() or "explicit" in descs.lower()
    assert "update-auto-scaling-group" in descs


def test_pinned_asg_records_blocker() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-pinned", "3", resolved=3)])
    plan = planner.plan_for_case(case)
    assert len(plan.blockers) >= 1
    assert "asg-pinned" in plan.blockers[0]


def test_pinned_asg_no_set_default_step() -> None:
    # Pinned ASG does not benefit from a "set new default" step
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-pinned", "3", resolved=3)])
    plan = planner.plan_for_case(case)
    # Should NOT include the "modify-launch-template" step (that's for $Default/$Latest only)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert "modify-launch-template" not in hints


# ---------------------------------------------------------------------------
# Mixed selectors: one $Default + one pinned → both steps present
# ---------------------------------------------------------------------------


def test_mixed_selectors_both_steps_present() -> None:
    case = _make_case(
        defective_asg_evidence=[
            _asg_evidence("asg-dynamic", "$Default"),
            _asg_evidence("asg-pinned", "2", resolved=2),
        ]
    )
    plan = planner.plan_for_case(case)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert "modify-launch-template" in hints  # for $Default
    assert "update-auto-scaling-group" in hints  # for pinned
    assert len(plan.blockers) >= 1


# ---------------------------------------------------------------------------
# No defective ASGs (HISTORICAL or UNKNOWN) — no ASG update steps
# ---------------------------------------------------------------------------


def test_historical_case_no_asg_update_steps() -> None:
    case = _make_case(
        recurrence=RecurrenceStatus.HISTORICAL,
        defective_asg_evidence=None,
    )
    plan = planner.plan_for_case(case)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    # No ASG update hints needed — all ASGs already fixed
    assert "update-auto-scaling-group" not in hints
    assert "modify-launch-template" not in hints
    # Still creates fixed LT version + delete volumes
    assert "create-launch-template-version" in hints
    assert plan.priority == "FIX_SOURCE_FIRST"


def test_historical_case_no_blockers() -> None:
    case = _make_case(recurrence=RecurrenceStatus.HISTORICAL)
    assert planner.plan_for_case(case).blockers == []


# ---------------------------------------------------------------------------
# Instance refresh step present when defective ASGs exist
# ---------------------------------------------------------------------------


def test_instance_refresh_step_present_for_active_case() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert "start-instance-refresh" in hints


# ---------------------------------------------------------------------------
# EBS_UNATTACHED_STALE observation
# ---------------------------------------------------------------------------


def test_ebs_unattached_stale_priority() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    assert planner.plan_for_observation(obs).priority == "CLEAN_RESIDUE"


def test_ebs_unattached_stale_three_steps() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    plan = planner.plan_for_observation(obs)
    assert len(plan.steps) == 3


def test_ebs_unattached_stale_step_orders() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    plan = planner.plan_for_observation(obs)
    assert _step_orders(plan) == [1, 2, 3]


def test_ebs_unattached_stale_volume_id_in_steps() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    plan = planner.plan_for_observation(obs)
    all_text = " ".join(s.description + (s.aws_cli_hint or "") for s in plan.steps)
    assert "vol-dead" in all_text


def test_ebs_unattached_stale_snapshot_step_present() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    plan = planner.plan_for_observation(obs)
    titles = _step_titles(plan)
    assert any("snapshot" in t.lower() for t in titles)


def test_ebs_unattached_stale_delete_step_has_hint() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    plan = planner.plan_for_observation(obs)
    delete_step = plan.steps[-1]
    assert delete_step.aws_cli_hint is not None
    assert "delete-volume" in delete_step.aws_cli_hint


def test_ebs_unattached_stale_no_blockers() -> None:
    assert planner.plan_for_observation(_make_obs("EBS_UNATTACHED_STALE")).blockers == []


# ---------------------------------------------------------------------------
# EBS_GP2_TO_GP3 observation
# ---------------------------------------------------------------------------


def test_gp2_to_gp3_priority() -> None:
    obs = _make_obs("EBS_GP2_TO_GP3", "vol-old")
    assert planner.plan_for_observation(obs).priority == "OPTIMIZE"


def test_gp2_to_gp3_three_steps() -> None:
    obs = _make_obs("EBS_GP2_TO_GP3", "vol-old")
    assert len(planner.plan_for_observation(obs).steps) == 3


def test_gp2_to_gp3_step_orders() -> None:
    obs = _make_obs("EBS_GP2_TO_GP3", "vol-old")
    assert _step_orders(planner.plan_for_observation(obs)) == [1, 2, 3]


def test_gp2_to_gp3_modify_volume_hint() -> None:
    obs = _make_obs("EBS_GP2_TO_GP3", "vol-old")
    plan = planner.plan_for_observation(obs)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert "modify-volume" in hints
    assert "gp3" in hints


def test_gp2_to_gp3_iops_check_first() -> None:
    obs = _make_obs("EBS_GP2_TO_GP3", "vol-old")
    plan = planner.plan_for_observation(obs)
    first_step = plan.steps[0]
    hint = (first_step.aws_cli_hint or "").lower()
    assert "iops" in first_step.description.lower() or "cloudwatch" in hint


def test_gp2_to_gp3_no_blockers() -> None:
    assert planner.plan_for_observation(_make_obs("EBS_GP2_TO_GP3")).blockers == []


# ---------------------------------------------------------------------------
# LT_DELETE_ON_TERMINATION_FALSE observation
# ---------------------------------------------------------------------------


def test_lt_dot_false_priority() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    assert planner.plan_for_observation(obs).priority == "FIX_SOURCE_FIRST"


def test_lt_dot_false_four_steps() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    plan = planner.plan_for_observation(obs)
    assert len(plan.steps) == 4


def test_lt_dot_false_step_orders() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    assert _step_orders(planner.plan_for_observation(obs)) == [1, 2, 3, 4]


def test_lt_dot_false_create_version_hint() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    plan = planner.plan_for_observation(obs)
    assert "create-launch-template-version" in (plan.steps[0].aws_cli_hint or "")


def test_lt_dot_false_update_pinned_step_present() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    plan = planner.plan_for_observation(obs)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert "update-auto-scaling-group" in hints


def test_lt_dot_false_instance_refresh_step_present() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    plan = planner.plan_for_observation(obs)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert "start-instance-refresh" in hints


def test_lt_dot_false_no_blockers() -> None:
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    assert planner.plan_for_observation(obs).blockers == []


# ---------------------------------------------------------------------------
# Region included in CLI hints
# ---------------------------------------------------------------------------


def test_region_in_cli_hints_for_case() -> None:
    case = _make_case(defective_asg_evidence=[_asg_evidence("asg-prod", "$Default")])
    plan = planner.plan_for_case(case)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert REGION in hints


def test_region_in_cli_hints_for_stale_obs() -> None:
    obs = _make_obs("EBS_UNATTACHED_STALE", "vol-dead")
    plan = planner.plan_for_observation(obs)
    hints = " ".join(s.aws_cli_hint or "" for s in plan.steps)
    assert REGION in hints


# ---------------------------------------------------------------------------
# LT_DELETE_ON_TERMINATION_FALSE — historical defect (source already corrected)
# ---------------------------------------------------------------------------


def _make_historical_lt_obs(template_id: str = TEMPLATE_ID, version: int = 5) -> Observation:
    """Observation for a historical LT defect (LT_VERSION_HISTORICALLY_DEFECTIVE evidence)."""
    return Observation(
        observation_id=(
            f"LT_DELETE_ON_TERMINATION_FALSE:{ACCOUNT}:{REGION}"
            f":launch_template_version:{template_id}:v{version}"
        ),
        rule_id="LT_DELETE_ON_TERMINATION_FALSE",
        resource_ref=ResourceRef(
            resource_id=template_id,
            resource_type="launch_template_version",
            region=REGION,
            account_id=ACCOUNT,
        ),
        severity=Severity.INFO,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        evidence=[
            Evidence(
                code="LT_VERSION_HISTORICALLY_DEFECTIVE",
                kind=EvidenceKind.SUPPORTING,
                description=f"Version {version} is historical; source already corrected.",
                api_source="ec2:DescribeLaunchTemplates",
                value=version,
            ),
            Evidence(
                code="LT_VERSION_NOT_REFERENCED_BY_ACTIVE_ASG",
                kind=EvidenceKind.CONTRADICTING,
                description="No active ASG uses this version.",
                api_source="autoscaling:DescribeAutoScalingGroups",
            ),
        ],
        evidence_strength=EvidenceStrength.LOW,
    )


def test_historical_lt_obs_priority_is_historical() -> None:
    obs = _make_historical_lt_obs()
    plan = planner.plan_for_observation(obs)
    assert plan.priority == "HISTORICAL"


def test_historical_lt_obs_has_one_step() -> None:
    obs = _make_historical_lt_obs()
    plan = planner.plan_for_observation(obs)
    assert len(plan.steps) == 1


def test_historical_lt_obs_no_blockers() -> None:
    obs = _make_historical_lt_obs()
    plan = planner.plan_for_observation(obs)
    assert plan.blockers == []


def test_historical_lt_obs_step_has_no_cli_hint() -> None:
    obs = _make_historical_lt_obs()
    plan = planner.plan_for_observation(obs)
    assert plan.steps[0].aws_cli_hint is None


def test_historical_lt_obs_no_create_lt_version_instruction() -> None:
    obs = _make_historical_lt_obs()
    plan = planner.plan_for_observation(obs)
    combined = " ".join(s.title + " " + (s.description or "") for s in plan.steps)
    assert "create-launch-template-version" not in combined
    assert "create a new" not in combined.lower()


def test_current_lt_obs_still_gets_fix_source_first() -> None:
    """Observation without LT_VERSION_HISTORICALLY_DEFECTIVE → FIX_SOURCE_FIRST unchanged."""
    obs = _make_obs("LT_DELETE_ON_TERMINATION_FALSE", TEMPLATE_ID, "launch_template_version")
    plan = planner.plan_for_observation(obs)
    assert plan.priority == "FIX_SOURCE_FIRST"
    assert len(plan.steps) == 4
