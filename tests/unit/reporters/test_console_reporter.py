"""Tests for ConsoleReporter."""

from __future__ import annotations

import io
from datetime import UTC, datetime
from decimal import Decimal

from rich.console import Console

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    RecurrenceStatus,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import (
    CostEstimate,
    ForensicCase,
    Observation,
    RemediationPlan,
    RemediationStep,
)
from aws_cost_forensics.domain.inventory import ScanError, ScanResult, ScanSummary
from aws_cost_forensics.reporters.console import ConsoleReporter, _mask_acct

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _con() -> tuple[Console, io.StringIO]:
    buf = io.StringIO()
    return Console(file=buf, no_color=True, width=120), buf


def _ref(resource_id: str = "vol-abc123", resource_type: str = "ebs_volume") -> ResourceRef:
    return ResourceRef(
        resource_id=resource_id,
        resource_type=resource_type,
        region="eu-central-1",
        account_id="123456789012",
        display_name=None,
    )


def _evidence() -> Evidence:
    return Evidence(
        code="VOLUME_UNATTACHED",
        kind=EvidenceKind.SUPPORTING,
        description="Volume has no attachments.",
        api_source="ec2:DescribeVolumes",
    )


def _cost(monthly: str = "10.00", saving: str | None = "10.00") -> CostEstimate:
    return CostEstimate(
        monthly_cost_usd=Decimal(monthly),
        potential_saving_usd=Decimal(saving) if saving else None,
        pricing_source="static",
    )


def _plan(priority: str = "CLEAN_RESIDUE") -> RemediationPlan:
    return RemediationPlan(
        priority=priority,
        steps=[
            RemediationStep(
                order=1,
                title="Verify no reattachment needed",
                description="Check that no workload requires this volume.",
                aws_cli_hint="aws ec2 describe-volumes --volume-ids vol-abc123",
            )
        ],
        blockers=[],
    )


def _obs(
    rule_id: str = "EBS_UNATTACHED_STALE",
    resource_id: str = "vol-abc123",
    severity: Severity = Severity.MEDIUM,
    superseded_by: str | None = None,
    cost: CostEstimate | None = None,
    plan: RemediationPlan | None = None,
) -> Observation:
    return Observation(
        observation_id=f"{rule_id}:123456789012:eu-central-1:ebs_volume:{resource_id}",
        rule_id=rule_id,
        resource_ref=_ref(resource_id),
        severity=severity,
        decision_class=DecisionClass.REMEDIATION_CANDIDATE,
        evidence=[_evidence()],
        evidence_strength=EvidenceStrength.HIGH,
        cost_estimate=cost,
        remediation_plan=plan,
        superseded_by=superseded_by,
    )


def _case(
    case_id: str = "ASG_EBS_LEAK:123456789012:eu-central-1:lt-001",
    cost: CostEstimate | None = None,
    plan: RemediationPlan | None = None,
    recurrence: RecurrenceStatus = RecurrenceStatus.ACTIVE,
) -> ForensicCase:
    return ForensicCase(
        case_id=case_id,
        case_type="ASG_EBS_LEAK",
        title="ASG EBS orphan chain traced to Launch Template: lt-001",
        description="46 orphan volumes linked to DeleteOnTermination=false in LT.",
        severity=Severity.HIGH,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        recurrence=recurrence,
        evidence_strength=EvidenceStrength.HIGH,
        root_cause_ref=_ref("lt-001", "launch_template"),
        affected_resource_refs=[_ref("vol-abc123")],
        evidence=[_evidence()],
        cost_estimate=cost,
        remediation_plan=plan,
    )


def _summary(
    n_cases: int = 0,
    n_obs: int = 0,
    n_superseded: int = 0,
    n_affected: int = 0,
    waste: str | None = None,
    active_recurrence: bool = False,
    n_errors: int = 0,
) -> ScanSummary:
    return ScanSummary(
        forensic_cases=n_cases,
        observations=n_obs,
        observations_superseded=n_superseded,
        affected_resources=n_affected,
        total_monthly_waste_usd=Decimal(waste) if waste else None,
        has_active_recurrence=active_recurrence,
        scan_errors=n_errors,
    )


def _result(
    forensic_cases: list[ForensicCase] | None = None,
    observations: list[Observation] | None = None,
    scan_errors: list[ScanError] | None = None,
    summary: ScanSummary | None = None,
) -> ScanResult:
    forensic_cases = forensic_cases or []
    observations = observations or []
    scan_errors = scan_errors or []
    if summary is None:
        summary = _summary()
    return ScanResult(
        tool_version="0.1.0",
        generated_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        account_id="123456789012",
        region="eu-central-1",
        pricing_source="static",
        observations=observations,
        forensic_cases=forensic_cases,
        scan_errors=scan_errors,
        summary=summary,
    )


# ---------------------------------------------------------------------------
# _mask_acct
# ---------------------------------------------------------------------------


def test_mask_acct_masks_last_four() -> None:
    assert _mask_acct("123456789012", mask=True) == "****9012"


def test_mask_acct_no_mask_returns_full() -> None:
    assert _mask_acct("123456789012", mask=False) == "123456789012"


def test_mask_acct_short_id_returns_as_is() -> None:
    assert _mask_acct("abc", mask=True) == "abc"


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------


def test_header_shows_tool_version() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    out = buf.getvalue()
    assert "v0.1.0" in out


def test_header_shows_schema_version() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    out = buf.getvalue()
    assert "schema 1.0" in out


def test_header_shows_region() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    assert "eu-central-1" in buf.getvalue()


def test_header_shows_pricing_source() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    assert "static" in buf.getvalue()


# ---------------------------------------------------------------------------
# Account ID masking
# ---------------------------------------------------------------------------


def test_account_id_masked_by_default() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    out = buf.getvalue()
    assert "****9012" in out
    assert "123456789012" not in out


def test_account_id_shown_when_masking_disabled() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con, mask_account_id=False)
    assert "123456789012" in buf.getvalue()


# ---------------------------------------------------------------------------
# Scan errors shown as warnings
# ---------------------------------------------------------------------------


def test_scan_errors_shown_as_warnings() -> None:
    err = ScanError(
        collector="autoscaling",
        error_code="PERMISSION_DENIED",
        message="Access denied to DescribeAutoScalingGroups",
        is_permission_error=True,
    )
    con, buf = _con()
    ConsoleReporter().render(
        _result(scan_errors=[err], summary=_summary(n_errors=1)),
        console=con,
    )
    out = buf.getvalue()
    assert "PARTIAL SCAN" in out
    assert "autoscaling" in out
    assert "PERMISSION_DENIED" in out


def test_no_partial_scan_banner_when_no_errors() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    assert "PARTIAL SCAN" not in buf.getvalue()


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_summary_shows_waste_when_available() -> None:
    con, buf = _con()
    ConsoleReporter().render(
        _result(summary=_summary(waste="274.40")),
        console=con,
    )
    assert "$274.40" in buf.getvalue()


def test_summary_shows_pricing_unavailable_when_none() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(summary=_summary(waste=None)), console=con)
    assert "pricing unavailable" in buf.getvalue()


def test_summary_shows_active_recurrence_flag() -> None:
    con, buf = _con()
    ConsoleReporter().render(
        _result(summary=_summary(n_cases=1, active_recurrence=True)),
        console=con,
    )
    assert "ACTIVE recurrence" in buf.getvalue()


def test_summary_shows_superseded_count() -> None:
    con, buf = _con()
    ConsoleReporter().render(
        _result(summary=_summary(n_obs=5, n_superseded=3)),
        console=con,
    )
    assert "3 superseded" in buf.getvalue()


# ---------------------------------------------------------------------------
# Forensic cases section
# ---------------------------------------------------------------------------


def test_forensic_case_appears_before_observations() -> None:
    case = _case()
    obs = _obs(rule_id="EBS_GP2_TO_GP3", resource_id="vol-gp2")
    con, buf = _con()
    ConsoleReporter().render(
        _result(forensic_cases=[case], observations=[obs]),
        console=con,
    )
    out = buf.getvalue()
    assert out.index("ASG_EBS_LEAK") < out.index("EBS_GP2_TO_GP3")


def test_forensic_case_shows_title() -> None:
    case = _case()
    con, buf = _con()
    ConsoleReporter().render(_result(forensic_cases=[case]), console=con)
    assert "ASG EBS orphan chain traced to Launch Template" in buf.getvalue()


def test_forensic_case_shows_recurrence() -> None:
    case = _case(recurrence=RecurrenceStatus.HISTORICAL)
    con, buf = _con()
    ConsoleReporter().render(_result(forensic_cases=[case]), console=con)
    assert "HISTORICAL" in buf.getvalue()


def test_forensic_case_shows_cost() -> None:
    case = _case(cost=_cost("274.40", "274.40"))
    con, buf = _con()
    ConsoleReporter().render(_result(forensic_cases=[case]), console=con)
    assert "$274.40" in buf.getvalue()


def test_forensic_case_shows_root_cause() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(forensic_cases=[_case()]), console=con)
    assert "lt-001" in buf.getvalue()
    assert "launch_template" in buf.getvalue()


def test_forensic_case_shows_remediation_plan() -> None:
    case = _case(plan=_plan("FIX_SOURCE_FIRST"))
    con, buf = _con()
    ConsoleReporter().render(_result(forensic_cases=[case]), console=con)
    out = buf.getvalue()
    assert "FIX_SOURCE_FIRST" in out
    assert "Verify no reattachment needed" in out


# ---------------------------------------------------------------------------
# Superseded observations shown under their case, not in main list
# ---------------------------------------------------------------------------


def test_superseded_obs_shown_under_case() -> None:
    case_id = "ASG_EBS_LEAK:123456789012:eu-central-1:lt-001"
    case = _case(case_id=case_id)
    sup_obs = _obs(
        rule_id="EBS_UNATTACHED_STALE",
        resource_id="vol-superseded",
        superseded_by=case_id,
    )
    con, buf = _con()
    ConsoleReporter().render(
        _result(forensic_cases=[case], observations=[sup_obs]),
        console=con,
    )
    out = buf.getvalue()
    # superseded volume appears in output
    assert "vol-superseded" in out
    # it appears AFTER the case headline
    assert out.index("ASG_EBS_LEAK") < out.index("vol-superseded")


def test_superseded_obs_not_in_active_observations_section() -> None:
    case_id = "ASG_EBS_LEAK:123456789012:eu-central-1:lt-001"
    case = _case(case_id=case_id)
    sup_obs = _obs(superseded_by=case_id)
    con, buf = _con()
    ConsoleReporter().render(
        _result(forensic_cases=[case], observations=[sup_obs]),
        console=con,
    )
    # "Active Observations" section should not appear — all obs are superseded
    assert "Active Observations" not in buf.getvalue()


def test_gp2_superseded_shows_suppression_note() -> None:
    case_id = "ASG_EBS_LEAK:123456789012:eu-central-1:lt-001"
    case = _case(case_id=case_id)
    sup_obs = _obs(
        rule_id="EBS_GP2_TO_GP3",
        resource_id="vol-gp2",
        superseded_by=case_id,
        cost=_cost("10.00", "1.50"),
    )
    con, buf = _con()
    ConsoleReporter().render(
        _result(forensic_cases=[case], observations=[sup_obs]),
        console=con,
    )
    assert "suppressed" in buf.getvalue()


def test_active_obs_in_active_section_when_some_superseded() -> None:
    case_id = "ASG_EBS_LEAK:123456789012:eu-central-1:lt-001"
    case = _case(case_id=case_id)
    sup_obs = _obs(resource_id="vol-sup", superseded_by=case_id)
    active_obs = _obs(rule_id="EBS_GP2_TO_GP3", resource_id="vol-active")
    con, buf = _con()
    ConsoleReporter().render(
        _result(forensic_cases=[case], observations=[sup_obs, active_obs]),
        console=con,
    )
    out = buf.getvalue()
    assert "Active Observations" in out
    assert "vol-active" in out


# ---------------------------------------------------------------------------
# Active observations section
# ---------------------------------------------------------------------------


def test_active_observation_shows_rule_id() -> None:
    obs = _obs(rule_id="EBS_UNATTACHED_STALE")
    con, buf = _con()
    ConsoleReporter().render(_result(observations=[obs]), console=con)
    assert "EBS_UNATTACHED_STALE" in buf.getvalue()


def test_active_observation_shows_resource_id() -> None:
    obs = _obs(resource_id="vol-xyz")
    con, buf = _con()
    ConsoleReporter().render(_result(observations=[obs]), console=con)
    assert "vol-xyz" in buf.getvalue()


def test_active_observation_shows_cost_saving() -> None:
    obs = _obs(cost=_cost("10.00", "1.20"), rule_id="EBS_GP2_TO_GP3")
    con, buf = _con()
    ConsoleReporter().render(_result(observations=[obs]), console=con)
    assert "save $1.20" in buf.getvalue()


def test_active_observation_shows_remediation() -> None:
    obs = _obs(plan=_plan("OPTIMIZE"))
    con, buf = _con()
    ConsoleReporter().render(_result(observations=[obs]), console=con)
    assert "OPTIMIZE" in buf.getvalue()


# ---------------------------------------------------------------------------
# Empty result
# ---------------------------------------------------------------------------


def test_no_findings_message_when_clean() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    assert "No findings" in buf.getvalue()


def test_no_crash_on_minimal_result() -> None:
    con, buf = _con()
    ConsoleReporter().render(_result(), console=con)
    # Just check it ran without error
    assert len(buf.getvalue()) > 0


# ---------------------------------------------------------------------------
# Historical LT observations — collapsed reporter rendering
# ---------------------------------------------------------------------------


def _historical_lt_obs(
    template_id: str = "lt-aabbccdd",
    version: int = 5,
    region: str = "eu-central-1",
) -> Observation:
    """Build a historical LT defect observation (source already corrected)."""
    return Observation(
        observation_id=(
            f"LT_DELETE_ON_TERMINATION_FALSE:123456789012:{region}"
            f":launch_template_version:{template_id}:v{version}"
        ),
        rule_id="LT_DELETE_ON_TERMINATION_FALSE",
        resource_ref=ResourceRef(
            resource_id=template_id,
            resource_type="launch_template_version",
            region=region,
            account_id="123456789012",
            display_name=f"{template_id}:v{version}",
        ),
        severity=Severity.INFO,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        evidence=[
            Evidence(
                code="LT_VERSION_HISTORICALLY_DEFECTIVE",
                kind=EvidenceKind.SUPPORTING,
                description=f"Version {version} is historical.",
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


def test_historical_lt_obs_collapsed_into_single_block() -> None:
    """Multiple historical versions of the same template → one summary block."""
    obs_list = [_historical_lt_obs(version=v) for v in range(1, 6)]  # v1-v5
    con, buf = _con()
    ConsoleReporter().render(
        _result(observations=obs_list, summary=_summary(n_obs=5)),
        console=con,
    )
    out = buf.getvalue()
    # Should appear once, not five times
    assert out.count("lt-aabbccdd") <= 2  # template ID in header and one summary line


def test_historical_lt_obs_shows_version_range() -> None:
    """Collapsed block shows defective version range."""
    obs_list = [_historical_lt_obs(version=v) for v in [1, 2, 3]]
    con, buf = _con()
    ConsoleReporter().render(
        _result(observations=obs_list, summary=_summary(n_obs=3)),
        console=con,
    )
    out = buf.getvalue()
    assert "v1" in out
    assert "v3" in out


def test_historical_lt_obs_shows_corrected_message() -> None:
    """Collapsed block states source is corrected."""
    obs_list = [_historical_lt_obs(version=1)]
    con, buf = _con()
    ConsoleReporter().render(
        _result(observations=obs_list, summary=_summary(n_obs=1)),
        console=con,
    )
    out = buf.getvalue()
    assert "corrected" in out.lower() or "no source remediation" in out.lower()


def test_historical_lt_obs_does_not_repeat_fix_source_steps() -> None:
    """Multiple historical versions do NOT each print FIX_SOURCE_FIRST remediation."""
    # Give each obs a HISTORICAL plan (as the planner would)
    plan = RemediationPlan(
        priority="HISTORICAL",
        steps=[RemediationStep(order=1, title="No action", description="Source corrected.")],
        blockers=[],
    )
    obs_list = [
        Observation(
            observation_id=(
                f"LT_DELETE_ON_TERMINATION_FALSE:123456789012:eu-central-1"
                f":launch_template_version:lt-aabbccdd:v{v}"
            ),
            rule_id="LT_DELETE_ON_TERMINATION_FALSE",
            resource_ref=ResourceRef(
                resource_id="lt-aabbccdd",
                resource_type="launch_template_version",
                region="eu-central-1",
                account_id="123456789012",
            ),
            severity=Severity.INFO,
            decision_class=DecisionClass.CONFIGURATION_DEFECT,
            evidence=[
                Evidence(
                    code="LT_VERSION_HISTORICALLY_DEFECTIVE",
                    kind=EvidenceKind.SUPPORTING,
                    description=f"Version {v} is historical.",
                    api_source="ec2:DescribeLaunchTemplates",
                    value=v,
                )
            ],
            evidence_strength=EvidenceStrength.LOW,
            remediation_plan=plan,
        )
        for v in range(1, 6)
    ]
    con, buf = _con()
    ConsoleReporter().render(
        _result(observations=obs_list, summary=_summary(n_obs=5)),
        console=con,
    )
    out = buf.getvalue()
    # FIX_SOURCE_FIRST must not appear
    assert "FIX_SOURCE_FIRST" not in out
    # create-launch-template-version must not appear
    assert "create-launch-template-version" not in out


def test_normal_observations_still_rendered_alongside_historical() -> None:
    """Non-historical observations continue to render normally when historical ones are present."""
    stale_obs = _obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-stale")
    hist_obs = _historical_lt_obs(version=10)
    con, buf = _con()
    ConsoleReporter().render(
        _result(observations=[stale_obs, hist_obs], summary=_summary(n_obs=2)),
        console=con,
    )
    out = buf.getvalue()
    assert "EBS_UNATTACHED_STALE" in out
    assert "vol-stale" in out
    # Historical block also present
    assert "lt-aabbccdd" in out
