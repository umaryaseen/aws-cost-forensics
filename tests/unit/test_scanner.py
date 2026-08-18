"""Tests for the Scanner orchestrator (T014).

Covers:
- _collect_safe: success, CollectionError, unexpected exception
- _apply_supersession: correct supersession by rule_id and resource_id
- _price_observations: fills cost_estimate on EBS_UNATTACHED_STALE
- _price_cases: aggregates volume costs for ForensicCase
- _build_summary: correct counts, waste totals, None when all unavailable
- Scanner.run(): end-to-end with mocked collectors; error propagation
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    RecurrenceStatus,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import CostEstimate, ForensicCase, Observation
from aws_cost_forensics.domain.inventory import Inventory, ScanError, ScanResult
from aws_cost_forensics.domain.resources import EBSVolume
from aws_cost_forensics.scanner import (
    ScanConfig,
    Scanner,
    _apply_supersession,
    _build_summary,
    _collect_safe,
    _price_cases,
    _price_observations,
)

REGION = "eu-central-1"
ACCOUNT = "123456789012"
NOW = datetime(2024, 6, 1, tzinfo=UTC)

# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _resource_ref(
    resource_id: str = "vol-001",
    resource_type: str = "ebs_volume",
    region: str = REGION,
    account_id: str = ACCOUNT,
) -> ResourceRef:
    return ResourceRef(
        resource_id=resource_id,
        resource_type=resource_type,
        region=region,
        account_id=account_id,
    )


def _evidence() -> Evidence:
    return Evidence(
        code="VOLUME_UNATTACHED",
        kind=EvidenceKind.SUPPORTING,
        description="Volume has no EC2 attachments.",
        api_source="ec2:DescribeVolumes",
    )


def _make_obs(
    rule_id: str = "EBS_UNATTACHED_STALE",
    resource_id: str = "vol-001",
    *,
    cost_estimate: CostEstimate | None = None,
    superseded_by: str | None = None,
) -> Observation:
    return Observation(
        observation_id=f"{rule_id}:{ACCOUNT}:{REGION}:ebs_volume:{resource_id}",
        rule_id=rule_id,
        resource_ref=_resource_ref(resource_id=resource_id),
        severity=Severity.MEDIUM,
        decision_class=DecisionClass.REMEDIATION_CANDIDATE,
        evidence=[_evidence()],
        evidence_strength=EvidenceStrength.HIGH,
        cost_estimate=cost_estimate,
        superseded_by=superseded_by,
    )


def _make_case(
    case_id: str = "ASG_EBS_LEAK:123:eu-central-1:lt-001",
    affected_ids: list[str] | None = None,
    *,
    recurrence: RecurrenceStatus = RecurrenceStatus.ACTIVE,
    cost_estimate: CostEstimate | None = None,
) -> ForensicCase:
    if affected_ids is None:
        affected_ids = ["vol-001"]
    return ForensicCase(
        case_id=case_id,
        case_type="ASG_EBS_LEAK",
        title="Test case",
        description="Test description",
        severity=Severity.HIGH,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        recurrence=recurrence,
        evidence_strength=EvidenceStrength.HIGH,
        root_cause_ref=_resource_ref(resource_id="lt-001", resource_type="launch_template"),
        affected_resource_refs=[_resource_ref(resource_id=vid) for vid in affected_ids],
        evidence=[_evidence()],
        cost_estimate=cost_estimate,
    )


def _make_volume(
    volume_id: str = "vol-001",
    volume_type: str = "gp2",
    size_gib: int = 100,
    region: str = REGION,
) -> EBSVolume:
    return EBSVolume(
        volume_id=volume_id,
        region=region,
        account_id=ACCOUNT,
        state="available",
        size_gib=size_gib,
        volume_type=volume_type,
        create_time=NOW - timedelta(days=60),
        availability_zone=f"{region}a",
    )


def _make_inventory(volumes: list[EBSVolume] | None = None) -> Inventory:
    return Inventory(
        account_id=ACCOUNT,
        region=REGION,
        scanned_at=NOW,
        volumes=volumes or [],
        snapshots=[],
        amis=[],
        instances=[],
        launch_template_versions=[],
        auto_scaling_groups=[],
    )


def _make_cost_estimate(monthly: str = "10.00") -> CostEstimate:
    return CostEstimate(
        monthly_cost_usd=Decimal(monthly),
        potential_saving_usd=Decimal(monthly),
        pricing_source="static_table_v1",
    )


# ---------------------------------------------------------------------------
# _collect_safe
# ---------------------------------------------------------------------------


def test_collect_safe_success():
    scan_errors: list[ScanError] = []
    result = _collect_safe("x", lambda: [1, 2, 3], scan_errors, [])
    assert result == [1, 2, 3]
    assert scan_errors == []


def test_collect_safe_collection_error_records_scan_error():
    scan_errors: list[ScanError] = []

    def _fail() -> list[str]:
        raise CollectionError("ebs", "Access denied", is_permission_error=True)

    result = _collect_safe("ebs", _fail, scan_errors, [])
    assert result == []
    assert len(scan_errors) == 1
    err = scan_errors[0]
    assert err.collector == "ebs"
    assert err.error_code == "PERMISSION_DENIED"
    assert err.is_permission_error is True


def test_collect_safe_non_permission_collection_error():
    scan_errors: list[ScanError] = []

    def _fail() -> list[str]:
        raise CollectionError("snapshots", "Throttled", is_permission_error=False)

    _collect_safe("snapshots", _fail, scan_errors, [])
    assert scan_errors[0].error_code == "COLLECTION_FAILED"
    assert scan_errors[0].is_permission_error is False


def test_collect_safe_unexpected_exception():
    scan_errors: list[ScanError] = []

    def _fail() -> list[str]:
        raise RuntimeError("boom")

    result = _collect_safe("amis", _fail, scan_errors, [])
    assert result == []
    assert scan_errors[0].error_code == "UNEXPECTED_ERROR"
    assert scan_errors[0].collector == "amis"
    assert scan_errors[0].is_permission_error is False


def test_collect_safe_dict_default():
    scan_errors: list[ScanError] = []

    def _fail() -> dict[str, int]:
        raise CollectionError("lt", "Fail")

    result: dict[str, int] = _collect_safe("lt", _fail, scan_errors, {})
    assert result == {}


# ---------------------------------------------------------------------------
# _apply_supersession
# ---------------------------------------------------------------------------


def test_apply_supersession_marks_matching_observation():
    case = _make_case(affected_ids=["vol-001"])
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-001")
    result = _apply_supersession([obs], [case], ["EBS_UNATTACHED_STALE", "EBS_GP2_TO_GP3"])
    assert result[0].superseded_by == case.case_id


def test_apply_supersession_skips_rule_not_in_supersedes():
    case = _make_case(affected_ids=["vol-001"])
    obs = _make_obs(rule_id="LT_DELETE_ON_TERMINATION_FALSE", resource_id="vol-001")
    result = _apply_supersession([obs], [case], ["EBS_UNATTACHED_STALE"])
    assert result[0].superseded_by is None


def test_apply_supersession_skips_resource_not_in_case():
    case = _make_case(affected_ids=["vol-999"])
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-001")
    result = _apply_supersession([obs], [case], ["EBS_UNATTACHED_STALE"])
    assert result[0].superseded_by is None


def test_apply_supersession_gp2_to_gp3_also_superseded():
    case = _make_case(affected_ids=["vol-001"])
    obs = _make_obs(rule_id="EBS_GP2_TO_GP3", resource_id="vol-001")
    result = _apply_supersession([obs], [case], ["EBS_UNATTACHED_STALE", "EBS_GP2_TO_GP3"])
    assert result[0].superseded_by == case.case_id


def test_apply_supersession_correct_case_id_assigned():
    case_a = _make_case(case_id="CASE:A", affected_ids=["vol-a"])
    case_b = _make_case(case_id="CASE:B", affected_ids=["vol-b"])
    obs_a = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-a")
    obs_b = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-b")
    result = _apply_supersession([obs_a, obs_b], [case_a, case_b], ["EBS_UNATTACHED_STALE"])
    assert result[0].superseded_by == "CASE:A"
    assert result[1].superseded_by == "CASE:B"


def test_apply_supersession_empty_inputs():
    result = _apply_supersession([], [], ["EBS_UNATTACHED_STALE"])
    assert result == []


# ---------------------------------------------------------------------------
# _price_observations
# ---------------------------------------------------------------------------


def test_price_observations_fills_stale_estimate():
    vol = _make_volume("vol-001", volume_type="gp2", size_gib=100)
    inv = _make_inventory([vol])
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-001")

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    pricing = StaticPricingProvider()
    result = _price_observations([obs], pricing, inv)
    assert result[0].cost_estimate is not None
    assert result[0].cost_estimate.monthly_cost_usd > Decimal("0")
    assert result[0].cost_estimate.potential_saving_usd == result[0].cost_estimate.monthly_cost_usd


def test_price_observations_does_not_overwrite_existing_estimate():
    vol = _make_volume("vol-001")
    inv = _make_inventory([vol])
    existing = _make_cost_estimate("99.99")
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-001", cost_estimate=existing)

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_observations([obs], StaticPricingProvider(), inv)
    assert result[0].cost_estimate is existing


def test_price_observations_skips_gp2_observation():
    vol = _make_volume("vol-001")
    inv = _make_inventory([vol])
    existing = _make_cost_estimate("5.00")
    obs = _make_obs(rule_id="EBS_GP2_TO_GP3", resource_id="vol-001", cost_estimate=existing)

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_observations([obs], StaticPricingProvider(), inv)
    assert result[0].cost_estimate is existing


def test_price_observations_unknown_region_leaves_no_estimate():
    vol = _make_volume("vol-001", region="ap-unknown-1")
    inv = _make_inventory([vol])
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-001")
    obs = obs.model_copy(
        update={"resource_ref": _resource_ref(resource_id="vol-001", region="ap-unknown-1")}
    )

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_observations([obs], StaticPricingProvider(), inv)
    assert result[0].cost_estimate is None


def test_price_observations_volume_not_in_inventory_leaves_no_estimate():
    inv = _make_inventory([])
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-missing")

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_observations([obs], StaticPricingProvider(), inv)
    assert result[0].cost_estimate is None


# ---------------------------------------------------------------------------
# _price_cases
# ---------------------------------------------------------------------------


def test_price_cases_aggregates_volume_costs():
    vol_a = _make_volume("vol-001", size_gib=100)
    vol_b = _make_volume("vol-002", size_gib=200)
    inv = _make_inventory([vol_a, vol_b])
    case = _make_case(affected_ids=["vol-001", "vol-002"])

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    pricing = StaticPricingProvider()
    result = _price_cases([case], pricing, inv)
    ce = result[0].cost_estimate
    assert ce is not None
    expected = (pricing.ebs_monthly_cost(REGION, "gp2", 100) or Decimal("0")) + (
        pricing.ebs_monthly_cost(REGION, "gp2", 200) or Decimal("0")
    )
    assert ce.monthly_cost_usd == expected
    assert ce.potential_saving_usd == expected


def test_price_cases_does_not_overwrite_existing_estimate():
    inv = _make_inventory([])
    existing = _make_cost_estimate("42.00")
    case = _make_case(cost_estimate=existing)

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_cases([case], StaticPricingProvider(), inv)
    assert result[0].cost_estimate is existing


def test_price_cases_partial_pricing_adds_note():
    known_vol = _make_volume("vol-001", size_gib=100)
    inv = _make_inventory([known_vol])
    case = _make_case(affected_ids=["vol-001", "vol-missing"])

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_cases([case], StaticPricingProvider(), inv)
    ce = result[0].cost_estimate
    assert ce is not None
    assert ce.note is not None
    assert "partial" in (ce.note or "").lower()


def test_price_cases_all_unknown_region_no_estimate():
    vol = _make_volume("vol-001", region="ap-unknown-1")
    inv = _make_inventory([vol])
    case = _make_case(affected_ids=["vol-001"])
    case = case.model_copy(
        update={"affected_resource_refs": [_resource_ref("vol-001", region="ap-unknown-1")]}
    )

    from aws_cost_forensics.pricing.static import StaticPricingProvider

    result = _price_cases([case], StaticPricingProvider(), inv)
    assert result[0].cost_estimate is None


# ---------------------------------------------------------------------------
# _build_summary
# ---------------------------------------------------------------------------


def test_build_summary_empty_pipeline():
    s = _build_summary([], [], [])
    assert s.forensic_cases == 0
    assert s.observations == 0
    assert s.observations_superseded == 0
    assert s.affected_resources == 0
    assert s.total_monthly_waste_usd is None
    assert s.has_active_recurrence is False
    assert s.scan_errors == 0


def test_build_summary_counts_correctly():
    obs1 = _make_obs(resource_id="vol-001")
    obs2 = _make_obs(resource_id="vol-002", superseded_by="CASE:X")
    case = _make_case(affected_ids=["vol-002"])
    errors = [ScanError(collector="ebs", error_code="FAIL", message="x", is_permission_error=False)]
    s = _build_summary([obs1, obs2], [case], errors)
    assert s.observations == 2
    assert s.observations_superseded == 1
    assert s.forensic_cases == 1
    assert s.affected_resources == 1
    assert s.scan_errors == 1


def test_build_summary_waste_includes_case_cost():
    case = _make_case(cost_estimate=_make_cost_estimate("50.00"))
    s = _build_summary([], [case], [])
    assert s.total_monthly_waste_usd == Decimal("50.00")


def test_build_summary_waste_includes_non_superseded_stale():
    obs = _make_obs(
        rule_id="EBS_UNATTACHED_STALE",
        resource_id="vol-001",
        cost_estimate=_make_cost_estimate("8.00"),
    )
    s = _build_summary([obs], [], [])
    assert s.total_monthly_waste_usd == Decimal("8.00")


def test_build_summary_waste_includes_gp2_savings():
    saving_estimate = CostEstimate(
        monthly_cost_usd=Decimal("10.00"),
        potential_saving_usd=Decimal("2.50"),
        pricing_source="static_table_v1",
    )
    obs = _make_obs(
        rule_id="EBS_GP2_TO_GP3",
        resource_id="vol-001",
        cost_estimate=saving_estimate,
    )
    s = _build_summary([obs], [], [])
    assert s.total_monthly_waste_usd == Decimal("2.50")


def test_build_summary_superseded_obs_excluded_from_waste():
    obs = _make_obs(
        rule_id="EBS_UNATTACHED_STALE",
        resource_id="vol-001",
        cost_estimate=_make_cost_estimate("8.00"),
        superseded_by="CASE:X",
    )
    case = _make_case(cost_estimate=_make_cost_estimate("8.00"))
    s = _build_summary([obs], [case], [])
    # only case cost counted, not the superseded obs cost
    assert s.total_monthly_waste_usd == Decimal("8.00")


def test_build_summary_has_active_recurrence():
    case_active = _make_case(recurrence=RecurrenceStatus.ACTIVE)
    s = _build_summary([], [case_active], [])
    assert s.has_active_recurrence is True


def test_build_summary_historical_case_not_active():
    case = _make_case(recurrence=RecurrenceStatus.HISTORICAL)
    s = _build_summary([], [case], [])
    assert s.has_active_recurrence is False


def test_build_summary_total_waste_none_when_all_unavailable():
    obs = _make_obs(rule_id="EBS_UNATTACHED_STALE")  # no cost_estimate
    s = _build_summary([obs], [], [])
    assert s.total_monthly_waste_usd is None


# ---------------------------------------------------------------------------
# Scanner.run() — mocked AWS
# ---------------------------------------------------------------------------

_MOCK_PATH = "aws_cost_forensics.scanner"


@patch(f"{_MOCK_PATH}.create_session")
@patch(f"{_MOCK_PATH}.resolve_region", return_value=REGION)
@patch(f"{_MOCK_PATH}.collect_account_id", return_value=ACCOUNT)
@patch(f"{_MOCK_PATH}.collect_volumes", return_value=[])
@patch(f"{_MOCK_PATH}.collect_instances", return_value=[])
@patch(f"{_MOCK_PATH}.collect_snapshots", return_value=[])
@patch(f"{_MOCK_PATH}.collect_amis", return_value=[])
@patch(f"{_MOCK_PATH}.collect_launch_template_metadata", return_value={})
@patch(f"{_MOCK_PATH}.collect_asgs", return_value=[])
def test_scanner_run_returns_scan_result(
    _asgs, _lt_meta, _amis, _snaps, _insts, _vols, _acct, _region, _session
) -> None:
    config = ScanConfig(region=REGION)
    result = Scanner().run(config)
    assert isinstance(result, ScanResult)
    assert result.account_id == ACCOUNT
    assert result.region == REGION
    assert result.schema_version == "1.0"
    assert result.summary.forensic_cases == 0
    assert result.summary.observations == 0
    assert result.summary.scan_errors == 0


@patch(f"{_MOCK_PATH}.create_session")
@patch(f"{_MOCK_PATH}.resolve_region", return_value=REGION)
@patch(f"{_MOCK_PATH}.collect_account_id", return_value=ACCOUNT)
@patch(
    f"{_MOCK_PATH}.collect_volumes",
    side_effect=CollectionError("ebs", "AccessDenied", is_permission_error=True),
)
@patch(f"{_MOCK_PATH}.collect_instances", return_value=[])
@patch(f"{_MOCK_PATH}.collect_snapshots", return_value=[])
@patch(f"{_MOCK_PATH}.collect_amis", return_value=[])
@patch(f"{_MOCK_PATH}.collect_launch_template_metadata", return_value={})
@patch(f"{_MOCK_PATH}.collect_asgs", return_value=[])
def test_scanner_run_propagates_collection_error(
    _asgs, _lt_meta, _amis, _snaps, _insts, _vols, _acct, _region, _session
) -> None:
    config = ScanConfig(region=REGION)
    result = Scanner().run(config)
    assert result.summary.scan_errors == 1
    assert len(result.scan_errors) == 1
    err = result.scan_errors[0]
    assert err.is_permission_error is True
    assert err.error_code == "PERMISSION_DENIED"


@patch(f"{_MOCK_PATH}.create_session")
@patch(f"{_MOCK_PATH}.resolve_region", return_value=REGION)
@patch(f"{_MOCK_PATH}.collect_account_id", return_value=ACCOUNT)
@patch(f"{_MOCK_PATH}.collect_volumes", return_value=[])
@patch(f"{_MOCK_PATH}.collect_instances", return_value=[])
@patch(f"{_MOCK_PATH}.collect_snapshots", return_value=[])
@patch(f"{_MOCK_PATH}.collect_amis", return_value=[])
@patch(f"{_MOCK_PATH}.collect_launch_template_metadata", return_value={})
@patch(
    f"{_MOCK_PATH}.collect_asgs",
    side_effect=CollectionError("autoscaling", "Throttled", is_permission_error=False),
)
def test_scanner_run_continues_after_asg_error(
    _asgs, _lt_meta, _amis, _snaps, _insts, _vols, _acct, _region, _session
) -> None:
    config = ScanConfig(region=REGION)
    result = Scanner().run(config)
    assert result.summary.scan_errors == 1
    assert result.scan_errors[0].error_code == "COLLECTION_FAILED"
    # scan itself still completed
    assert isinstance(result, ScanResult)


@patch(f"{_MOCK_PATH}.create_session")
@patch(f"{_MOCK_PATH}.resolve_region", return_value=REGION)
@patch(f"{_MOCK_PATH}.collect_account_id", return_value=ACCOUNT)
@patch(f"{_MOCK_PATH}.collect_volumes", return_value=[])
@patch(f"{_MOCK_PATH}.collect_instances", return_value=[])
@patch(f"{_MOCK_PATH}.collect_snapshots", return_value=[])
@patch(f"{_MOCK_PATH}.collect_amis", return_value=[])
@patch(f"{_MOCK_PATH}.collect_launch_template_metadata", return_value={})
@patch(f"{_MOCK_PATH}.collect_asgs", return_value=[])
def test_scanner_run_stale_days_passed_to_detector(
    _asgs, _lt_meta, _amis, _snaps, _insts, _vols, _acct, _region, _session
) -> None:
    stale_vol = EBSVolume(
        volume_id="vol-stale",
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        size_gib=50,
        volume_type="gp2",
        create_time=datetime(2020, 1, 1, tzinfo=UTC),
        availability_zone=f"{REGION}a",
    )
    _vols.return_value = [stale_vol]
    config = ScanConfig(region=REGION, stale_volume_days=30)
    result = Scanner().run(config)
    # A stale volume should produce at least one observation
    stale_obs = [o for o in result.observations if o.rule_id == "EBS_UNATTACHED_STALE"]
    assert len(stale_obs) == 1
    assert stale_obs[0].resource_ref.resource_id == "vol-stale"


@patch(f"{_MOCK_PATH}.create_session")
@patch(f"{_MOCK_PATH}.resolve_region", return_value=REGION)
@patch(f"{_MOCK_PATH}.collect_account_id", return_value=ACCOUNT)
@patch(f"{_MOCK_PATH}.collect_volumes", return_value=[])
@patch(f"{_MOCK_PATH}.collect_instances", return_value=[])
@patch(f"{_MOCK_PATH}.collect_snapshots", return_value=[])
@patch(f"{_MOCK_PATH}.collect_amis", return_value=[])
@patch(f"{_MOCK_PATH}.collect_launch_template_metadata", return_value={})
@patch(f"{_MOCK_PATH}.collect_asgs", return_value=[])
def test_scanner_run_remediation_plans_attached(
    _asgs, _lt_meta, _amis, _snaps, _insts, _vols, _acct, _region, _session
) -> None:
    stale_vol = EBSVolume(
        volume_id="vol-stale",
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        size_gib=50,
        volume_type="gp2",
        create_time=datetime(2020, 1, 1, tzinfo=UTC),
        availability_zone=f"{REGION}a",
    )
    _vols.return_value = [stale_vol]
    config = ScanConfig(region=REGION)
    result = Scanner().run(config)
    for obs in result.observations:
        assert obs.remediation_plan is not None, f"{obs.rule_id} has no remediation_plan"


@patch(f"{_MOCK_PATH}.create_session")
@patch(f"{_MOCK_PATH}.resolve_region", return_value=REGION)
@patch(f"{_MOCK_PATH}.collect_account_id", return_value=ACCOUNT)
@patch(f"{_MOCK_PATH}.collect_volumes", return_value=[])
@patch(f"{_MOCK_PATH}.collect_instances", return_value=[])
@patch(f"{_MOCK_PATH}.collect_snapshots", return_value=[])
@patch(f"{_MOCK_PATH}.collect_amis", return_value=[])
@patch(f"{_MOCK_PATH}.collect_launch_template_metadata", return_value={})
@patch(f"{_MOCK_PATH}.collect_asgs", return_value=[])
def test_scanner_run_cost_estimates_filled_for_stale(
    _asgs, _lt_meta, _amis, _snaps, _insts, _vols, _acct, _region, _session
) -> None:
    stale_vol = EBSVolume(
        volume_id="vol-stale",
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        size_gib=50,
        volume_type="gp2",
        create_time=datetime(2020, 1, 1, tzinfo=UTC),
        availability_zone=f"{REGION}a",
    )
    _vols.return_value = [stale_vol]
    config = ScanConfig(region=REGION)
    result = Scanner().run(config)
    stale_obs = [o for o in result.observations if o.rule_id == "EBS_UNATTACHED_STALE"]
    assert stale_obs[0].cost_estimate is not None
    assert stale_obs[0].cost_estimate.monthly_cost_usd > Decimal("0")
