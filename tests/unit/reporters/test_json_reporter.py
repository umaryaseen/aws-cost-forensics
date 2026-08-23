"""Tests for JsonReporter."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    RecurrenceStatus,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef
from aws_cost_forensics.domain.findings import CostEstimate, ForensicCase, Observation
from aws_cost_forensics.domain.inventory import ScanResult, ScanSummary
from aws_cost_forensics.reporters.json_reporter import JsonReporter

# ---------------------------------------------------------------------------
# Helpers (shared shape with test_console_reporter)
# ---------------------------------------------------------------------------


def _ref(resource_id: str = "vol-abc123") -> ResourceRef:
    return ResourceRef(
        resource_id=resource_id,
        resource_type="ebs_volume",
        region="eu-central-1",
        account_id="123456789012",
    )


def _evidence() -> Evidence:
    return Evidence(
        code="VOLUME_UNATTACHED",
        kind=EvidenceKind.SUPPORTING,
        description="No attachments.",
        api_source="ec2:DescribeVolumes",
    )


def _obs(rule_id: str = "EBS_UNATTACHED_STALE") -> Observation:
    return Observation(
        observation_id=f"{rule_id}:123456789012:eu-central-1:ebs_volume:vol-abc123",
        rule_id=rule_id,
        resource_ref=_ref(),
        severity=Severity.MEDIUM,
        decision_class=DecisionClass.REMEDIATION_CANDIDATE,
        evidence=[_evidence()],
        evidence_strength=EvidenceStrength.HIGH,
        cost_estimate=CostEstimate(
            monthly_cost_usd=Decimal("10.50"),
            potential_saving_usd=Decimal("10.50"),
            pricing_source="static",
        ),
    )


def _case() -> ForensicCase:
    return ForensicCase(
        case_id="ASG_EBS_LEAK:123456789012:eu-central-1:lt-001",
        case_type="ASG_EBS_LEAK",
        title="Orphan chain from lt-001",
        description="desc",
        severity=Severity.HIGH,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        recurrence=RecurrenceStatus.ACTIVE,
        evidence_strength=EvidenceStrength.HIGH,
        root_cause_ref=_ref("lt-001"),
        affected_resource_refs=[_ref()],
        evidence=[_evidence()],
        cost_estimate=CostEstimate(
            monthly_cost_usd=Decimal("274.40"),
            potential_saving_usd=Decimal("274.40"),
            pricing_source="static",
        ),
    )


def _result(
    observations: list[Observation] | None = None,
    forensic_cases: list[ForensicCase] | None = None,
) -> ScanResult:
    return ScanResult(
        tool_version="0.1.0",
        generated_at=datetime(2024, 1, 15, 10, 30, 0, tzinfo=UTC),
        account_id="123456789012",
        region="eu-central-1",
        pricing_source="static",
        observations=observations or [],
        forensic_cases=forensic_cases or [],
        scan_errors=[],
        summary=ScanSummary(
            forensic_cases=len(forensic_cases or []),
            observations=len(observations or []),
            observations_superseded=0,
            affected_resources=0,
            total_monthly_waste_usd=Decimal("274.40") if forensic_cases else None,
            has_active_recurrence=bool(forensic_cases),
            scan_errors=0,
        ),
    )


# ---------------------------------------------------------------------------
# Output is valid JSON
# ---------------------------------------------------------------------------


def test_render_returns_valid_json() -> None:
    output = JsonReporter().render(_result())
    parsed = json.loads(output)
    assert isinstance(parsed, dict)


def test_render_indented_by_default() -> None:
    output = JsonReporter().render(_result())
    assert "\n" in output


def test_render_less_indented_when_zero() -> None:
    default_out = JsonReporter().render(_result(), indent=2)
    compact_out = JsonReporter().render(_result(), indent=0)
    assert len(compact_out) < len(default_out)


# ---------------------------------------------------------------------------
# Schema contract fields
# ---------------------------------------------------------------------------


def test_schema_version_is_1_0() -> None:
    data = json.loads(JsonReporter().render(_result()))
    assert data["schema_version"] == "1.0"


def test_tool_version_is_present_and_separate() -> None:
    data = json.loads(JsonReporter().render(_result()))
    assert data["tool_version"] == "0.1.0"
    assert "schema_version" in data
    assert data["schema_version"] != data["tool_version"]


def test_account_id_in_output() -> None:
    data = json.loads(JsonReporter().render(_result()))
    assert data["account_id"] == "123456789012"


def test_region_in_output() -> None:
    data = json.loads(JsonReporter().render(_result()))
    assert data["region"] == "eu-central-1"


# ---------------------------------------------------------------------------
# Decimal serialized as string (not float)
# ---------------------------------------------------------------------------


def test_decimal_serialized_as_string() -> None:
    data = json.loads(JsonReporter().render(_result(observations=[_obs()])))
    cost = data["observations"][0]["cost_estimate"]
    assert isinstance(cost["monthly_cost_usd"], str)
    assert cost["monthly_cost_usd"] == "10.50"


def test_decimal_preserves_trailing_zero() -> None:
    data = json.loads(JsonReporter().render(_result(forensic_cases=[_case()])))
    cost = data["forensic_cases"][0]["cost_estimate"]
    assert cost["monthly_cost_usd"] == "274.40"


def test_summary_waste_is_string() -> None:
    data = json.loads(JsonReporter().render(_result(forensic_cases=[_case()])))
    assert isinstance(data["summary"]["total_monthly_waste_usd"], str)


def test_summary_waste_is_none_when_unset() -> None:
    data = json.loads(JsonReporter().render(_result()))
    assert data["summary"]["total_monthly_waste_usd"] is None


# ---------------------------------------------------------------------------
# Datetime serialized as ISO 8601 UTC
# ---------------------------------------------------------------------------


def test_datetime_is_iso8601_utc() -> None:
    data = json.loads(JsonReporter().render(_result()))
    ts = data["generated_at"]
    assert "T" in ts
    assert ts.endswith("Z") or "+00:00" in ts


# ---------------------------------------------------------------------------
# Round-trip fidelity
# ---------------------------------------------------------------------------


def test_round_trip_preserves_observations() -> None:
    original = _result(observations=[_obs()])
    json_str = JsonReporter().render(original)
    restored = ScanResult.model_validate_json(json_str)
    assert len(restored.observations) == 1
    assert restored.observations[0].rule_id == "EBS_UNATTACHED_STALE"


def test_round_trip_preserves_forensic_case() -> None:
    original = _result(forensic_cases=[_case()])
    json_str = JsonReporter().render(original)
    restored = ScanResult.model_validate_json(json_str)
    assert len(restored.forensic_cases) == 1
    assert restored.forensic_cases[0].case_type == "ASG_EBS_LEAK"


def test_round_trip_preserves_decimal_precision() -> None:
    original = _result(forensic_cases=[_case()])
    json_str = JsonReporter().render(original)
    restored = ScanResult.model_validate_json(json_str)
    assert restored.forensic_cases[0].cost_estimate is not None
    assert restored.forensic_cases[0].cost_estimate.monthly_cost_usd == Decimal("274.40")


def test_round_trip_preserves_schema_version() -> None:
    original = _result()
    restored = ScanResult.model_validate_json(JsonReporter().render(original))
    assert restored.schema_version == "1.0"


# ---------------------------------------------------------------------------
# Full structure
# ---------------------------------------------------------------------------


def test_top_level_keys_present() -> None:
    result = _result(observations=[_obs()], forensic_cases=[_case()])
    data = json.loads(JsonReporter().render(result))
    for key in (
        "schema_version",
        "tool_version",
        "generated_at",
        "account_id",
        "region",
        "pricing_source",
        "observations",
        "forensic_cases",
        "scan_errors",
        "summary",
    ):
        assert key in data, f"Missing top-level key: {key}"


def test_observation_has_superseded_by_null_when_active() -> None:
    data = json.loads(JsonReporter().render(_result(observations=[_obs()])))
    assert data["observations"][0]["superseded_by"] is None
