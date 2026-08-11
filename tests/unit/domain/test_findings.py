"""Tests for evidence, findings, inventory, and ScanResult models."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

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

REGION = "eu-central-1"
ACCOUNT = "111111111111"
NOW = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def make_ref(resource_id: str = "vol-001", resource_type: str = "ebs_volume") -> ResourceRef:
    return ResourceRef(
        resource_id=resource_id,
        resource_type=resource_type,
        region=REGION,
        account_id=ACCOUNT,
    )


def make_evidence(code: str = "VOLUME_UNATTACHED") -> Evidence:
    return Evidence(
        code=code,
        kind=EvidenceKind.SUPPORTING,
        description="Volume has no attachments",
        api_source="ec2:DescribeVolumes",
    )


def make_observation(
    rule_id: str = "EBS_UNATTACHED_STALE",
    resource_id: str = "vol-001",
    superseded_by: str | None = None,
) -> Observation:
    obs_id = f"{rule_id}:{ACCOUNT}:{REGION}:ebs_volume:{resource_id}"
    return Observation(
        observation_id=obs_id,
        rule_id=rule_id,
        resource_ref=make_ref(resource_id),
        severity=Severity.MEDIUM,
        decision_class=DecisionClass.REMEDIATION_CANDIDATE,
        evidence=[make_evidence()],
        evidence_strength=EvidenceStrength.HIGH,
        superseded_by=superseded_by,
    )


def make_case() -> ForensicCase:
    return ForensicCase(
        case_id=f"ASG_EBS_LEAK:{ACCOUNT}:{REGION}:lt-prod",
        case_type="ASG_EBS_LEAK",
        title="EBS volumes leaked by ASG",
        description="Launch template defect causes volume orphans",
        severity=Severity.HIGH,
        decision_class=DecisionClass.CONFIGURATION_DEFECT,
        recurrence=RecurrenceStatus.ACTIVE,
        evidence_strength=EvidenceStrength.HIGH,
        root_cause_ref=make_ref("lt-prod", "launch_template"),
        affected_resource_refs=[make_ref("vol-001")],
        evidence=[make_evidence("LT_DELETE_ON_TERMINATION_FALSE")],
    )


def make_scan_result(
    observations: list[Observation] | None = None,
    forensic_cases: list[ForensicCase] | None = None,
) -> ScanResult:
    observations = observations or []
    forensic_cases = forensic_cases or []
    return ScanResult(
        tool_version="0.1.0",
        generated_at=NOW,
        account_id=ACCOUNT,
        region=REGION,
        pricing_source="static_table_v1",
        observations=observations,
        forensic_cases=forensic_cases,
        scan_errors=[],
        summary=ScanSummary(
            forensic_cases=len(forensic_cases),
            observations=len(observations),
            observations_superseded=0,
            affected_resources=0,
            total_monthly_waste_usd=None,
            has_active_recurrence=False,
            scan_errors=0,
        ),
    )


# --- ResourceRef ---


def test_resource_ref_to_key() -> None:
    ref = make_ref("vol-001")
    key = ref.to_key()
    assert key.resource_id == "vol-001"
    assert key.qualifier is None


def test_resource_ref_to_key_with_qualifier() -> None:
    ref = make_ref("lt-prod", "launch_template_version")
    key = ref.to_key(qualifier="3")
    assert key.qualifier == "3"


# --- Observation ---


def test_observation_id_canonical_format() -> None:
    obs = make_observation(rule_id="EBS_UNATTACHED_STALE", resource_id="vol-abc")
    assert obs.observation_id == f"EBS_UNATTACHED_STALE:{ACCOUNT}:{REGION}:ebs_volume:vol-abc"


def test_observation_cost_estimate_defaults_none() -> None:
    obs = make_observation()
    assert obs.cost_estimate is None


def test_observation_remediation_plan_defaults_none() -> None:
    obs = make_observation()
    assert obs.remediation_plan is None


def test_observation_superseded_by_defaults_none() -> None:
    obs = make_observation()
    assert obs.superseded_by is None


def test_observation_superseded_by_set() -> None:
    case_id = f"ASG_EBS_LEAK:{ACCOUNT}:{REGION}:lt-prod"
    obs = make_observation(superseded_by=case_id)
    assert obs.superseded_by == case_id


def test_observation_frozen() -> None:
    obs = make_observation()
    with pytest.raises(ValidationError):
        obs.superseded_by = "some-case"  # type: ignore[misc]


# --- ForensicCase ---


def test_case_id_canonical_format() -> None:
    case = make_case()
    assert case.case_id == f"ASG_EBS_LEAK:{ACCOUNT}:{REGION}:lt-prod"


def test_case_cost_estimate_defaults_none() -> None:
    assert make_case().cost_estimate is None


def test_case_remediation_plan_defaults_none() -> None:
    assert make_case().remediation_plan is None


def test_case_no_candidate_root_cause_refs_field() -> None:
    """ForensicCase must not have candidate_root_cause_refs — ambiguity goes to observations."""
    case = make_case()
    assert not hasattr(case, "candidate_root_cause_refs")


# --- CostEstimate ---


def test_cost_estimate_basis_is_modeled() -> None:
    est = CostEstimate(monthly_cost_usd=Decimal("12.50"), pricing_source="static_table_v1")
    assert est.basis == "modeled"


def test_cost_estimate_potential_saving_none() -> None:
    est = CostEstimate(monthly_cost_usd=Decimal("12.50"), pricing_source="static_table_v1")
    assert est.potential_saving_usd is None


# --- ScanResult ---


def test_scan_result_schema_version_default() -> None:
    result = make_scan_result()
    assert result.schema_version == "1.0"


def test_scan_result_tool_version_independent() -> None:
    """schema_version and tool_version are independent fields."""
    result = make_scan_result()
    assert result.schema_version == "1.0"
    assert result.tool_version == "0.1.0"


def test_scan_result_json_round_trip() -> None:
    obs = make_observation()
    case = make_case()
    result = make_scan_result(observations=[obs], forensic_cases=[case])
    serialized = result.model_dump_json()
    data = json.loads(serialized)
    assert data["schema_version"] == "1.0"
    assert data["tool_version"] == "0.1.0"
    assert len(data["observations"]) == 1
    assert len(data["forensic_cases"]) == 1


def test_scan_result_monetary_values_as_decimal_strings() -> None:
    """Monetary values must survive JSON round-trip as exact strings."""
    obs = make_observation()
    cost = CostEstimate(
        monthly_cost_usd=Decimal("274.40"),
        potential_saving_usd=Decimal("274.40"),
        pricing_source="static_table_v1",
    )
    obs_with_cost = obs.model_copy(update={"cost_estimate": cost})
    result = make_scan_result(observations=[obs_with_cost])
    data = json.loads(result.model_dump_json())
    assert data["observations"][0]["cost_estimate"]["monthly_cost_usd"] == "274.40"


# --- Canonical ID uniqueness ---


def test_canonical_ids_differ_by_region() -> None:
    id1 = f"EBS_UNATTACHED_STALE:{ACCOUNT}:us-east-1:ebs_volume:vol-abc123"
    id2 = f"EBS_UNATTACHED_STALE:{ACCOUNT}:eu-central-1:ebs_volume:vol-abc123"
    assert id1 != id2


def test_canonical_ids_differ_by_account() -> None:
    id1 = f"EBS_UNATTACHED_STALE:111111111111:{REGION}:ebs_volume:vol-abc123"
    id2 = f"EBS_UNATTACHED_STALE:222222222222:{REGION}:ebs_volume:vol-abc123"
    assert id1 != id2


# --- ScanError ---


def test_scan_error_fields() -> None:
    err = ScanError(
        collector="ebs",
        error_code="AccessDenied",
        message="not authorized",
        is_permission_error=True,
    )
    assert err.is_permission_error is True


# --- RemediationPlan ---


def test_remediation_plan_steps() -> None:
    plan = RemediationPlan(
        priority="FIX_SOURCE_FIRST",
        steps=[RemediationStep(order=1, title="Fix LT", description="Update LT version")],
        blockers=[],
    )
    assert plan.steps[0].order == 1
