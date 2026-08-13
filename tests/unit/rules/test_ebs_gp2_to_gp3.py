from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

import pytest

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    Severity,
)
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resources import EBSVolume
from aws_cost_forensics.pricing.static import StaticPricingProvider
from aws_cost_forensics.rules.ebs_gp2_to_gp3 import EBSGP2ToGP3Detector

REGION = "us-east-1"
ACCOUNT = "123456789012"
NOW = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)


def _make_inventory(volumes: list[EBSVolume]) -> Inventory:
    return Inventory(
        account_id=ACCOUNT,
        region=REGION,
        scanned_at=NOW,
        volumes=volumes,
        snapshots=[],
        amis=[],
        instances=[],
        launch_template_versions=[],
        auto_scaling_groups=[],
    )


def _volume(
    volume_id: str = "vol-aaa",
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


@pytest.fixture(scope="module")
def pricing() -> StaticPricingProvider:
    return StaticPricingProvider()


@pytest.fixture(scope="module")
def detector(pricing: StaticPricingProvider) -> EBSGP2ToGP3Detector:
    return EBSGP2ToGP3Detector(pricing=pricing)


# ---------------------------------------------------------------------------
# Only gp2 volumes fire
# ---------------------------------------------------------------------------


def test_gp3_volume_not_flagged(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume(volume_type="gp3")])
    assert detector.detect(inv) == []


def test_io1_volume_not_flagged(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume(volume_type="io1")])
    assert detector.detect(inv) == []


def test_gp2_volume_flagged(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume(volume_type="gp2")])
    assert len(detector.detect(inv)) == 1


def test_empty_inventory(detector: EBSGP2ToGP3Detector) -> None:
    assert detector.detect(_make_inventory([])) == []


def test_multiple_gp2_all_flagged(detector: EBSGP2ToGP3Detector) -> None:
    vols = [_volume(f"vol-{i}", volume_type="gp2") for i in range(4)]
    inv = _make_inventory(vols)
    assert len(detector.detect(inv)) == 4


def test_mixed_types_only_gp2_flagged(detector: EBSGP2ToGP3Detector) -> None:
    vols = [
        _volume("vol-gp2", volume_type="gp2"),
        _volume("vol-gp3", volume_type="gp3"),
        _volume("vol-io2", volume_type="io2"),
    ]
    inv = _make_inventory(vols)
    obs = detector.detect(inv)
    assert len(obs) == 1
    assert obs[0].resource_ref.resource_id == "vol-gp2"


# ---------------------------------------------------------------------------
# Observation metadata
# ---------------------------------------------------------------------------


def test_rule_id(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.rule_id == "EBS_GP2_TO_GP3"


def test_severity_low(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.severity == Severity.LOW


def test_decision_class_remediation_candidate(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.decision_class == DecisionClass.REMEDIATION_CANDIDATE


def test_evidence_strength_high(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.evidence_strength == EvidenceStrength.HIGH


def test_observation_id_format(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume("vol-xyz")])
    obs = detector.detect(inv)[0]
    assert obs.observation_id == f"EBS_GP2_TO_GP3:{ACCOUNT}:{REGION}:ebs_volume:vol-xyz"


# ---------------------------------------------------------------------------
# Evidence codes
# ---------------------------------------------------------------------------


def test_volume_type_gp2_evidence(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    codes = [e.code for e in obs.evidence]
    assert "VOLUME_TYPE_GP2" in codes


def test_workload_iops_unknown_missing_evidence(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    missing = [e for e in obs.evidence if e.kind == EvidenceKind.MISSING]
    assert any(e.code == "WORKLOAD_IOPS_UNKNOWN" for e in missing)


# ---------------------------------------------------------------------------
# Cost estimate — known region
# ---------------------------------------------------------------------------


def test_cost_estimate_present_for_known_region(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume(size_gib=100)])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None


def test_cost_estimate_gp2_100gb_us_east_1(detector: EBSGP2ToGP3Detector) -> None:
    # us-east-1 gp2 100 GiB = $10.00
    inv = _make_inventory([_volume(size_gib=100)])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None
    assert obs.cost_estimate.monthly_cost_usd == Decimal("10.00")


def test_potential_saving_positive_for_small_volume(detector: EBSGP2ToGP3Detector) -> None:
    # 100 GiB: gp2_iops = 300, gp3 free baseline covers it → gp3 cheaper
    inv = _make_inventory([_volume(size_gib=100)])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None
    assert obs.cost_estimate.potential_saving_usd is not None
    assert obs.cost_estimate.potential_saving_usd > Decimal("0")


def test_cost_estimate_basis_modeled(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None
    assert obs.cost_estimate.basis == "modeled"


def test_cost_estimate_pricing_source(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None
    assert obs.cost_estimate.pricing_source == "static_table_v1"


# ---------------------------------------------------------------------------
# Cost estimate — gp3 IOPS provisioning math
# ---------------------------------------------------------------------------


def test_large_volume_gp3_iops_provisioned_above_baseline(
    detector: EBSGP2ToGP3Detector,
) -> None:
    # 2000 GiB: gp2_iops = min(6000, 16000) = 6000; gp3_provisioned = 3000
    # gp2: $0.10 * 2000 = $200
    # gp3: $0.08 * 2000 + $0.005 * 3000 = $160 + $15 = $175
    inv = _make_inventory([_volume(size_gib=2000)])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None
    assert obs.cost_estimate.monthly_cost_usd == Decimal("200.00")
    assert obs.cost_estimate.potential_saving_usd == Decimal("25.00")


def test_capped_iops_volume(detector: EBSGP2ToGP3Detector) -> None:
    # 6000 GiB: gp2_iops = min(18000, 16000) = 16000; gp3_provisioned = 13000
    # gp2: $0.10 * 6000 = $600
    # gp3: $0.08 * 6000 + $0.005 * 13000 = $480 + $65 = $545
    inv = _make_inventory([_volume(size_gib=6000)])
    obs = detector.detect(inv)[0]
    assert obs.cost_estimate is not None
    assert obs.cost_estimate.monthly_cost_usd == Decimal("600.00")
    assert obs.cost_estimate.potential_saving_usd == Decimal("55.00")


# ---------------------------------------------------------------------------
# Cost estimate — unknown region
# ---------------------------------------------------------------------------


def test_cost_estimate_none_for_unknown_region(pricing: StaticPricingProvider) -> None:
    det = EBSGP2ToGP3Detector(pricing=pricing)
    vol = _volume(region="xx-unknown-1")
    inv = Inventory(
        account_id=ACCOUNT,
        region="xx-unknown-1",
        scanned_at=NOW,
        volumes=[vol],
        snapshots=[],
        amis=[],
        instances=[],
        launch_template_versions=[],
        auto_scaling_groups=[],
    )
    obs = det.detect(inv)[0]
    assert obs.cost_estimate is None


# ---------------------------------------------------------------------------
# superseded_by is None by default
# ---------------------------------------------------------------------------


def test_superseded_by_none_by_default(detector: EBSGP2ToGP3Detector) -> None:
    inv = _make_inventory([_volume()])
    obs = detector.detect(inv)[0]
    assert obs.superseded_by is None
