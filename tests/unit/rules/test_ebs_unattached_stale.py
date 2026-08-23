from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceKind,
    EvidenceStrength,
    Severity,
)
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resources import EBSSnapshot, EBSVolume, VolumeAttachment
from aws_cost_forensics.rules.ebs_unattached_stale import EBSUnattachedStaleDetector

REGION = "us-east-1"
ACCOUNT = "123456789012"
NOW = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
STALE_DAYS = 30


def _det(stale_days: int = STALE_DAYS) -> EBSUnattachedStaleDetector:
    return EBSUnattachedStaleDetector(stale_days=stale_days)


def _run(inv: Inventory, stale_days: int = STALE_DAYS) -> list:
    return _det(stale_days).detect(inv, now=NOW)


def _make_inventory(
    volumes: list[EBSVolume],
    snapshots: list[EBSSnapshot] | None = None,
) -> Inventory:
    return Inventory(
        account_id=ACCOUNT,
        region=REGION,
        scanned_at=NOW,
        volumes=volumes,
        snapshots=snapshots or [],
        amis=[],
        instances=[],
        launch_template_versions=[],
        auto_scaling_groups=[],
    )


def _available_volume(
    volume_id: str = "vol-aaa",
    age_days: int = 60,
    snapshot_id: str | None = None,
    tags: dict[str, str] | None = None,
) -> EBSVolume:
    return EBSVolume(
        volume_id=volume_id,
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        size_gib=100,
        volume_type="gp2",
        create_time=NOW - timedelta(days=age_days),
        availability_zone=f"{REGION}a",
        snapshot_id=snapshot_id,
        tags=tags or {},
    )


def _attached_volume(volume_id: str = "vol-bbb") -> EBSVolume:
    return EBSVolume(
        volume_id=volume_id,
        region=REGION,
        account_id=ACCOUNT,
        state="in-use",
        size_gib=50,
        volume_type="gp2",
        create_time=NOW - timedelta(days=100),
        availability_zone=f"{REGION}a",
        attachments=[
            VolumeAttachment(
                instance_id="i-abc",
                device="/dev/xvda",
                state="attached",
                delete_on_termination=True,
            )
        ],
    )


# ---------------------------------------------------------------------------
# Attached volumes must never fire
# ---------------------------------------------------------------------------


def test_attached_volume_never_fires() -> None:
    assert _run(_make_inventory([_attached_volume()])) == []


def test_in_use_state_not_flagged() -> None:
    vol = EBSVolume(
        volume_id="vol-x",
        region=REGION,
        account_id=ACCOUNT,
        state="in-use",
        size_gib=100,
        volume_type="gp2",
        create_time=NOW - timedelta(days=200),
        availability_zone=f"{REGION}a",
    )
    assert _run(_make_inventory([vol])) == []


# ---------------------------------------------------------------------------
# Age threshold boundary conditions
# ---------------------------------------------------------------------------


def test_volume_exactly_at_threshold_fires() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=STALE_DAYS)]))
    assert len(obs) == 1


def test_volume_one_day_short_does_not_fire() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=STALE_DAYS - 1)]))
    assert obs == []


def test_volume_one_day_over_fires() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=STALE_DAYS + 1)]))
    assert len(obs) == 1


def test_empty_inventory_produces_no_observations() -> None:
    assert _run(_make_inventory([])) == []


# ---------------------------------------------------------------------------
# Multiple volumes — correct count
# ---------------------------------------------------------------------------


def test_multiple_stale_volumes_all_flagged() -> None:
    vols = [_available_volume(f"vol-{i}", age_days=60) for i in range(5)]
    assert len(_run(_make_inventory(vols))) == 5


def test_mixed_volumes_only_stale_available_flagged() -> None:
    vols = [
        _attached_volume("vol-attached"),
        _available_volume("vol-young", age_days=5),
        _available_volume("vol-old", age_days=90),
    ]
    obs = _run(_make_inventory(vols))
    assert len(obs) == 1
    assert obs[0].resource_ref.resource_id == "vol-old"


# ---------------------------------------------------------------------------
# Observation metadata
# ---------------------------------------------------------------------------


def test_observation_severity_and_class() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    assert obs.severity == Severity.MEDIUM
    assert obs.decision_class == DecisionClass.REMEDIATION_CANDIDATE


def test_evidence_strength_always_high() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    assert obs.evidence_strength == EvidenceStrength.HIGH


def test_observation_id_format() -> None:
    obs = _run(_make_inventory([_available_volume("vol-xyz", age_days=60)]))[0]
    assert obs.observation_id == f"EBS_UNATTACHED_STALE:{ACCOUNT}:{REGION}:ebs_volume:vol-xyz"


def test_rule_id() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    assert obs.rule_id == "EBS_UNATTACHED_STALE"


# ---------------------------------------------------------------------------
# Evidence codes
# ---------------------------------------------------------------------------


def test_supporting_evidence_includes_unattached_and_age() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    codes = [e.code for e in obs.evidence]
    assert "VOLUME_UNATTACHED" in codes
    assert "VOLUME_AGE_DAYS" in codes


def test_missing_evidence_includes_attachment_history_unavailable() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    missing = [e.code for e in obs.evidence if e.kind == EvidenceKind.MISSING]
    assert "ATTACHMENT_HISTORY_UNAVAILABLE" in missing


def test_volume_age_value_in_days() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    age_ev = next(e for e in obs.evidence if e.code == "VOLUME_AGE_DAYS")
    assert age_ev.value == 60


def test_volume_missing_tags_evidence_when_no_tags() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60, tags={})]))[0]
    codes = [e.code for e in obs.evidence]
    assert "VOLUME_MISSING_TAGS" in codes


def test_no_missing_tags_evidence_when_tagged() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60, tags={"Name": "my-vol"})]))[0]
    codes = [e.code for e in obs.evidence]
    assert "VOLUME_MISSING_TAGS" not in codes


# ---------------------------------------------------------------------------
# Snapshot evidence
# ---------------------------------------------------------------------------


def test_snapshot_source_exists_when_snapshot_in_inventory() -> None:
    snap = EBSSnapshot(
        snapshot_id="snap-111",
        region=REGION,
        account_id=ACCOUNT,
        volume_size_gib=100,
        state="completed",
        start_time=NOW - timedelta(days=90),
    )
    vol = _available_volume(age_days=60, snapshot_id="snap-111")
    obs = _run(_make_inventory([vol], snapshots=[snap]))[0]
    codes = [e.code for e in obs.evidence]
    assert "SNAPSHOT_SOURCE_EXISTS" in codes
    assert "SNAPSHOT_NOT_IN_INVENTORY" not in codes


def test_snapshot_not_in_inventory_when_snapshot_missing() -> None:
    vol = _available_volume(age_days=60, snapshot_id="snap-999")
    obs = _run(_make_inventory([vol], snapshots=[]))[0]
    codes = [e.code for e in obs.evidence]
    assert "SNAPSHOT_NOT_IN_INVENTORY" in codes
    assert "SNAPSHOT_SOURCE_EXISTS" not in codes


def test_no_snapshot_evidence_when_no_snapshot_id() -> None:
    vol = _available_volume(age_days=60, snapshot_id=None)
    obs = _run(_make_inventory([vol]))[0]
    codes = [e.code for e in obs.evidence]
    assert "SNAPSHOT_SOURCE_EXISTS" not in codes
    assert "SNAPSHOT_NOT_IN_INVENTORY" not in codes


# ---------------------------------------------------------------------------
# Cost estimate is None (set during pricing pass, not by this detector)
# ---------------------------------------------------------------------------


def test_no_cost_estimate_set_by_detector() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    assert obs.cost_estimate is None


def test_superseded_by_is_none_by_default() -> None:
    obs = _run(_make_inventory([_available_volume(age_days=60)]))[0]
    assert obs.superseded_by is None


# ---------------------------------------------------------------------------
# Custom stale threshold
# ---------------------------------------------------------------------------


def test_custom_stale_days_threshold() -> None:
    inv = _make_inventory([_available_volume(age_days=10)])
    assert _run(inv, stale_days=30) == []
    assert len(_run(inv, stale_days=7)) == 1
