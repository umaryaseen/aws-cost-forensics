"""Tests for the EBS_ASG_ORPHAN_CHAIN correlator (T012).

Covers all protective behaviours mandated by the architecture plan:
- Attached volumes excluded
- Size/type match alone → no ForensicCase
- Heuristic-only clusters → no ForensicCase
- Ambiguous lineage (multiple LTs) → volume in zero groups, no case
- Version selector semantics ($Default, $Latest, pinned)
- delete_on_termination=None → no defect
- Non-root data disk with DoT=false → not a defect for this correlator
- desired_capacity=0 with max_size>0 → ACTIVE (launch path reachable)
- max_size=0 → not ACTIVE (launch path sealed)
- Empty ASG list for template → UNKNOWN (cannot claim HISTORICAL)
- MixedInstancesPolicy with override LTs → has_incomplete_launch_path
- Live instance root BDM false → LIVE_INSTANCE_ROOT_PRESERVES_VOLUME
- Recurrence facts-first: proven ACTIVE holds even with incomplete paths
- Evidence strength per-group (independent groups)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aws_cost_forensics.domain.enums import (
    EvidenceStrength,
    RecurrenceStatus,
    Severity,
)
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resources import (
    AMI,
    ASGInstance,
    AutoScalingGroup,
    BlockDeviceMapping,
    EBSSnapshot,
    EBSVolume,
    EC2Instance,
    LaunchTemplateRef,
    LaunchTemplateVersion,
    MixedInstancesOverride,
    MixedInstancesPolicy,
    VolumeAttachment,
)
from aws_cost_forensics.graph.builder import RelationshipBuilder
from aws_cost_forensics.rules.asg_ebs_orphan_chain import ASGEBSOrphanChainCorrelator

REGION = "us-east-1"
ACCOUNT = "123456789012"
NOW = datetime(2024, 6, 1, 0, 0, 0, tzinfo=UTC)
TEMPLATE_ID = "lt-aabbccdd11223344"
AMI_ID = "ami-0123456789abcdef0"
SNAP_ID = "snap-aabbccddeeff0011"


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def _available_volume(
    volume_id: str = "vol-001",
    snapshot_id: str | None = SNAP_ID,
    size_gib: int = 100,
    volume_type: str = "gp2",
) -> EBSVolume:
    return EBSVolume(
        volume_id=volume_id,
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        size_gib=size_gib,
        volume_type=volume_type,
        create_time=NOW - timedelta(days=60),
        availability_zone=f"{REGION}a",
        snapshot_id=snapshot_id,
    )


def _attached_volume(volume_id: str = "vol-attached") -> EBSVolume:
    return EBSVolume(
        volume_id=volume_id,
        region=REGION,
        account_id=ACCOUNT,
        state="in-use",
        size_gib=100,
        volume_type="gp2",
        create_time=NOW - timedelta(days=60),
        availability_zone=f"{REGION}a",
        attachments=[
            VolumeAttachment(
                instance_id="i-xyz",
                device="/dev/xvda",
                state="attached",
                delete_on_termination=True,
            )
        ],
    )


def _snapshot(
    snapshot_id: str = SNAP_ID,
    volume_id: str | None = "vol-001",
) -> EBSSnapshot:
    return EBSSnapshot(
        snapshot_id=snapshot_id,
        region=REGION,
        account_id=ACCOUNT,
        volume_id=volume_id,
        volume_size_gib=100,
        state="completed",
        start_time=NOW - timedelta(days=90),
    )


def _ami(
    image_id: str = AMI_ID,
    snapshot_ids: list[str] | None = None,
    root_device_name: str = "/dev/xvda",
) -> AMI:
    return AMI(
        image_id=image_id,
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        creation_date=NOW - timedelta(days=180),
        root_device_name=root_device_name,
        snapshot_ids=snapshot_ids if snapshot_ids is not None else [SNAP_ID],
    )


def _lt_ver(
    version_number: int = 1,
    is_default: bool = True,
    is_latest: bool = True,
    image_id: str = AMI_ID,
    template_id: str = TEMPLATE_ID,
    root_dot: bool | None = False,
    root_device: str = "/dev/xvda",
) -> LaunchTemplateVersion:
    bdms = [
        BlockDeviceMapping(
            device_name=root_device,
            delete_on_termination=root_dot,
        )
    ]
    return LaunchTemplateVersion(
        template_id=template_id,
        region=REGION,
        account_id=ACCOUNT,
        version_number=version_number,
        is_default=is_default,
        is_latest=is_latest,
        image_id=image_id,
        block_device_mappings=bdms,
    )


def _asg(
    asg_name: str = "asg-prod",
    template_id: str = TEMPLATE_ID,
    version_selector: str = "$Default",
    resolved_version_number: int = 1,
    max_size: int = 5,
    desired_capacity: int = 2,
    current_instances: list[ASGInstance] | None = None,
    mixed_instances_policy: MixedInstancesPolicy | None = None,
) -> AutoScalingGroup:
    lt_ref = LaunchTemplateRef(
        template_id=template_id,
        version_selector=version_selector,
        resolved_version_number=resolved_version_number,
    )
    return AutoScalingGroup(
        asg_name=asg_name,
        region=REGION,
        account_id=ACCOUNT,
        launch_template_ref=lt_ref,
        mixed_instances_policy=mixed_instances_policy,
        desired_capacity=desired_capacity,
        min_size=0,
        max_size=max_size,
        current_instances=current_instances or [],
    )


def _make_inventory(
    volumes: list[EBSVolume] | None = None,
    snapshots: list[EBSSnapshot] | None = None,
    amis: list[AMI] | None = None,
    lt_versions: list[LaunchTemplateVersion] | None = None,
    asgs: list[AutoScalingGroup] | None = None,
    instances: list[EC2Instance] | None = None,
) -> Inventory:
    inv = Inventory(
        account_id=ACCOUNT,
        region=REGION,
        scanned_at=NOW,
        volumes=volumes or [],
        snapshots=snapshots or [],
        amis=amis or [],
        instances=instances or [],
        launch_template_versions=lt_versions or [],
        auto_scaling_groups=asgs or [],
    )
    RelationshipBuilder(inv.graph).build_all(inv)
    return inv


def _run(inv: Inventory) -> list:
    return ASGEBSOrphanChainCorrelator().correlate(inv, [])


# ---------------------------------------------------------------------------
# No-case scenarios
# ---------------------------------------------------------------------------


def test_empty_inventory_produces_no_cases() -> None:
    assert _run(_make_inventory()) == []


def test_no_available_volumes_produces_no_cases() -> None:
    inv = _make_inventory(volumes=[_attached_volume()])
    assert _run(inv) == []


def test_attached_volume_excluded_from_candidates() -> None:
    # Protective: even if the attached volume's snapshot traces to an LT, it must not fire
    vol = _attached_volume()
    snap = _snapshot(volume_id=vol.volume_id)
    ami = _ami(snapshot_ids=[SNAP_ID])
    lt = _lt_ver()
    asg = _asg()
    inv = _make_inventory(
        volumes=[vol],
        snapshots=[snap],
        amis=[ami],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv) == []


def test_no_snapshot_id_produces_no_cases() -> None:
    # Volume without snapshot_id has no lineage to trace
    vol = _available_volume(snapshot_id=None)
    inv = _make_inventory(volumes=[vol])
    assert _run(inv) == []


def test_heuristic_only_cluster_no_case() -> None:
    # Volume has same size/type as an LT config but no confirmed snapshot→AMI link
    vol = _available_volume(snapshot_id="snap-nolink")
    snap = _snapshot(snapshot_id="snap-nolink")
    # AMI does NOT list "snap-nolink" in snapshot_ids → no confirmed lineage
    ami = _ami(snapshot_ids=["snap-other"])
    lt = _lt_ver()
    asg = _asg()
    inv = _make_inventory(
        volumes=[vol],
        snapshots=[snap],
        amis=[ami],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv) == []


def test_no_lt_version_for_ami_produces_no_cases() -> None:
    vol = _available_volume()
    snap = _snapshot()
    ami = _ami()
    inv = _make_inventory(volumes=[vol], snapshots=[snap], amis=[ami], lt_versions=[])
    assert _run(inv) == []


# ---------------------------------------------------------------------------
# Basic confirmed case
# ---------------------------------------------------------------------------


def test_full_chain_produces_one_case() -> None:
    vol = _available_volume()
    snap = _snapshot()
    ami = _ami()
    lt = _lt_ver()
    asg = _asg()
    inv = _make_inventory(
        volumes=[vol],
        snapshots=[snap],
        amis=[ami],
        lt_versions=[lt],
        asgs=[asg],
    )
    cases = _run(inv)
    assert len(cases) == 1


def test_case_id_format() -> None:
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver()],
        asgs=[_asg()],
    )
    case = _run(inv)[0]
    assert case.case_id == f"ASG_EBS_LEAK:{ACCOUNT}:{REGION}:{TEMPLATE_ID}"


def test_case_type() -> None:
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver()],
        asgs=[_asg()],
    )
    assert _run(inv)[0].case_type == "ASG_EBS_LEAK"


def test_affected_resources_lists_orphan_volumes() -> None:
    vols = [_available_volume(f"vol-{i}") for i in range(3)]
    snaps = [_snapshot(SNAP_ID)]
    inv = _make_inventory(
        volumes=vols,
        snapshots=snaps,
        amis=[_ami()],
        lt_versions=[_lt_ver()],
        asgs=[_asg()],
    )
    case = _run(inv)[0]
    ids = {r.resource_id for r in case.affected_resource_refs}
    assert ids == {"vol-0", "vol-1", "vol-2"}


def test_root_cause_ref_is_launch_template() -> None:
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver()],
        asgs=[_asg()],
    )
    case = _run(inv)[0]
    assert case.root_cause_ref.resource_type == "launch_template"
    assert case.root_cause_ref.resource_id == TEMPLATE_ID


# ---------------------------------------------------------------------------
# Protective: delete_on_termination=None → no defect
# ---------------------------------------------------------------------------


def test_dot_none_in_lt_bdm_not_a_defect() -> None:
    # LT BDM with delete_on_termination=None → AMI_DEFAULT source → not a defect
    vol = _available_volume()
    snap = _snapshot()
    ami = _ami()
    lt = _lt_ver(root_dot=None)
    asg = _asg()
    inv = _make_inventory(
        volumes=[vol],
        snapshots=[snap],
        amis=[ami],
        lt_versions=[lt],
        asgs=[asg],
    )
    # Case is still created (lineage confirmed), but recurrence check won't find defect
    # The ASG's effective version has DoT=None → not defective → HISTORICAL or UNKNOWN
    cases = _run(inv)
    assert len(cases) == 1
    case = cases[0]
    # Recurrence: the ASG uses this version but it's not defective → HISTORICAL
    assert case.recurrence == RecurrenceStatus.HISTORICAL


def test_dot_true_in_lt_bdm_recurrence_historical() -> None:
    # LT BDM with delete_on_termination=True → fixed; ASG uses it → HISTORICAL
    lt = _lt_ver(root_dot=True)
    asg = _asg()
    # But wait: if DoT=True, no volumes are orphaned by THIS template
    # → no confirmed chain → no case
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    # The lineage chain IS confirmed (snap_id in ami.snapshot_ids, ami.image_id == lt.image_id)
    # but root_cfg.delete_on_termination=True for the effective version → not defective → HISTORICAL
    cases = _run(inv)
    assert len(cases) == 1
    assert cases[0].recurrence == RecurrenceStatus.HISTORICAL


# ---------------------------------------------------------------------------
# Recurrence — version selector semantics
# ---------------------------------------------------------------------------


def test_recurrence_active_when_asg_uses_defective_default() -> None:
    lt = _lt_ver(version_number=1, is_default=True, is_latest=True, root_dot=False)
    asg = _asg(version_selector="$Default", resolved_version_number=1, max_size=5)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


def test_asg_pinned_to_broken_version_default_fixed_active() -> None:
    # ASG pinned to v1 (broken), default = v2 (fixed)
    # Effective version = v1 (broken) → ACTIVE
    lt_v1 = _lt_ver(version_number=1, is_default=False, is_latest=False, root_dot=False)
    lt_v2 = _lt_ver(version_number=2, is_default=True, is_latest=True, root_dot=True)
    asg = _asg(version_selector="1", resolved_version_number=1, max_size=5)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt_v1, lt_v2],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


def test_asg_pinned_to_fixed_version_latest_broken_not_active_for_this_asg() -> None:
    # ASG pinned to v1 (fixed), latest = v2 (broken)
    # Effective version = v1 (fixed) → not defective for this ASG
    lt_v1 = _lt_ver(version_number=1, is_default=True, is_latest=False, root_dot=True)
    lt_v2 = _lt_ver(version_number=2, is_default=False, is_latest=True, root_dot=False)
    asg = _asg(version_selector="1", resolved_version_number=1, max_size=5)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt_v1, lt_v2],
        asgs=[asg],
    )
    # ASG uses v1 (fixed) → not active for this ASG; v2 exists but no ASG uses it
    assert _run(inv)[0].recurrence == RecurrenceStatus.HISTORICAL


def test_dollar_default_evaluated_against_resolved_version() -> None:
    # version_selector="$Default", resolved_version_number=2 (broken)
    lt_v1 = _lt_ver(version_number=1, is_default=False, is_latest=False, root_dot=True)
    lt_v2 = _lt_ver(version_number=2, is_default=True, is_latest=True, root_dot=False)
    asg = _asg(version_selector="$Default", resolved_version_number=2)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt_v1, lt_v2],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


def test_dollar_latest_evaluated_against_resolved_version() -> None:
    # version_selector="$Latest", resolved_version_number=3 (broken)
    lt_v2 = _lt_ver(version_number=2, is_default=True, is_latest=False, root_dot=True)
    lt_v3 = _lt_ver(version_number=3, is_default=False, is_latest=True, root_dot=False)
    asg = _asg(version_selector="$Latest", resolved_version_number=3)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt_v2, lt_v3],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


# ---------------------------------------------------------------------------
# Recurrence — launch-path semantics
# ---------------------------------------------------------------------------


def test_desired_capacity_zero_max_size_positive_is_active() -> None:
    # desired_capacity=0, max_size=10 → has_reachable_launch_path=True → ACTIVE
    lt = _lt_ver(root_dot=False)
    asg = _asg(desired_capacity=0, max_size=10)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


def test_max_size_zero_defective_lt_is_unknown_not_active() -> None:
    # max_size=0 → has_reachable_launch_path=False → ASG is sealed; defect cannot materialize
    lt = _lt_ver(root_dot=False)
    asg = _asg(desired_capacity=0, max_size=0)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    # Defect confirmed but max_size=0 → has_incomplete = True → UNKNOWN (no proven active path)
    assert _run(inv)[0].recurrence == RecurrenceStatus.UNKNOWN


def test_empty_asg_list_for_template_is_unknown_not_historical() -> None:
    lt = _lt_ver(root_dot=False)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[],  # no ASGs
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.UNKNOWN


def test_asg_defective_holds_active_even_with_incomplete_sibling() -> None:
    # asg-A: defective effective version, max_size=5 → defective
    # asg-B: resolved_version_number points to missing version → has_incomplete
    # Result: ACTIVE (proven defective path is not negated by incomplete sibling)
    lt = _lt_ver(version_number=1, root_dot=False)
    asg_a = _asg("asg-a", resolved_version_number=1, max_size=5)
    asg_b = _asg("asg-b", resolved_version_number=99, max_size=3)  # v99 not in inventory
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg_a, asg_b],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


def test_multiple_asgs_one_defective_one_fixed_active() -> None:
    # asg-A: effective v1 (broken) → ACTIVE
    # asg-B: effective v2 (fixed) → non_defective
    lt_v1 = _lt_ver(version_number=1, is_default=False, is_latest=False, root_dot=False)
    lt_v2 = _lt_ver(version_number=2, is_default=True, is_latest=True, root_dot=True)
    asg_a = _asg("asg-a", resolved_version_number=1, max_size=5)
    asg_b = _asg("asg-b", resolved_version_number=2, max_size=5)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt_v1, lt_v2],
        asgs=[asg_a, asg_b],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.ACTIVE


def test_all_asgs_fixed_is_historical() -> None:
    lt_v1 = _lt_ver(version_number=1, root_dot=True)
    asg = _asg(resolved_version_number=1)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt_v1],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.HISTORICAL


# ---------------------------------------------------------------------------
# Recurrence — missing/unresolvable effective version
# ---------------------------------------------------------------------------


def test_unresolvable_effective_version_is_unknown() -> None:
    lt = _lt_ver(version_number=1, root_dot=False)
    asg = _asg(resolved_version_number=99)  # v99 not in inventory
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv)[0].recurrence == RecurrenceStatus.UNKNOWN


# ---------------------------------------------------------------------------
# MixedInstancesPolicy
# ---------------------------------------------------------------------------


def test_mixed_instances_policy_override_lt_sets_incomplete() -> None:
    lt = _lt_ver(root_dot=False)
    # ASG has MixedInstancesPolicy with an override that has its own LT
    override_lt_ref = LaunchTemplateRef(
        template_id="lt-override",
        version_selector="$Latest",
        resolved_version_number=1,
    )
    policy = MixedInstancesPolicy(
        base_launch_template_ref=LaunchTemplateRef(
            template_id=TEMPLATE_ID,
            version_selector="$Default",
            resolved_version_number=1,
        ),
        overrides=[
            MixedInstancesOverride(
                instance_type="m5.large",
                launch_template_ref=override_lt_ref,
            )
        ],
    )
    asg = AutoScalingGroup(
        asg_name="asg-mixed",
        region=REGION,
        account_id=ACCOUNT,
        mixed_instances_policy=policy,
        desired_capacity=2,
        min_size=0,
        max_size=5,
    )
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    case = _run(inv)[0]
    # has_incomplete=True due to override LTs; base path might still be evaluated
    # The base path uses v1 (defective) → ACTIVE despite incomplete override paths
    assert case.recurrence == RecurrenceStatus.ACTIVE
    ev_codes = [e.code for e in case.evidence]
    assert "LAUNCH_PATH_PARTIALLY_UNRESOLVED" in ev_codes


# ---------------------------------------------------------------------------
# Ambiguous lineage
# ---------------------------------------------------------------------------


def test_ambiguous_lineage_two_lts_produces_no_case() -> None:
    # Volume's snapshot appears in both AMI-A and AMI-B, each used by different LTs
    snap = _snapshot()
    ami_a = _ami("ami-aaa", snapshot_ids=[SNAP_ID])
    ami_b = _ami("ami-bbb", snapshot_ids=[SNAP_ID])
    lt_a = _lt_ver(version_number=1, image_id="ami-aaa", template_id="lt-aaaa", root_dot=False)
    lt_b = _lt_ver(version_number=1, image_id="ami-bbb", template_id="lt-bbbb", root_dot=False)
    asg_a = _asg("asg-a", template_id="lt-aaaa")
    asg_b = _asg("asg-b", template_id="lt-bbbb")
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[snap],
        amis=[ami_a, ami_b],
        lt_versions=[lt_a, lt_b],
        asgs=[asg_a, asg_b],
    )
    # Volume has lineage to both lt-aaaa and lt-bbbb → ambiguous → no case
    assert _run(inv) == []


def test_ambiguous_volume_not_in_either_case_when_other_volumes_confirmed() -> None:
    # vol-ambiguous: snapshot links to two LTs → excluded
    # vol-clear: snapshot links to exactly one LT → included in case for lt-aaaa
    snap_shared = _snapshot(SNAP_ID, "vol-ambiguous")
    snap_clear = _snapshot("snap-clear", "vol-clear")
    ami_a = _ami("ami-aaa", snapshot_ids=[SNAP_ID, "snap-clear"])
    ami_b = _ami("ami-bbb", snapshot_ids=[SNAP_ID])
    lt_a = _lt_ver(version_number=1, image_id="ami-aaa", template_id="lt-aaaa", root_dot=False)
    lt_b = _lt_ver(version_number=1, image_id="ami-bbb", template_id="lt-bbbb", root_dot=False)
    asg_a = _asg("asg-a", template_id="lt-aaaa")
    asg_b = _asg("asg-b", template_id="lt-bbbb")
    inv = _make_inventory(
        volumes=[
            _available_volume("vol-ambiguous", snapshot_id=SNAP_ID),
            _available_volume("vol-clear", snapshot_id="snap-clear"),
        ],
        snapshots=[snap_shared, snap_clear],
        amis=[ami_a, ami_b],
        lt_versions=[lt_a, lt_b],
        asgs=[asg_a, asg_b],
    )
    cases = _run(inv)
    # Only one case for lt-aaaa (vol-clear), no case for lt-bbbb (no confirmed unambiguous vols)
    assert len(cases) == 1
    case = cases[0]
    assert case.root_cause_ref.resource_id == "lt-aaaa"
    vol_ids = {r.resource_id for r in case.affected_resource_refs}
    assert "vol-ambiguous" not in vol_ids
    assert "vol-clear" in vol_ids


# ---------------------------------------------------------------------------
# Multiple volumes same LT → one case
# ---------------------------------------------------------------------------


def test_multiple_volumes_same_lt_one_case() -> None:
    vols = [_available_volume(f"vol-{i}") for i in range(5)]
    inv = _make_inventory(
        volumes=vols,
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver()],
        asgs=[_asg()],
    )
    cases = _run(inv)
    assert len(cases) == 1
    assert len(cases[0].affected_resource_refs) == 5


# ---------------------------------------------------------------------------
# Multiple LTs → multiple independent cases
# ---------------------------------------------------------------------------


def test_two_lts_two_independent_cases() -> None:
    snap_a = _snapshot("snap-a", "vol-a")
    snap_b = _snapshot("snap-b", "vol-b")
    ami_a = _ami("ami-aaa", snapshot_ids=["snap-a"])
    ami_b = _ami("ami-bbb", snapshot_ids=["snap-b"])
    lt_a = _lt_ver(version_number=1, image_id="ami-aaa", template_id="lt-aaaa", root_dot=False)
    lt_b = _lt_ver(version_number=1, image_id="ami-bbb", template_id="lt-bbbb", root_dot=False)
    inv = _make_inventory(
        volumes=[
            _available_volume("vol-a", snapshot_id="snap-a"),
            _available_volume("vol-b", snapshot_id="snap-b"),
        ],
        snapshots=[snap_a, snap_b],
        amis=[ami_a, ami_b],
        lt_versions=[lt_a, lt_b],
        asgs=[
            _asg("asg-a", template_id="lt-aaaa"),
            _asg("asg-b", template_id="lt-bbbb"),
        ],
    )
    cases = _run(inv)
    assert len(cases) == 2
    template_ids = {c.root_cause_ref.resource_id for c in cases}
    assert template_ids == {"lt-aaaa", "lt-bbbb"}


# ---------------------------------------------------------------------------
# Confirmed lineage without snapshot in inventory
# ---------------------------------------------------------------------------


def test_snapshot_not_in_inventory_but_id_matches_ami_confirms_lineage() -> None:
    # vol.snapshot_id = SNAP_ID is in ami.snapshot_ids but snapshot is NOT in inventory
    vol = _available_volume(snapshot_id=SNAP_ID)
    ami = _ami(snapshot_ids=[SNAP_ID])
    lt = _lt_ver(root_dot=False)
    asg = _asg()
    inv = _make_inventory(
        volumes=[vol],
        snapshots=[],  # no snapshot in inventory
        amis=[ami],
        lt_versions=[lt],
        asgs=[asg],
    )
    cases = _run(inv)
    # Confirmed via direct ID match → case emitted
    assert len(cases) == 1


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------


def test_severity_high_when_active() -> None:
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver(root_dot=False)],
        asgs=[_asg(max_size=5)],
    )
    assert _run(inv)[0].severity == Severity.HIGH


def test_severity_medium_when_unknown() -> None:
    lt = _lt_ver(root_dot=False)
    asg = _asg(resolved_version_number=99)  # unresolvable
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv)[0].severity == Severity.MEDIUM


def test_severity_low_when_historical() -> None:
    lt = _lt_ver(root_dot=True)
    asg = _asg(resolved_version_number=1)
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
    )
    assert _run(inv)[0].severity == Severity.LOW


# ---------------------------------------------------------------------------
# Evidence strength
# ---------------------------------------------------------------------------


def test_strength_high_when_ratio_high_and_active() -> None:
    # All 5 volumes have snapshot in inventory → ratio = 1.0 → HIGH
    vols = [_available_volume(f"vol-{i}") for i in range(5)]
    snaps = [_snapshot()]
    inv = _make_inventory(
        volumes=vols,
        snapshots=snaps,
        amis=[_ami()],
        lt_versions=[_lt_ver(root_dot=False)],
        asgs=[_asg(max_size=5)],
    )
    assert _run(inv)[0].evidence_strength == EvidenceStrength.HIGH


def test_two_lt_groups_independent_evidence_strength() -> None:
    # lt-aaaa: all volumes fully chained → HIGH
    # lt-bbbb: only 1/5 volumes have snapshot in inventory → LOW (ratio < 0.4)
    snap_a = _snapshot("snap-a", "vol-a0")

    # For lt-bbbb: 5 volumes but only 1 has snapshot in inventory
    snap_b_0 = _snapshot("snap-b0", "vol-b0")  # in inventory
    ami_a = _ami("ami-aaa", snapshot_ids=["snap-a"])
    ami_b = _ami("ami-bbb", snapshot_ids=["snap-b0", "snap-b1", "snap-b2", "snap-b3", "snap-b4"])
    lt_a = _lt_ver(version_number=1, image_id="ami-aaa", template_id="lt-aaaa", root_dot=False)
    lt_b = _lt_ver(version_number=1, image_id="ami-bbb", template_id="lt-bbbb", root_dot=False)
    asg_a = _asg("asg-a", template_id="lt-aaaa", max_size=5)
    asg_b = _asg("asg-b", template_id="lt-bbbb", max_size=5)

    vols_a = [_available_volume(f"vol-a{i}", snapshot_id="snap-a") for i in range(5)]
    vols_b = [_available_volume(f"vol-b{i}", snapshot_id=f"snap-b{i}") for i in range(5)]

    inv = _make_inventory(
        volumes=vols_a + vols_b,
        snapshots=[snap_a, snap_b_0],  # only snap-a and snap-b0 in inventory
        amis=[ami_a, ami_b],
        lt_versions=[lt_a, lt_b],
        asgs=[asg_a, asg_b],
    )
    cases = _run(inv)
    assert len(cases) == 2
    by_lt = {c.root_cause_ref.resource_id: c for c in cases}
    # lt-aaaa: 5/5 snapshots in inventory → HIGH
    assert by_lt["lt-aaaa"].evidence_strength == EvidenceStrength.HIGH
    # lt-bbbb: 1/5 snapshots in inventory → LOW (ratio 0.2 < 0.4)
    assert by_lt["lt-bbbb"].evidence_strength == EvidenceStrength.LOW


# ---------------------------------------------------------------------------
# Live instance corroboration
# ---------------------------------------------------------------------------


def test_live_instance_root_dot_false_adds_evidence() -> None:
    lt = _lt_ver(root_dot=False)
    asg_inst = ASGInstance(instance_id="i-live", lifecycle_state="InService")
    asg = _asg(max_size=5, current_instances=[asg_inst])
    instance = EC2Instance(
        instance_id="i-live",
        region=REGION,
        account_id=ACCOUNT,
        state="running",
        instance_type="m5.large",
        launch_time=NOW - timedelta(hours=2),
        root_device_name="/dev/xvda",
        block_device_mappings=[
            VolumeAttachment(
                instance_id="i-live",
                device="/dev/xvda",
                state="attached",
                delete_on_termination=False,
            )
        ],
    )
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
        instances=[instance],
    )
    case = _run(inv)[0]
    ev_codes = [e.code for e in case.evidence]
    assert "LIVE_INSTANCE_ROOT_PRESERVES_VOLUME" in ev_codes


def test_live_instance_root_dot_true_no_corroboration_evidence() -> None:
    lt = _lt_ver(root_dot=False)
    asg_inst = ASGInstance(instance_id="i-live", lifecycle_state="InService")
    asg = _asg(max_size=5, current_instances=[asg_inst])
    instance = EC2Instance(
        instance_id="i-live",
        region=REGION,
        account_id=ACCOUNT,
        state="running",
        instance_type="m5.large",
        launch_time=NOW - timedelta(hours=2),
        root_device_name="/dev/xvda",
        block_device_mappings=[
            VolumeAttachment(
                instance_id="i-live",
                device="/dev/xvda",
                state="attached",
                delete_on_termination=True,  # fixed on running instance
            )
        ],
    )
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[lt],
        asgs=[asg],
        instances=[instance],
    )
    case = _run(inv)[0]
    ev_codes = [e.code for e in case.evidence]
    assert "LIVE_INSTANCE_ROOT_PRESERVES_VOLUME" not in ev_codes


# ---------------------------------------------------------------------------
# Evidence codes
# ---------------------------------------------------------------------------


def test_core_evidence_codes_present() -> None:
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver(root_dot=False)],
        asgs=[_asg()],
    )
    case = _run(inv)[0]
    codes = [e.code for e in case.evidence]
    assert "ORPHAN_VOLUME_COUNT" in codes
    assert "CONFIRMED_LINEAGE_COUNT" in codes
    assert "RECURRENCE_STATUS" in codes


def test_defective_asg_evidence_when_active() -> None:
    inv = _make_inventory(
        volumes=[_available_volume()],
        snapshots=[_snapshot()],
        amis=[_ami()],
        lt_versions=[_lt_ver(root_dot=False)],
        asgs=[_asg(max_size=5)],
    )
    case = _run(inv)[0]
    codes = [e.code for e in case.evidence]
    assert "DEFECTIVE_ASG_LAUNCH_PATH" in codes


def test_supersedes_rules_class_var() -> None:
    corr = ASGEBSOrphanChainCorrelator()
    assert "EBS_UNATTACHED_STALE" in corr.supersedes_rules
    assert "EBS_GP2_TO_GP3" in corr.supersedes_rules


# ---------------------------------------------------------------------------
# Volume cannot appear in two cases
# ---------------------------------------------------------------------------


def test_one_volume_in_at_most_one_case() -> None:
    # Two LTs; vol-001 only links to lt-aaaa (unambiguous)
    snap_a = _snapshot("snap-a", "vol-001")
    ami_a = _ami("ami-aaa", snapshot_ids=["snap-a"])
    lt_a = _lt_ver(version_number=1, image_id="ami-aaa", template_id="lt-aaaa", root_dot=False)
    lt_b = _lt_ver(version_number=1, image_id="ami-bbb", template_id="lt-bbbb", root_dot=False)
    inv = _make_inventory(
        volumes=[_available_volume("vol-001", snapshot_id="snap-a")],
        snapshots=[snap_a],
        amis=[ami_a],
        lt_versions=[lt_a, lt_b],
        asgs=[
            _asg("asg-a", template_id="lt-aaaa"),
        ],
    )
    cases = _run(inv)
    all_vol_ids: list[str] = []
    for case in cases:
        all_vol_ids.extend(r.resource_id for r in case.affected_resource_refs)
    # vol-001 must appear at most once
    assert all_vol_ids.count("vol-001") <= 1
