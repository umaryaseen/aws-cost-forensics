"""Tests for ResourceGraph, RelationshipBuilder, and resolve_effective_root_device."""

from __future__ import annotations

from datetime import UTC, datetime

from aws_cost_forensics.domain.enums import (
    DeleteOnTerminationSource,
    RelationshipType,
)
from aws_cost_forensics.domain.inventory import Inventory
from aws_cost_forensics.domain.resource_key import ResourceKey
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
from aws_cost_forensics.graph.builder import RelationshipBuilder, resolve_effective_root_device
from aws_cost_forensics.graph.resource_graph import ResourceGraph

REGION = "eu-central-1"
ACCOUNT = "111111111111"
NOW = datetime(2024, 1, 15, tzinfo=UTC)


def make_vol(vol_id: str, snapshot_id: str | None = None) -> EBSVolume:
    return EBSVolume(
        volume_id=vol_id,
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        size_gib=100,
        volume_type="gp2",
        create_time=NOW,
        availability_zone="eu-central-1a",
        snapshot_id=snapshot_id,
    )


def make_snap(snap_id: str) -> EBSSnapshot:
    return EBSSnapshot(
        snapshot_id=snap_id,
        region=REGION,
        account_id=ACCOUNT,
        volume_size_gib=100,
        state="completed",
        start_time=NOW,
    )


def make_ami(image_id: str, snapshot_ids: list[str], root_device: str = "/dev/xvda") -> AMI:
    return AMI(
        image_id=image_id,
        region=REGION,
        account_id=ACCOUNT,
        state="available",
        creation_date=NOW,
        root_device_name=root_device,
        snapshot_ids=snapshot_ids,
    )


def make_lt_ver(
    template_id: str,
    version: int,
    image_id: str | None = None,
    bdms: list[BlockDeviceMapping] | None = None,
    is_default: bool = True,
    is_latest: bool = True,
) -> LaunchTemplateVersion:
    return LaunchTemplateVersion(
        template_id=template_id,
        region=REGION,
        account_id=ACCOUNT,
        version_number=version,
        is_default=is_default,
        is_latest=is_latest,
        image_id=image_id,
        block_device_mappings=bdms or [],
    )


def make_asg(
    asg_name: str,
    template_id: str,
    version_selector: str = "$Default",
    resolved_version: int = 1,
) -> AutoScalingGroup:
    return AutoScalingGroup(
        asg_name=asg_name,
        region=REGION,
        account_id=ACCOUNT,
        launch_template_ref=LaunchTemplateRef(
            template_id=template_id,
            version_selector=version_selector,
            resolved_version_number=resolved_version,
        ),
        desired_capacity=2,
        min_size=1,
        max_size=10,
    )


def make_inventory(**kwargs: object) -> Inventory:
    defaults: dict[str, object] = {
        "account_id": ACCOUNT,
        "region": REGION,
        "scanned_at": NOW,
        "volumes": [],
        "snapshots": [],
        "amis": [],
        "instances": [],
        "launch_template_versions": [],
        "auto_scaling_groups": [],
    }
    defaults.update(kwargs)
    return Inventory(**defaults)  # type: ignore[arg-type]


def build(inventory: Inventory) -> ResourceGraph:
    graph = ResourceGraph()
    RelationshipBuilder(graph).build_all(inventory)
    inventory.graph = graph
    return graph


# =============================================================================
# ResourceGraph
# =============================================================================

def test_graph_add_and_targets() -> None:
    g = ResourceGraph()
    src = ResourceKey("ebs_volume", "vol-1", REGION, ACCOUNT)
    tgt = ResourceKey("snapshot", "snap-1", REGION, ACCOUNT)
    g.add(src, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT, tgt)
    assert g.targets(src, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT) == [tgt]


def test_graph_sources() -> None:
    g = ResourceGraph()
    src = ResourceKey("snapshot", "snap-1", REGION, ACCOUNT)
    tgt = ResourceKey("ami", "ami-1", REGION, ACCOUNT)
    g.add(src, RelationshipType.SNAPSHOT_BELONGS_TO_AMI, tgt)
    assert g.sources(tgt, RelationshipType.SNAPSHOT_BELONGS_TO_AMI) == [src]


def test_graph_has_edge_true() -> None:
    g = ResourceGraph()
    src = ResourceKey("ebs_volume", "vol-1", REGION, ACCOUNT)
    tgt = ResourceKey("snapshot", "snap-1", REGION, ACCOUNT)
    g.add(src, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT, tgt)
    assert g.has_edge(src, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT, tgt)


def test_graph_has_edge_false() -> None:
    g = ResourceGraph()
    src = ResourceKey("ebs_volume", "vol-1", REGION, ACCOUNT)
    tgt = ResourceKey("snapshot", "snap-1", REGION, ACCOUNT)
    assert not g.has_edge(src, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT, tgt)


def test_graph_empty_targets() -> None:
    g = ResourceGraph()
    src = ResourceKey("ebs_volume", "vol-1", REGION, ACCOUNT)
    assert g.targets(src, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT) == []


def test_graph_multiple_targets() -> None:
    g = ResourceGraph()
    snap = ResourceKey("snapshot", "snap-1", REGION, ACCOUNT)
    ami1 = ResourceKey("ami", "ami-1", REGION, ACCOUNT)
    ami2 = ResourceKey("ami", "ami-2", REGION, ACCOUNT)
    g.add(snap, RelationshipType.SNAPSHOT_BELONGS_TO_AMI, ami1)
    g.add(snap, RelationshipType.SNAPSHOT_BELONGS_TO_AMI, ami2)
    assert set(g.targets(snap, RelationshipType.SNAPSHOT_BELONGS_TO_AMI)) == {ami1, ami2}


# =============================================================================
# RelationshipBuilder — all 7 relationship types
# =============================================================================

def test_volume_to_snapshot() -> None:
    snap = make_snap("snap-1")
    vol = make_vol("vol-1", snapshot_id="snap-1")
    inv = make_inventory(volumes=[vol], snapshots=[snap])
    g = build(inv)
    assert g.has_edge(
        vol.resource_key, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT, snap.resource_key
    )


def test_volume_without_snapshot_no_edge() -> None:
    vol = make_vol("vol-1", snapshot_id=None)
    inv = make_inventory(volumes=[vol])
    g = build(inv)
    assert g.targets(vol.resource_key, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT) == []


def test_snapshot_to_ami() -> None:
    snap = make_snap("snap-1")
    ami = make_ami("ami-1", snapshot_ids=["snap-1"])
    inv = make_inventory(snapshots=[snap], amis=[ami])
    g = build(inv)
    assert g.has_edge(
        snap.resource_key, RelationshipType.SNAPSHOT_BELONGS_TO_AMI, ami.resource_key
    )


def test_lt_version_to_ami() -> None:
    ami = make_ami("ami-1", snapshot_ids=[])
    lt_ver = make_lt_ver("lt-prod", 1, image_id="ami-1")
    inv = make_inventory(amis=[ami], launch_template_versions=[lt_ver])
    g = build(inv)
    assert g.has_edge(
        lt_ver.resource_key, RelationshipType.LT_VERSION_USES_AMI, ami.resource_key
    )


def test_lt_version_to_lt() -> None:
    lt_ver = make_lt_ver("lt-prod", 1)
    inv = make_inventory(launch_template_versions=[lt_ver])
    g = build(inv)
    assert g.has_edge(
        lt_ver.resource_key, RelationshipType.LT_VERSION_BELONGS_TO_LT, lt_ver.template_key
    )


def test_asg_to_lt() -> None:
    asg = make_asg("asg-web", "lt-prod")
    inv = make_inventory(auto_scaling_groups=[asg])
    g = build(inv)
    lt_key = ResourceKey("launch_template", "lt-prod", REGION, ACCOUNT)
    assert g.has_edge(asg.resource_key, RelationshipType.ASG_USES_LAUNCH_TEMPLATE, lt_key)


def test_asg_to_instance() -> None:
    inst = EC2Instance(
        instance_id="i-abc",
        region=REGION,
        account_id=ACCOUNT,
        state="running",
        instance_type="m5.large",
        launch_time=NOW,
    )
    asg = AutoScalingGroup(
        asg_name="asg-web",
        region=REGION,
        account_id=ACCOUNT,
        desired_capacity=1,
        min_size=1,
        max_size=5,
        current_instances=[ASGInstance(instance_id="i-abc", lifecycle_state="InService")],
    )
    inv = make_inventory(instances=[inst], auto_scaling_groups=[asg])
    g = build(inv)
    assert g.has_edge(asg.resource_key, RelationshipType.ASG_HAS_INSTANCE, inst.resource_key)


def test_instance_to_volume_via_attachment() -> None:
    attach = VolumeAttachment(
        instance_id="i-abc", device="/dev/xvda", state="attached", delete_on_termination=True
    )
    vol = EBSVolume(
        volume_id="vol-1",
        region=REGION,
        account_id=ACCOUNT,
        state="in-use",
        size_gib=100,
        volume_type="gp2",
        create_time=NOW,
        availability_zone="eu-central-1a",
        attachments=[attach],
    )
    inst = EC2Instance(
        instance_id="i-abc",
        region=REGION,
        account_id=ACCOUNT,
        state="running",
        instance_type="m5.large",
        launch_time=NOW,
        block_device_mappings=[attach],
    )
    inv = make_inventory(volumes=[vol], instances=[inst])
    g = build(inv)
    assert g.has_edge(inst.resource_key, RelationshipType.INSTANCE_USES_VOLUME, vol.resource_key)


def test_asg_mixed_instances_base_and_override_lt() -> None:
    ref_base = LaunchTemplateRef(
        template_id="lt-base",
        version_selector="$Default",
        resolved_version_number=1,
    )
    ref_override = LaunchTemplateRef(
        template_id="lt-override",
        version_selector="$Default",
        resolved_version_number=2,
    )
    policy = MixedInstancesPolicy(
        base_launch_template_ref=ref_base,
        overrides=[MixedInstancesOverride(launch_template_ref=ref_override)],
    )
    asg = AutoScalingGroup(
        asg_name="asg-mixed",
        region=REGION,
        account_id=ACCOUNT,
        mixed_instances_policy=policy,
        desired_capacity=2,
        min_size=1,
        max_size=10,
    )
    inv = make_inventory(auto_scaling_groups=[asg])
    g = build(inv)
    lt_base_key = ResourceKey("launch_template", "lt-base", REGION, ACCOUNT)
    lt_override_key = ResourceKey("launch_template", "lt-override", REGION, ACCOUNT)
    assert g.has_edge(asg.resource_key, RelationshipType.ASG_USES_LAUNCH_TEMPLATE, lt_base_key)
    assert g.has_edge(
        asg.resource_key, RelationshipType.ASG_USES_LAUNCH_TEMPLATE, lt_override_key
    )


# =============================================================================
# Traversal chain
# =============================================================================

def test_full_orphan_chain_traversal() -> None:
    """vol → snap → AMI ← LT version → LT ← ASG — all edges present."""
    snap_with_ami = EBSSnapshot(
        snapshot_id="snap-1",
        region=REGION,
        account_id=ACCOUNT,
        volume_size_gib=100,
        state="completed",
        start_time=NOW,
    )
    ami = make_ami("ami-1", snapshot_ids=["snap-1"])
    lt_ver = make_lt_ver("lt-prod", 1, image_id="ami-1")
    vol = make_vol("vol-1", snapshot_id="snap-1")
    asg = make_asg("asg-web", "lt-prod")
    inv = make_inventory(
        volumes=[vol],
        snapshots=[snap_with_ami],
        amis=[ami],
        launch_template_versions=[lt_ver],
        auto_scaling_groups=[asg],
    )
    g = build(inv)

    # Volume → Snapshot
    snap_keys = g.targets(vol.resource_key, RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT)
    assert len(snap_keys) == 1
    # Snapshot → AMI
    ami_keys = g.targets(snap_keys[0], RelationshipType.SNAPSHOT_BELONGS_TO_AMI)
    assert len(ami_keys) == 1
    # AMI ← LT version
    lt_ver_keys = g.sources(ami_keys[0], RelationshipType.LT_VERSION_USES_AMI)
    assert len(lt_ver_keys) == 1
    # LT version → LT
    lt_keys = g.targets(lt_ver_keys[0], RelationshipType.LT_VERSION_BELONGS_TO_LT)
    assert len(lt_keys) == 1
    # LT ← ASG
    asg_keys = g.sources(lt_keys[0], RelationshipType.ASG_USES_LAUNCH_TEMPLATE)
    assert len(asg_keys) == 1


# =============================================================================
# resolve_effective_root_device
# =============================================================================

def test_resolve_lt_explicit_false() -> None:
    bdm = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=False)
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[bdm])
    ami = make_ami("ami-1", snapshot_ids=[], root_device="/dev/xvda")
    cfg = resolve_effective_root_device(lt_ver, ami)
    assert cfg.source == DeleteOnTerminationSource.LT_EXPLICIT
    assert cfg.delete_on_termination is False


def test_resolve_lt_explicit_true() -> None:
    bdm = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=True)
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[bdm])
    ami = make_ami("ami-1", snapshot_ids=[], root_device="/dev/xvda")
    cfg = resolve_effective_root_device(lt_ver, ami)
    assert cfg.source == DeleteOnTerminationSource.LT_EXPLICIT
    assert cfg.delete_on_termination is True


def test_resolve_bdm_none_with_ami_gives_ami_default() -> None:
    """delete_on_termination=None in BDM + AMI available → AMI_DEFAULT (True)."""
    bdm = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=None)
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[bdm])
    ami = make_ami("ami-1", snapshot_ids=[], root_device="/dev/xvda")
    cfg = resolve_effective_root_device(lt_ver, ami)
    assert cfg.source == DeleteOnTerminationSource.AMI_DEFAULT
    assert cfg.delete_on_termination is True


def test_resolve_no_bdm_with_ami_gives_ami_default() -> None:
    """No BDM at all + AMI available → AMI_DEFAULT."""
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[])
    ami = make_ami("ami-1", snapshot_ids=[], root_device="/dev/xvda")
    cfg = resolve_effective_root_device(lt_ver, ami)
    assert cfg.source == DeleteOnTerminationSource.AMI_DEFAULT


def test_resolve_no_ami_gives_unresolved() -> None:
    """AMI unavailable and no explicit BDM → UNRESOLVED."""
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[])
    cfg = resolve_effective_root_device(lt_ver, ami=None)
    assert cfg.source == DeleteOnTerminationSource.UNRESOLVED
    assert cfg.delete_on_termination is None


def test_resolve_non_root_device_not_confused_with_root() -> None:
    """Data disk /dev/xvdb with False must not be mistaken for the root device."""
    bdm_root = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=None)
    bdm_data = BlockDeviceMapping(device_name="/dev/xvdb", delete_on_termination=False)
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[bdm_root, bdm_data])
    ami = make_ami("ami-1", snapshot_ids=[], root_device="/dev/xvda")
    cfg = resolve_effective_root_device(lt_ver, ami)
    # Root device has no explicit value → AMI_DEFAULT, not LT_EXPLICIT
    assert cfg.source == DeleteOnTerminationSource.AMI_DEFAULT
    assert cfg.device_name == "/dev/xvda"


def test_resolve_uses_ami_root_device_name_first() -> None:
    """AMI.root_device_name takes priority over BDM heuristics."""
    bdm = BlockDeviceMapping(device_name="/dev/sda1", delete_on_termination=False)
    lt_ver = make_lt_ver("lt-prod", 1, bdms=[bdm])
    ami = make_ami("ami-1", snapshot_ids=[], root_device="/dev/xvda")
    cfg = resolve_effective_root_device(lt_ver, ami)
    # AMI says root is /dev/xvda, but BDM only has /dev/sda1 → no BDM match → AMI_DEFAULT
    assert cfg.source == DeleteOnTerminationSource.AMI_DEFAULT
    assert cfg.device_name == "/dev/xvda"
