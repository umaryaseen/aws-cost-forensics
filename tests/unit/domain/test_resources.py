"""Tests for domain resource models."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from aws_cost_forensics.domain.enums import DeleteOnTerminationSource
from aws_cost_forensics.domain.resource_key import ResourceKey
from aws_cost_forensics.domain.resources import (
    ASGInstance,
    AutoScalingGroup,
    BlockDeviceMapping,
    EBSVolume,
    EffectiveRootDeviceConfig,
    LaunchTemplateRef,
    LaunchTemplateVersion,
    MixedInstancesOverride,
    MixedInstancesPolicy,
    VolumeAttachment,
)

NOW = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)
REGION = "eu-central-1"
ACCOUNT = "111111111111"


def make_volume(
    volume_id: str = "vol-001",
    state: str = "available",
    snapshot_id: str | None = None,
) -> EBSVolume:
    return EBSVolume(
        volume_id=volume_id,
        region=REGION,
        account_id=ACCOUNT,
        state=state,
        size_gib=100,
        volume_type="gp2",
        create_time=NOW,
        availability_zone="eu-central-1a",
        snapshot_id=snapshot_id,
    )


def make_lt_ref(
    version_selector: str = "$Default",
    resolved_version_number: int = 5,
) -> LaunchTemplateRef:
    return LaunchTemplateRef(
        template_id="lt-prod",
        version_selector=version_selector,
        resolved_version_number=resolved_version_number,
    )


def make_asg(
    max_size: int = 10,
    desired_capacity: int = 2,
    min_size: int = 1,
    lt_ref: LaunchTemplateRef | None = None,
    mixed_policy: MixedInstancesPolicy | None = None,
) -> AutoScalingGroup:
    return AutoScalingGroup(
        asg_name="asg-web",
        region=REGION,
        account_id=ACCOUNT,
        launch_template_ref=lt_ref,
        mixed_instances_policy=mixed_policy,
        desired_capacity=desired_capacity,
        min_size=min_size,
        max_size=max_size,
    )


# --- EBSVolume ---


def test_volume_resource_key() -> None:
    vol = make_volume("vol-123")
    assert vol.resource_key == ResourceKey("ebs_volume", "vol-123", REGION, ACCOUNT)


def test_volume_frozen() -> None:
    vol = make_volume()
    with pytest.raises(ValidationError):
        vol.state = "in-use"  # type: ignore[misc]


def test_volume_snapshot_id_none() -> None:
    vol = make_volume(snapshot_id=None)
    assert vol.snapshot_id is None


def test_volume_snapshot_id_set() -> None:
    vol = make_volume(snapshot_id="snap-abc")
    assert vol.snapshot_id == "snap-abc"


# --- BlockDeviceMapping ---


def test_bdm_delete_on_termination_none() -> None:
    """Absent AWS API field must remain None — not coerced to False."""
    bdm = BlockDeviceMapping(device_name="/dev/xvda")
    assert bdm.delete_on_termination is None


def test_bdm_delete_on_termination_false() -> None:
    bdm = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=False)
    assert bdm.delete_on_termination is False


def test_bdm_delete_on_termination_true() -> None:
    bdm = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=True)
    assert bdm.delete_on_termination is True


def test_bdm_frozen() -> None:
    bdm = BlockDeviceMapping(device_name="/dev/xvda", delete_on_termination=False)
    with pytest.raises(ValidationError):
        bdm.device_name = "/dev/sda1"  # type: ignore[misc]


# --- EffectiveRootDeviceConfig ---


def test_effective_root_config_lt_explicit_false() -> None:
    cfg = EffectiveRootDeviceConfig(
        device_name="/dev/xvda",
        delete_on_termination=False,
        source=DeleteOnTerminationSource.LT_EXPLICIT,
    )
    assert cfg.delete_on_termination is False
    assert cfg.source == DeleteOnTerminationSource.LT_EXPLICIT


def test_effective_root_config_unresolved_allows_none() -> None:
    cfg = EffectiveRootDeviceConfig(
        device_name="/dev/xvda",
        delete_on_termination=None,
        source=DeleteOnTerminationSource.UNRESOLVED,
    )
    assert cfg.delete_on_termination is None


# --- LaunchTemplateVersion ---


def test_lt_version_resource_key() -> None:
    ltv = LaunchTemplateVersion(
        template_id="lt-prod",
        region=REGION,
        account_id=ACCOUNT,
        version_number=3,
        is_default=False,
        is_latest=True,
    )
    key = ltv.resource_key
    assert key == ResourceKey("launch_template_version", "lt-prod", REGION, ACCOUNT, qualifier="3")


def test_lt_version_template_key() -> None:
    ltv = LaunchTemplateVersion(
        template_id="lt-prod",
        region=REGION,
        account_id=ACCOUNT,
        version_number=3,
        is_default=False,
        is_latest=True,
    )
    assert ltv.template_key == ResourceKey("launch_template", "lt-prod", REGION, ACCOUNT)


# --- AutoScalingGroup.has_reachable_launch_path ---


def test_has_reachable_launch_path_normal_asg() -> None:
    assert make_asg(max_size=10).has_reachable_launch_path is True


def test_has_reachable_launch_path_desired_zero_max_positive() -> None:
    """desired_capacity=0 with max_size>0 retains a reachable launch path."""
    asg = make_asg(max_size=10, desired_capacity=0, min_size=0)
    assert asg.has_reachable_launch_path is True


def test_has_reachable_launch_path_max_size_zero() -> None:
    """max_size=0 means the ASG cannot launch — no reachable path."""
    asg = make_asg(max_size=0, desired_capacity=0, min_size=0)
    assert asg.has_reachable_launch_path is False


def test_has_reachable_launch_path_min_size_zero_does_not_matter() -> None:
    """min_size alone doesn't gate reachability — only max_size does."""
    asg = make_asg(max_size=5, desired_capacity=0, min_size=0)
    assert asg.has_reachable_launch_path is True


# --- AutoScalingGroup.effective_lt_ref ---


def test_effective_lt_ref_direct() -> None:
    ref = make_lt_ref()
    asg = make_asg(lt_ref=ref)
    assert asg.effective_lt_ref is ref


def test_effective_lt_ref_from_mixed_instances_base() -> None:
    ref = make_lt_ref()
    policy = MixedInstancesPolicy(base_launch_template_ref=ref)
    asg = make_asg(mixed_policy=policy)
    assert asg.effective_lt_ref is ref


def test_effective_lt_ref_none_when_no_lt() -> None:
    asg = make_asg()
    assert asg.effective_lt_ref is None


def test_effective_lt_ref_none_when_mixed_policy_has_no_base() -> None:
    policy = MixedInstancesPolicy()
    asg = make_asg(mixed_policy=policy)
    assert asg.effective_lt_ref is None


# --- MixedInstancesPolicy.has_override_specific_lt ---


def test_mixed_policy_no_override_lt() -> None:
    policy = MixedInstancesPolicy(overrides=[MixedInstancesOverride(instance_type="m5.large")])
    assert policy.has_override_specific_lt is False


def test_mixed_policy_with_override_lt() -> None:
    ref = make_lt_ref()
    policy = MixedInstancesPolicy(overrides=[MixedInstancesOverride(launch_template_ref=ref)])
    assert policy.has_override_specific_lt is True


# --- VolumeAttachment frozen ---


def test_volume_attachment_frozen() -> None:
    attach = VolumeAttachment(
        instance_id="i-abc", device="/dev/xvda", state="attached", delete_on_termination=True
    )
    with pytest.raises(ValidationError):
        attach.state = "detaching"  # type: ignore[misc]


# --- ASGInstance ---


def test_asg_instance_fields() -> None:
    inst = ASGInstance(instance_id="i-abc123", lifecycle_state="InService")
    assert inst.instance_id == "i-abc123"
    assert inst.lifecycle_state == "InService"
