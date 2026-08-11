from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.autoscaling import collect_asgs
from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.collectors.launch_templates import LaunchTemplateMetadata
from aws_cost_forensics.aws.readonly_client import ReadOnlyASGClient

REGION = "eu-central-1"
ACCOUNT = "123456789012"
LT_META: dict[str, LaunchTemplateMetadata] = {
    "lt-abc": LaunchTemplateMetadata(
        template_id="lt-abc",
        template_name="prod-web",
        default_version_number=3,
        latest_version_number=5,
    )
}


def _client(*asgs: dict) -> ReadOnlyASGClient:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"AutoScalingGroups": list(asgs)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyASGClient(raw)


def _raw_asg(**overrides: object) -> dict:
    base: dict = {
        "AutoScalingGroupName": "asg-prod",
        "AutoScalingGroupARN": f"arn:aws:autoscaling:{REGION}:{ACCOUNT}:autoScalingGroup:x",
        "DesiredCapacity": 3,
        "MinSize": 1,
        "MaxSize": 10,
        "SuspendedProcesses": [],
        "Instances": [],
        "Tags": [],
    }
    base.update(overrides)
    return base


# ── basic fields ──────────────────────────────────────────────────────────────


def test_collect_asgs_empty() -> None:
    assert collect_asgs(_client(), {}, REGION, ACCOUNT) == []


def test_collect_asgs_basic_fields() -> None:
    asgs = collect_asgs(_client(_raw_asg()), {}, REGION, ACCOUNT)
    assert len(asgs) == 1
    a = asgs[0]
    assert a.asg_name == "asg-prod"
    assert a.region == REGION
    assert a.account_id == ACCOUNT
    assert a.desired_capacity == 3
    assert a.min_size == 1
    assert a.max_size == 10
    assert a.launch_template_ref is None
    assert a.mixed_instances_policy is None
    assert a.suspended_processes == []
    assert a.current_instances == []
    assert a.tags == {}


def test_collect_asgs_tags_normalized() -> None:
    raw = _raw_asg(Tags=[{"Key": "Env", "Value": "prod"}])
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert a.tags == {"Env": "prod"}


def test_collect_asgs_suspended_processes() -> None:
    raw = _raw_asg(SuspendedProcesses=[{"ProcessName": "Launch"}, {"ProcessName": "Terminate"}])
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert a.suspended_processes == ["Launch", "Terminate"]


def test_collect_asgs_current_instances() -> None:
    raw = _raw_asg(
        Instances=[
            {"InstanceId": "i-111", "LifecycleState": "InService"},
            {"InstanceId": "i-222", "LifecycleState": "Pending"},
        ]
    )
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert len(a.current_instances) == 2
    assert a.current_instances[0].instance_id == "i-111"
    assert a.current_instances[0].lifecycle_state == "InService"
    assert a.current_instances[1].lifecycle_state == "Pending"


# ── LaunchTemplateRef resolution ──────────────────────────────────────────────


def test_collect_asgs_direct_lt_dollar_default() -> None:
    raw = _raw_asg(LaunchTemplate={"LaunchTemplateId": "lt-abc", "Version": "$Default"})
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.launch_template_ref is not None
    assert a.launch_template_ref.template_id == "lt-abc"
    assert a.launch_template_ref.version_selector == "$Default"
    assert a.launch_template_ref.resolved_version_number == 3  # default_version_number


def test_collect_asgs_direct_lt_dollar_latest() -> None:
    raw = _raw_asg(LaunchTemplate={"LaunchTemplateId": "lt-abc", "Version": "$Latest"})
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.launch_template_ref is not None
    assert a.launch_template_ref.version_selector == "$Latest"
    assert a.launch_template_ref.resolved_version_number == 5  # latest_version_number


def test_collect_asgs_direct_lt_explicit_version() -> None:
    raw = _raw_asg(LaunchTemplate={"LaunchTemplateId": "lt-abc", "Version": "3"})
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.launch_template_ref is not None
    assert a.launch_template_ref.version_selector == "3"
    assert a.launch_template_ref.resolved_version_number == 3


def test_collect_asgs_direct_lt_pinned_non_default() -> None:
    raw = _raw_asg(LaunchTemplate={"LaunchTemplateId": "lt-abc", "Version": "2"})
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.launch_template_ref is not None
    assert a.launch_template_ref.resolved_version_number == 2


def test_collect_asgs_direct_lt_unknown_template_resolves_zero() -> None:
    raw = _raw_asg(LaunchTemplate={"LaunchTemplateId": "lt-unknown", "Version": "$Default"})
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert a.launch_template_ref is not None
    assert a.launch_template_ref.resolved_version_number == 0


def test_collect_asgs_launch_config_has_no_lt_ref() -> None:
    raw = _raw_asg(LaunchConfigurationName="lc-prod")
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert a.launch_template_ref is None
    assert a.mixed_instances_policy is None


# ── MixedInstancesPolicy ──────────────────────────────────────────────────────


def test_collect_asgs_mixed_instances_policy_base_lt() -> None:
    raw = _raw_asg(
        MixedInstancesPolicy={
            "LaunchTemplate": {
                "LaunchTemplateSpecification": {
                    "LaunchTemplateId": "lt-abc",
                    "Version": "$Default",
                },
                "Overrides": [],
            }
        }
    )
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.mixed_instances_policy is not None
    base = a.mixed_instances_policy.base_launch_template_ref
    assert base is not None
    assert base.template_id == "lt-abc"
    assert base.resolved_version_number == 3


def test_collect_asgs_mixed_instances_policy_instance_type_override() -> None:
    raw = _raw_asg(
        MixedInstancesPolicy={
            "LaunchTemplate": {
                "LaunchTemplateSpecification": {
                    "LaunchTemplateId": "lt-abc",
                    "Version": "$Default",
                },
                "Overrides": [
                    {"InstanceType": "m5.large"},
                    {"InstanceType": "c5.large"},
                ],
            }
        }
    )
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.mixed_instances_policy is not None
    overrides = a.mixed_instances_policy.overrides
    assert len(overrides) == 2
    assert overrides[0].instance_type == "m5.large"
    assert overrides[0].launch_template_ref is None
    assert not a.mixed_instances_policy.has_override_specific_lt


def test_collect_asgs_mixed_instances_policy_override_with_lt() -> None:
    raw = _raw_asg(
        MixedInstancesPolicy={
            "LaunchTemplate": {
                "LaunchTemplateSpecification": {
                    "LaunchTemplateId": "lt-abc",
                    "Version": "$Default",
                },
                "Overrides": [
                    {
                        "InstanceType": "m5.large",
                        "LaunchTemplateSpecification": {
                            "LaunchTemplateId": "lt-abc",
                            "Version": "$Latest",
                        },
                    }
                ],
            }
        }
    )
    a = collect_asgs(_client(raw), LT_META, REGION, ACCOUNT)[0]
    assert a.mixed_instances_policy is not None
    override = a.mixed_instances_policy.overrides[0]
    assert override.launch_template_ref is not None
    assert override.launch_template_ref.resolved_version_number == 5
    assert a.mixed_instances_policy.has_override_specific_lt is True


# ── error handling ────────────────────────────────────────────────────────────


def test_collect_asgs_permission_error() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
        "DescribeAutoScalingGroups",
    )
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator

    with pytest.raises(CollectionError) as exc_info:
        collect_asgs(ReadOnlyASGClient(raw), {}, REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is True
    assert exc_info.value.collector == "autoscaling"


def test_collect_asgs_no_status_field_used() -> None:
    raw = _raw_asg(Status="Delete in progress")  # Status field should be ignored
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    # Confirm we still get the ASG regardless of Status field
    assert a.asg_name == "asg-prod"


def test_collect_asgs_has_reachable_launch_path_max_size_zero() -> None:
    raw = _raw_asg(DesiredCapacity=0, MinSize=0, MaxSize=0)
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert a.has_reachable_launch_path is False


def test_collect_asgs_has_reachable_launch_path_desired_zero_max_nonzero() -> None:
    raw = _raw_asg(DesiredCapacity=0, MinSize=0, MaxSize=10)
    a = collect_asgs(_client(raw), {}, REGION, ACCOUNT)[0]
    assert a.has_reachable_launch_path is True
