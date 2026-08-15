from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from aws_cost_forensics.aws.readonly_client import (
    ReadOnlyASGClient,
    ReadOnlyEC2Client,
    ReadOnlySTSClient,
    ReadOnlyViolation,
)


def _ec2() -> ReadOnlyEC2Client:
    return ReadOnlyEC2Client(MagicMock())


def _asg() -> ReadOnlyASGClient:
    return ReadOnlyASGClient(MagicMock())


def _sts() -> ReadOnlySTSClient:
    return ReadOnlySTSClient(MagicMock())


# ── EC2: approved ─────────────────────────────────────────────────────────────


def test_ec2_allows_describe_volumes() -> None:
    _ = _ec2().describe_volumes


def test_ec2_allows_describe_instances() -> None:
    _ = _ec2().describe_instances


def test_ec2_allows_describe_snapshots() -> None:
    _ = _ec2().describe_snapshots


def test_ec2_allows_describe_images() -> None:
    _ = _ec2().describe_images


def test_ec2_allows_describe_launch_templates() -> None:
    _ = _ec2().describe_launch_templates


def test_ec2_allows_describe_launch_template_versions() -> None:
    _ = _ec2().describe_launch_template_versions


def test_ec2_allows_get_paginator() -> None:
    _ = _ec2().get_paginator


# ── EC2: blocked ──────────────────────────────────────────────────────────────


def test_ec2_blocks_delete_volume() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _ec2().delete_volume


def test_ec2_blocks_create_volume() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _ec2().create_volume


def test_ec2_blocks_create_launch_template_version() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _ec2().create_launch_template_version


def test_ec2_blocks_modify_volume() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _ec2().modify_volume


def test_ec2_blocks_terminate_instances() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _ec2().terminate_instances


def test_ec2_violation_message_contains_operation_name() -> None:
    with pytest.raises(ReadOnlyViolation, match="run_instances"):
        _ = _ec2().run_instances


# ── ASG: approved ─────────────────────────────────────────────────────────────


def test_asg_allows_describe_auto_scaling_groups() -> None:
    _ = _asg().describe_auto_scaling_groups


def test_asg_allows_get_paginator() -> None:
    _ = _asg().get_paginator


# ── ASG: blocked ──────────────────────────────────────────────────────────────


def test_asg_blocks_update_auto_scaling_group() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _asg().update_auto_scaling_group


def test_asg_blocks_delete_auto_scaling_group() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _asg().delete_auto_scaling_group


def test_asg_blocks_create_auto_scaling_group() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _asg().create_auto_scaling_group


def test_asg_blocks_set_desired_capacity() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _asg().set_desired_capacity


def test_asg_violation_message_contains_operation_name() -> None:
    with pytest.raises(ReadOnlyViolation, match="put_scaling_policy"):
        _ = _asg().put_scaling_policy


# ── STS: approved ─────────────────────────────────────────────────────────────


def test_sts_allows_get_caller_identity() -> None:
    _ = _sts().get_caller_identity


# ── STS: blocked ──────────────────────────────────────────────────────────────


def test_sts_blocks_assume_role() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _sts().assume_role


def test_sts_blocks_assume_role_with_web_identity() -> None:
    with pytest.raises(ReadOnlyViolation):
        _ = _sts().assume_role_with_web_identity


def test_sts_violation_message_contains_operation_name() -> None:
    with pytest.raises(ReadOnlyViolation, match="get_federation_token"):
        _ = _sts().get_federation_token
