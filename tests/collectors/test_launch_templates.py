from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.collectors.launch_templates import (
    LaunchTemplateMetadata,
    collect_launch_template_metadata,
    collect_lt_versions,
)
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client

REGION = "eu-central-1"
ACCOUNT = "123456789012"
META = LaunchTemplateMetadata(
    template_id="lt-abc123",
    template_name="prod-web",
    default_version_number=3,
    latest_version_number=5,
)


def _client_with_templates(*templates: dict) -> ReadOnlyEC2Client:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"LaunchTemplates": list(templates)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyEC2Client(raw)


def _client_with_versions(*versions: dict) -> ReadOnlyEC2Client:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"LaunchTemplateVersions": list(versions)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyEC2Client(raw)


def _raw_template(**overrides: object) -> dict:
    base: dict = {
        "LaunchTemplateId": "lt-abc123",
        "LaunchTemplateName": "prod-web",
        "DefaultVersionNumber": 3,
        "LatestVersionNumber": 5,
    }
    base.update(overrides)
    return base


def _raw_version(version_number: int, **overrides: object) -> dict:
    base: dict = {
        "VersionNumber": version_number,
        "LaunchTemplateId": "lt-abc123",
        "LaunchTemplateData": {
            "ImageId": "ami-xyz",
            "BlockDeviceMappings": [],
        },
        "Tags": [],
    }
    base.update(overrides)
    return base


# ── collect_launch_template_metadata ─────────────────────────────────────────


def test_collect_lt_metadata_empty() -> None:
    assert collect_launch_template_metadata(_client_with_templates()) == {}


def test_collect_lt_metadata_basic_fields() -> None:
    result = collect_launch_template_metadata(_client_with_templates(_raw_template()))
    assert "lt-abc123" in result
    m = result["lt-abc123"]
    assert m.template_id == "lt-abc123"
    assert m.template_name == "prod-web"
    assert m.default_version_number == 3
    assert m.latest_version_number == 5


def test_collect_lt_metadata_multiple_templates() -> None:
    result = collect_launch_template_metadata(
        _client_with_templates(
            _raw_template(LaunchTemplateId="lt-1", LaunchTemplateName="a"),
            _raw_template(LaunchTemplateId="lt-2", LaunchTemplateName="b"),
        )
    )
    assert set(result.keys()) == {"lt-1", "lt-2"}


def test_collect_lt_metadata_permission_error() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeLaunchTemplates"
    )
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator

    with pytest.raises(CollectionError) as exc_info:
        collect_launch_template_metadata(ReadOnlyEC2Client(raw))
    assert exc_info.value.is_permission_error is True


# ── collect_lt_versions ───────────────────────────────────────────────────────


def test_collect_lt_versions_empty() -> None:
    result = collect_lt_versions(_client_with_versions(), "lt-abc123", META, REGION, ACCOUNT)
    assert result == []


def test_collect_lt_versions_basic_fields() -> None:
    client = _client_with_versions(_raw_version(3))
    versions = collect_lt_versions(client, "lt-abc123", META, REGION, ACCOUNT)
    assert len(versions) == 1
    v = versions[0]
    assert v.template_id == "lt-abc123"
    assert v.template_name == "prod-web"
    assert v.version_number == 3
    assert v.region == REGION
    assert v.account_id == ACCOUNT
    assert v.image_id == "ami-xyz"


def test_collect_lt_versions_is_default_flag() -> None:
    client = _client_with_versions(_raw_version(3), _raw_version(5))
    versions = collect_lt_versions(client, "lt-abc123", META, REGION, ACCOUNT)
    by_num = {v.version_number: v for v in versions}
    assert by_num[3].is_default is True
    assert by_num[5].is_default is False


def test_collect_lt_versions_is_latest_flag() -> None:
    client = _client_with_versions(_raw_version(3), _raw_version(5))
    versions = collect_lt_versions(client, "lt-abc123", META, REGION, ACCOUNT)
    by_num = {v.version_number: v for v in versions}
    assert by_num[5].is_latest is True
    assert by_num[3].is_latest is False


def test_collect_lt_versions_bdm_delete_on_termination_false() -> None:
    raw = _raw_version(
        3,
        LaunchTemplateData={
            "ImageId": "ami-xyz",
            "BlockDeviceMappings": [
                {
                    "DeviceName": "/dev/xvda",
                    "Ebs": {"DeleteOnTermination": False, "VolumeType": "gp2"},
                }
            ],
        },
    )
    v = collect_lt_versions(_client_with_versions(raw), "lt-abc123", META, REGION, ACCOUNT)[0]
    assert len(v.block_device_mappings) == 1
    bdm = v.block_device_mappings[0]
    assert bdm.device_name == "/dev/xvda"
    assert bdm.delete_on_termination is False


def test_collect_lt_versions_bdm_delete_on_termination_true() -> None:
    raw = _raw_version(
        3,
        LaunchTemplateData={
            "ImageId": "ami-xyz",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/xvda", "Ebs": {"DeleteOnTermination": True}},
            ],
        },
    )
    v = collect_lt_versions(_client_with_versions(raw), "lt-abc123", META, REGION, ACCOUNT)[0]
    assert v.block_device_mappings[0].delete_on_termination is True


def test_collect_lt_versions_bdm_delete_on_termination_absent_is_none() -> None:
    """Absent DeleteOnTermination key must normalize to None — not False."""
    raw = _raw_version(
        3,
        LaunchTemplateData={
            "ImageId": "ami-xyz",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/xvda", "Ebs": {"VolumeType": "gp2"}},
            ],
        },
    )
    v = collect_lt_versions(_client_with_versions(raw), "lt-abc123", META, REGION, ACCOUNT)[0]
    assert v.block_device_mappings[0].delete_on_termination is None


def test_collect_lt_versions_skips_non_ebs_bdm() -> None:
    raw = _raw_version(
        3,
        LaunchTemplateData={
            "ImageId": "ami-xyz",
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/sda1"},  # instance store
                {"DeviceName": "/dev/xvdb", "Ebs": {"DeleteOnTermination": True}},
            ],
        },
    )
    v = collect_lt_versions(_client_with_versions(raw), "lt-abc123", META, REGION, ACCOUNT)[0]
    assert len(v.block_device_mappings) == 1
    assert v.block_device_mappings[0].device_name == "/dev/xvdb"


def test_collect_lt_versions_template_id_in_paginator_call() -> None:
    raw = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"LaunchTemplateVersions": []}]
    raw.get_paginator.return_value = paginator
    collect_lt_versions(ReadOnlyEC2Client(raw), "lt-abc123", META, REGION, ACCOUNT)
    paginator.paginate.assert_called_once_with(LaunchTemplateId="lt-abc123")


def test_collect_lt_versions_permission_error() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
        "DescribeLaunchTemplateVersions",
    )
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator

    with pytest.raises(CollectionError) as exc_info:
        collect_lt_versions(ReadOnlyEC2Client(raw), "lt-abc123", META, REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is True
