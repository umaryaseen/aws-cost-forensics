from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.amis import collect_amis
from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client

REGION = "eu-central-1"
ACCOUNT = "123456789012"
TS = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _client(*amis: dict) -> ReadOnlyEC2Client:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Images": list(amis)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyEC2Client(raw)


def _raw_ami(**overrides: object) -> dict:
    base: dict = {
        "ImageId": "ami-abc123",
        "State": "available",
        "CreationDate": TS,
        "BlockDeviceMappings": [],
        "Tags": [],
    }
    base.update(overrides)
    return base


def test_collect_amis_empty() -> None:
    assert collect_amis(_client(), REGION, ACCOUNT) == []


def test_collect_amis_basic_fields() -> None:
    amis = collect_amis(_client(_raw_ami()), REGION, ACCOUNT)
    assert len(amis) == 1
    a = amis[0]
    assert a.image_id == "ami-abc123"
    assert a.state == "available"
    assert a.creation_date == TS
    assert a.region == REGION
    assert a.account_id == ACCOUNT
    assert a.root_device_name is None
    assert a.snapshot_ids == []


def test_collect_amis_name_preserved() -> None:
    a = collect_amis(_client(_raw_ami(Name="my-ami")), REGION, ACCOUNT)[0]
    assert a.name == "my-ami"


def test_collect_amis_root_device_name() -> None:
    a = collect_amis(_client(_raw_ami(RootDeviceName="/dev/xvda")), REGION, ACCOUNT)[0]
    assert a.root_device_name == "/dev/xvda"


def test_collect_amis_extracts_snapshot_ids_from_bdms() -> None:
    raw = _raw_ami(
        BlockDeviceMappings=[
            {"DeviceName": "/dev/xvda", "Ebs": {"SnapshotId": "snap-111"}},
            {"DeviceName": "/dev/xvdb", "Ebs": {"SnapshotId": "snap-222"}},
        ]
    )
    a = collect_amis(_client(raw), REGION, ACCOUNT)[0]
    assert sorted(a.snapshot_ids) == ["snap-111", "snap-222"]


def test_collect_amis_skips_non_ebs_bdm_entries() -> None:
    raw = _raw_ami(
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1"},  # instance store — no "Ebs" key
            {"DeviceName": "/dev/xvdb", "Ebs": {"SnapshotId": "snap-333"}},
        ]
    )
    a = collect_amis(_client(raw), REGION, ACCOUNT)[0]
    assert a.snapshot_ids == ["snap-333"]


def test_collect_amis_skips_bdm_without_snapshot_id() -> None:
    raw = _raw_ami(
        BlockDeviceMappings=[
            {"DeviceName": "/dev/xvda", "Ebs": {}},  # no SnapshotId
        ]
    )
    a = collect_amis(_client(raw), REGION, ACCOUNT)[0]
    assert a.snapshot_ids == []


def test_collect_amis_tags_normalized() -> None:
    a = collect_amis(_client(_raw_ami(Tags=[{"Key": "Name", "Value": "base"}])), REGION, ACCOUNT)[0]
    assert a.tags == {"Name": "base"}


def test_collect_amis_owners_self_passed() -> None:
    raw = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Images": []}]
    raw.get_paginator.return_value = paginator
    client = ReadOnlyEC2Client(raw)
    collect_amis(client, REGION, ACCOUNT)
    paginator.paginate.assert_called_once_with(Owners=["self"])


def test_collect_amis_permission_error() -> None:
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeImages")
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator

    with pytest.raises(CollectionError) as exc_info:
        collect_amis(ReadOnlyEC2Client(raw), REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is True
    assert exc_info.value.collector == "amis"
