from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.collectors.snapshots import collect_snapshots
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client

REGION = "eu-central-1"
ACCOUNT = "123456789012"
TS = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _client(*snapshots: dict) -> ReadOnlyEC2Client:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Snapshots": list(snapshots)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyEC2Client(raw)


def _raw_snap(**overrides: object) -> dict:
    base: dict = {
        "SnapshotId": "snap-abc123",
        "VolumeId": "vol-xyz",
        "VolumeSize": 20,
        "State": "completed",
        "StartTime": TS,
        "Description": "",
        "Tags": [],
    }
    base.update(overrides)
    return base


def test_collect_snapshots_empty() -> None:
    assert collect_snapshots(_client(), REGION, ACCOUNT) == []


def test_collect_snapshots_basic_fields() -> None:
    snaps = collect_snapshots(_client(_raw_snap()), REGION, ACCOUNT)
    assert len(snaps) == 1
    s = snaps[0]
    assert s.snapshot_id == "snap-abc123"
    assert s.volume_id == "vol-xyz"
    assert s.volume_size_gib == 20
    assert s.state == "completed"
    assert s.start_time == TS
    assert s.region == REGION
    assert s.account_id == ACCOUNT


def test_collect_snapshots_volume_id_none_when_empty() -> None:
    s = collect_snapshots(_client(_raw_snap(VolumeId="")), REGION, ACCOUNT)[0]
    assert s.volume_id is None


def test_collect_snapshots_description_preserved() -> None:
    s = collect_snapshots(_client(_raw_snap(Description="backup")), REGION, ACCOUNT)[0]
    assert s.description == "backup"


def test_collect_snapshots_tags_normalized() -> None:
    client = _client(_raw_snap(Tags=[{"Key": "Env", "Value": "prod"}]))
    s = collect_snapshots(client, REGION, ACCOUNT)[0]
    assert s.tags == {"Env": "prod"}


def test_collect_snapshots_owner_ids_self_passed() -> None:
    raw = MagicMock()
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Snapshots": []}]
    raw.get_paginator.return_value = paginator
    client = ReadOnlyEC2Client(raw)
    collect_snapshots(client, REGION, ACCOUNT)
    paginator.paginate.assert_called_once_with(OwnerIds=["self"])


def test_collect_snapshots_permission_error() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeSnapshots"
    )
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator

    with pytest.raises(CollectionError) as exc_info:
        collect_snapshots(ReadOnlyEC2Client(raw), REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is True
    assert exc_info.value.collector == "snapshots"
