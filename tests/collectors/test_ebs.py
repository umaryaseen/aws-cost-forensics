from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.collectors.ebs import collect_instances, collect_volumes
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client

REGION = "eu-central-1"
ACCOUNT = "123456789012"
TS = datetime(2024, 1, 15, 10, 0, 0, tzinfo=UTC)


def _client_with_volumes(*volumes: dict) -> ReadOnlyEC2Client:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Volumes": list(volumes)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyEC2Client(raw)


def _client_with_reservations(*reservations: dict) -> ReadOnlyEC2Client:
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Reservations": list(reservations)}]
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    return ReadOnlyEC2Client(raw)


def _raw_volume(**overrides: object) -> dict:
    base: dict = {
        "VolumeId": "vol-abc123",
        "State": "available",
        "Size": 20,
        "VolumeType": "gp2",
        "CreateTime": TS,
        "AvailabilityZone": "eu-central-1a",
        "Attachments": [],
        "Tags": [],
    }
    base.update(overrides)
    return base


def _raw_instance(**overrides: object) -> dict:
    base: dict = {
        "InstanceId": "i-abc123",
        "State": {"Name": "running"},
        "InstanceType": "t3.medium",
        "LaunchTime": TS,
        "BlockDeviceMappings": [],
        "Tags": [],
    }
    base.update(overrides)
    return base


# ── collect_volumes ───────────────────────────────────────────────────────────


def test_collect_volumes_empty() -> None:
    assert collect_volumes(_client_with_volumes(), REGION, ACCOUNT) == []


def test_collect_volumes_basic_fields() -> None:
    client = _client_with_volumes(_raw_volume())
    vols = collect_volumes(client, REGION, ACCOUNT)
    assert len(vols) == 1
    v = vols[0]
    assert v.volume_id == "vol-abc123"
    assert v.state == "available"
    assert v.size_gib == 20
    assert v.volume_type == "gp2"
    assert v.create_time == TS
    assert v.availability_zone == "eu-central-1a"
    assert v.region == REGION
    assert v.account_id == ACCOUNT


def test_collect_volumes_snapshot_id_preserved() -> None:
    client = _client_with_volumes(_raw_volume(SnapshotId="snap-111"))
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.snapshot_id == "snap-111"


def test_collect_volumes_empty_snapshot_id_becomes_none() -> None:
    client = _client_with_volumes(_raw_volume(SnapshotId=""))
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.snapshot_id is None


def test_collect_volumes_absent_snapshot_id_is_none() -> None:
    client = _client_with_volumes(_raw_volume())
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.snapshot_id is None


def test_collect_volumes_iops_absent_is_none() -> None:
    client = _client_with_volumes(_raw_volume())
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.iops is None


def test_collect_volumes_iops_present() -> None:
    client = _client_with_volumes(_raw_volume(Iops=3000))
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.iops == 3000


def test_collect_volumes_throughput_absent_is_none() -> None:
    client = _client_with_volumes(_raw_volume())
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.throughput is None


def test_collect_volumes_tags_normalized() -> None:
    client = _client_with_volumes(_raw_volume(Tags=[{"Key": "Name", "Value": "my-vol"}]))
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert v.tags == {"Name": "my-vol"}


def test_collect_volumes_attachment_normalized() -> None:
    raw = _raw_volume(
        State="in-use",
        Attachments=[
            {
                "InstanceId": "i-xyz",
                "Device": "/dev/xvda",
                "State": "attached",
                "DeleteOnTermination": True,
            }
        ],
    )
    client = _client_with_volumes(raw)
    v = collect_volumes(client, REGION, ACCOUNT)[0]
    assert len(v.attachments) == 1
    att = v.attachments[0]
    assert att.instance_id == "i-xyz"
    assert att.device == "/dev/xvda"
    assert att.state == "attached"
    assert att.delete_on_termination is True


def test_collect_volumes_attachment_delete_on_termination_false() -> None:
    raw = _raw_volume(
        State="in-use",
        Attachments=[
            {
                "InstanceId": "i-xyz",
                "Device": "/dev/xvda",
                "State": "attached",
                "DeleteOnTermination": False,
            }
        ],
    )
    v = collect_volumes(_client_with_volumes(raw), REGION, ACCOUNT)[0]
    assert v.attachments[0].delete_on_termination is False


def test_collect_volumes_multiple_volumes() -> None:
    client = _client_with_volumes(
        _raw_volume(VolumeId="vol-1"),
        _raw_volume(VolumeId="vol-2"),
    )
    vols = collect_volumes(client, REGION, ACCOUNT)
    assert [v.volume_id for v in vols] == ["vol-1", "vol-2"]


def test_collect_volumes_permission_error_raises_collection_error() -> None:
    error = ClientError({"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeVolumes")
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    client = ReadOnlyEC2Client(raw)

    with pytest.raises(CollectionError) as exc_info:
        collect_volumes(client, REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is True
    assert exc_info.value.collector == "ebs"


def test_collect_volumes_non_permission_error_raises_collection_error() -> None:
    paginator = MagicMock()
    paginator.paginate.side_effect = RuntimeError("network timeout")
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    client = ReadOnlyEC2Client(raw)

    with pytest.raises(CollectionError) as exc_info:
        collect_volumes(client, REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is False


# ── collect_instances ─────────────────────────────────────────────────────────


def test_collect_instances_empty() -> None:
    assert collect_instances(_client_with_reservations(), REGION, ACCOUNT) == []


def test_collect_instances_basic_fields() -> None:
    client = _client_with_reservations({"Instances": [_raw_instance()]})
    insts = collect_instances(client, REGION, ACCOUNT)
    assert len(insts) == 1
    i = insts[0]
    assert i.instance_id == "i-abc123"
    assert i.state == "running"
    assert i.instance_type == "t3.medium"
    assert i.launch_time == TS
    assert i.region == REGION
    assert i.account_id == ACCOUNT
    assert i.root_device_name is None
    assert i.block_device_mappings == []


def test_collect_instances_root_device_name() -> None:
    client = _client_with_reservations({"Instances": [_raw_instance(RootDeviceName="/dev/xvda")]})
    i = collect_instances(client, REGION, ACCOUNT)[0]
    assert i.root_device_name == "/dev/xvda"


def test_collect_instances_tags_normalized() -> None:
    raw = _raw_instance(Tags=[{"Key": "Name", "Value": "web-server"}])
    client = _client_with_reservations({"Instances": [raw]})
    i = collect_instances(client, REGION, ACCOUNT)[0]
    assert i.tags == {"Name": "web-server"}


def test_collect_instances_bdm_normalized() -> None:
    raw = _raw_instance(
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {"Status": "attached", "DeleteOnTermination": True, "VolumeId": "vol-x"},
            }
        ]
    )
    client = _client_with_reservations({"Instances": [raw]})
    i = collect_instances(client, REGION, ACCOUNT)[0]
    assert len(i.block_device_mappings) == 1
    bdm = i.block_device_mappings[0]
    assert bdm.instance_id == "i-abc123"
    assert bdm.device == "/dev/xvda"
    assert bdm.state == "attached"
    assert bdm.delete_on_termination is True


def test_collect_instances_bdm_delete_on_termination_false() -> None:
    raw = _raw_instance(
        BlockDeviceMappings=[
            {
                "DeviceName": "/dev/xvda",
                "Ebs": {"Status": "attached", "DeleteOnTermination": False, "VolumeId": "vol-x"},
            }
        ]
    )
    i = collect_instances(_client_with_reservations({"Instances": [raw]}), REGION, ACCOUNT)[0]
    assert i.block_device_mappings[0].delete_on_termination is False


def test_collect_instances_skips_non_ebs_devices() -> None:
    raw = _raw_instance(
        BlockDeviceMappings=[
            {"DeviceName": "/dev/sda1"},  # no "Ebs" key → skip
            {
                "DeviceName": "/dev/xvdb",
                "Ebs": {"Status": "attached", "DeleteOnTermination": True, "VolumeId": "vol-y"},
            },
        ]
    )
    i = collect_instances(_client_with_reservations({"Instances": [raw]}), REGION, ACCOUNT)[0]
    assert len(i.block_device_mappings) == 1
    assert i.block_device_mappings[0].device == "/dev/xvdb"


def test_collect_instances_multiple_reservations() -> None:
    client = _client_with_reservations(
        {"Instances": [_raw_instance(InstanceId="i-1")]},
        {"Instances": [_raw_instance(InstanceId="i-2"), _raw_instance(InstanceId="i-3")]},
    )
    insts = collect_instances(client, REGION, ACCOUNT)
    assert [i.instance_id for i in insts] == ["i-1", "i-2", "i-3"]


def test_collect_instances_permission_error_raises_collection_error() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "DescribeInstances"
    )
    paginator = MagicMock()
    paginator.paginate.side_effect = error
    raw = MagicMock()
    raw.get_paginator.return_value = paginator
    client = ReadOnlyEC2Client(raw)

    with pytest.raises(CollectionError) as exc_info:
        collect_instances(client, REGION, ACCOUNT)
    assert exc_info.value.is_permission_error is True
    assert exc_info.value.collector == "instances"


def test_collect_instances_reservation_without_instances_key() -> None:
    client = _client_with_reservations({"OwnerId": "123"})  # no "Instances" key
    assert collect_instances(client, REGION, ACCOUNT) == []
