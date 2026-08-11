from __future__ import annotations

from aws_cost_forensics.aws.collectors.base import CollectionError, is_permission_error, paginate
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client
from aws_cost_forensics.domain.resources import EBSVolume, EC2Instance, VolumeAttachment


def collect_volumes(ec2_client: ReadOnlyEC2Client, region: str, account_id: str) -> list[EBSVolume]:
    try:
        raw_volumes = list(paginate(ec2_client, "describe_volumes", "Volumes"))
    except Exception as exc:
        raise CollectionError(
            "ebs",
            f"DescribeVolumes failed: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    result = []
    for raw in raw_volumes:
        attachments = [
            VolumeAttachment(
                instance_id=att["InstanceId"],
                device=att["Device"],
                state=att["State"],
                delete_on_termination=att["DeleteOnTermination"],
            )
            for att in raw.get("Attachments", [])
        ]
        result.append(
            EBSVolume(
                volume_id=raw["VolumeId"],
                region=region,
                account_id=account_id,
                state=raw["State"],
                size_gib=raw["Size"],
                volume_type=raw["VolumeType"],
                iops=raw.get("Iops"),
                throughput=raw.get("Throughput"),
                create_time=raw["CreateTime"],
                availability_zone=raw["AvailabilityZone"],
                snapshot_id=raw.get("SnapshotId") or None,
                attachments=attachments,
                tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
            )
        )
    return result


def collect_instances(
    ec2_client: ReadOnlyEC2Client, region: str, account_id: str
) -> list[EC2Instance]:
    try:
        raw_reservations = list(paginate(ec2_client, "describe_instances", "Reservations"))
    except Exception as exc:
        raise CollectionError(
            "instances",
            f"DescribeInstances failed: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    result = []
    for reservation in raw_reservations:
        for raw in reservation.get("Instances", []):
            bdms = [
                VolumeAttachment(
                    instance_id=raw["InstanceId"],
                    device=bdm["DeviceName"],
                    state=bdm["Ebs"]["Status"],
                    delete_on_termination=bdm["Ebs"]["DeleteOnTermination"],
                )
                for bdm in raw.get("BlockDeviceMappings", [])
                if "Ebs" in bdm
            ]
            result.append(
                EC2Instance(
                    instance_id=raw["InstanceId"],
                    region=region,
                    account_id=account_id,
                    state=raw["State"]["Name"],
                    instance_type=raw["InstanceType"],
                    launch_time=raw["LaunchTime"],
                    root_device_name=raw.get("RootDeviceName"),
                    block_device_mappings=bdms,
                    tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
                )
            )
    return result
