from __future__ import annotations

from aws_cost_forensics.aws.collectors.base import CollectionError, is_permission_error, paginate
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client
from aws_cost_forensics.domain.resources import AMI


def collect_amis(ec2_client: ReadOnlyEC2Client, region: str, account_id: str) -> list[AMI]:
    try:
        raw_amis = list(
            paginate(
                ec2_client,
                "describe_images",
                "Images",
                Owners=["self"],
            )
        )
    except Exception as exc:
        raise CollectionError(
            "amis",
            f"DescribeImages failed: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    return [
        AMI(
            image_id=raw["ImageId"],
            region=region,
            account_id=account_id,
            name=raw.get("Name"),
            state=raw["State"],
            creation_date=raw["CreationDate"],
            root_device_name=raw.get("RootDeviceName"),
            snapshot_ids=_extract_snapshot_ids(raw),
            tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
        )
        for raw in raw_amis
    ]


def _extract_snapshot_ids(raw_ami: dict) -> list[str]:  # type: ignore[type-arg]
    return [
        bdm["Ebs"]["SnapshotId"]
        for bdm in raw_ami.get("BlockDeviceMappings", [])
        if "Ebs" in bdm and bdm["Ebs"].get("SnapshotId")
    ]
