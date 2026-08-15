from __future__ import annotations

from aws_cost_forensics.aws.collectors.base import CollectionError, is_permission_error, paginate
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client
from aws_cost_forensics.domain.resources import EBSSnapshot


def collect_snapshots(
    ec2_client: ReadOnlyEC2Client, region: str, account_id: str
) -> list[EBSSnapshot]:
    try:
        raw_snapshots = list(
            paginate(
                ec2_client,
                "describe_snapshots",
                "Snapshots",
                OwnerIds=["self"],
            )
        )
    except Exception as exc:
        raise CollectionError(
            "snapshots",
            f"DescribeSnapshots failed: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    return [
        EBSSnapshot(
            snapshot_id=raw["SnapshotId"],
            region=region,
            account_id=account_id,
            volume_id=raw.get("VolumeId") or None,
            volume_size_gib=raw["VolumeSize"],
            state=raw["State"],
            start_time=raw["StartTime"],
            description=raw.get("Description", ""),
            tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
        )
        for raw in raw_snapshots
    ]
