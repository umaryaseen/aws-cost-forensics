from __future__ import annotations

from dataclasses import dataclass

from aws_cost_forensics.aws.collectors.base import CollectionError, is_permission_error, paginate
from aws_cost_forensics.aws.readonly_client import ReadOnlyEC2Client
from aws_cost_forensics.domain.resources import BlockDeviceMapping, LaunchTemplateVersion


@dataclass
class LaunchTemplateMetadata:
    template_id: str
    template_name: str | None
    default_version_number: int
    latest_version_number: int


def collect_launch_template_metadata(
    ec2_client: ReadOnlyEC2Client,
) -> dict[str, LaunchTemplateMetadata]:
    """Collect LT metadata for all templates. Returns mapping keyed by template_id."""
    try:
        raw_templates = list(paginate(ec2_client, "describe_launch_templates", "LaunchTemplates"))
    except Exception as exc:
        raise CollectionError(
            "launch_templates",
            f"DescribeLaunchTemplates failed: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    return {
        raw["LaunchTemplateId"]: LaunchTemplateMetadata(
            template_id=raw["LaunchTemplateId"],
            template_name=raw.get("LaunchTemplateName"),
            default_version_number=raw["DefaultVersionNumber"],
            latest_version_number=raw["LatestVersionNumber"],
        )
        for raw in raw_templates
    }


def collect_lt_versions(
    ec2_client: ReadOnlyEC2Client,
    template_id: str,
    metadata: LaunchTemplateMetadata,
    region: str,
    account_id: str,
) -> list[LaunchTemplateVersion]:
    """Collect all versions of a specific launch template."""
    try:
        raw_versions = list(
            paginate(
                ec2_client,
                "describe_launch_template_versions",
                "LaunchTemplateVersions",
                LaunchTemplateId=template_id,
            )
        )
    except Exception as exc:
        raise CollectionError(
            "launch_template_versions",
            f"DescribeLaunchTemplateVersions failed for {template_id}: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    return [
        LaunchTemplateVersion(
            template_id=template_id,
            template_name=metadata.template_name,
            region=region,
            account_id=account_id,
            version_number=raw["VersionNumber"],
            is_default=(raw["VersionNumber"] == metadata.default_version_number),
            is_latest=(raw["VersionNumber"] == metadata.latest_version_number),
            image_id=raw.get("LaunchTemplateData", {}).get("ImageId"),
            block_device_mappings=_normalize_bdms(raw.get("LaunchTemplateData", {})),
            tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
        )
        for raw in raw_versions
    ]


def _normalize_bdms(lt_data: dict) -> list[BlockDeviceMapping]:  # type: ignore[type-arg]
    return [
        bdm
        for raw_bdm in lt_data.get("BlockDeviceMappings", [])
        if (bdm := _normalize_bdm(raw_bdm)) is not None
    ]


def _normalize_bdm(raw_bdm: dict) -> BlockDeviceMapping | None:  # type: ignore[type-arg]
    ebs = raw_bdm.get("Ebs")
    if ebs is None:
        return None  # instance store device — not an EBS mapping

    return BlockDeviceMapping(
        device_name=raw_bdm["DeviceName"],
        snapshot_id=ebs.get("SnapshotId") or None,
        volume_size_gib=ebs.get("VolumeSize"),
        volume_type=ebs.get("VolumeType"),
        delete_on_termination=ebs.get("DeleteOnTermination"),  # None if AWS omitted the key
        iops=ebs.get("Iops"),
        throughput=ebs.get("Throughput"),
    )
