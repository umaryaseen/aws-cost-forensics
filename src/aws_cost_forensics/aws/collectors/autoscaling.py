from __future__ import annotations

from aws_cost_forensics.aws.collectors.base import CollectionError, is_permission_error, paginate
from aws_cost_forensics.aws.collectors.launch_templates import LaunchTemplateMetadata
from aws_cost_forensics.aws.readonly_client import ReadOnlyASGClient
from aws_cost_forensics.domain.resources import (
    ASGInstance,
    AutoScalingGroup,
    LaunchTemplateRef,
    MixedInstancesOverride,
    MixedInstancesPolicy,
)


def collect_asgs(
    asg_client: ReadOnlyASGClient,
    lt_metadata_by_id: dict[str, LaunchTemplateMetadata],
    region: str,
    account_id: str,
) -> list[AutoScalingGroup]:
    try:
        raw_asgs = list(paginate(asg_client, "describe_auto_scaling_groups", "AutoScalingGroups"))
    except Exception as exc:
        raise CollectionError(
            "autoscaling",
            f"DescribeAutoScalingGroups failed: {exc}",
            is_permission_error=is_permission_error(exc),
        ) from exc

    result = []
    for raw in raw_asgs:
        lt_ref = _resolve_direct_lt(raw.get("LaunchTemplate"), lt_metadata_by_id)
        mip = _normalize_mixed_instances_policy(raw.get("MixedInstancesPolicy"), lt_metadata_by_id)
        result.append(
            AutoScalingGroup(
                asg_name=raw["AutoScalingGroupName"],
                region=region,
                account_id=account_id,
                launch_template_ref=lt_ref,
                mixed_instances_policy=mip,
                desired_capacity=raw["DesiredCapacity"],
                min_size=raw["MinSize"],
                max_size=raw["MaxSize"],
                suspended_processes=[p["ProcessName"] for p in raw.get("SuspendedProcesses", [])],
                current_instances=[
                    ASGInstance(
                        instance_id=inst["InstanceId"],
                        lifecycle_state=inst["LifecycleState"],
                    )
                    for inst in raw.get("Instances", [])
                ],
                tags={t["Key"]: t["Value"] for t in raw.get("Tags", [])},
            )
        )
    return result


def _resolve_direct_lt(
    raw_lt: dict | None,  # type: ignore[type-arg]
    lt_metadata_by_id: dict[str, LaunchTemplateMetadata],
) -> LaunchTemplateRef | None:
    if raw_lt is None:
        return None
    template_id = raw_lt.get("LaunchTemplateId", "")
    if not template_id:
        return None
    return _make_lt_ref(template_id, raw_lt.get("Version", "$Default"), lt_metadata_by_id)


def _normalize_mixed_instances_policy(
    raw_mip: dict | None,  # type: ignore[type-arg]
    lt_metadata_by_id: dict[str, LaunchTemplateMetadata],
) -> MixedInstancesPolicy | None:
    if raw_mip is None:
        return None

    raw_launch_template = raw_mip.get("LaunchTemplate", {})
    raw_base = raw_launch_template.get("LaunchTemplateSpecification")
    base_ref = None
    if raw_base:
        template_id = raw_base.get("LaunchTemplateId", "")
        if template_id:
            base_ref = _make_lt_ref(
                template_id, raw_base.get("Version", "$Default"), lt_metadata_by_id
            )

    overrides = [
        _normalize_override(ov, lt_metadata_by_id)
        for ov in raw_launch_template.get("Overrides", [])
    ]

    return MixedInstancesPolicy(base_launch_template_ref=base_ref, overrides=overrides)


def _normalize_override(
    raw_ov: dict,  # type: ignore[type-arg]
    lt_metadata_by_id: dict[str, LaunchTemplateMetadata],
) -> MixedInstancesOverride:
    raw_lt_spec = raw_ov.get("LaunchTemplateSpecification")
    override_ref = None
    if raw_lt_spec:
        template_id = raw_lt_spec.get("LaunchTemplateId", "")
        if template_id:
            override_ref = _make_lt_ref(
                template_id, raw_lt_spec.get("Version", "$Default"), lt_metadata_by_id
            )
    return MixedInstancesOverride(
        instance_type=raw_ov.get("InstanceType"),
        launch_template_ref=override_ref,
    )


def _make_lt_ref(
    template_id: str,
    version_selector: str,
    lt_metadata_by_id: dict[str, LaunchTemplateMetadata],
) -> LaunchTemplateRef:
    resolved = _resolve_version_number(template_id, version_selector, lt_metadata_by_id)
    return LaunchTemplateRef(
        template_id=template_id,
        template_name=lt_metadata_by_id.get(
            template_id,
            LaunchTemplateMetadata(
                template_id=template_id,
                template_name=None,
                default_version_number=0,
                latest_version_number=0,
            ),
        ).template_name,
        version_selector=version_selector,
        resolved_version_number=resolved,
    )


def _resolve_version_number(
    template_id: str,
    version_selector: str,
    lt_metadata_by_id: dict[str, LaunchTemplateMetadata],
) -> int:
    metadata = lt_metadata_by_id.get(template_id)
    if metadata is None:
        return 0  # metadata unavailable; 0 signals unresolvable

    if version_selector == "$Default":
        return metadata.default_version_number
    if version_selector == "$Latest":
        return metadata.latest_version_number
    try:
        return int(version_selector)
    except ValueError:
        return 0
