"""Normalized AWS resource models — all frozen Pydantic models."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from aws_cost_forensics.domain.enums import DeleteOnTerminationSource
from aws_cost_forensics.domain.resource_key import ResourceKey


class VolumeAttachment(BaseModel):
    model_config = ConfigDict(frozen=True)

    instance_id: str
    device: str
    state: str
    delete_on_termination: bool


class EBSVolume(BaseModel):
    model_config = ConfigDict(frozen=True)

    volume_id: str
    region: str
    account_id: str
    state: str
    size_gib: int
    volume_type: str
    iops: int | None = None
    throughput: int | None = None
    create_time: datetime
    availability_zone: str
    snapshot_id: str | None = None
    attachments: list[VolumeAttachment] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def resource_key(self) -> ResourceKey:
        return ResourceKey("ebs_volume", self.volume_id, self.region, self.account_id)


class EBSSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    snapshot_id: str
    region: str
    account_id: str
    volume_id: str | None = None
    volume_size_gib: int
    state: str
    start_time: datetime
    description: str = ""
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def resource_key(self) -> ResourceKey:
        return ResourceKey("snapshot", self.snapshot_id, self.region, self.account_id)


class AMI(BaseModel):
    model_config = ConfigDict(frozen=True)

    image_id: str
    region: str
    account_id: str
    name: str | None = None
    state: str
    creation_date: datetime
    root_device_name: str | None = None
    snapshot_ids: list[str] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def resource_key(self) -> ResourceKey:
        return ResourceKey("ami", self.image_id, self.region, self.account_id)


class EC2Instance(BaseModel):
    model_config = ConfigDict(frozen=True)

    instance_id: str
    region: str
    account_id: str
    state: str
    instance_type: str
    launch_time: datetime
    root_device_name: str | None = None
    block_device_mappings: list[VolumeAttachment] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def resource_key(self) -> ResourceKey:
        return ResourceKey("ec2_instance", self.instance_id, self.region, self.account_id)


class BlockDeviceMapping(BaseModel):
    """A block device mapping entry in a Launch Template version.

    delete_on_termination is None when the AWS API omits the field — meaning the
    value is inherited from the AMI default. It must never be coerced to False.
    """

    model_config = ConfigDict(frozen=True)

    device_name: str
    snapshot_id: str | None = None
    volume_size_gib: int | None = None
    volume_type: str | None = None
    delete_on_termination: bool | None = None
    iops: int | None = None
    throughput: int | None = None


class EffectiveRootDeviceConfig(BaseModel):
    """Resolved root EBS device configuration for a specific LT version.

    delete_on_termination is None only when source is UNRESOLVED (AMI unavailable).
    """

    model_config = ConfigDict(frozen=True)

    device_name: str
    delete_on_termination: bool | None
    source: DeleteOnTerminationSource
    volume_type: str | None = None
    volume_size_gib: int | None = None


class LaunchTemplateRef(BaseModel):
    """Reference from an ASG or MixedInstancesPolicy to a specific LT version.

    version_selector preserves the raw string from the ASG config ("$Default", "$Latest",
    or an explicit version number string). resolved_version_number is the concrete integer
    resolved at collection time against the LT metadata.
    """

    model_config = ConfigDict(frozen=True)

    template_id: str
    template_name: str | None = None
    version_selector: str
    resolved_version_number: int


class LaunchTemplateVersion(BaseModel):
    model_config = ConfigDict(frozen=True)

    template_id: str
    template_name: str | None = None
    region: str
    account_id: str
    version_number: int
    is_default: bool
    is_latest: bool
    image_id: str | None = None
    block_device_mappings: list[BlockDeviceMapping] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def resource_key(self) -> ResourceKey:
        return ResourceKey(
            "launch_template_version",
            self.template_id,
            self.region,
            self.account_id,
            qualifier=str(self.version_number),
        )

    @property
    def template_key(self) -> ResourceKey:
        return ResourceKey("launch_template", self.template_id, self.region, self.account_id)


class MixedInstancesOverride(BaseModel):
    model_config = ConfigDict(frozen=True)

    instance_type: str | None = None
    launch_template_ref: LaunchTemplateRef | None = None


class MixedInstancesPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    base_launch_template_ref: LaunchTemplateRef | None = None
    overrides: list[MixedInstancesOverride] = Field(default_factory=list)

    @property
    def has_override_specific_lt(self) -> bool:
        return any(o.launch_template_ref is not None for o in self.overrides)


class ASGInstance(BaseModel):
    model_config = ConfigDict(frozen=True)

    instance_id: str
    lifecycle_state: str


class AutoScalingGroup(BaseModel):
    model_config = ConfigDict(frozen=True)

    asg_name: str
    region: str
    account_id: str
    launch_template_ref: LaunchTemplateRef | None = None
    mixed_instances_policy: MixedInstancesPolicy | None = None
    desired_capacity: int
    min_size: int
    max_size: int
    suspended_processes: list[str] = Field(default_factory=list)
    current_instances: list[ASGInstance] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)

    @property
    def resource_key(self) -> ResourceKey:
        return ResourceKey("asg", self.asg_name, self.region, self.account_id)

    @property
    def effective_lt_ref(self) -> LaunchTemplateRef | None:
        """Base LT reference: direct or from MixedInstancesPolicy base."""
        if self.launch_template_ref:
            return self.launch_template_ref
        if self.mixed_instances_policy:
            return self.mixed_instances_policy.base_launch_template_ref
        return None

    @property
    def has_reachable_launch_path(self) -> bool:
        """
        True when this ASG's launch configuration can materialize instances.

        max_size=0 means the ASG is administratively sealed — it cannot launch
        even if a scale-up is attempted. desired_capacity=0 with max_size>0 can
        still be scaled at any time, so the launch path remains reachable.
        """
        return self.max_size > 0
