"""RelationshipBuilder and resolve_effective_root_device."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aws_cost_forensics.domain.enums import DeleteOnTerminationSource, RelationshipType
from aws_cost_forensics.domain.resource_key import ResourceKey
from aws_cost_forensics.domain.resources import (
    AMI,
    BlockDeviceMapping,
    EBSVolume,
    EffectiveRootDeviceConfig,
    LaunchTemplateVersion,
)
from aws_cost_forensics.graph.resource_graph import ResourceGraph

if TYPE_CHECKING:
    from aws_cost_forensics.domain.inventory import Inventory

_LIKELY_ROOT_DEVICES = frozenset({"/dev/xvda", "/dev/sda1", "/dev/xvda1"})


def resolve_effective_root_device(
    lt_ver: LaunchTemplateVersion,
    ami: AMI | None,
) -> EffectiveRootDeviceConfig:
    """Resolve the effective root device config for a Launch Template version.

    Resolution order:
    1. Identify the root device name — from AMI.root_device_name if available,
       otherwise heuristic (first BDM matching known root device names, then
       the first BDM overall).
    2. Find the matching BDM in the LT version.
    3. LT BDM has delete_on_termination explicitly set → source=LT_EXPLICIT.
    4. BDM absent or delete_on_termination=None and AMI available →
       source=AMI_DEFAULT (AWS default for root device = True).
    5. AMI unavailable and no explicit BDM value → UNRESOLVED.
    """
    root_device_name = _resolve_root_device_name(lt_ver, ami)
    root_bdm = _find_bdm(lt_ver, root_device_name) if root_device_name else None

    if root_bdm is not None and root_bdm.delete_on_termination is not None:
        return EffectiveRootDeviceConfig(
            device_name=root_bdm.device_name,
            delete_on_termination=root_bdm.delete_on_termination,
            source=DeleteOnTerminationSource.LT_EXPLICIT,
            volume_type=root_bdm.volume_type,
            volume_size_gib=root_bdm.volume_size_gib,
        )

    device_name = root_device_name or (root_bdm.device_name if root_bdm else "unknown")

    if ami is not None:
        return EffectiveRootDeviceConfig(
            device_name=device_name,
            delete_on_termination=True,
            source=DeleteOnTerminationSource.AMI_DEFAULT,
        )

    return EffectiveRootDeviceConfig(
        device_name=device_name,
        delete_on_termination=None,
        source=DeleteOnTerminationSource.UNRESOLVED,
    )


def _resolve_root_device_name(
    lt_ver: LaunchTemplateVersion, ami: AMI | None
) -> str | None:
    if ami and ami.root_device_name:
        return ami.root_device_name
    for bdm in lt_ver.block_device_mappings:
        if bdm.device_name in _LIKELY_ROOT_DEVICES:
            return bdm.device_name
    if lt_ver.block_device_mappings:
        return lt_ver.block_device_mappings[0].device_name
    return None


def _find_bdm(lt_ver: LaunchTemplateVersion, device_name: str) -> BlockDeviceMapping | None:
    for bdm in lt_ver.block_device_mappings:
        if bdm.device_name == device_name:
            return bdm
    return None


class RelationshipBuilder:
    """Builds all ResourceGraph edges from pre-fetched inventory collections.

    Relies only on data already in the Inventory — no additional API calls.
    """

    def __init__(self, graph: ResourceGraph) -> None:
        self._g = graph

    def build_all(self, inventory: Inventory) -> None:
        self._volume_to_snapshot(inventory)
        self._instance_to_volume(inventory)
        self._snapshot_to_ami(inventory)
        self._lt_version_to_ami(inventory)
        self._lt_version_to_lt(inventory)
        self._asg_to_lt(inventory)
        self._asg_to_instance(inventory)

    def _volume_to_snapshot(self, inventory: Inventory) -> None:
        for vol in inventory.volumes:
            if vol.snapshot_id:
                snap = inventory.get_snapshot(vol.snapshot_id)
                if snap:
                    self._g.add(
                        vol.resource_key,
                        RelationshipType.VOLUME_CREATED_FROM_SNAPSHOT,
                        snap.resource_key,
                    )

    def _instance_to_volume(self, inventory: Inventory) -> None:
        for inst in inventory.instances:
            for bdm in inst.block_device_mappings:
                vol = _find_volume_by_attachment(inventory, inst.instance_id, bdm.device)
                if vol:
                    self._g.add(
                        inst.resource_key,
                        RelationshipType.INSTANCE_USES_VOLUME,
                        vol.resource_key,
                    )

    def _snapshot_to_ami(self, inventory: Inventory) -> None:
        for ami in inventory.amis:
            for snap_id in ami.snapshot_ids:
                snap = inventory.get_snapshot(snap_id)
                if snap:
                    self._g.add(
                        snap.resource_key,
                        RelationshipType.SNAPSHOT_BELONGS_TO_AMI,
                        ami.resource_key,
                    )

    def _lt_version_to_ami(self, inventory: Inventory) -> None:
        for lt_ver in inventory.launch_template_versions:
            if lt_ver.image_id:
                ami = inventory.get_ami(lt_ver.image_id)
                if ami:
                    self._g.add(
                        lt_ver.resource_key,
                        RelationshipType.LT_VERSION_USES_AMI,
                        ami.resource_key,
                    )

    def _lt_version_to_lt(self, inventory: Inventory) -> None:
        for lt_ver in inventory.launch_template_versions:
            self._g.add(
                lt_ver.resource_key,
                RelationshipType.LT_VERSION_BELONGS_TO_LT,
                lt_ver.template_key,
            )

    def _asg_to_lt(self, inventory: Inventory) -> None:
        for asg in inventory.auto_scaling_groups:
            template_ids: list[str] = []
            if asg.launch_template_ref:
                template_ids.append(asg.launch_template_ref.template_id)
            if asg.mixed_instances_policy:
                base = asg.mixed_instances_policy.base_launch_template_ref
                if base:
                    template_ids.append(base.template_id)
                for override in asg.mixed_instances_policy.overrides:
                    if override.launch_template_ref:
                        template_ids.append(override.launch_template_ref.template_id)
            for template_id in dict.fromkeys(template_ids):
                lt_key = ResourceKey(
                    "launch_template", template_id, asg.region, asg.account_id
                )
                self._g.add(
                    asg.resource_key, RelationshipType.ASG_USES_LAUNCH_TEMPLATE, lt_key
                )

    def _asg_to_instance(self, inventory: Inventory) -> None:
        for asg in inventory.auto_scaling_groups:
            for asg_inst in asg.current_instances:
                inst = inventory.get_instance(asg_inst.instance_id)
                if inst:
                    self._g.add(
                        asg.resource_key,
                        RelationshipType.ASG_HAS_INSTANCE,
                        inst.resource_key,
                    )


def _find_volume_by_attachment(
    inventory: Inventory, instance_id: str, device: str
) -> EBSVolume | None:
    for vol in inventory.volumes:
        for att in vol.attachments:
            if att.instance_id == instance_id and att.device == device:
                return vol
    return None
