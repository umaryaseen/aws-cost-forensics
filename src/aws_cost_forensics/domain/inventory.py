"""Inventory (runtime internal state) and ScanResult (JSON output target)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import TYPE_CHECKING

from pydantic import BaseModel, ConfigDict

from aws_cost_forensics.domain.findings import ForensicCase, Observation
from aws_cost_forensics.domain.resource_key import ResourceKey
from aws_cost_forensics.domain.resources import (
    AMI,
    AutoScalingGroup,
    EBSSnapshot,
    EBSVolume,
    EC2Instance,
    LaunchTemplateVersion,
)

if TYPE_CHECKING:
    from aws_cost_forensics.graph.resource_graph import ResourceGraph


# ---------------------------------------------------------------------------
# Inventory — plain dataclass; never serialized
# ---------------------------------------------------------------------------


@dataclass
class Inventory:
    """Runtime collection of all normalized AWS resources for one scan.

    Internal only — not serialized to JSON. Provides indexed lookups so rule
    implementations can retrieve resources by ID in O(1) without repeated list scans.
    """

    account_id: str
    region: str
    scanned_at: datetime
    volumes: list[EBSVolume]
    snapshots: list[EBSSnapshot]
    amis: list[AMI]
    instances: list[EC2Instance]
    launch_template_versions: list[LaunchTemplateVersion]
    auto_scaling_groups: list[AutoScalingGroup]
    graph: ResourceGraph = field(default_factory=lambda: _make_empty_graph())

    _volumes_by_id: dict[str, EBSVolume] = field(default_factory=dict, init=False, repr=False)
    _snapshots_by_id: dict[str, EBSSnapshot] = field(default_factory=dict, init=False, repr=False)
    _amis_by_id: dict[str, AMI] = field(default_factory=dict, init=False, repr=False)
    _instances_by_id: dict[str, EC2Instance] = field(default_factory=dict, init=False, repr=False)
    _asgs_by_name: dict[str, AutoScalingGroup] = field(default_factory=dict, init=False, repr=False)
    _lt_versions_by_key: dict[ResourceKey, LaunchTemplateVersion] = field(
        default_factory=dict, init=False, repr=False
    )
    _lt_versions_by_template_id: dict[str, list[LaunchTemplateVersion]] = field(
        default_factory=dict, init=False, repr=False
    )

    def __post_init__(self) -> None:
        self._build_indexes()

    def _build_indexes(self) -> None:
        self._volumes_by_id = {v.volume_id: v for v in self.volumes}
        self._snapshots_by_id = {s.snapshot_id: s for s in self.snapshots}
        self._amis_by_id = {a.image_id: a for a in self.amis}
        self._instances_by_id = {i.instance_id: i for i in self.instances}
        self._asgs_by_name = {a.asg_name: a for a in self.auto_scaling_groups}
        self._lt_versions_by_key = {v.resource_key: v for v in self.launch_template_versions}
        by_template: dict[str, list[LaunchTemplateVersion]] = {}
        for v in self.launch_template_versions:
            by_template.setdefault(v.template_id, []).append(v)
        self._lt_versions_by_template_id = by_template

    def get_volume(self, volume_id: str) -> EBSVolume | None:
        return self._volumes_by_id.get(volume_id)

    def get_snapshot(self, snapshot_id: str) -> EBSSnapshot | None:
        return self._snapshots_by_id.get(snapshot_id)

    def get_ami(self, image_id: str) -> AMI | None:
        return self._amis_by_id.get(image_id)

    def get_instance(self, instance_id: str) -> EC2Instance | None:
        return self._instances_by_id.get(instance_id)

    def get_asg(self, asg_name: str) -> AutoScalingGroup | None:
        return self._asgs_by_name.get(asg_name)

    def get_lt_version(self, key: ResourceKey) -> LaunchTemplateVersion | None:
        return self._lt_versions_by_key.get(key)

    def get_lt_versions_for_template(self, template_id: str) -> list[LaunchTemplateVersion]:
        return self._lt_versions_by_template_id.get(template_id, [])

    def resolve_lt_version(self, template_id: str, selector: str) -> LaunchTemplateVersion | None:
        """Resolve $Default, $Latest, or an explicit version number to an LT version."""
        versions = self.get_lt_versions_for_template(template_id)
        if not versions:
            return None
        if selector == "$Default":
            return next((v for v in versions if v.is_default), None)
        if selector == "$Latest":
            return next((v for v in versions if v.is_latest), None)
        try:
            number = int(selector)
        except ValueError:
            return None
        return next((v for v in versions if v.version_number == number), None)


def _make_empty_graph() -> ResourceGraph:
    from aws_cost_forensics.graph.resource_graph import ResourceGraph

    return ResourceGraph()


# ---------------------------------------------------------------------------
# ScanResult and supporting models — Pydantic; this is the JSON output target
# ---------------------------------------------------------------------------


class ScanError(BaseModel):
    model_config = ConfigDict(frozen=True)

    collector: str
    error_code: str
    message: str
    is_permission_error: bool


class ScanSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    forensic_cases: int
    observations: int
    observations_superseded: int
    affected_resources: int
    total_monthly_waste_usd: Decimal | None
    has_active_recurrence: bool
    scan_errors: int


class ScanResult(BaseModel):
    """The complete output of one acf scan. This is the JSON artifact target."""

    model_config = ConfigDict(frozen=True)

    schema_version: str = "1.0"
    tool_version: str
    generated_at: datetime
    account_id: str
    region: str
    pricing_source: str
    observations: list[Observation]
    forensic_cases: list[ForensicCase]
    scan_errors: list[ScanError]
    summary: ScanSummary
