"""Evidence and ResourceRef models."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from aws_cost_forensics.domain.enums import EvidenceKind, EvidenceStrength
from aws_cost_forensics.domain.resource_key import ResourceKey


class ResourceRef(BaseModel):
    """Serializable display reference to an AWS resource — companion to ResourceKey."""

    model_config = ConfigDict(frozen=True)

    resource_id: str
    resource_type: str
    region: str
    account_id: str
    display_name: str | None = None

    def to_key(self, qualifier: str | None = None) -> ResourceKey:
        return ResourceKey(
            self.resource_type, self.resource_id, self.region, self.account_id, qualifier
        )


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    kind: EvidenceKind
    description: str
    resource_ref: ResourceRef | None = None
    api_source: str
    value: str | int | bool | None = None


__all__ = ["Evidence", "EvidenceStrength", "ResourceRef"]
