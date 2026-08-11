"""Composite, hashable, globally unique resource identity for graph nodes."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ResourceKey:
    """
    Composite identity for a single AWS resource scoped to account and region.

    LT versions use qualifier=str(version_number) to distinguish versions of the
    same template. All other resource types leave qualifier as None.
    """

    resource_type: str
    resource_id: str
    region: str
    account_id: str
    qualifier: str | None = None

    def __str__(self) -> str:
        base = f"{self.resource_type}:{self.account_id}:{self.region}:{self.resource_id}"
        return f"{base}:{self.qualifier}" if self.qualifier else base
