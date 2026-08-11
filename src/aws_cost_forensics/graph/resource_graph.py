"""Lightweight resource graph keyed on ResourceKey — implemented in T004."""

from __future__ import annotations

from collections import defaultdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aws_cost_forensics.domain.enums import RelationshipType
    from aws_cost_forensics.domain.resource_key import ResourceKey


class ResourceGraph:
    """Placeholder — full implementation in T004."""

    def __init__(self) -> None:
        self._out: dict[
            tuple[ResourceKey, RelationshipType], list[ResourceKey]
        ] = defaultdict(list)
        self._in: dict[
            tuple[ResourceKey, RelationshipType], list[ResourceKey]
        ] = defaultdict(list)
