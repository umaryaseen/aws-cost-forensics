"""Lightweight directed graph keyed on ResourceKey."""

from __future__ import annotations

from collections import defaultdict

from aws_cost_forensics.domain.enums import RelationshipType
from aws_cost_forensics.domain.resource_key import ResourceKey

_EdgeKey = tuple[ResourceKey, RelationshipType]


class ResourceGraph:
    """Directed adjacency graph for AWS resource relationships.

    Edges are directional and named. Call add(source, rel, target) to record
    a relationship, then query via targets(source, rel) or sources(target, rel).
    """

    def __init__(self) -> None:
        self._out: dict[_EdgeKey, list[ResourceKey]] = defaultdict(list)
        self._in: dict[_EdgeKey, list[ResourceKey]] = defaultdict(list)

    def add(self, source: ResourceKey, rel: RelationshipType, target: ResourceKey) -> None:
        self._out[(source, rel)].append(target)
        self._in[(target, rel)].append(source)

    def targets(self, source: ResourceKey, rel: RelationshipType) -> list[ResourceKey]:
        return list(self._out[(source, rel)])

    def sources(self, target: ResourceKey, rel: RelationshipType) -> list[ResourceKey]:
        return list(self._in[(target, rel)])

    def has_edge(self, source: ResourceKey, rel: RelationshipType, target: ResourceKey) -> bool:
        return target in self._out[(source, rel)]
