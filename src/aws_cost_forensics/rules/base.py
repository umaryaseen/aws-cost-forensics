from __future__ import annotations

from typing import ClassVar, Protocol

from aws_cost_forensics.domain.findings import ForensicCase, Observation
from aws_cost_forensics.domain.inventory import Inventory


class Detector(Protocol):
    rule_id: ClassVar[str]

    def detect(self, inventory: Inventory) -> list[Observation]: ...


class Correlator(Protocol):
    case_type: ClassVar[str]
    supersedes_rules: ClassVar[list[str]]

    def correlate(
        self, inventory: Inventory, observations: list[Observation]
    ) -> list[ForensicCase]: ...
