"""Observation, ForensicCase, CostEstimate, and RemediationPlan models."""

from __future__ import annotations

from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict

from aws_cost_forensics.domain.enums import (
    DecisionClass,
    EvidenceStrength,
    RecurrenceStatus,
    Severity,
)
from aws_cost_forensics.domain.evidence import Evidence, ResourceRef


class CostEstimate(BaseModel):
    model_config = ConfigDict(frozen=True)

    monthly_cost_usd: Decimal
    potential_saving_usd: Decimal | None = None
    basis: Literal["modeled"] = "modeled"
    pricing_source: str
    note: str | None = None


class RemediationStep(BaseModel):
    model_config = ConfigDict(frozen=True)

    order: int
    title: str
    description: str
    aws_cli_hint: str | None = None


class RemediationPlan(BaseModel):
    model_config = ConfigDict(frozen=True)

    priority: str
    steps: list[RemediationStep]
    blockers: list[str]


class Observation(BaseModel):
    """A single-resource finding emitted by a Detector rule."""

    model_config = ConfigDict(frozen=True)

    observation_id: str
    rule_id: str
    resource_ref: ResourceRef
    severity: Severity
    decision_class: DecisionClass
    evidence: list[Evidence]
    evidence_strength: EvidenceStrength
    cost_estimate: CostEstimate | None = None
    remediation_plan: RemediationPlan | None = None
    superseded_by: str | None = None


class ForensicCase(BaseModel):
    """A cross-resource causal conclusion emitted by a Correlator rule."""

    model_config = ConfigDict(frozen=True)

    case_id: str
    case_type: str
    title: str
    description: str
    severity: Severity
    decision_class: DecisionClass
    recurrence: RecurrenceStatus
    evidence_strength: EvidenceStrength
    root_cause_ref: ResourceRef
    affected_resource_refs: list[ResourceRef]
    evidence: list[Evidence]
    cost_estimate: CostEstimate | None = None
    remediation_plan: RemediationPlan | None = None
