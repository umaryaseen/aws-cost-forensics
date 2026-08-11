"""All domain enumerations."""

from enum import StrEnum


class EvidenceKind(StrEnum):
    SUPPORTING = "supporting"
    CONTRADICTING = "contradicting"
    MISSING = "missing"


class EvidenceStrength(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecurrenceStatus(StrEnum):
    ACTIVE = "ACTIVE"
    HISTORICAL = "HISTORICAL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class DecisionClass(StrEnum):
    CONFIGURATION_DEFECT = "CONFIGURATION_DEFECT"
    REMEDIATION_CANDIDATE = "REMEDIATION_CANDIDATE"
    INCOMPLETE_DATA = "INCOMPLETE_DATA"
    BUSINESS_DECISION = "BUSINESS_DECISION"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DeleteOnTerminationSource(StrEnum):
    LT_EXPLICIT = "lt_explicit"
    AMI_DEFAULT = "ami_default"
    UNRESOLVED = "unresolved"


class RelationshipType(StrEnum):
    # Named to reflect source → target direction
    VOLUME_CREATED_FROM_SNAPSHOT = "VOLUME_CREATED_FROM_SNAPSHOT"
    SNAPSHOT_BELONGS_TO_AMI = "SNAPSHOT_BELONGS_TO_AMI"
    LT_VERSION_USES_AMI = "LT_VERSION_USES_AMI"
    LT_VERSION_BELONGS_TO_LT = "LT_VERSION_BELONGS_TO_LT"
    ASG_USES_LAUNCH_TEMPLATE = "ASG_USES_LAUNCH_TEMPLATE"
    INSTANCE_USES_VOLUME = "INSTANCE_USES_VOLUME"
    ASG_HAS_INSTANCE = "ASG_HAS_INSTANCE"
