from __future__ import annotations

from typing import Any


class ReadOnlyViolation(Exception):
    """Raised when code attempts a non-allowlisted AWS operation."""


class ReadOnlyEC2Client:
    """Wraps a boto3 EC2 client, blocking every operation not on the read-only allowlist."""

    APPROVED_OPERATIONS: frozenset[str] = frozenset(
        {
            "describe_volumes",
            "describe_instances",
            "describe_snapshots",
            "describe_images",
            "describe_launch_templates",
            "describe_launch_template_versions",
            "get_paginator",
        }
    )

    def __init__(self, client: Any) -> None:
        self._client: Any = client

    def __getattr__(self, name: str) -> Any:
        if name not in self.APPROVED_OPERATIONS:
            raise ReadOnlyViolation(
                f"EC2 operation '{name}' is not in the read-only allowlist. "
                "aws-cost-forensics performs no mutations."
            )
        return getattr(self._client, name)


class ReadOnlyASGClient:
    """Wraps a boto3 AutoScaling client, blocking every operation not on the read-only allowlist."""

    APPROVED_OPERATIONS: frozenset[str] = frozenset(
        {
            "describe_auto_scaling_groups",
            "get_paginator",
        }
    )

    def __init__(self, client: Any) -> None:
        self._client: Any = client

    def __getattr__(self, name: str) -> Any:
        if name not in self.APPROVED_OPERATIONS:
            raise ReadOnlyViolation(
                f"AutoScaling operation '{name}' is not in the read-only allowlist. "
                "aws-cost-forensics performs no mutations."
            )
        return getattr(self._client, name)


class ReadOnlySTSClient:
    """Wraps a boto3 STS client, blocking every operation not on the read-only allowlist."""

    APPROVED_OPERATIONS: frozenset[str] = frozenset(
        {
            "get_caller_identity",
        }
    )

    def __init__(self, client: Any) -> None:
        self._client: Any = client

    def __getattr__(self, name: str) -> Any:
        if name not in self.APPROVED_OPERATIONS:
            raise ReadOnlyViolation(
                f"STS operation '{name}' is not in the read-only allowlist. "
                "aws-cost-forensics performs no mutations."
            )
        return getattr(self._client, name)
