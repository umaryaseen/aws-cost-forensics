"""JSON serializer for ScanResult scan artifacts."""

from __future__ import annotations

from aws_cost_forensics.domain.inventory import ScanResult


class JsonReporter:
    """Serializes a ScanResult to a JSON string.

    Decimal values are serialized as strings to preserve precision.
    Datetimes are ISO 8601 UTC (e.g. "2024-01-15T10:30:00Z").
    schema_version and tool_version are separate top-level fields.
    """

    def render(self, scan_result: ScanResult, *, indent: int = 2) -> str:
        """Return the full ScanResult as a formatted JSON string."""
        return scan_result.model_dump_json(indent=indent)
