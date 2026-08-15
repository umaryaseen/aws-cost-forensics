from __future__ import annotations

import json
from decimal import Decimal
from importlib import resources
from typing import Any


class StaticPricingProvider:
    """Pricing provider backed by a bundled JSON table."""

    _SOURCE_NAME = "static_table_v1"

    def __init__(self) -> None:
        self._table: dict[str, dict[str, dict[str, str]]] = self._load()

    @staticmethod
    def _load() -> dict[str, Any]:
        pkg = resources.files("aws_cost_forensics.pricing.data")
        data = (pkg / "ebs_prices.json").read_text(encoding="utf-8")
        return json.loads(data)["regions"]  # type: ignore[no-any-return]

    def ebs_monthly_cost(
        self,
        region: str,
        volume_type: str,
        size_gib: int,
        iops: int | None = None,
        throughput_mibps: int | None = None,
    ) -> Decimal | None:
        region_data = self._table.get(region)
        if region_data is None:
            return None
        vt_data = region_data.get(volume_type)
        if vt_data is None:
            return None

        cost = Decimal(vt_data["storage_per_gb"]) * size_gib

        if volume_type in ("gp3", "io1", "io2") and "iops_per_iops" in vt_data:
            cost += Decimal(vt_data["iops_per_iops"]) * (iops or 0)

        if volume_type == "gp3" and "throughput_per_mibps" in vt_data:
            cost += Decimal(vt_data["throughput_per_mibps"]) * (throughput_mibps or 0)

        return cost

    def pricing_source_name(self) -> str:
        return self._SOURCE_NAME
