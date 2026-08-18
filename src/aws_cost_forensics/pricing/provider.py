from __future__ import annotations

from decimal import Decimal
from typing import Protocol


class PricingProvider(Protocol):
    def ebs_monthly_cost(
        self,
        region: str,
        volume_type: str,
        size_gib: int,
        iops: int | None = None,
        throughput_mibps: int | None = None,
    ) -> Decimal | None:
        """
        Return the monthly EBS cost in USD, or None if the region is not in the table.

        For gp3: iops = provisioned IOPS above the 3000 free baseline;
                 throughput_mibps = provisioned MiB/s above the 125 free baseline.
        For io1/io2: iops = total provisioned IOPS.
        """
        ...

    def pricing_source_name(self) -> str:
        """Human-readable identifier for the pricing data source."""
        ...
