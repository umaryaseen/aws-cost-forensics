from __future__ import annotations

from decimal import Decimal

import pytest

from aws_cost_forensics.pricing.static import StaticPricingProvider


@pytest.fixture(scope="module")
def provider() -> StaticPricingProvider:
    return StaticPricingProvider()


# ---------------------------------------------------------------------------
# pricing_source_name
# ---------------------------------------------------------------------------


def test_pricing_source_name(provider: StaticPricingProvider) -> None:
    assert provider.pricing_source_name() == "static_table_v1"


# ---------------------------------------------------------------------------
# Unknown region / volume type
# ---------------------------------------------------------------------------


def test_unknown_region_returns_none(provider: StaticPricingProvider) -> None:
    assert provider.ebs_monthly_cost("xx-unknown-1", "gp2", 100) is None


def test_unknown_volume_type_returns_none(provider: StaticPricingProvider) -> None:
    assert provider.ebs_monthly_cost("us-east-1", "gp99", 100) is None


# ---------------------------------------------------------------------------
# gp2 — storage only
# ---------------------------------------------------------------------------


def test_gp2_us_east_1(provider: StaticPricingProvider) -> None:
    # us-east-1 gp2: $0.10/GB
    result = provider.ebs_monthly_cost("us-east-1", "gp2", 50)
    assert result == Decimal("5.00")


def test_gp2_eu_central_1(provider: StaticPricingProvider) -> None:
    # eu-central-1 gp2: $0.119/GB
    result = provider.ebs_monthly_cost("eu-central-1", "gp2", 100)
    assert result == Decimal("11.9")


def test_gp2_ignores_iops_arg(provider: StaticPricingProvider) -> None:
    # gp2 cost must not be affected by iops or throughput_mibps args
    base = provider.ebs_monthly_cost("us-east-1", "gp2", 100)
    with_iops = provider.ebs_monthly_cost("us-east-1", "gp2", 100, iops=500)
    assert base == with_iops


# ---------------------------------------------------------------------------
# gp3 — storage + provisioned IOPS above baseline + throughput above baseline
# ---------------------------------------------------------------------------


def test_gp3_storage_only_no_iops_no_throughput(provider: StaticPricingProvider) -> None:
    # us-east-1 gp3: $0.08/GB; no extra charges when iops=None, throughput_mibps=None
    result = provider.ebs_monthly_cost("us-east-1", "gp3", 100)
    assert result == Decimal("8.00")


def test_gp3_with_provisioned_iops(provider: StaticPricingProvider) -> None:
    # us-east-1 gp3: $0.08 * 100 GB + $0.005 * 2000 IOPS = 8.00 + 10.00 = 18.00
    result = provider.ebs_monthly_cost("us-east-1", "gp3", 100, iops=2000)
    assert result == Decimal("18.00")


def test_gp3_with_throughput(provider: StaticPricingProvider) -> None:
    # us-east-1 gp3: $0.08 * 100 GB + $0.04 * 250 MiB/s = 8.00 + 10.00 = 18.00
    result = provider.ebs_monthly_cost("us-east-1", "gp3", 100, throughput_mibps=250)
    assert result == Decimal("18.00")


def test_gp3_with_iops_and_throughput(provider: StaticPricingProvider) -> None:
    # us-east-1 gp3: 0.08*100 + 0.005*3000 + 0.04*500 = 8.00 + 15.00 + 20.00 = 43.00
    result = provider.ebs_monthly_cost("us-east-1", "gp3", 100, iops=3000, throughput_mibps=500)
    assert result == Decimal("43.00")


def test_gp3_iops_zero_no_charge(provider: StaticPricingProvider) -> None:
    # iops=0 → no IOPS charge
    result = provider.ebs_monthly_cost("us-east-1", "gp3", 100, iops=0)
    assert result == Decimal("8.00")


def test_gp2_to_gp3_model_500gb(provider: StaticPricingProvider) -> None:
    """
    Performance-preserving gp2→gp3 cost model for a 500 GiB volume.

    gp2: $0.10 * 500 = $50.00
    gp2_iops = min(500 * 3, 16000) = 1500   (≤ 3000 gp3 free baseline)
    gp3_provisioned_iops = max(0, 1500 - 3000) = 0
    gp3: $0.08 * 500 + $0.005 * 0 = $40.00
    Saving: $10.00
    """
    size_gib = 500
    gp2_iops = min(size_gib * 3, 16000)
    gp3_provisioned_iops = max(0, gp2_iops - 3000)

    gp2_cost = provider.ebs_monthly_cost("us-east-1", "gp2", size_gib)
    gp3_cost = provider.ebs_monthly_cost("us-east-1", "gp3", size_gib, iops=gp3_provisioned_iops)

    assert gp2_cost is not None and gp3_cost is not None
    assert gp2_cost == Decimal("50.00")
    assert gp3_cost == Decimal("40.00")
    assert gp3_cost < gp2_cost


def test_gp2_to_gp3_model_high_iops_volume(provider: StaticPricingProvider) -> None:
    """
    Performance-preserving gp2→gp3 for a 2000 GiB volume (gp2 IOPS exceed gp3 baseline).

    gp2_iops = min(2000 * 3, 16000) = 6000
    gp3_provisioned_iops = max(0, 6000 - 3000) = 3000
    gp2: $0.10 * 2000 = $200.00
    gp3: $0.08 * 2000 + $0.005 * 3000 = $160.00 + $15.00 = $175.00
    Still cheaper at this size.
    """
    size_gib = 2000
    gp2_iops = min(size_gib * 3, 16000)
    gp3_provisioned_iops = max(0, gp2_iops - 3000)

    gp2_cost = provider.ebs_monthly_cost("us-east-1", "gp2", size_gib)
    gp3_cost = provider.ebs_monthly_cost("us-east-1", "gp3", size_gib, iops=gp3_provisioned_iops)

    assert gp2_cost is not None and gp3_cost is not None
    assert gp2_cost == Decimal("200.00")
    assert gp3_cost == Decimal("175.00")
    assert gp3_cost < gp2_cost


def test_gp2_to_gp3_model_capped_iops(provider: StaticPricingProvider) -> None:
    """
    gp2 IOPS cap at 16000 for volumes ≥ 5334 GiB.

    size_gib = 6000 → gp2_iops = min(18000, 16000) = 16000
    gp3_provisioned_iops = 16000 - 3000 = 13000
    gp2: $0.10 * 6000 = $600
    gp3: $0.08 * 6000 + $0.005 * 13000 = $480 + $65 = $545
    """
    size_gib = 6000
    gp2_iops = min(size_gib * 3, 16000)
    gp3_provisioned_iops = max(0, gp2_iops - 3000)

    assert gp2_iops == 16000
    assert gp3_provisioned_iops == 13000

    gp2_cost = provider.ebs_monthly_cost("us-east-1", "gp2", size_gib)
    gp3_cost = provider.ebs_monthly_cost("us-east-1", "gp3", size_gib, iops=gp3_provisioned_iops)

    assert gp2_cost == Decimal("600.00")
    assert gp3_cost == Decimal("545.00")


# ---------------------------------------------------------------------------
# io1 / io2 — storage + IOPS
# ---------------------------------------------------------------------------


def test_io1_cost(provider: StaticPricingProvider) -> None:
    # us-east-1 io1: $0.125/GB + $0.065/IOPS
    result = provider.ebs_monthly_cost("us-east-1", "io1", 100, iops=1000)
    assert result == Decimal("12.5") + Decimal("65.0")


def test_io2_cost(provider: StaticPricingProvider) -> None:
    # us-east-1 io2: same pricing as io1
    result = provider.ebs_monthly_cost("us-east-1", "io2", 100, iops=1000)
    assert result == Decimal("12.5") + Decimal("65.0")


def test_io1_no_iops_arg(provider: StaticPricingProvider) -> None:
    # iops=None → 0 IOPS charge
    result = provider.ebs_monthly_cost("us-east-1", "io1", 100)
    assert result == Decimal("12.5")


# ---------------------------------------------------------------------------
# sc1 / st1 / standard — storage only
# ---------------------------------------------------------------------------


def test_sc1_cost(provider: StaticPricingProvider) -> None:
    result = provider.ebs_monthly_cost("us-east-1", "sc1", 1000)
    assert result == Decimal("15.0")


def test_st1_cost(provider: StaticPricingProvider) -> None:
    result = provider.ebs_monthly_cost("us-east-1", "st1", 1000)
    assert result == Decimal("45.0")


def test_standard_cost(provider: StaticPricingProvider) -> None:
    result = provider.ebs_monthly_cost("us-east-1", "standard", 100)
    assert result == Decimal("5.0")


# ---------------------------------------------------------------------------
# Regional coverage spot-checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "region",
    [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "eu-central-1",
        "ap-southeast-1",
        "ap-northeast-1",
        "sa-east-1",
    ],
)
def test_region_has_gp2_and_gp3(provider: StaticPricingProvider, region: str) -> None:
    assert provider.ebs_monthly_cost(region, "gp2", 100) is not None
    assert provider.ebs_monthly_cost(region, "gp3", 100) is not None


def test_return_type_is_decimal(provider: StaticPricingProvider) -> None:
    result = provider.ebs_monthly_cost("us-east-1", "gp2", 100)
    assert isinstance(result, Decimal)
