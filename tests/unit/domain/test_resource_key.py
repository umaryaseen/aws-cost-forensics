"""Tests for ResourceKey composite identity."""

from aws_cost_forensics.domain.resource_key import ResourceKey


def _vol(region: str = "eu-central-1", account: str = "111111111111") -> ResourceKey:
    return ResourceKey("ebs_volume", "vol-abc123", region, account)


def test_equality_same_fields() -> None:
    assert _vol() == _vol()


def test_inequality_different_region() -> None:
    assert _vol(region="us-east-1") != _vol(region="eu-central-1")


def test_inequality_different_account() -> None:
    assert _vol(account="111111111111") != _vol(account="222222222222")


def test_inequality_different_type() -> None:
    a = ResourceKey("ebs_volume", "vol-abc123", "eu-central-1", "111111111111")
    b = ResourceKey("snapshot", "vol-abc123", "eu-central-1", "111111111111")
    assert a != b


def test_hashable_usable_as_dict_key() -> None:
    key = _vol()
    d: dict[ResourceKey, str] = {key: "value"}
    assert d[key] == "value"


def test_hashable_same_key_in_set() -> None:
    assert len({_vol(), _vol()}) == 1


def test_different_region_different_hash() -> None:
    assert hash(_vol(region="us-east-1")) != hash(_vol(region="eu-central-1"))


def test_different_account_different_hash() -> None:
    assert hash(_vol(account="111111111111")) != hash(_vol(account="222222222222"))


def test_str_without_qualifier() -> None:
    key = ResourceKey("ebs_volume", "vol-abc123", "eu-central-1", "111111111111")
    assert str(key) == "ebs_volume:111111111111:eu-central-1:vol-abc123"


def test_str_with_qualifier() -> None:
    key = ResourceKey(
        "launch_template_version", "lt-12345", "eu-central-1", "111111111111", qualifier="3"
    )
    assert str(key) == "launch_template_version:111111111111:eu-central-1:lt-12345:3"


def test_qualifier_none_vs_set_are_not_equal() -> None:
    base = ResourceKey("launch_template_version", "lt-12345", "eu-central-1", "111111111111")
    versioned = ResourceKey(
        "launch_template_version", "lt-12345", "eu-central-1", "111111111111", qualifier="1"
    )
    assert base != versioned


def test_same_resource_id_different_regions_are_different() -> None:
    """vol-abc123 in two regions must produce different keys."""
    k1 = ResourceKey("ebs_volume", "vol-abc123", "us-east-1", "111111111111")
    k2 = ResourceKey("ebs_volume", "vol-abc123", "eu-central-1", "111111111111")
    assert k1 != k2
    assert k1 not in {k2}


def test_same_resource_id_different_accounts_are_different() -> None:
    """vol-abc123 in two accounts must produce different keys."""
    k1 = ResourceKey("ebs_volume", "vol-abc123", "eu-central-1", "111111111111")
    k2 = ResourceKey("ebs_volume", "vol-abc123", "eu-central-1", "222222222222")
    assert k1 != k2
    assert k1 not in {k2}
