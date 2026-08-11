from __future__ import annotations

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.base import CollectionError, is_permission_error, paginate


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "Denied"}}, "DescribeVolumes")


# ── is_permission_error ───────────────────────────────────────────────────────


def test_access_denied_is_permission_error() -> None:
    assert is_permission_error(_client_error("AccessDenied")) is True


def test_access_denied_exception_is_permission_error() -> None:
    assert is_permission_error(_client_error("AccessDeniedException")) is True


def test_unauthorized_operation_is_permission_error() -> None:
    assert is_permission_error(_client_error("UnauthorizedOperation")) is True


def test_auth_failure_is_permission_error() -> None:
    assert is_permission_error(_client_error("AuthFailure")) is True


def test_other_client_error_is_not_permission_error() -> None:
    assert is_permission_error(_client_error("NoSuchEntity")) is False


def test_non_client_error_is_not_permission_error() -> None:
    assert is_permission_error(ValueError("not a client error")) is False


def test_generic_exception_is_not_permission_error() -> None:
    assert is_permission_error(Exception("random")) is False


# ── paginate ──────────────────────────────────────────────────────────────────


def _mock_client(*pages: dict) -> MagicMock:
    paginator = MagicMock()
    paginator.paginate.return_value = list(pages)
    client = MagicMock()
    client.get_paginator.return_value = paginator
    return client


def test_paginate_yields_items_across_pages() -> None:
    client = _mock_client(
        {"Volumes": [{"VolumeId": "vol-1"}, {"VolumeId": "vol-2"}]},
        {"Volumes": [{"VolumeId": "vol-3"}]},
    )
    result = list(paginate(client, "describe_volumes", "Volumes"))
    assert result == [{"VolumeId": "vol-1"}, {"VolumeId": "vol-2"}, {"VolumeId": "vol-3"}]


def test_paginate_calls_get_paginator_with_operation() -> None:
    client = _mock_client({"Volumes": []})
    list(paginate(client, "describe_volumes", "Volumes"))
    client.get_paginator.assert_called_once_with("describe_volumes")


def test_paginate_passes_kwargs_to_paginator() -> None:
    client = _mock_client({"Volumes": []})
    filters = [{"Name": "status", "Values": ["available"]}]
    list(paginate(client, "describe_volumes", "Volumes", Filters=filters))
    paginator = client.get_paginator.return_value
    paginator.paginate.assert_called_once_with(Filters=filters)


def test_paginate_empty_page_yields_nothing() -> None:
    client = _mock_client({"Volumes": []})
    assert list(paginate(client, "describe_volumes", "Volumes")) == []


def test_paginate_missing_result_key_yields_nothing() -> None:
    client = _mock_client({"OtherKey": [{"id": "x"}]})
    assert list(paginate(client, "describe_volumes", "Volumes")) == []


# ── CollectionError ───────────────────────────────────────────────────────────


def test_collection_error_stores_collector_and_message() -> None:
    err = CollectionError("ebs", "failed to collect volumes")
    assert err.collector == "ebs"
    assert str(err) == "failed to collect volumes"


def test_collection_error_permission_flag_true() -> None:
    err = CollectionError("snapshots", "denied", is_permission_error=True)
    assert err.is_permission_error is True


def test_collection_error_permission_flag_default_false() -> None:
    err = CollectionError("amis", "timeout")
    assert err.is_permission_error is False
