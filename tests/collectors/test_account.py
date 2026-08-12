from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from aws_cost_forensics.aws.collectors.account import collect_account_id
from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.readonly_client import ReadOnlySTSClient


def _sts(account_id: str) -> ReadOnlySTSClient:
    raw = MagicMock()
    raw.get_caller_identity.return_value = {
        "Account": account_id,
        "UserId": "u",
        "Arn": "arn:aws:sts::x:x",
    }
    return ReadOnlySTSClient(raw)


def test_collect_account_id_returns_account() -> None:
    assert collect_account_id(_sts("123456789012")) == "123456789012"


def test_collect_account_id_different_account() -> None:
    assert collect_account_id(_sts("999888777666")) == "999888777666"


def test_collect_account_id_raises_collection_error_on_failure() -> None:
    error = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "Denied"}}, "GetCallerIdentity"
    )
    raw = MagicMock()
    raw.get_caller_identity.side_effect = error
    client = ReadOnlySTSClient(raw)

    with pytest.raises(CollectionError) as exc_info:
        collect_account_id(client)
    assert exc_info.value.collector == "account"


def test_collect_account_id_raises_on_generic_error() -> None:
    raw = MagicMock()
    raw.get_caller_identity.side_effect = RuntimeError("network error")
    client = ReadOnlySTSClient(raw)

    with pytest.raises(CollectionError):
        collect_account_id(client)
