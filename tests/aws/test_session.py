from __future__ import annotations

from unittest.mock import MagicMock

import boto3
import pytest

from aws_cost_forensics.aws.session import ConfigurationError, create_session, resolve_region


def _session(region: str | None) -> MagicMock:
    s = MagicMock(spec=boto3.Session)
    s.region_name = region
    return s


def test_resolve_region_uses_cli_arg() -> None:
    assert resolve_region(_session("eu-central-1"), "us-west-2") == "us-west-2"


def test_resolve_region_prefers_cli_over_session() -> None:
    assert resolve_region(_session("eu-central-1"), "ap-southeast-1") == "ap-southeast-1"


def test_resolve_region_falls_back_to_session_when_no_cli() -> None:
    assert resolve_region(_session("eu-central-1"), None) == "eu-central-1"


def test_resolve_region_raises_when_no_region() -> None:
    with pytest.raises(ConfigurationError):
        resolve_region(_session(None), None)


def test_resolve_region_error_message_mentions_region_flag() -> None:
    with pytest.raises(ConfigurationError, match="--region"):
        resolve_region(_session(None), None)


def test_resolve_region_error_message_mentions_env_var() -> None:
    with pytest.raises(ConfigurationError, match="ACF_REGION"):
        resolve_region(_session(None), None)


def test_resolve_region_no_implicit_us_east_1_fallback() -> None:
    with pytest.raises(ConfigurationError):
        resolve_region(_session(None), None)


def test_create_session_returns_boto3_session() -> None:
    session = create_session()
    assert isinstance(session, boto3.Session)
