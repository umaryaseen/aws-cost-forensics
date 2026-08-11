from __future__ import annotations

import boto3


class ConfigurationError(Exception):
    """Raised when required configuration (e.g. region) cannot be resolved."""


def create_session(profile: str | None = None) -> boto3.Session:
    return boto3.Session(profile_name=profile)


def resolve_region(session: boto3.Session, cli_region: str | None) -> str:
    """
    Return the effective AWS region. Precedence: cli_region → session.region_name → error.
    Never falls back to us-east-1 implicitly.
    """
    if cli_region:
        return cli_region
    region = session.region_name
    if region:
        return region
    raise ConfigurationError(
        "AWS region could not be determined.\n"
        "Provide it with --region <region>, the ACF_REGION env var,\n"
        "or configure a default region in ~/.aws/config."
    )
