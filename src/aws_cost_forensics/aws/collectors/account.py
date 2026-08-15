from __future__ import annotations

from aws_cost_forensics.aws.collectors.base import CollectionError
from aws_cost_forensics.aws.readonly_client import ReadOnlySTSClient


def collect_account_id(sts_client: ReadOnlySTSClient) -> str:
    """Return the AWS account ID for the active credentials. Fatal if this fails."""
    try:
        response = sts_client.get_caller_identity()
        account_id: str = response["Account"]
        return account_id
    except Exception as exc:
        raise CollectionError("account", f"STS GetCallerIdentity failed: {exc}") from exc
