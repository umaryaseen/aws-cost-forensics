from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from botocore.exceptions import ClientError


class CollectionError(Exception):
    def __init__(self, collector: str, message: str, *, is_permission_error: bool = False) -> None:
        super().__init__(message)
        self.collector = collector
        self.is_permission_error = is_permission_error


def is_permission_error(error: Exception) -> bool:
    """Return True when a botocore ClientError indicates an IAM permissions denial."""
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        return code in {
            "AccessDenied",
            "AccessDeniedException",
            "AuthFailure",
            "UnauthorizedOperation",
        }
    return False


def paginate(
    client: Any,
    operation: str,
    result_key: str,
    **kwargs: Any,
) -> Iterator[dict[str, Any]]:
    """Yield individual items from a paginated boto3 API call."""
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(result_key, [])
