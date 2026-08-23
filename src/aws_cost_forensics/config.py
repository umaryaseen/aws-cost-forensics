"""AcfConfig — resolved configuration for one acf invocation.

Precedence (highest → lowest):
  1. CLI flags
  2. ACF_PROFILE / ACF_REGION environment variables
  3. ~/.acf/config.toml
  4. Default values
  (region additionally falls through to boto3 configured region in session.py)
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict

_DEFAULT_CONFIG_PATH = Path.home() / ".acf" / "config.toml"


class AcfConfig(BaseModel):
    """Immutable, fully-resolved configuration for one acf invocation."""

    model_config = ConfigDict(frozen=True)

    profile: str | None = None
    region: str | None = None
    stale_volume_days: int = 30
    output_path: Path | None = None
    log_level: str = "WARNING"
    mask_account_id: bool = True
    no_color: bool = False
    pricing_source: str = "static"


def load_config(
    *,
    profile: str | None = None,
    region: str | None = None,
    stale_days: int | None = None,
    output: str | None = None,
    verbose: bool = False,
    no_color: bool = False,
    config_path: Path | None = None,
) -> AcfConfig:
    """Build AcfConfig by merging sources in precedence order."""
    file_cfg = _read_config_file(config_path or _DEFAULT_CONFIG_PATH)

    resolved_profile: str | None = (
        profile or os.environ.get("ACF_PROFILE") or _str(file_cfg.get("profile"))
    )
    resolved_region: str | None = (
        region or os.environ.get("ACF_REGION") or _str(file_cfg.get("region"))
    )
    resolved_stale_days: int = (
        stale_days if stale_days is not None else _int(file_cfg.get("stale_volume_days"), 30)
    )

    return AcfConfig(
        profile=resolved_profile or None,
        region=resolved_region or None,
        stale_volume_days=resolved_stale_days,
        output_path=Path(output) if output else None,
        log_level="DEBUG" if verbose else "WARNING",
        mask_account_id=bool(file_cfg.get("mask_account_id", True)),
        no_color=no_color,
        pricing_source=_str(file_cfg.get("pricing_source")) or "static",
    )


def _read_config_file(path: Path) -> dict[str, object]:
    """Return parsed TOML config or empty dict if file absent or unreadable."""
    if not path.exists():
        return {}
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except Exception:
        return {}


def _str(value: object) -> str | None:
    return str(value) if value is not None else None


def _int(value: object, default: int) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, (str, float)):
        try:
            return int(value)
        except ValueError:
            pass
    return default
