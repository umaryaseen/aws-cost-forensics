"""Tests for AcfConfig and load_config."""

from __future__ import annotations

from pathlib import Path

import pytest

from aws_cost_forensics.config import _read_config_file, load_config

# ---------------------------------------------------------------------------
# load_config — default values
# ---------------------------------------------------------------------------


def test_defaults_when_no_overrides(tmp_path: Path) -> None:
    cfg = load_config(config_path=tmp_path / "missing.toml")
    assert cfg.profile is None
    assert cfg.region is None
    assert cfg.stale_volume_days == 30
    assert cfg.output_path is None
    assert cfg.log_level == "WARNING"
    assert cfg.mask_account_id is True
    assert cfg.no_color is False
    assert cfg.pricing_source == "static"


# ---------------------------------------------------------------------------
# load_config — CLI flags override everything
# ---------------------------------------------------------------------------


def test_cli_profile_overrides_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACF_PROFILE", "env-profile")
    cfg = load_config(profile="cli-profile", config_path=tmp_path / "missing.toml")
    assert cfg.profile == "cli-profile"


def test_cli_region_overrides_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACF_REGION", "us-west-2")
    cfg = load_config(region="eu-central-1", config_path=tmp_path / "missing.toml")
    assert cfg.region == "eu-central-1"


def test_cli_stale_days_overrides_file(tmp_path: Path) -> None:
    toml = tmp_path / "config.toml"
    toml.write_text("stale_volume_days = 90\n")
    cfg = load_config(stale_days=7, config_path=toml)
    assert cfg.stale_volume_days == 7


def test_verbose_sets_debug_log_level(tmp_path: Path) -> None:
    cfg = load_config(verbose=True, config_path=tmp_path / "missing.toml")
    assert cfg.log_level == "DEBUG"


def test_no_verbose_sets_warning_log_level(tmp_path: Path) -> None:
    cfg = load_config(verbose=False, config_path=tmp_path / "missing.toml")
    assert cfg.log_level == "WARNING"


def test_no_color_flag_propagates(tmp_path: Path) -> None:
    cfg = load_config(no_color=True, config_path=tmp_path / "missing.toml")
    assert cfg.no_color is True


def test_output_path_parsed(tmp_path: Path) -> None:
    cfg = load_config(output=str(tmp_path / "out.json"), config_path=tmp_path / "missing.toml")
    assert cfg.output_path == tmp_path / "out.json"


# ---------------------------------------------------------------------------
# load_config — env var precedence (below CLI, above file)
# ---------------------------------------------------------------------------


def test_env_profile_used_when_no_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACF_PROFILE", "env-profile")
    cfg = load_config(config_path=tmp_path / "missing.toml")
    assert cfg.profile == "env-profile"


def test_env_region_used_when_no_cli(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACF_REGION", "ap-southeast-1")
    cfg = load_config(config_path=tmp_path / "missing.toml")
    assert cfg.region == "ap-southeast-1"


def test_env_overrides_file_for_profile(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACF_PROFILE", "env-profile")
    toml = tmp_path / "config.toml"
    toml.write_text('profile = "file-profile"\n')
    cfg = load_config(config_path=toml)
    assert cfg.profile == "env-profile"


def test_env_overrides_file_for_region(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("ACF_REGION", "ca-central-1")
    toml = tmp_path / "config.toml"
    toml.write_text('region = "eu-west-1"\n')
    cfg = load_config(config_path=toml)
    assert cfg.region == "ca-central-1"


# ---------------------------------------------------------------------------
# load_config — config file (lowest explicit source)
# ---------------------------------------------------------------------------


def test_file_profile_used_when_no_cli_or_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ACF_PROFILE", raising=False)
    toml = tmp_path / "config.toml"
    toml.write_text('profile = "file-profile"\n')
    cfg = load_config(config_path=toml)
    assert cfg.profile == "file-profile"


def test_file_region_used_when_no_cli_or_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ACF_REGION", raising=False)
    toml = tmp_path / "config.toml"
    toml.write_text('region = "eu-north-1"\n')
    cfg = load_config(config_path=toml)
    assert cfg.region == "eu-north-1"


def test_file_stale_days_used(tmp_path: Path) -> None:
    toml = tmp_path / "config.toml"
    toml.write_text("stale_volume_days = 60\n")
    cfg = load_config(config_path=toml)
    assert cfg.stale_volume_days == 60


def test_file_mask_account_id_false(tmp_path: Path) -> None:
    toml = tmp_path / "config.toml"
    toml.write_text("mask_account_id = false\n")
    cfg = load_config(config_path=toml)
    assert cfg.mask_account_id is False


def test_file_pricing_source(tmp_path: Path) -> None:
    toml = tmp_path / "config.toml"
    toml.write_text('pricing_source = "live"\n')
    cfg = load_config(config_path=toml)
    assert cfg.pricing_source == "live"


# ---------------------------------------------------------------------------
# _read_config_file — graceful error handling
# ---------------------------------------------------------------------------


def test_missing_config_file_returns_empty(tmp_path: Path) -> None:
    result = _read_config_file(tmp_path / "does_not_exist.toml")
    assert result == {}


def test_invalid_toml_returns_empty(tmp_path: Path) -> None:
    bad = tmp_path / "bad.toml"
    bad.write_text("this is not valid toml ][[\n")
    result = _read_config_file(bad)
    assert result == {}


def test_empty_toml_returns_empty(tmp_path: Path) -> None:
    empty = tmp_path / "empty.toml"
    empty.write_text("")
    result = _read_config_file(empty)
    assert result == {}


# ---------------------------------------------------------------------------
# AcfConfig — immutability
# ---------------------------------------------------------------------------


def test_acfconfig_is_frozen(tmp_path: Path) -> None:
    from pydantic import ValidationError

    cfg = load_config(config_path=tmp_path / "missing.toml")
    with pytest.raises(ValidationError):
        cfg.region = "mutated"  # type: ignore[misc]
