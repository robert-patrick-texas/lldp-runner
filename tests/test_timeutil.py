"""Timezone-policy regression coverage for LLDP-Runner wall-clock helpers."""

from __future__ import annotations

from datetime import datetime

import pytest

from lldp_runner.config import ConfigError, CredentialMode, load_config
from lldp_runner.timeutil import (
    configure_timezone,
    configured_timezone_name,
    datetime_from_timestamp,
    format_iso_wall_clock,
    now,
)


def test_timezone_aliases_and_iana_names_are_supported(tmp_path) -> None:
    """Aliases and IANA names initialize one consistent process-local policy."""

    config_path = tmp_path / "config.toml"
    config_path.write_text('[time]\ntimezone = "utc"\n', encoding="utf-8")
    config = load_config(config_path, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)
    assert config.time.timezone == "utc"
    assert configured_timezone_name() == "UTC"
    assert now().utcoffset().total_seconds() == 0

    config_path.write_text('[time]\ntimezone = "America/Denver"\n', encoding="utf-8")
    load_config(config_path, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)
    assert configured_timezone_name() == "America/Denver"
    summer = datetime_from_timestamp(datetime(2026, 8, 24, 12).timestamp())
    assert summer.tzinfo is not None

    configure_timezone("eastern")
    assert configured_timezone_name() == "America/New_York"


def test_local_timezone_policy_returns_aware_datetimes(tmp_path) -> None:
    """The local policy delegates timezone selection to the underlying host."""

    config_path = tmp_path / "config.toml"
    config_path.write_text('[time]\ntimezone = "local"\n', encoding="utf-8")
    config = load_config(config_path, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)
    assert config.time.timezone == "local"
    assert configured_timezone_name() == "local"
    assert now().tzinfo is not None
    assert now().utcoffset() is not None


def test_invalid_timezone_fails_configuration(tmp_path) -> None:
    """Unknown IANA names fail before a command can begin discovery work."""

    config_path = tmp_path / "config.toml"
    config_path.write_text('[time]\ntimezone = "Mars/Olympus"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown timezone"):
        load_config(config_path, credential_mode=CredentialMode.OPTIONAL, resolve_paths=False)


def test_iso_wall_clock_conversion_requires_timestamp_provenance() -> None:
    """Aware ISO values convert by instant; missing/naive/malformed values do not."""

    configure_timezone("America/Denver")
    assert format_iso_wall_clock("2026-08-25T21:52:26+00:00") == ("2026-08-25 15:52:26")
    assert format_iso_wall_clock("2026-08-25T15:52:26") is None
    assert format_iso_wall_clock("not-a-time") is None
    assert format_iso_wall_clock(None) is None
