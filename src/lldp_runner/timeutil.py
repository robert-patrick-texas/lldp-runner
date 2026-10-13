"""Project-wide wall-clock helpers with a configurable timezone policy.

LLDP-Runner persists timezone-aware timestamps and also renders timestamps in
operator-facing logs and summaries.  The effective timezone is process-local,
which matters because discovery workers use multiprocessing ``spawn`` and must
initialize the same policy independently of the coordinator process.
"""

from __future__ import annotations

import time
from datetime import datetime
from datetime import tzinfo
from zoneinfo import ZoneInfo
from zoneinfo import ZoneInfoNotFoundError

_DEFAULT_TIMEZONE = "America/New_York"
_TIMEZONE_ALIASES = {
    "eastern": _DEFAULT_TIMEZONE,
    "utc": "UTC",
    "local": "local",
}
_configured_timezone_name = _DEFAULT_TIMEZONE
_configured_timezone: tzinfo | None = ZoneInfo(_DEFAULT_TIMEZONE)


def normalize_timezone_name(value: str) -> str:
    """Normalize one operator timezone setting to its canonical policy name.

    Args:
        value: Configured timezone.  The convenience aliases ``eastern``, ``utc``,
            and ``local`` are case-insensitive; other values are treated as IANA
            timezone names and preserve their case.

    Returns:
        ``America/New_York`` for ``eastern``, ``UTC`` for ``utc``, ``local`` for
        host-local time, or the supplied IANA timezone name.

    Raises:
        ValueError: If ``value`` is empty or an IANA timezone cannot be loaded.
    """

    text = str(value).strip()
    if not text:
        raise ValueError("time.timezone must be a non-empty timezone name")
    alias = _TIMEZONE_ALIASES.get(text.casefold())
    if alias is not None:
        return alias
    try:
        ZoneInfo(text)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone {text!r}") from exc
    return text


def configure_timezone(value: str) -> str:
    """Set the process-local timezone used by all LLDP-Runner wall-clock helpers.

    Args:
        value: Alias or IANA timezone name accepted by
            :func:`normalize_timezone_name`.

    Returns:
        Canonical configured timezone name.  ``local`` remains a sentinel so each
        timestamp asks the host operating system for its effective local zone.

    Raises:
        ValueError: If the configured timezone is empty or unknown.

    Notes:
        Spawned workers do not inherit module globals.  ``worker_main`` therefore
        calls this function with ``config.time.timezone`` before creating logs or
        observation timestamps.
    """

    global _configured_timezone_name, _configured_timezone
    normalized = normalize_timezone_name(value)
    _configured_timezone_name = normalized
    _configured_timezone = None if normalized == "local" else ZoneInfo(normalized)
    return normalized


def configured_timezone_name() -> str:
    """Return the canonical process-local timezone policy name."""

    return _configured_timezone_name


def datetime_from_timestamp(epoch: float) -> datetime:
    """Convert one epoch to the configured timezone, including host-local mode.

    Args:
        epoch: Unix timestamp in seconds.

    Returns:
        Timezone-aware :class:`datetime` using the configured project policy.
    """

    if _configured_timezone_name == "local":
        return datetime.fromtimestamp(epoch).astimezone()
    assert _configured_timezone is not None
    return datetime.fromtimestamp(epoch, _configured_timezone)


def now() -> datetime:
    """Return the current timezone-aware datetime using the configured policy."""

    return datetime_from_timestamp(time.time())


def iso_now() -> str:
    """Return the current configured-timezone timestamp with millisecond precision."""

    return now().isoformat(timespec="milliseconds")


def human_now() -> str:
    """Return the current wall clock as ``YYYY-mm-dd HH:MM:SS ZONE`` text."""

    return now().strftime("%Y-%m-%d %H:%M:%S %Z")


def format_iso_wall_clock(value: str | None) -> str | None:
    """Render one aware ISO timestamp in the configured timezone to seconds.

    Args:
        value: ISO-8601 timestamp carrying an explicit UTC offset or ``Z``.

    Returns:
        ``YYYY-mm-dd HH:MM:SS`` in the configured timezone, or ``None`` when the
        input is absent, malformed, or timezone-naive. Persisted provenance is
        never guessed from a naive timestamp.
    """

    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return datetime_from_timestamp(parsed.timestamp()).strftime("%Y-%m-%d %H:%M:%S")


def format_epoch(epoch: float) -> str:
    """Format one epoch in the configured timezone with millisecond precision.

    Args:
        epoch: Unix timestamp in seconds.

    Returns:
        ISO-8601 text carrying the effective UTC offset.
    """

    return datetime_from_timestamp(epoch).isoformat(timespec="milliseconds")


def iso_after(seconds: float) -> str:
    """Return an ISO timestamp ``seconds`` after the current epoch.

    Args:
        seconds: Number of seconds to add.  This is epoch-based instead of adding
            a wall-clock timedelta so DST transitions remain correct.

    Returns:
        Future ISO-8601 timestamp in the configured timezone.
    """

    return datetime_from_timestamp(time.time() + seconds).isoformat(timespec="milliseconds")


def datetime_after(seconds: float) -> datetime:
    """Return a configured-timezone datetime ``seconds`` after now.

    This helper is primarily useful to callers that need ``strftime`` rather than
    ISO serialization.  Epoch arithmetic preserves correct local/DST transitions.
    """

    return datetime_from_timestamp(time.time() + seconds)
