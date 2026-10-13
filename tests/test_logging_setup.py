from __future__ import annotations

import logging
import multiprocessing as mp
from pathlib import Path

import pytest

from lldp_runner.logging_setup import start_log_listener


def _restore_root_logger(handlers: list[logging.Handler], level: int) -> None:
    """Restore root logging after a listener test mutates process-global handlers."""

    root = logging.getLogger()
    root.handlers.clear()
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)


def test_log_listener_appends_to_enabled_file_destination(tmp_path: Path) -> None:
    """File logging creates parents and preserves records from earlier runs."""

    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    queue = mp.get_context("spawn").Queue()
    log_path = tmp_path / "central" / "lldprunner.log"
    log_path.parent.mkdir(parents=True)
    log_path.write_text("prior run sentinel\n", encoding="utf-8")

    listener = start_log_listener(queue, log_path, "INFO", console=False)
    try:
        logging.getLogger("lldp_runner.test").info("file logging works")
        listener.stop()
    finally:
        _restore_root_logger(previous_handlers, previous_level)
        queue.close()
        queue.join_thread()

    text = log_path.read_text(encoding="utf-8")
    assert text.startswith("prior run sentinel\n")
    assert "INFO MainProcess lldp_runner.test: file logging works" in text


def test_log_listener_reports_append_open_failure(tmp_path: Path) -> None:
    """An unusable activity-log pathname fails with operator-facing context."""

    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    queue = mp.get_context("spawn").Queue()
    log_path = tmp_path / "lldprunner.log"
    log_path.mkdir()
    try:
        with pytest.raises(OSError, match="unable to open activity log for append") as exc:
            start_log_listener(queue, log_path, "INFO", console=False)
        assert str(log_path) in str(exc.value)
    finally:
        _restore_root_logger(previous_handlers, previous_level)
        queue.close()
        queue.join_thread()


def test_log_listener_accepts_no_destinations(tmp_path: Path) -> None:
    """With file and console disabled the queue is drained without creating a file."""

    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    queue = mp.get_context("spawn").Queue()
    listener = start_log_listener(queue, None, "INFO", console=False)
    try:
        logging.getLogger("lldp_runner.test").info("intentionally discarded")
        listener.stop()
    finally:
        _restore_root_logger(previous_handlers, previous_level)
        queue.close()
        queue.join_thread()

    assert list(tmp_path.iterdir()) == []


def test_log_listener_can_write_console_without_file(capsys) -> None:
    """Console-only logging remains available when activity.log is disabled."""

    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    queue = mp.get_context("spawn").Queue()
    listener = start_log_listener(queue, None, "INFO", console=True)
    try:
        logging.getLogger("lldp_runner.test").info("console logging works")
        listener.stop()
    finally:
        _restore_root_logger(previous_handlers, previous_level)
        queue.close()
        queue.join_thread()

    assert "lldp_runner.test: console logging works" in capsys.readouterr().err


def test_log_formatter_uses_configured_timezone_policy() -> None:
    """Log record epochs follow the same timezone policy as discovery timestamps."""

    from lldp_runner.logging_setup import ConfiguredTimezoneFormatter
    from lldp_runner.timeutil import configure_timezone

    record = logging.LogRecord(
        name="lldp_runner.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="timezone test",
        args=(),
        exc_info=None,
    )
    # 2026-08-25 01:00:00 UTC. Using a fixed epoch avoids depending on the
    # sandbox's local timezone while proving formatter conversion is configured.
    record.created = 1787619600.0
    formatter = ConfiguredTimezoneFormatter(datefmt="%Y-%m-%d %H:%M:%S %Z")
    try:
        configure_timezone("utc")
        assert formatter.formatTime(record, formatter.datefmt).endswith("UTC")
        configure_timezone("America/Denver")
        assert formatter.formatTime(record, formatter.datefmt).endswith("MDT")
    finally:
        configure_timezone("eastern")


def test_activity_only_records_are_file_logged_but_not_written_to_stderr(
    tmp_path: Path, capsys
) -> None:
    """Seed-credential match warnings stay in activity.log even with console logging."""

    root = logging.getLogger()
    previous_handlers = list(root.handlers)
    previous_level = root.level
    queue = mp.get_context("spawn").Queue()
    log_path = tmp_path / "activity.log"
    listener = start_log_listener(queue, log_path, "INFO", console=True)
    try:
        logging.getLogger("lldp_runner.test").warning(
            "activity only warning", extra={"activity_only": True}
        )
        listener.stop()
    finally:
        _restore_root_logger(previous_handlers, previous_level)
        queue.close()
        queue.join_thread()

    assert "activity only warning" in log_path.read_text(encoding="utf-8")
    assert "activity only warning" not in capsys.readouterr().err


def test_snmp_message_contract_places_target_after_standard_prefix() -> None:
    """SNMP target stays at one parseable position in file and console records."""

    from lldp_runner.logging_setup import ConfiguredTimezoneFormatter

    record = logging.LogRecord(
        name="lldp_runner.worker",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=(
            "SNMP target=198.51.100.252 neighbor collector transient failure "
            "retry operation=cdp category=timeout attempt=2"
        ),
        args=(),
        exc_info=None,
    )
    record.processName = "lldp-worker-12"
    formatter = ConfiguredTimezoneFormatter(
        "%(asctime)s %(levelname)s %(processName)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %Z",
    )

    rendered = formatter.format(record)

    assert (
        "INFO lldp-worker-12 lldp_runner.worker: SNMP target=198.51.100.252 "
        "neighbor collector transient failure retry operation=cdp "
        "category=timeout attempt=2"
    ) in rendered
