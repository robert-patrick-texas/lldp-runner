"""Multiprocessing-safe logging helpers."""

from __future__ import annotations

import logging
import logging.handlers
import multiprocessing as mp
from pathlib import Path

from lldp_runner.timeutil import datetime_from_timestamp


class ConfiguredTimezoneFormatter(logging.Formatter):
    """Format log records with LLDP-Runner's operator-facing timezone policy.

    Instances are used like :class:`logging.Formatter`; callers supply the normal
    logging format/date format strings, and :meth:`formatTime` converts record
    epochs through the project timezone before the record is emitted.
    """

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        """Render a logging record timestamp in LLDP-Runner's operator timezone.

        Args:
            record: Standard logging record whose creation epoch is formatted.
            datefmt: Optional ``strftime`` format supplied by ``logging``.

        Returns:
            Configured-timezone text using ``datefmt`` when provided, otherwise an ISO
            timestamp with millisecond precision.
        """

        dt = datetime_from_timestamp(record.created)
        if datefmt:
            return dt.strftime(datefmt)
        return dt.isoformat(timespec="milliseconds")


class _ExcludeActivityOnly(logging.Filter):
    """Keep file-only activity records off the console/stderr destination."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not bool(getattr(record, "activity_only", False))


def configure_worker_logging(log_queue: mp.Queue, level: str) -> None:  # type: ignore[type-arg]
    """Route worker-process logging records through the coordinator queue.

    Args:
        log_queue: Multiprocessing queue consumed by the coordinator listener.
        level: Python logging level name such as ``INFO`` or ``DEBUG``.

    Returns:
        ``None``. The worker root logger is replaced with a single QueueHandler so
        child processes never contend directly for console or file destinations.
    """

    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())
    root.addHandler(logging.handlers.QueueHandler(log_queue))


def start_log_listener(
    log_queue: mp.Queue,  # type: ignore[type-arg]
    log_path: Path | None,
    level: str,
    *,
    console: bool,
) -> logging.handlers.QueueListener:
    """Start the coordinator-side listener for enabled logging destinations.

    Args:
        log_queue: Shared queue receiving root/worker logging records.
        log_path: File destination, or ``None`` when ``logging.file=false``.
        level: Logging threshold applied to handlers and the process root logger.
        console: Add a stream handler when true.

    Returns:
        A started :class:`logging.handlers.QueueListener`. Call ``stop()`` during
        coordinator cleanup. With both file and console disabled the listener still
        drains the multiprocessing queue but intentionally publishes no records.

    Raises:
        OSError: If an enabled file destination cannot create/open its path.
    """

    formatter = ConfiguredTimezoneFormatter(
        "%(asctime)s %(levelname)s %(processName)s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %Z",
    )
    handlers: list[logging.Handler] = []
    if log_path is not None:
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            # Append is explicit because centralized log destinations commonly
            # span many discovery runs and are an operator-visible data contract.
            file_handler = logging.FileHandler(
                log_path,
                mode="a",
                encoding="utf-8",
            )
        except OSError as exc:
            raise OSError(
                f"unable to open activity log for append: {log_path}: {exc}"
            ) from exc
        file_handler.setLevel(level.upper())
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level.upper())
        console_handler.setFormatter(formatter)
        console_handler.addFilter(_ExcludeActivityOnly())
        handlers.append(console_handler)
    listener = logging.handlers.QueueListener(log_queue, *handlers, respect_handler_level=True)
    listener.start()
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())
    root.addHandler(logging.handlers.QueueHandler(log_queue))
    return listener
