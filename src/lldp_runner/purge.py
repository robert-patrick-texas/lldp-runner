"""Retention cleanup for finalized LLDP-Runner output directories.

``purge`` is intentionally separate from ``clean``: purge touches only finalized
output directories, while clean owns durable/scratch run state. Retention ordering
prefers persisted run timestamps and falls back conservatively to filesystem mtimes.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from lldp_runner.config import AppConfig


@dataclass(frozen=True, slots=True)
class PurgeRun:
    """One finalized output directory with its retention ordering timestamp."""

    run_id: str
    path: Path
    timestamp: float
    timestamp_source: str


@dataclass(frozen=True, slots=True)
class PurgeResult:
    """Finalized-output retention result returned to the CLI renderer."""

    root: Path
    removed: tuple[PurgeRun, ...]
    preserved: tuple[PurgeRun, ...]
    latest_run_id: str | None
    current_run_id: str | None
    keep: int
    dry_run: bool


def _parse_aware_timestamp(value: object) -> float | None:
    """Return an epoch for one timezone-aware ISO value, otherwise ``None``."""

    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.timestamp()


def _read_json_object(path: Path) -> dict[str, object] | None:
    """Best-effort read of one retention metadata document."""

    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _filesystem_fallback(path: Path) -> tuple[float, str]:
    """Use the oldest available mtime among run.json, discovery.json, and directory."""

    candidates: list[tuple[float, str]] = []
    for child_name in ("run.json", "discovery.json"):
        child = path / child_name
        try:
            candidates.append((child.stat().st_mtime, f"mtime:{child_name}"))
        except OSError:
            pass
    try:
        candidates.append((path.stat().st_mtime, "mtime:directory"))
    except OSError:
        pass
    if not candidates:
        return 0.0, "mtime:unavailable"
    return min(candidates, key=lambda item: (item[0], item[1]))


def _retention_timestamp(path: Path) -> tuple[float, str]:
    """Return purge ordering timestamp using the documented provenance chain."""

    run_document = _read_json_object(path / "run.json")
    if run_document is not None:
        for field in ("completed", "ended"):
            parsed = _parse_aware_timestamp(run_document.get(field))
            if parsed is not None:
                return parsed, f"run.json:{field}"

    discovery = _read_json_object(path / "discovery.json")
    if discovery is not None:
        metadata = discovery.get("discovery")
        if isinstance(metadata, dict):
            parsed = _parse_aware_timestamp(metadata.get("completed"))
            if parsed is not None:
                return parsed, "discovery.json:discovery.completed"
            parsed = _parse_aware_timestamp(metadata.get("generated"))
            if parsed is not None:
                return parsed, "discovery.json:discovery.generated"

    return _filesystem_fallback(path)


def _output_directories(output_root: Path) -> list[Path]:
    """Return real finalized output child directories, excluding aliases/files."""

    if not output_root.exists():
        return []
    if not output_root.is_dir():
        raise OSError(f"persistent output path is not a directory: {output_root}")
    result: list[Path] = []
    for entry in output_root.iterdir():
        if entry.name == "latest" or entry.is_symlink():
            continue
        try:
            if entry.is_dir():
                result.append(entry)
        except OSError:
            continue
    return result


def _strict_latest_target(output_root: Path) -> str | None:
    """Resolve a valid in-root latest symlink or reject malformed latest state."""

    latest = output_root / "latest"
    if not latest.exists() and not latest.is_symlink():
        return None
    if not latest.is_symlink():
        raise OSError(f"persistent output latest path is not a symlink: {latest}")
    try:
        raw_target = os.readlink(latest)
        target = Path(raw_target)
        if not target.is_absolute():
            target = output_root / target
        resolved = target.resolve(strict=False)
        root = output_root.resolve(strict=False)
    except OSError as exc:
        raise OSError(f"unable to resolve persistent output latest symlink: {exc}") from exc
    if resolved.parent != root:
        raise OSError(f"persistent output latest points outside output root: {latest}")
    if not resolved.is_dir() or resolved.is_symlink():
        raise OSError(f"persistent output latest target is not a run directory: {resolved}")
    return resolved.name


def _current_target(scratch_root: Path | None) -> str | None:
    """Best-effort resolve an in-root scratch ``current`` run ID."""

    if scratch_root is None:
        return None
    current = scratch_root / "current"
    if not current.is_symlink():
        return None
    try:
        raw_target = os.readlink(current)
        target = Path(raw_target)
        if not target.is_absolute():
            target = scratch_root / target
        resolved = target.resolve(strict=False)
        root = scratch_root.resolve(strict=False)
    except OSError:
        return None
    if resolved.parent != root:
        return None
    return resolved.name


def purge_output_history(
    config: AppConfig,
    *,
    persistent_root: Path,
    scratch_root: Path | None,
    keep: int,
    dry_run: bool = False,
) -> PurgeResult:
    """Remove finalized output directories outside the configured retention set.

    ``keep`` means additional timestamp-ranked directories beyond ``latest``. When
    no latest alias exists, the newest ranked output is retained as the latest
    equivalent so an unattended purge never deletes every available output.
    """

    if isinstance(keep, bool) or not isinstance(keep, int) or keep < 0:
        raise ValueError("purge keep value must be a non-negative integer")

    output_root = persistent_root / config.paths.output_dirname
    directories = _output_directories(output_root)
    latest_run_id = _strict_latest_target(output_root) if output_root.exists() else None
    current_run_id = _current_target(scratch_root)

    ranked = [
        PurgeRun(path.name, path, *_retention_timestamp(path))
        for path in directories
    ]
    ranked.sort(key=lambda item: (item.timestamp, item.run_id), reverse=True)

    protected: set[str] = set()
    effective_latest = latest_run_id
    if effective_latest is not None:
        protected.add(effective_latest)
    elif ranked:
        effective_latest = ranked[0].run_id
        protected.add(effective_latest)

    additional = [item for item in ranked if item.run_id != effective_latest][:keep]
    protected.update(item.run_id for item in additional)
    if current_run_id is not None:
        protected.add(current_run_id)

    removed: list[PurgeRun] = []
    preserved: list[PurgeRun] = []
    for item in ranked:
        if item.run_id in protected:
            preserved.append(item)
            continue
        if not dry_run:
            try:
                shutil.rmtree(item.path)
            except OSError as exc:
                raise OSError(f"unable to purge output directory {item.path}: {exc}") from exc
        removed.append(item)

    return PurgeResult(
        root=output_root,
        removed=tuple(removed),
        preserved=tuple(preserved),
        latest_run_id=latest_run_id,
        current_run_id=current_run_id,
        keep=keep,
        dry_run=dry_run,
    )
