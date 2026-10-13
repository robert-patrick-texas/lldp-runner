"""Conservative cleanup of historical LLDP-Runner run artifacts.

The persistent and scratch trees have deliberately different layouts. Durable
state lives below ``<persistent_root>/<runs_dirname>/<run-id>`` while scratch
run directories live directly below ``<scratch_root>`` and are selected by the
``current`` symlink. Cleanup follows those existing runtime layouts rather than
inventing a second scratch ``runs`` namespace.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from lldp_runner.config import AppConfig
from lldp_runner.outputs import OUTPUT_NAMES
from lldp_runner.scoreboard import SCOREBOARD_DIRECTORY_NAME


@dataclass(frozen=True, slots=True)
class CleanAreaResult:
    """Result for one cleanup area.

    Attributes:
        label: Operator-facing area name.
        root: Directory inspected for historical run entries.
        removed: Entry names removed from ``root``.
        preserved: Entry names deliberately retained in ``root``.
    """

    label: str
    root: Path
    removed: tuple[str, ...]
    preserved: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CleanResult:
    """Combined cleanup result returned to the CLI renderer."""

    areas: tuple[CleanAreaResult, ...]

    @property
    def removed_count(self) -> int:
        """Return the number of top-level LLDP-Runner artifacts removed."""

        return sum(len(area.removed) for area in self.areas)


def _alias_target_name(alias: Path, *, expected_parent: Path) -> str | None:
    """Return an in-tree symlink target basename without following outside paths.

    ``current`` and ``latest`` are operator-significant aliases. Their target run
    IDs should be preserved when the target belongs to the expected LLDP-Runner
    namespace. A malformed or external symlink is itself left untouched but does
    not grant protection to an unrelated pathname.
    """

    if not alias.is_symlink():
        return None
    try:
        raw_target = os.readlink(alias)
        target = Path(raw_target)
        if not target.is_absolute():
            target = alias.parent / target
        resolved_target = target.resolve(strict=False)
        resolved_parent = expected_parent.resolve(strict=False)
    except OSError:
        return None
    if resolved_target.parent != resolved_parent:
        return None
    return resolved_target.name


def _entry_mtime_ns(path: Path) -> int:
    """Return one entry's lstat modification time, sorting unreadable entries last."""

    try:
        return path.lstat().st_mtime_ns
    except OSError:
        return -1


def _newest_directory_name(entries: Iterable[Path]) -> str | None:
    """Return the newest real directory name using mtime then name as tie-breaker."""

    directories: list[Path] = []
    for entry in entries:
        try:
            if entry.is_dir() and not entry.is_symlink():
                directories.append(entry)
        except OSError:
            continue
    if not directories:
        return None
    newest = max(directories, key=lambda item: (_entry_mtime_ns(item), item.name))
    return newest.name


def _remove_entry(path: Path) -> None:
    """Remove one top-level run artifact without following symlinks."""

    if path.is_symlink() or not path.is_dir():
        path.unlink()
        return
    shutil.rmtree(path)


def _persistent_area(
    config: AppConfig,
    *,
    persistent_root: Path,
    active_run_id: str | None,
    dry_run: bool,
) -> CleanAreaResult:
    """Remove old durable run-state entries while retaining newest/latest/current."""

    runs_root = persistent_root / config.paths.runs_dirname
    if not runs_root.exists():
        return CleanAreaResult("persistent", runs_root, (), ())
    if not runs_root.is_dir():
        raise OSError(f"persistent runs path is not a directory: {runs_root}")

    entries = list(runs_root.iterdir())
    protected: set[str] = {"current", "latest"}

    newest = _newest_directory_name(entries)
    if newest is not None:
        protected.add(newest)

    run_latest_id = _alias_target_name(
        runs_root / "latest",
        expected_parent=runs_root,
    )
    if run_latest_id is not None:
        protected.add(run_latest_id)

    # Finalized output is outside runs/, but keeping the matching state directory
    # makes the durable latest output and its run history remain coherent.
    output_root = persistent_root / config.paths.output_dirname
    latest_run_id = _alias_target_name(output_root / "latest", expected_parent=output_root)
    if latest_run_id is not None:
        protected.add(latest_run_id)
    if active_run_id is not None:
        protected.add(active_run_id)

    removed: list[str] = []
    preserved: list[str] = []
    for entry in sorted(entries, key=lambda item: item.name):
        if entry.name in protected:
            preserved.append(entry.name)
            continue
        if not dry_run:
            try:
                _remove_entry(entry)
            except OSError as exc:
                raise OSError(f"unable to remove persistent run artifact {entry}: {exc}") from exc
        removed.append(entry.name)

    return CleanAreaResult(
        "persistent",
        runs_root,
        tuple(removed),
        tuple(sorted(preserved)),
    )


def _looks_like_scratch_run(path: Path, config: AppConfig, *, known_run_ids: set[str]) -> bool:
    """Return whether one scratch child is recognizable as LLDP-Runner run state.

    Scratch roots may be operator-selected paths, so cleanup must never assume
    every child belongs to LLDP-Runner. Historical directories are eligible when
    their run ID is known from durable/output state or they contain LLDP-Runner's
    distinctive scratch artifacts. This intentionally favors leaving an unknown
    directory behind over deleting unrelated operator data.
    """

    if path.name in known_run_ids:
        return True
    try:
        if not path.is_dir() or path.is_symlink():
            return False
    except OSError:
        return False

    marker_names = {
        "scoreboard.json",
        "scoreboard.txt",
        "run.json",
        "run.json.draft",
        config.resume.pause_indicator,
        *OUTPUT_NAMES,
    }
    return any((path / name).exists() for name in marker_names)


def _known_run_ids(config: AppConfig, *, persistent_root: Path | None) -> set[str]:
    """Collect durable/output run IDs used to recognize scratch run directories."""

    if persistent_root is None:
        return set()

    names: set[str] = set()
    for root in (
        persistent_root / config.paths.runs_dirname,
        persistent_root / config.paths.output_dirname,
    ):
        if not root.exists() or not root.is_dir():
            continue
        for entry in root.iterdir():
            if entry.name == "latest":
                continue
            try:
                if entry.is_dir() and not entry.is_symlink():
                    names.add(entry.name)
            except OSError:
                continue
    return names


def _scratch_area(
    config: AppConfig,
    *,
    scratch_root: Path,
    persistent_root: Path | None,
    dry_run: bool,
) -> tuple[CleanAreaResult, str | None]:
    """Remove the live scoreboard and recognized historical scratch runs.

    Run directories retain the current/newest protections described below. The
    dedicated ``scoreboard`` directory is an explicitly owned transient
    publication area, so ``clean`` removes it independently rather than allowing
    newest-run heuristics to preserve it.
    """

    if not scratch_root.exists():
        return CleanAreaResult("scratch", scratch_root, (), ()), None
    if not scratch_root.is_dir():
        raise OSError(f"scratch root is not a directory: {scratch_root}")

    current = scratch_root / "current"
    current_run_id = _alias_target_name(current, expected_parent=scratch_root)
    known_run_ids = _known_run_ids(config, persistent_root=persistent_root)
    latest_run_ids: set[str] = set()
    if persistent_root is not None:
        output_root = persistent_root / config.paths.output_dirname
        output_latest_run_id = _alias_target_name(
            output_root / "latest", expected_parent=output_root
        )
        runs_root = persistent_root / config.paths.runs_dirname
        run_latest_run_id = _alias_target_name(runs_root / "latest", expected_parent=runs_root)
        latest_run_ids.update(
            run_id for run_id in (output_latest_run_id, run_latest_run_id) if run_id is not None
        )
    if current_run_id is not None:
        known_run_ids.add(current_run_id)
    known_run_ids.update(latest_run_ids)

    entries = list(scratch_root.iterdir())
    scoreboard = scratch_root / SCOREBOARD_DIRECTORY_NAME
    candidates = [
        entry
        for entry in entries
        if entry.name not in {"current", "latest", SCOREBOARD_DIRECTORY_NAME}
        and _looks_like_scratch_run(entry, config, known_run_ids=known_run_ids)
    ]

    protected: set[str] = {"current", "latest"}
    newest = _newest_directory_name(candidates)
    if newest is not None:
        protected.add(newest)
    if current_run_id is not None:
        protected.add(current_run_id)
    protected.update(latest_run_ids)

    removed: list[str] = []
    preserved: list[str] = []
    if scoreboard.exists() or scoreboard.is_symlink():
        if not dry_run:
            try:
                _remove_entry(scoreboard)
            except OSError as exc:
                raise OSError(
                    f"unable to remove live scoreboard artifact {scoreboard}: {exc}"
                ) from exc
        removed.append(SCOREBOARD_DIRECTORY_NAME)

    for entry in sorted(candidates, key=lambda item: item.name):
        if entry.name in protected:
            preserved.append(entry.name)
            continue
        if not dry_run:
            try:
                _remove_entry(entry)
            except OSError as exc:
                raise OSError(f"unable to remove scratch run artifact {entry}: {exc}") from exc
        removed.append(entry.name)

    # Alias names are not candidates for deletion, but mention an existing one in
    # the result so operator output makes it explicit that current was preserved.
    if current.exists() or current.is_symlink():
        preserved.append("current")

    return (
        CleanAreaResult(
            "scratch",
            scratch_root,
            tuple(removed),
            tuple(sorted(set(preserved))),
        ),
        current_run_id,
    )


def clean_run_history(
    config: AppConfig,
    *,
    persistent_root: Path | None,
    scratch_root: Path,
    scratch_only: bool,
    dry_run: bool = False,
) -> CleanResult:
    """Clean historical run artifacts according to the requested command scope.

    Args:
        config: Effective credential-disabled configuration.
        persistent_root: Resolved persistent root, or ``None`` for scratch-only.
        scratch_root: Resolved scratch root used by discovery/current scoreboard.
        scratch_only: When true, do not inspect or modify persistent run state.
        dry_run: Report eligible removals without deleting any filesystem entry.

    Returns:
        ``CleanResult`` describing top-level entries removed/preserved.

    Notes:
        The scratch area is processed first so the current run ID can also protect
        its durable state directory during an all-area cleanup. Both areas always
        retain their newest recognizable run directory in addition to aliases.
    """

    scratch_result, current_run_id = _scratch_area(
        config,
        scratch_root=scratch_root,
        persistent_root=persistent_root,
        dry_run=dry_run,
    )
    if scratch_only:
        return CleanResult((scratch_result,))

    if persistent_root is None:
        raise ValueError("persistent_root is required for all-area cleanup")
    persistent_result = _persistent_area(
        config,
        persistent_root=persistent_root,
        active_run_id=current_run_id,
        dry_run=dry_run,
    )
    return CleanResult((persistent_result, scratch_result))
