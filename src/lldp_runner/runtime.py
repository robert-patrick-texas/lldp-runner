"""Run directory layout, resume discovery, and storage-preflight helpers."""

from __future__ import annotations

import os
import shutil
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from lldp_runner.config import AppConfig
from lldp_runner.runid import (
    compile_run_id_template,
    next_counter,
    render_run_id,
    validate_run_id_component,
)
from lldp_runner.scoreboard import (
    SCOREBOARD_DIRECTORY_NAME,
    current_scoreboard_directory,
)
from lldp_runner.timeutil import now


@dataclass(slots=True)
class RunPaths:
    """Filesystem locations associated with one logical discovery run.

    ``activity_log`` is ``None`` when file logging is disabled. All other paths
    are run-state or output locations required regardless of logging destination.
    """

    run_id: str
    run_dir: Path
    state_path: Path
    activity_log: Path | None
    scratch_dir: Path
    scoreboard_dir: Path
    output_root: Path
    output_run_dir: Path
    latest_link: Path
    run_latest_link: Path
    is_new: bool = False


def canonical_operator_path(path: Path) -> Path:
    """Resolve retained storage symlinks before displaying a runtime path.

    Earlier installations may retain ``output -> outputs`` while current
    configuration and bundle tooling use ``outputs`` directly.  Filesystem access
    through either spelling is valid, but operator logs and machine summaries
    should consistently name the effective canonical destination.
    """

    return path.resolve(strict=False)


def _existing_run_associated_names(config: AppConfig) -> set[str]:
    """Return existing run-associated entry names used for collision detection.

    Args:
        config: Runtime configuration with resolved persistent and scratch roots.

    Returns:
        Union of child names beneath the persistent runs directory, persistent
        output directory, and scratch root.  Looking across all three avoids
        reusing an ID when one run artifact was retained while another was
        manually removed.
    """

    roots = (
        config.paths.persistent_root / config.paths.runs_dirname,
        config.paths.persistent_root / config.paths.output_dirname,
        config.paths.scratch_root,
    )
    names: set[str] = set()
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            names.update(entry.name for entry in root.iterdir())
        except OSError as exc:
            raise OSError(f"unable to inspect existing run IDs under {root}: {exc}") from exc
    return names


_RESERVED_SCRATCH_ENTRY_NAMES = frozenset({"current", SCOREBOARD_DIRECTORY_NAME})


def _validate_runtime_run_id(run_id: str) -> str:
    """Reject safe-looking run IDs that collide with reserved scratch entries."""

    validated = validate_run_id_component(run_id)
    if validated in _RESERVED_SCRATCH_ENTRY_NAMES:
        raise ValueError(f"run ID uses reserved scratch name: {validated}")
    return validated


def allocate_run_id(config: AppConfig) -> str:
    """Allocate one new run ID using configured time formatting and stateless count.

    Args:
        config: Effective runtime configuration. ``paths.run_id_format`` may use
            supported strftime directives and one optional ``{counter}`` token.

    Returns:
        Safe new run-ID component. Counter formats use the highest matching
        existing numeric counter plus one, rendered as ``00`` through ``99``.

    Raises:
        OSError: If existing run-associated directories cannot be inspected.
        ValueError: If the format is invalid, a timestamp-only ID collides, or a
            counter namespace is exhausted past ``99``.

    Notes:
        The counter is intentionally stateless: no SQLite metadata or sequence
        file is consulted. Timestamp directives are expanded first, so formats
        such as ``%y%m%d-{counter}`` naturally start a new namespace each day.
    """

    template = compile_run_id_template(config.paths.run_id_format, now())
    existing = _existing_run_associated_names(config)
    if template.uses_counter:
        candidate = render_run_id(template, next_counter(template, existing))
        return _validate_runtime_run_id(candidate)

    candidate = _validate_runtime_run_id(render_run_id(template))
    if candidate in existing:
        raise ValueError(
            f"run ID already exists: {candidate}; check paths.runs_dirname and "
            "paths.run_id_format to prevent collision; consider adding {counter} "
            "or using a higher-precision timestamp such as %f"
        )
    return candidate


def make_run_paths(config: AppConfig, run_id: str | None = None) -> RunPaths:
    """Resolve persistent, scratch, output, and optional log paths for a run.

    Args:
        config: Effective configuration with runtime path roots already resolved.
        run_id: Existing run identifier when resuming, or ``None`` to allocate a
            fresh identifier from ``paths.run_id_format``.

    Returns:
        A :class:`RunPaths` instance. Relative ``logging.filename`` values are
        rooted beneath ``runs/<run-id>/``; absolute or ``~``-expanded paths are
        used as centralized log destinations. ``activity_log`` is ``None`` when
        ``logging.file`` is false.
    """

    is_new = run_id is None
    run_id = allocate_run_id(config) if run_id is None else _validate_runtime_run_id(run_id)
    persistent = config.paths.persistent_root
    scratch = config.paths.scratch_root
    run_dir = persistent / config.paths.runs_dirname / run_id
    output_root = persistent / config.paths.output_dirname
    activity_log: Path | None = None
    if config.logging.file:
        configured_log = Path(config.logging.filename).expanduser()
        activity_log = (
            configured_log.resolve()
            if configured_log.is_absolute()
            else (run_dir / configured_log).resolve()
        )
    return RunPaths(
        run_id=run_id,
        run_dir=run_dir,
        state_path=run_dir / "discovery-state.sqlite",
        activity_log=activity_log,
        scratch_dir=scratch / run_id,
        scoreboard_dir=current_scoreboard_directory(scratch),
        output_root=output_root,
        output_run_dir=output_root / run_id,
        latest_link=output_root / "latest",
        run_latest_link=run_dir.parent / "latest",
        is_new=is_new,
    )


def _preflight_atomic_file_output(directory: Path, *, label: str) -> None:
    """Prove one directory supports LLDP-Runner's atomic file-write pattern.

    Args:
        directory: Existing directory that will receive runtime/output files.
        label: Operator-facing description included in any failure message.

    Returns:
        ``None`` after creating, fsyncing, atomically renaming, and deleting a
        short probe file in ``directory``.

    Raises:
        OSError: If create/write/fsync/rename/delete fails. The original error is
        retained as the exception cause while the message identifies the output
        location that would otherwise fail later in discovery.
    """

    token = uuid.uuid4().hex
    temporary = directory / f".lldp-runner-preflight-{token}.tmp"
    published = directory / f".lldp-runner-preflight-{token}.ready"
    try:
        with temporary.open("xb") as handle:
            handle.write(b"lldp-runner storage preflight\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, published)
        published.unlink()
    except OSError as exc:
        # Cleanup is best-effort only on the error path. Preserve the actual
        # storage failure instead of obscuring it with a secondary unlink error.
        for probe in (temporary, published):
            try:
                probe.unlink(missing_ok=True)
            except OSError:
                pass
        raise OSError(
            f"{label} cannot support atomic file output: {directory}: {exc}"
        ) from exc


def _preflight_latest_symlink(
    latest_link: Path,
    target_directory: Path,
    *,
    label: str,
) -> None:
    """Verify one persistent root can atomically publish a ``latest`` symlink.

    Args:
        latest_link: Final sibling symlink that will be published after success.
        target_directory: Run-ID directory that supplies the relative link target.
        label: Operator-facing persistent-area description used in errors.

    Returns:
        ``None`` after creating, atomically renaming, and deleting a temporary
        symlink. The real ``latest`` link is never modified by this probe.

    Raises:
        OSError: If symlink creation, rename, or cleanup is unavailable in the
        persistent root.
    """

    if (
        latest_link.exists() or latest_link.is_symlink()
    ) and not latest_link.is_symlink():
        raise OSError(
            f"{label} latest path exists and is not a symlink: {latest_link}"
        )

    token = uuid.uuid4().hex
    root = latest_link.parent
    temporary = root / f".lldp-runner-latest-preflight-{token}.tmp"
    published = root / f".lldp-runner-latest-preflight-{token}.ready"
    try:
        temporary.symlink_to(target_directory.name)
        os.replace(temporary, published)
        published.unlink()
    except OSError as exc:
        for probe in (temporary, published):
            try:
                probe.unlink(missing_ok=True)
            except OSError:
                pass
        raise OSError(
            f"{label} root cannot publish the latest symlink: {root}: {exc}"
        ) from exc


def publish_latest_symlink(latest_link: Path, target_directory: Path) -> None:
    """Atomically point a sibling ``latest`` symlink at one completed run.

    Args:
        latest_link: Alias path, normally ``runs/latest`` or ``outputs/latest``.
        target_directory: Existing run-ID directory beside ``latest_link``.

    Returns:
        ``None`` after an atomic symlink replacement using a relative target.

    Raises:
        OSError: If the target/root is invalid, a non-symlink occupies the alias,
            or the temporary symlink cannot be created or published.

    Notes:
        Relative sibling targets keep a persistent tree relocatable. A UUID in
        the temporary name also makes concurrent run completion safe: whichever
        completion publishes last becomes the newest completed-run alias.
    """

    if latest_link.parent != target_directory.parent:
        raise OSError(
            "latest symlink and target directory must share a parent: "
            f"{latest_link} and {target_directory}"
        )
    if not target_directory.exists() or not target_directory.is_dir():
        raise OSError(f"latest symlink target is not a directory: {target_directory}")
    if (
        latest_link.exists() or latest_link.is_symlink()
    ) and not latest_link.is_symlink():
        raise OSError(f"latest path exists and is not a symlink: {latest_link}")

    temporary = latest_link.with_name(
        f".{latest_link.name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
    )
    try:
        temporary.symlink_to(target_directory.name)
        os.replace(temporary, latest_link)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise OSError(
            f"unable to publish latest symlink {latest_link} -> "
            f"{target_directory.name}: {exc}"
        ) from exc


def _paths_overlap(first: Path, second: Path) -> bool:
    """Return whether two resolved paths are equal or contain one another."""

    first_resolved = first.resolve(strict=False)
    second_resolved = second.resolve(strict=False)
    return (
        first_resolved == second_resolved
        or first_resolved in second_resolved.parents
        or second_resolved in first_resolved.parents
    )


def clean_completed_scratch(paths: RunPaths) -> None:
    """Remove one completed run's transient files and matching ``current`` link.

    Args:
        paths: Completed run paths. Only ``scratch_dir`` and its sibling
            ``current`` alias are modified.

    Returns:
        ``None`` when the scratch run directory is absent or has been removed.

    Raises:
        OSError: If scratch overlaps persistent run/output storage, is itself a
            symlink/non-directory, or cannot be removed completely.

    Notes:
        The ``current`` alias is removed only when it still resolves to this run.
        A newer concurrent run may already own the alias and must be left intact.
        ``shutil.rmtree`` intentionally removes every transient artifact rather
        than relying on a filename allowlist that could miss future draft files.
    """

    scratch_dir = paths.scratch_dir
    for persistent_path in (paths.run_dir, paths.output_run_dir):
        if _paths_overlap(scratch_dir, persistent_path):
            raise OSError(
                "refusing to clean completed scratch because it overlaps "
                f"persistent storage: {scratch_dir} and {persistent_path}"
            )
    if scratch_dir.is_symlink():
        raise OSError(f"refusing to clean symlinked scratch run directory: {scratch_dir}")
    if scratch_dir.exists() and not scratch_dir.is_dir():
        raise OSError(f"scratch run path is not a directory: {scratch_dir}")

    current = scratch_dir.parent / "current"
    try:
        if current.is_symlink():
            raw_target = Path(os.readlink(current))
            target = (
                raw_target
                if raw_target.is_absolute()
                else current.parent / raw_target
            )
            if target.resolve(strict=False) == scratch_dir.resolve(strict=False):
                current.unlink()
        if scratch_dir.exists():
            shutil.rmtree(scratch_dir)
    except OSError as exc:
        raise OSError(
            f"unable to clean completed scratch directory {scratch_dir}: {exc}"
        ) from exc


def preflight_run_storage(paths: RunPaths) -> None:
    """Validate storage operations that otherwise occur after SNMP discovery.

    Args:
        paths: Existing run/scratch/output paths prepared for one invocation.

    Returns:
        ``None`` after proving that the exact scratch run directory and stable
        live scoreboard directory can accept atomic files, that the final run-ID
        output directory can be created and written atomically, and that the
        output root can publish symlinks.
        A newly created output-run directory is removed after the probe so only
        successfully finalized runs normally remain below the output root.

    Raises:
        OSError: If any tested storage operation fails. This function is called
        before workers start so ordinary permission/path failures do not consume
        time performing SNMP discovery that cannot later be persisted.

    Notes:
        Preflight cannot guarantee future capacity or availability. Disk-full,
        quota, remote-filesystem, or permission changes can still fail during a
        long run, so normal write-time error handling remains required.
    """

    _preflight_atomic_file_output(paths.scratch_dir, label="scratch run directory")
    _preflight_atomic_file_output(
        paths.scoreboard_dir,
        label="live scoreboard directory",
    )

    created_output_run_dir = False
    try:
        if paths.output_run_dir.exists():
            if not paths.output_run_dir.is_dir():
                raise OSError(
                    "persistent output destination is not a directory: "
                    f"{paths.output_run_dir}"
                )
        else:
            paths.output_run_dir.mkdir(parents=True, exist_ok=False)
            created_output_run_dir = True

        _preflight_atomic_file_output(
            paths.output_run_dir,
            label="persistent output directory",
        )
        _preflight_latest_symlink(
            paths.latest_link,
            paths.output_run_dir,
            label="persistent output",
        )
        _preflight_latest_symlink(
            paths.run_latest_link,
            paths.run_dir,
            label="persistent run",
        )

        if created_output_run_dir:
            paths.output_run_dir.rmdir()
            created_output_run_dir = False
    except OSError:
        if created_output_run_dir:
            try:
                paths.output_run_dir.rmdir()
            except OSError:
                pass
        raise


def ensure_run_directories(paths: RunPaths) -> None:
    """Create run directories, preflight storage, and refresh scratch ``current``.

    Args:
        paths: Resolved run paths from :func:`make_run_paths`.

    Returns:
        ``None``. Required directories are created, storage needed by snapshots
        and end-of-run persistence is tested, then the scratch ``current`` symlink
        is updated atomically where possible. External log directories are left
        to the logging subsystem because file logging may be disabled.

    Raises:
        OSError: If directory creation, storage preflight, or scratch-current
        symlink publication fails. Callers should report this before discovery.
    """

    try:
        paths.run_dir.mkdir(parents=True, exist_ok=not paths.is_new)
    except FileExistsError as exc:
        raise OSError(
            f"new run ID was claimed concurrently or already exists: {paths.run_id}; "
            "retry the run or use a higher-precision paths.run_id_format"
        ) from exc
    paths.scratch_dir.mkdir(parents=True, exist_ok=True)
    paths.scoreboard_dir.mkdir(parents=True, exist_ok=True)
    paths.output_root.mkdir(parents=True, exist_ok=True)

    # The root-level configuration probes prove that the selected filesystem
    # roots are generally writable. This exact-run probe closes the remaining
    # gap for resumed/reused child directories and terminal output publication.
    preflight_run_storage(paths)

    current = paths.scratch_dir.parent / "current"
    temp_link = paths.scratch_dir.parent / f".current.{os.getpid()}"
    try:
        temp_link.unlink(missing_ok=True)
        temp_link.symlink_to(paths.scratch_dir.name)
        os.replace(temp_link, current)
    finally:
        temp_link.unlink(missing_ok=True)


def find_resumable_run(config: AppConfig) -> str | None:
    """Return the newest run whose persisted status permits resume.

    Args:
        config: Effective configuration containing the persistent run root.

    Returns:
        The newest resumable run ID, or ``None`` when no suitable state database
        can be found/read. Corrupt or inaccessible candidate state files are
        skipped so an older valid resumable run can still be selected.
    """

    runs_root = config.paths.persistent_root / config.paths.runs_dirname
    if not runs_root.exists():
        return None
    for directory in sorted(
        (x for x in runs_root.iterdir() if x.is_dir() and not x.is_symlink()),
        reverse=True,
    ):
        state_path = directory / "discovery-state.sqlite"
        if not state_path.exists():
            continue
        try:
            conn = sqlite3.connect(f"file:{state_path}?mode=ro", uri=True)
            row = conn.execute("SELECT value FROM meta WHERE key='status'").fetchone()
            conn.close()
        except sqlite3.Error:
            continue
        status = str(row[0]) if row else ""
        if status in {"RUNNING", "PAUSED", "INTERRUPTED", "LIMIT_REACHED"}:
            return directory.name
    return None
