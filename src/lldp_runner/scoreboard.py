"""Human and machine-readable live discovery scoreboards.

The actively refreshed files live in the stable ``<scratch_root>/scoreboard``
directory instead of a run-specific scratch tree.  That location lets status
and Watch continue to display the final completed snapshot after optional
cleanup removes ``<scratch_root>/<run-id>``.  Completed runs receive byte-for-
byte archive copies in durable run state and, when configured, retained scratch
state.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lldp_runner.state import StateStore
from lldp_runner.timeutil import human_now, iso_now

SCOREBOARD_SCHEMA = 1
SCOREBOARD_DIRECTORY_NAME = "scoreboard"
SCOREBOARD_JSON_NAME = "scoreboard.json"
SCOREBOARD_TEXT_NAME = "scoreboard.txt"


@dataclass(frozen=True, slots=True)
class ScoreboardSnapshot:
    """Complete rendered scoreboard payloads from one publication.

    Retaining the exact strings in memory avoids a race in which a newly
    started run replaces the shared live scoreboard before the completed run's
    archival copies are written.
    """

    text: str
    json: str


def current_scoreboard_directory(scratch_root: Path) -> Path:
    """Return the stable directory used for actively published scoreboards."""

    return Path(scratch_root) / SCOREBOARD_DIRECTORY_NAME


def current_scoreboard_path(scratch_root: Path, *, json_output: bool = False) -> Path:
    """Return the live scoreboard selected by one effective scratch root.

    Both ``status`` and the interactive ``watch`` command use this helper so the
    operator cannot accidentally observe different live publication locations.
    """

    name = SCOREBOARD_JSON_NAME if json_output else SCOREBOARD_TEXT_NAME
    return current_scoreboard_directory(scratch_root) / name


def _atomic_text(path: Path, text: str) -> None:
    """Atomically replace one scoreboard text/JSON file.

    Args:
        path: Final live or archived scoreboard pathname.
        text: Complete UTF-8 payload to publish.

    Results:
        Writes through a process-specific temporary sibling and atomically replaces
        ``path`` so readers never observe a partially rendered scoreboard.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temp.write_text(text, encoding="utf-8")
    os.replace(temp, path)


def write_scoreboard(
    state: StateStore,
    scoreboard_dir: Path,
    *,
    run_id: str,
    started: str,
    status: str,
    elapsed_seconds: float,
    worker_status: dict[int, dict[str, Any]],
    execution_plan: dict[str, Any] | None = None,
) -> ScoreboardSnapshot:
    """Render the current run scoreboard in JSON and aligned operator text.

    Args:
        state: Authoritative coordinator state used for host/result counters.
        scoreboard_dir: Stable live publication directory receiving both files.
        run_id: Operator-visible identifier for the logical discovery run.
        started: Human-readable logical run start timestamp.
        status: Current run status such as ``RUNNING`` or ``COMPLETED``.
        elapsed_seconds: Elapsed seconds for the current invocation.
        worker_status: Per-worker status/batch mapping maintained by the coordinator.
        execution_plan: Optional configured/effective scheduler information. Seed-only
            runs use this to expose runtime right-sizing decisions.

    Results:
        Atomically writes ``scoreboard.json`` and ``scoreboard.txt`` and returns
        their complete rendered strings. The versioned JSON form is the native
        ``lldp-runner watch`` interface; the text form is optimized for one-shot
        ``lldp-runner status`` and direct terminal reading.
    """

    counts = state.counts()
    payload: dict[str, Any] = {
        "scoreboard_schema": SCOREBOARD_SCHEMA,
        "run_id": run_id,
        "started": started,
        "status": status,
        "elapsed_seconds": round(elapsed_seconds, 1),
        "last_update": iso_now(),
        **counts,
        "workers": worker_status,
    }
    if execution_plan is not None:
        payload["execution_plan"] = execution_plan
    json_text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    _atomic_text(scoreboard_dir / SCOREBOARD_JSON_NAME, json_text)
    elapsed = int(elapsed_seconds)
    hh, rem = divmod(elapsed, 3600)
    mm, ss = divmod(rem, 60)
    lines = [
        f"Run:                {run_id}",
        f"Started:            {started}",
        f"Status:             {status}",
        f"Elapsed:            {hh:02d}:{mm:02d}:{ss:02d}",
    ]
    if execution_plan is not None:
        lines.extend(
            [
                "",
                "Execution plan:",
                f"  mode:             {execution_plan.get('mode', '-')}",
                "  workers:          "
                f"{execution_plan.get('configured_workers', '-')} configured -> "
                f"{execution_plan.get('effective_workers', '-')} effective",
                "  batch size:       "
                f"{execution_plan.get('configured_batch_size', '-')} configured -> "
                f"{execution_plan.get('effective_batch_size', '-')} effective",
                "  max outstanding:  "
                f"{execution_plan.get('max_outstanding_devices_per_worker', '-')} "
                "devices/worker",
            ]
        )
        if "ready_seeds" in execution_plan:
            lines.append(f"  READY seeds:      {int(execution_plan['ready_seeds']):,}")
    lines.extend(
        [
            "",
            f"Hosts discovered:   {counts['hosts_discovered']:,}",
            f"Managed devices:    {counts['managed_devices']:,}",
            f"  queued:            {counts['ready']:,}",
            f"  active:            {counts['active']:,}",
            f"  completed:         {counts['complete']:,}",
            f"  failed:            {counts['failed']:,}",
            f"Managed endpoints:  {counts['managed_endpoints']:,}",
            f"Unmanaged devices:  {counts['unmanaged_devices']:,}",
            f"Unknown devices:    {counts['unknown_devices']:,}",
            "",
            f"Primary successes:  {counts['primary_successes']:,}",
            f"Fallback successes: {counts['fallback_successes']:,}",
            f"Errors recorded:     {counts['errors']:,}",
            "",
        ]
    )
    for worker_id in sorted(worker_status):
        info = worker_status[worker_id]
        lines.append(
            f"Worker {worker_id:02d}: {str(info.get('status', 'UNKNOWN')):<8} "
            f"batch={info.get('batch', '-')} size={info.get('size', 0)}"
        )
    lines.extend(["", f"Last update:         {human_now()}"])
    text = "\n".join(lines) + "\n"
    _atomic_text(scoreboard_dir / SCOREBOARD_TEXT_NAME, text)
    return ScoreboardSnapshot(text=text, json=json_text)


def archive_scoreboard(snapshot: ScoreboardSnapshot, directory: Path) -> tuple[Path, Path]:
    """Atomically archive one completed scoreboard snapshot in ``directory``.

    Args:
        snapshot: Exact text and JSON strings returned by :func:`write_scoreboard`.
        directory: Completed run state directory that should retain the snapshot.

    Returns:
        Paths to the archived text and JSON files, in that order.

    Notes:
        The destination uses the same atomic replacement helper as the live
        publication.  Existing files are replaced so a resumed run can publish
        its newly completed terminal snapshot deterministically.
    """

    text_path = Path(directory) / SCOREBOARD_TEXT_NAME
    json_path = Path(directory) / SCOREBOARD_JSON_NAME
    _atomic_text(text_path, snapshot.text)
    _atomic_text(json_path, snapshot.json)
    return text_path, json_path
