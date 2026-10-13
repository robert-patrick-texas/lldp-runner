"""Interactive terminal dashboard for the current LLDP-Runner scoreboard.

The watcher deliberately reads the atomically published ``scoreboard.json``
rather than scraping ``scoreboard.txt``. Structured snapshots let the terminal
highlight meaningful metric/worker changes, detect stale active runs, and pack
large worker populations into a responsive display without spawning a new
``lldp-runner status`` process every refresh.
"""

from __future__ import annotations

import curses
import json
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from lldp_runner import APP_NAME, __version__
from lldp_runner.config import AppConfig
from lldp_runner.scoreboard import SCOREBOARD_SCHEMA, current_scoreboard_path

WORKER_VIEWS = ("auto", "full", "compact", "heatmap", "summary")
ACTIVE_STATES = frozenset({"RUNNING", "PAUSING"})

# Fixed-width patriotic art used by the optional America overlay. Keeping the
# glyph geometry static makes centering deterministic and easy to test.
_AMERICA_U = (
    "UU         UU",
    "UU         UU",
    "UU         UU",
    "UU         UU",
    "UU         UU",
    "UU         UU",
    " UUUUUUUUUUU ",
)
_AMERICA_S = (
    " SSSSSSSSSSS ",
    "SS           ",
    "SS           ",
    " SSSSSSSSSS  ",
    "           SS",
    "           SS",
    " SSSSSSSSSSS ",
)
_AMERICA_A = (
    "     AAA     ",
    "    AA AA    ",
    "   AA   AA   ",
    "  AA     AA  ",
    " AAAAAAAAAAA ",
    "AA         AA",
    "AA         AA",
)
_AMERICA_GAP = "    "
_AMERICA_TAGLINES = (
    "United States of America",
    "1776-2026",
    "250 years and the best has yet to come!",
)


def cycle_worker_view(current: str) -> str:
    """Return the next operator-selectable worker view in the stable UI cycle.

    Keeping the cycle in one helper makes the keyboard interaction predictable
    and easy to regression-test independently of the curses event loop.
    """

    try:
        index = WORKER_VIEWS.index(current)
    except ValueError as exc:
        raise ValueError(f"unknown worker view: {current}") from exc
    return WORKER_VIEWS[(index + 1) % len(WORKER_VIEWS)]


_METRICS: tuple[tuple[str, str, str], ...] = (
    ("Hosts", "hosts_discovered", "metric"),
    ("Managed", "managed_devices", "metric"),
    ("Endpoints", "managed_endpoints", "metric"),
    ("Unmanaged", "unmanaged_devices", "metric"),
    ("Unknown", "unknown_devices", "warning"),
    ("Queued", "ready", "metric"),
    ("Active", "active", "heading"),
    ("Complete", "complete", "success"),
    ("Failed", "failed", "error"),
    ("Primary", "primary_successes", "success"),
    ("Fallback", "fallback_successes", "success"),
    ("Errors", "errors", "error"),
)

_HELP_METRICS: tuple[tuple[str, str], ...] = (
    ("Hosts", "Unique hosts currently known to this discovery run."),
    ("Managed", "Hosts classified as managed network devices."),
    ("Endpoints", "Hosts classified as managed endpoints rather than infrastructure."),
    ("Unmanaged", "Hosts identified as devices LLDP-Runner should not manage/query."),
    ("Unknown", "Hosts without enough evidence for a safe final classification."),
    ("Queued", "Hosts in READY state waiting to be assigned to a worker."),
    ("Active", "Hosts currently assigned and in an active processing state."),
    ("Complete", "Hosts whose discovery state has reached COMPLETE."),
    ("Failed", "Hosts whose discovery state has reached FAILED."),
    ("Primary", "Hosts successfully queried with the primary credential."),
    ("Fallback", "Hosts successfully queried with a fallback credential."),
    ("Errors", "Error records accumulated by discovery so far."),
)

_WORKER_BATCH_WIDTH = 5
_WORKER_FULL_SIZE_WIDTH = 3
_WORKER_COMPACT_SIZE_WIDTH = 2
_WORKER_STATE_WIDTH = 4
_WATCH_SIDE_BORDER = 1
_WATCH_TOP_BORDER_ROWS = 1
_METRIC_LABEL_WIDTH = 10
_METRIC_DELTA_WIDTH = 8
_METRIC_MAX_BLOCK_WIDTH = 180
_METRIC_MAX_COLUMN_GAP = 16
_ROOMY_FOOTER_BLANK_THRESHOLD = 10


class WatchError(RuntimeError):
    """Raised for an operator-visible watch source or terminal problem."""


@dataclass(frozen=True, slots=True)
class ScoreboardSource:
    """One complete atomic scoreboard snapshot read from the current run."""

    path: Path
    payload: dict[str, Any]
    mtime_ns: int

    @property
    def key(self) -> tuple[str, str, int]:
        """Return an identity that changes whenever the published snapshot changes."""

        return (
            str(self.payload.get("run_id", "")),
            str(self.payload.get("last_update", "")),
            self.mtime_ns,
        )


@dataclass(frozen=True, slots=True)
class WatchSpan:
    """One text fragment carrying a semantic terminal role."""

    text: str
    role: str = "default"
    emphasize: bool = False


@dataclass(frozen=True, slots=True)
class WatchLine:
    """One dashboard line represented as individually styleable spans."""

    spans: tuple[WatchSpan, ...]

    @property
    def text(self) -> str:
        """Return visible text without terminal styling."""

        return "".join(span.text for span in self.spans)


@dataclass(frozen=True, slots=True)
class WatchFrame:
    """Rendered dashboard plus layout metadata useful to tests and adapters."""

    lines: tuple[WatchLine, ...]
    worker_view: str
    abbreviated: bool
    stale: bool


@dataclass(slots=True)
class WatchSession:
    """Track snapshot deltas and monotonic freshness across terminal refreshes."""

    payload: dict[str, Any] | None = None
    source_key: tuple[str, str, int] | None = None
    run_id: str | None = None
    previous_payload: dict[str, Any] | None = None
    metric_deltas: dict[str, int] = field(default_factory=dict)
    changed_workers: set[int] = field(default_factory=set)
    last_snapshot_monotonic: float | None = None
    source_available: bool = False
    source_message: str | None = None

    def observe(
        self,
        source: ScoreboardSource | None,
        *,
        now_monotonic: float,
        now_epoch: float,
        source_message: str | None = None,
    ) -> None:
        """Incorporate one source observation without losing the last good screen."""

        if source is None:
            self.source_available = False
            self.source_message = source_message
            return

        payload = source.payload
        run_id = str(payload.get("run_id", ""))
        new_run = self.run_id is not None and run_id != self.run_id
        changed = source.key != self.source_key

        if self.payload is None or new_run:
            self.previous_payload = None
            self.metric_deltas = {}
            self.changed_workers = set()
            age = max(0.0, now_epoch - (source.mtime_ns / 1_000_000_000))
            self.last_snapshot_monotonic = now_monotonic - age
        elif changed:
            self.previous_payload = self.payload
            self.metric_deltas = _metric_deltas(self.previous_payload, payload)
            self.changed_workers = _changed_worker_ids(self.previous_payload, payload)
            self.last_snapshot_monotonic = now_monotonic

        self.payload = payload
        self.source_key = source.key
        self.run_id = run_id
        self.source_available = True
        self.source_message = None

    def age_seconds(self, now_monotonic: float) -> float:
        """Return monotonic age of the last observed scoreboard publication."""

        if self.last_snapshot_monotonic is None:
            return 0.0
        return max(0.0, now_monotonic - self.last_snapshot_monotonic)


def load_current_scoreboard(scratch_root: Path) -> ScoreboardSource:
    """Read and validate the current scoreboard after every atomic publication.

    The pathname is reopened on each call because the coordinator publishes with
    ``os.replace`` and a newly started run may replace the stable live snapshot.
    """

    path = current_scoreboard_path(scratch_root, json_output=True)
    try:
        with path.open("r", encoding="utf-8") as handle:
            text = handle.read()
            stat = os.fstat(handle.fileno())
    except FileNotFoundError as exc:
        raise WatchError(f"waiting for current scoreboard under {path.parent}") from exc
    except OSError as exc:
        raise WatchError(f"unable to read scoreboard: {exc}") from exc

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise WatchError(f"invalid scoreboard JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise WatchError("scoreboard JSON root must be an object")
    schema = payload.get("scoreboard_schema")
    if schema != SCOREBOARD_SCHEMA:
        raise WatchError(f"unsupported scoreboard schema {schema!r}; expected {SCOREBOARD_SCHEMA}")
    workers = payload.get("workers", {})
    if not isinstance(workers, dict):
        raise WatchError("scoreboard workers must be an object")
    return ScoreboardSource(path=path, payload=payload, mtime_ns=stat.st_mtime_ns)


def stale_threshold(scoreboard_interval_seconds: float) -> float:
    """Return the active-run age at which the dashboard becomes stale."""

    return max(15.0, 3.0 * float(scoreboard_interval_seconds))


def is_stale(payload: dict[str, Any], age_seconds: float, threshold: float) -> bool:
    """Return whether an active scoreboard has stopped publishing for too long."""

    return str(payload.get("status", "")).upper() in ACTIVE_STATES and age_seconds > threshold


def _int_value(payload: dict[str, Any], key: str) -> int:
    """Return one scoreboard counter as an integer, tolerating absent values."""

    value = payload.get(key, 0)
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _metric_deltas(old: dict[str, Any], new: dict[str, Any]) -> dict[str, int]:
    """Compute counter deltas between two consecutive scoreboard publications."""

    return {key: _int_value(new, key) - _int_value(old, key) for _, key, _ in _METRICS}


def _workers(payload: dict[str, Any]) -> dict[int, dict[str, Any]]:
    """Normalize JSON worker keys back to integer worker identifiers."""

    result: dict[int, dict[str, Any]] = {}
    raw = payload.get("workers", {})
    if not isinstance(raw, dict):
        return result
    for key, value in raw.items():
        try:
            worker_id = int(key)
        except (TypeError, ValueError):
            continue
        result[worker_id] = value if isinstance(value, dict) else {}
    return result


def _changed_worker_ids(old: dict[str, Any], new: dict[str, Any]) -> set[int]:
    """Return worker IDs whose state/batch/size record changed in the new snapshot."""

    old_workers = _workers(old)
    new_workers = _workers(new)
    return {
        worker_id
        for worker_id in set(old_workers) | set(new_workers)
        if old_workers.get(worker_id) != new_workers.get(worker_id)
    }


def _elapsed_text(seconds: float | int) -> str:
    """Format seconds as compact HH:MM:SS text."""

    total = max(0, int(float(seconds)))
    hours, rem = divmod(total, 3600)
    minutes, secs = divmod(rem, 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def _age_text(seconds: float) -> str:
    """Format scoreboard age as total minutes and seconds.

    Total minutes intentionally continue past 59 so operators can read a stale
    duration directly without mentally combining an hours field.
    """

    total = max(0, int(seconds))
    minutes, secs = divmod(total, 60)
    return f"{minutes:02d}:{secs:02d}"


def _fit(text: str, width: int) -> str:
    """Truncate visible text to one terminal row without wrapping."""

    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _plain_line(text: str, role: str = "default", emphasize: bool = False) -> WatchLine:
    """Construct one single-span dashboard line."""

    return WatchLine((WatchSpan(text, role=role, emphasize=emphasize),))


def _truncate_line(line: WatchLine, width: int) -> WatchLine:
    """Fit one styled line to a terminal row without losing semantic spans."""

    if width <= 0:
        return _plain_line("")
    if len(line.text) <= width:
        return line

    marker_text = "..." if width > 3 else ""
    remaining = max(0, width - len(marker_text))
    spans: list[WatchSpan] = []
    marker_role = "default"
    marker_emphasis = False
    for span in line.spans:
        if remaining <= 0:
            break
        piece = span.text[:remaining]
        if piece:
            spans.append(WatchSpan(piece, role=span.role, emphasize=span.emphasize))
            marker_role = span.role
            marker_emphasis = span.emphasize
            remaining -= len(piece)
    if marker_text:
        spans.append(
            WatchSpan(
                marker_text,
                role=marker_role,
                emphasize=marker_emphasis,
            )
        )
    return WatchLine(tuple(spans))


def _prefix_line(line: WatchLine, count: int) -> WatchLine:
    """Add one stable left offset while preserving every semantic span."""

    if count <= 0 or not line.text:
        return line
    return WatchLine((WatchSpan(" " * count), *line.spans))


def _center_block(lines: list[WatchLine], width: int) -> list[WatchLine]:
    """Center a multi-line block by one common left offset.

    Each line keeps its natural width. The longest fitted line defines the
    block rectangle, so metric columns and worker summaries remain aligned
    rather than being stretched independently to the terminal edges.
    """

    fitted = [_truncate_line(line, width) for line in lines]
    block_width = max((len(line.text) for line in fitted), default=0)
    left = max(0, (width - block_width) // 2)
    return [_prefix_line(line, left) for line in fitted]


def _metric_column_count(width: int) -> int:
    """Return the responsive metric-column target for the bordered canvas."""

    return 3 if width >= 94 else 2 if width >= 58 else 1


def _bounded_metric_number(value: int, width: int, *, signed: bool = False) -> str:
    """Render one counter in a fixed field without allowing column reflow.

    The dashboard is expected to handle ordinary enterprise discovery counts,
    but a fixed-width field still needs an explicit overflow signal. Hash marks
    are preferable to silently shifting every following metric column when a
    counter exceeds the current terminal's budget.
    """

    text = f"{value:+,}" if signed else f"{value:,}"
    if len(text) > width:
        return "#" * max(0, width)
    return text.rjust(width)


def _metric_cell(
    label: str,
    key: str,
    payload: dict[str, Any],
    deltas: dict[str, int],
    *,
    width: int,
) -> str:
    """Render one stable-width metric cell with independently aligned fields."""

    # Two single-space separators keep the value and delta budgets independent.
    # That prevents a newly appearing delta or an added count digit from moving
    # the next metric column while still leaving the label easy to scan.
    value_width = max(1, width - _METRIC_LABEL_WIDTH - _METRIC_DELTA_WIDTH - 2)
    delta = deltas.get(key, 0)
    delta_text = (
        _bounded_metric_number(delta, _METRIC_DELTA_WIDTH, signed=True)
        if delta
        else " " * _METRIC_DELTA_WIDTH
    )
    return (
        f"{_fit(label, _METRIC_LABEL_WIDTH):<{_METRIC_LABEL_WIDTH}} "
        f"{_bounded_metric_number(_int_value(payload, key), value_width)} "
        f"{delta_text}"
    )


def _metric_block_geometry(width: int, columns: int) -> tuple[int, list[int], int]:
    """Return centered block width, equalized column widths, and inter-column gap.

    Wide terminals use most of the useful upper-screen area, capped at 180
    columns so individual counters do not become visually disconnected from
    their labels. Column widths depend only on terminal geometry, never on live
    counter digits, which keeps the dashboard stationary between refreshes.
    """

    block_width = min(max(1, width), _METRIC_MAX_BLOCK_WIDTH)
    if columns <= 1:
        return block_width, [block_width], 0

    gap = min(
        _METRIC_MAX_COLUMN_GAP,
        max(4, block_width // 12),
    )
    minimum_column = _METRIC_LABEL_WIDTH + _METRIC_DELTA_WIDTH + 5
    while columns > 1 and block_width - gap * (columns - 1) < columns * minimum_column:
        columns -= 1
    if columns <= 1:
        return block_width, [block_width], 0

    usable = block_width - gap * (columns - 1)
    base, remainder = divmod(usable, columns)
    widths = [base + (1 if index < remainder else 0) for index in range(columns)]
    return block_width, widths, gap


def _metric_lines(payload: dict[str, Any], deltas: dict[str, int], width: int) -> list[WatchLine]:
    """Pack counters into a wide, centered grid with invariant column starts."""

    columns = _metric_column_count(width)
    block_width, column_widths, gap = _metric_block_geometry(width, columns)
    columns = len(column_widths)
    left = max(0, (width - block_width) // 2)

    lines: list[WatchLine] = []
    for offset in range(0, len(_METRICS), columns):
        spans: list[WatchSpan] = []
        if left:
            spans.append(WatchSpan(" " * left))
        items = list(_METRICS[offset : offset + columns])
        for index, (label, key, role) in enumerate(items):
            cell_width = column_widths[index]
            spans.append(
                WatchSpan(
                    _metric_cell(
                        label,
                        key,
                        payload,
                        deltas,
                        width=cell_width,
                    ),
                    role=role,
                    emphasize=bool(deltas.get(key, 0)),
                )
            )
            if index < len(items) - 1:
                spans.append(WatchSpan(" " * gap))
        lines.append(_truncate_line(WatchLine(tuple(spans)), width))
    return lines


def _worker_state(info: dict[str, Any]) -> str:
    """Normalize worker state while preserving unexpected values for diagnostics."""

    state = str(info.get("status", "UNKNOWN")).upper().strip()
    return state or "UNKNOWN"


def _worker_role(state: str) -> str:
    """Map one worker state to its watch palette semantic role."""

    if state == "BUSY":
        return "busy"
    if state == "IDLE":
        return "idle"
    if state == "DEAD":
        return "dead"
    return "unknown"


def _bounded_worker_field(value: Any, width: int) -> str:
    """Return a stable-width worker field without allowing values to reflow the grid.

    Worker batch identifiers and sizes normally fit comfortably inside these budgets.
    Unused leading positions are filled with ``.`` rather than whitespace so the
    fixed budget remains visually obvious. If an operator config or unusually long
    run exceeds one, ``#`` characters make the overflow explicit instead of silently
    changing column count mid-run.
    """

    text = str(value)
    if len(text) > width:
        return "#" * width
    return text.rjust(width, ".")


def _worker_display_state(state: str) -> str:
    """Return the fixed-width state token used inside dense worker cells."""

    if state in {"BUSY", "IDLE", "DEAD"}:
        return state
    return "OTHR"


def _worker_id_width(workers: dict[int, dict[str, Any]]) -> int:
    """Reserve a stable worker-ID width for the current worker population."""

    if not workers:
        return 2
    return max(2, len(str(max(workers))))


def _worker_cell(
    worker_id: int,
    info: dict[str, Any],
    mode: str,
    *,
    id_width: int,
) -> str:
    """Render one fixed-width worker cell for the selected density.

    The cell width is determined by mode plus worker-ID width, not by the current
    batch/size values. This prevents a new decimal digit from making the table jump
    horizontally while an operator is watching it.
    """

    state = _worker_display_state(_worker_state(info))
    worker_text = str(worker_id)
    if len(worker_text) > id_width:
        worker_text = "#" * id_width
    else:
        worker_text = worker_text.zfill(id_width)
    if mode == "full":
        batch = _bounded_worker_field(info.get("batch", "-"), _WORKER_BATCH_WIDTH)
        size = _bounded_worker_field(info.get("size", 0), _WORKER_FULL_SIZE_WIDTH)
        return f"[Worker {worker_text} {state:<{_WORKER_STATE_WIDTH}} batch={batch} size={size}]"
    if mode == "compact":
        size = _bounded_worker_field(info.get("size", 0), _WORKER_COMPACT_SIZE_WIDTH)
        return f"[{worker_text} {state:<{_WORKER_STATE_WIDTH}} sz={size}]"
    if mode == "heatmap":
        return f"[{worker_text} {state:<{_WORKER_STATE_WIDTH}}]"
    raise ValueError(f"worker cell mode does not render individual workers: {mode}")


def _worker_cell_width(mode: str, id_width: int) -> int:
    """Return the invariant visible width for one worker cell in ``mode``."""

    exemplar = {"status": "BUSY", "batch": 0, "size": 0}
    return len(_worker_cell(0, exemplar, mode, id_width=id_width))


def _pack_worker_cells(
    workers: dict[int, dict[str, Any]],
    mode: str,
    width: int,
    changed_workers: set[int],
) -> list[WatchLine] | None:
    """Pack and center workers in stable fixed-width table columns.

    Capacity is selected from the full terminal width before centering. The
    common offset therefore never costs a worker column, and a partial final
    row remains aligned with the first table column instead of being centered
    independently.
    """

    if not workers:
        return []

    id_width = _worker_id_width(workers)
    cell_width = _worker_cell_width(mode, id_width)
    if cell_width > width:
        return None

    gap_text = " " if mode == "compact" else "  "
    gap_width = len(gap_text)
    columns = max(1, (width + gap_width) // (cell_width + gap_width))
    table_width = columns * cell_width + (columns - 1) * gap_width
    left = max(0, (width - table_width) // 2)
    worker_ids = sorted(workers)
    lines: list[WatchLine] = []

    for offset in range(0, len(worker_ids), columns):
        row_ids = worker_ids[offset : offset + columns]
        spans: list[WatchSpan] = []
        if left:
            spans.append(WatchSpan(" " * left))
        for column, worker_id in enumerate(row_ids):
            if column:
                spans.append(WatchSpan(gap_text))
            info = workers[worker_id]
            state = _worker_state(info)
            cell = _worker_cell(worker_id, info, mode, id_width=id_width)
            spans.append(
                WatchSpan(
                    cell,
                    role=_worker_role(state),
                    emphasize=worker_id in changed_workers,
                )
            )
        lines.append(WatchLine(tuple(spans)))
    return lines


def _worker_summary_lines(
    workers: dict[int, dict[str, Any]],
    width: int,
    changed_workers: set[int] | None = None,
) -> list[WatchLine]:
    """Render bounded aggregate/exception information for intentionally abbreviated view."""

    states = {_id: _worker_state(info) for _id, info in workers.items()}
    lines: list[WatchLine] = []

    attention = [
        f"{worker_id:02d} {state}"
        for worker_id, state in sorted(states.items())
        if state not in {"BUSY", "IDLE"}
    ]
    if attention:
        text = "Attention workers: " + ", ".join(attention)
        lines.append(_plain_line(_fit(text, width), "error", emphasize=True))

    changed = [
        f"{worker_id:02d} {states[worker_id]}"
        for worker_id in sorted(changed_workers or set())
        if worker_id in states
    ]
    if changed:
        text = "Changed workers: " + ", ".join(changed)
        lines.append(_plain_line(_fit(text, width), "metric", emphasize=True))
    return lines


def _choose_worker_lines(
    workers: dict[int, dict[str, Any]],
    requested: str,
    width: int,
    available_rows: int,
    changed_workers: set[int],
) -> tuple[str, list[WatchLine], bool]:
    """Choose or enforce one responsive worker view within the available rectangle."""

    if requested not in WORKER_VIEWS:
        raise ValueError(f"unknown worker view: {requested}")
    if requested == "summary":
        lines = _worker_summary_lines(workers, width, changed_workers)
        return "summary", lines[: max(0, available_rows)], len(lines) > available_rows

    modes = ("full", "compact", "heatmap") if requested == "auto" else (requested,)
    for mode in modes:
        lines = _pack_worker_cells(workers, mode, width, changed_workers)
        if lines is not None and len(lines) <= available_rows:
            return mode, lines, False

    summary = _worker_summary_lines(workers, width, changed_workers)
    return "summary", summary[: max(0, available_rows)], True


def _worker_gap_positions(line_count: int, blank_rows: int) -> set[int]:
    """Evenly distribute optional blank rows between worker-grid rows.

    The returned indexes name worker rows after which one blank line should appear.
    A tall terminal can therefore put whitespace between every row, while a medium
    terminal spreads whatever spare height exists rather than leaving one large void
    below the grid.
    """

    gap_count = max(0, line_count - 1)
    count = min(max(0, blank_rows), gap_count)
    if count == 0:
        return set()
    if count == gap_count:
        return set(range(gap_count))
    return {min(gap_count - 1, ((index + 1) * gap_count) // (count + 1)) for index in range(count)}


def _layout_spacing(
    surplus_rows: int,
    plan_line_count: int,
    metric_line_count: int,
    worker_line_count: int,
) -> tuple[int, int, set[int], int, int, set[int], int]:
    """Allocate optional whitespace around intact visual blocks.

    The title and Started/Elapsed line each receive a separator when possible.
    The aggregate worker headline then receives one blank row above and below.
    Spare height next opens the metric and worker grids one row at a time.

    After those ordinary readability gaps are allocated, more than ten rows
    left immediately above the footer indicates a genuinely roomy terminal.
    In that case one additional row is placed between the title and
    Started/Elapsed line, another remains after Started/Elapsed, and one is
    placed on both sides of the worker headline instead of leaving all of that
    whitespace in one large lower-screen block.
    """

    remaining = max(0, int(surplus_rows))
    after_header = 1 if remaining else 0
    remaining -= after_header

    after_plan = 1 if plan_line_count and remaining else 0
    remaining -= after_plan

    before_worker = 1 if remaining else 0
    remaining -= before_worker
    after_worker = 1 if remaining else 0
    remaining -= after_worker

    metric_blanks = min(remaining, max(0, metric_line_count - 1))
    metric_gaps = _worker_gap_positions(metric_line_count, metric_blanks)
    remaining -= metric_blanks

    worker_blanks = min(remaining, max(0, worker_line_count - 1))
    worker_gaps = _worker_gap_positions(worker_line_count, worker_blanks)
    remaining -= worker_blanks

    if remaining > _ROOMY_FOOTER_BLANK_THRESHOLD:
        if plan_line_count:
            after_header += 1
            remaining -= 1
            after_plan += 1
            remaining -= 1
        before_worker += 1
        after_worker += 1
        remaining -= 2

    return (
        after_header,
        after_plan,
        metric_gaps,
        before_worker,
        after_worker,
        worker_gaps,
        remaining,
    )


def _with_worker_row_spacing(
    lines: list[WatchLine],
    gap_positions: set[int],
) -> list[WatchLine]:
    """Insert blank rows at selected worker-grid boundaries."""

    spaced: list[WatchLine] = []
    for index, line in enumerate(lines):
        spaced.append(line)
        if index in gap_positions:
            spaced.append(_plain_line(""))
    return spaced


def _blank_lines(count: int) -> list[WatchLine]:
    """Return unstyled empty rows used only when terminal height permits."""

    return [_plain_line("") for _ in range(max(0, count))]


def _inset_watch_line(line: WatchLine, width: int) -> WatchLine:
    """Apply the one-column left border while reserving the right border cell.

    ``width`` is the already reduced interior width. The curses screen is erased
    before each draw, so fitting content to this width and prefixing one blank
    leaves the far-right physical terminal cell untouched and visibly blank.
    """

    fitted = _truncate_line(line, width)
    if not fitted.text:
        return fitted
    return WatchLine((WatchSpan(" " * _WATCH_SIDE_BORDER), *fitted.spans))


def _watch_footer(
    *,
    requested_worker_view: str,
    effective_worker_view: str,
    abbreviated: bool,
    width: int,
    terminal_width: int,
    height: int,
) -> WatchLine:
    """Render controls while always preserving exit guidance when shown."""

    if requested_worker_view == "auto":
        mode = f"auto->{effective_worker_view}"
    elif abbreviated and effective_worker_view != requested_worker_view:
        mode = f"{requested_worker_view}->{effective_worker_view}"
    else:
        mode = requested_worker_view

    detail = f"worker-view {mode} ({terminal_width}x{height})"
    controls = (
        "a america   h help   m cycle view   q/Ctrl-C exit",
        "h help   m cycle view   q/Ctrl-C exit",
        "m view   q/Ctrl-C exit",
    )
    for control_text in controls:
        if len(control_text) + len(detail) + 3 <= width:
            gap = " " * (width - len(control_text) - len(detail))
            return WatchLine(
                (
                    WatchSpan(control_text, role="muted"),
                    WatchSpan(gap),
                    WatchSpan(detail, role="muted"),
                )
            )
    for control_text in controls:
        if len(control_text) <= width:
            return _plain_line(control_text, "muted")
    return _plain_line(_fit("q/Ctrl-C exit", width), "muted")


def _run_state_role(status: str) -> str:
    """Map the overall run state to an operator-facing semantic color role."""

    state = status.upper()
    if state in {"RUNNING", "COMPLETED", "COMPLETED_LIMIT"}:
        return "success"
    if state in {"PAUSING", "PAUSED"}:
        return "warning"
    if state in {"FAILED", "INTERRUPTED", "ERROR"}:
        return "error"
    return "warning"


def _middle_fit(text: str, width: int) -> str:
    """Fit an identifier by preserving both its recognizable prefix and suffix."""

    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    left = (width - 3 + 1) // 2
    right = width - 3 - left
    return f"{text[:left]}...{text[-right:] if right else ''}"


def _short_run_state(status: str) -> str:
    """Return a compact but recognizable overall run-state token."""

    state = status.upper()
    aliases = {
        "RUNNING": "RUN",
        "PAUSING": "PAUSE",
        "PAUSED": "PAUSED",
        "COMPLETED": "DONE",
        "COMPLETED_LIMIT": "LIMIT",
        "FAILED": "FAIL",
        "INTERRUPTED": "STOP",
        "ERROR": "ERR",
    }
    return aliases.get(state, state[:5] or "?")


def _justify_header_segments(segments: tuple[WatchLine, ...], width: int) -> WatchLine:
    """Distribute all spare title-line columns approximately equally as gaps."""

    if len(segments) != 4:
        raise ValueError("watch title requires exactly four segments")
    text_width = sum(len(segment.text) for segment in segments)
    available = max(0, width - text_width)
    base, remainder = divmod(available, 3)
    gaps = [base + (1 if index < remainder else 0) for index in range(3)]

    spans: list[WatchSpan] = []
    for index, segment in enumerate(segments):
        spans.extend(segment.spans)
        if index < 3:
            spans.append(WatchSpan(" " * gaps[index]))
    return _truncate_line(WatchLine(tuple(spans)), width)


def _header_segment_candidates(
    *,
    run_id: str,
    status: str,
    age: str,
    stale: bool,
) -> list[tuple[WatchLine, WatchLine, WatchLine, WatchLine]]:
    """Return progressively compact four-part watch-title representations.

    Application version is the first content removed, matching the operator's
    preference. Labels are shortened only after the full identity/state/age
    representation cannot fit with at least one column between each segment.
    """

    state_role = "stale" if stale else _run_state_role(status)
    stale_full = "    *** STALE ***" if stale else ""
    stale_compact = " STALE" if stale else ""
    stale_mark = "!" if stale else ""

    def title(text: str) -> WatchLine:
        return _plain_line(text, "heading", True)

    def state(text: str) -> WatchLine:
        return _plain_line(text, state_role, True)

    return [
        (
            title(f"{APP_NAME} {__version__}"),
            _plain_line(f"Run ID = {run_id}", "muted"),
            state(f"STATE = {status}{stale_full}"),
            _plain_line(f"updated {age} ago"),
        ),
        (
            title(APP_NAME),
            _plain_line(f"Run ID = {run_id}", "muted"),
            state(f"STATE = {status}{stale_full}"),
            _plain_line(f"updated {age} ago"),
        ),
        (
            title(APP_NAME),
            _plain_line(f"Run {run_id}", "muted"),
            state(f"{status}{stale_compact}"),
            _plain_line(f"{age} ago"),
        ),
        (
            title(APP_NAME),
            _plain_line(run_id, "muted"),
            state(f"{_short_run_state(status)}{stale_compact}"),
            _plain_line(age),
        ),
        (
            title("LLDP"),
            _plain_line(run_id, "muted"),
            state(f"{_short_run_state(status)}{stale_mark}"),
            _plain_line(age),
        ),
    ]


def _watch_header_lines(
    *,
    run_id: str,
    status: str,
    width: int,
    age_seconds: float,
    stale: bool,
) -> list[WatchLine]:
    """Render one four-part title line, compacting only as width requires."""

    age = _age_text(age_seconds)
    for segments in _header_segment_candidates(
        run_id=run_id,
        status=status,
        age=age,
        stale=stale,
    ):
        # At least one blank column must remain between each of the four parts.
        if sum(len(segment.text) for segment in segments) + 3 <= width:
            return [_justify_header_segments(segments, width)]

    # The minimum supported terminal still preserves all four concepts. Run ID
    # receives the remaining budget after the application, state, and age tokens.
    title_text = "L"
    state_text = f"{status[:1] or '?'}{'!' if stale else ''}"
    run_budget = max(1, width - len(title_text) - len(state_text) - len(age) - 3)
    segments = (
        _plain_line(title_text, "heading", True),
        _plain_line(_middle_fit(run_id, run_budget), "muted"),
        _plain_line(state_text, "stale" if stale else _run_state_role(status), True),
        _plain_line(age),
    )
    return [_justify_header_segments(segments, width)]


def _center_line(
    text: str,
    width: int,
    role: str = "default",
    emphasize: bool = False,
) -> WatchLine:
    """Center one visible line in the available terminal width without wrapping."""

    fitted = _fit(text, width)
    left = max(0, (width - len(fitted)) // 2)
    return WatchLine(
        (
            WatchSpan(" " * left),
            WatchSpan(fitted, role=role, emphasize=emphasize),
        )
    )


def _america_art_width() -> int:
    """Return the fixed visible width of one complete USA art row."""

    return len(_AMERICA_U[0]) + len(_AMERICA_S[0]) + len(_AMERICA_A[0]) + 2 * len(_AMERICA_GAP)


def render_watch_america_frame(*, width: int, height: int) -> WatchFrame:
    """Render the modal America overlay, degrading to centered taglines if needed."""

    width = max(20, int(width))
    height = max(4, int(height))
    art_width = _america_art_width()
    art_height = len(_AMERICA_U)
    # Art plus the required blank row and the three taglines with blank rows
    # between them must all fit. Constrained screens retain the supplied
    # statements rather than clip the decorative logo.
    tagline_height = len(_AMERICA_TAGLINES) * 2 - 1
    show_art = width >= art_width and height >= art_height + 1 + tagline_height

    content: list[WatchLine] = []
    if show_art:
        art_left = max(0, (width - art_width) // 2)
        for u_text, s_text, a_text in zip(_AMERICA_U, _AMERICA_S, _AMERICA_A, strict=True):
            content.append(
                WatchLine(
                    (
                        WatchSpan(" " * art_left),
                        WatchSpan(u_text, role="america_red", emphasize=True),
                        WatchSpan(_AMERICA_GAP),
                        WatchSpan(s_text, role="america_white", emphasize=True),
                        WatchSpan(_AMERICA_GAP),
                        WatchSpan(a_text, role="america_blue", emphasize=True),
                    )
                )
            )
        content.append(_plain_line(""))

    spaced_taglines: list[WatchLine] = []
    for index, tagline in enumerate(_AMERICA_TAGLINES):
        if index:
            spaced_taglines.append(_plain_line(""))
        spaced_taglines.append(_center_line(tagline, width))
    if height >= len(spaced_taglines):
        content.extend(spaced_taglines)
    else:
        # A terminal shorter than five rows cannot physically preserve the blank
        # separators. Keep all statement text visible before decorative spacing.
        content.extend(_center_line(tagline, width) for tagline in _AMERICA_TAGLINES)

    # Center the complete overlay vertically when possible. With extremely short
    # terminals, keep the first three centered statements visible without scroll.
    if len(content) < height:
        top = (height - len(content)) // 2
        lines = _blank_lines(top) + content
    else:
        lines = content[:height]
    lines.extend(_blank_lines(max(0, height - len(lines))))
    return WatchFrame(
        lines=tuple(lines[:height]),
        worker_view="america",
        abbreviated=not show_art,
        stale=False,
    )


def _help_line(label: str, description: str, width: int) -> WatchLine:
    """Render one concise help definition while preserving its label emphasis."""

    prefix = f"  {label:<10} "
    available = max(0, width - len(prefix))
    return WatchLine(
        (
            WatchSpan(prefix, role="heading", emphasize=True),
            WatchSpan(_fit(description, available)),
        )
    )


def render_watch_help_frame(*, width: int, height: int) -> WatchFrame:
    """Render the built-in one-screen metric/worker help overlay."""

    width = max(20, int(width))
    height = max(4, int(height))
    lines: list[WatchLine] = [
        _plain_line(_fit(f"{APP_NAME} Watch help", width), "heading", True),
        _plain_line(""),
        _plain_line("Metrics", "heading", True),
    ]
    lines.extend(_help_line(label, description, width) for label, description in _HELP_METRICS)
    lines.extend(
        [
            _plain_line(""),
            _plain_line("Worker / plan terms", "heading", True),
            _help_line("Batch", "Coordinator work assignment currently owned by a worker.", width),
            _help_line("Size", "Number of devices in that worker's current batch.", width),
            _help_line(
                "Plan workers",
                "Configured worker target before runtime right-sizing.",
                width,
            ),
            _help_line(
                "Effective",
                "Workers actually launched after right-sizing the plan.",
                width,
            ),
        ]
    )

    footer = _plain_line(_fit("Press any key to return to the watch dashboard", width), "muted")
    if len(lines) + 1 <= height:
        lines.extend(_blank_lines(height - len(lines) - 1))
        lines.append(footer)
    else:
        lines = lines[: max(0, height - 1)]
        lines.append(footer)
    return WatchFrame(
        lines=tuple(lines[:height]),
        worker_view="help",
        abbreviated=False,
        stale=False,
    )


def _run_summary_text(
    payload: dict[str, Any],
    plan: dict[str, Any],
    width: int,
) -> str | None:
    """Choose the richest single-line Started/Elapsed summary that fits."""

    started = str(payload.get("started", "-"))
    elapsed = _elapsed_text(payload.get("elapsed_seconds", 0))
    effective_workers = plan.get("effective_workers", "-") if plan else "-"
    batch_size = plan.get("effective_batch_size", "-") if plan else "-"
    spacious_full_plan = (
        f"Started {started}      Elapsed {elapsed}      "
        f"Plan {effective_workers} workers / batch {batch_size}"
    )
    full_plan = (
        f"Started {started}   Elapsed {elapsed}   "
        f"Plan {effective_workers} workers / batch {batch_size}"
    )
    spacious_compact_plan = (
        f"Started {started}      Elapsed {elapsed}      Plan {effective_workers}/{batch_size}"
    )
    compact_plan = f"Started {started}   Elapsed {elapsed}   Plan {effective_workers}/{batch_size}"
    without_plan = f"Started {started}   Elapsed {elapsed}"

    started_parts = started.split()
    short_started = " ".join(started_parts[-2:]) if len(started_parts) >= 2 else started
    short_plan = (
        f"Started {short_started}   Elapsed {elapsed}   Plan {effective_workers}/{batch_size}"
    )
    short_without_plan = f"Started {short_started}   Elapsed {elapsed}"

    candidates = [
        spacious_full_plan,
        full_plan,
        spacious_compact_plan,
        compact_plan,
        without_plan,
        short_plan,
        short_without_plan,
    ]
    for candidate in candidates:
        if len(candidate) <= width:
            return candidate
    return None


def _worker_header_text(
    workers: dict[int, dict[str, Any]],
    *,
    width: int,
    abbreviated: bool,
) -> str:
    """Render full or compact aggregate worker state without hiding SMALL mode."""

    counts = Counter(_worker_state(info) for info in workers.values())
    busy = counts.get("BUSY", 0)
    idle = counts.get("IDLE", 0)
    dead = counts.get("DEAD", 0)
    other = len(workers) - busy - idle - dead

    full = f"Workers {len(workers)}:  BUSY {busy}   IDLE {idle}   DEAD {dead}"
    compact = f"W{len(workers)} B{busy} I{idle} D{dead}"
    if other:
        full += f"   OTHER {other}"
        compact += f" O{other}"

    if not abbreviated:
        return full if len(full) <= width else _fit(compact, width)

    long_text = full + "   ABBREVIATED: small terminal"
    if len(long_text) <= width:
        return long_text
    for short_marker in (" SMALL", " SM"):
        if len(compact) + len(short_marker) <= width:
            return compact + short_marker
    # Preserve every aggregate state count before the abbreviation marker. The
    # final one-character marker is intentionally terse only on the minimum
    # supported terminal where spelling SMALL would hide IDLE/DEAD entirely.
    if len(compact) + 1 <= width:
        return compact + "*"
    return _fit(compact, width)


def _select_worker_layout(
    *,
    workers: dict[int, dict[str, Any]],
    requested_worker_view: str,
    width: int,
    height: int,
    fixed_rows: int,
    optional_line_count: int,
    changed_workers: set[int],
) -> tuple[int, str, list[WatchLine], bool]:
    """Choose optional summary density without losing attainable worker cells."""

    maximum_optional = min(optional_line_count, max(0, height - fixed_rows))

    def candidate(count: int) -> tuple[str, list[WatchLine], bool]:
        available = max(0, height - fixed_rows - count)
        return _choose_worker_lines(
            workers,
            requested_worker_view,
            width,
            available,
            changed_workers,
        )

    selected = candidate(maximum_optional)
    if requested_worker_view != "summary" and selected[0] == "summary":
        # Drop lower-priority metric rows only when doing so can recover at least
        # one individual-worker representation. Do not discard metrics merely to
        # upgrade heatmap to compact or compact to full.
        for count in range(maximum_optional - 1, -1, -1):
            proposed = candidate(count)
            if proposed[0] != "summary":
                return count, *proposed

        # If individual cells are impossible, reserve a row for changed or
        # attention workers before spending every remaining row on metrics.
        detail_lines = _worker_summary_lines(workers, width, changed_workers)
        if detail_lines:
            for count in range(maximum_optional, -1, -1):
                proposed = candidate(count)
                if proposed[1]:
                    return count, *proposed

    return maximum_optional, *selected


def _render_watch_frame_core(
    payload: dict[str, Any],
    *,
    width: int,
    height: int,
    requested_worker_view: str,
    metric_deltas: dict[str, int] | None = None,
    changed_workers: set[int] | None = None,
    age_seconds: float = 0.0,
    stale: bool = False,
    source_available: bool = True,
    source_message: str | None = None,
) -> WatchFrame:
    """Render one no-scroll dashboard with explicit information priorities."""

    terminal_width = max(20, int(width))
    height = max(4, int(height))
    content_width = max(1, terminal_width - (2 * _WATCH_SIDE_BORDER))
    metric_deltas = metric_deltas or {}
    changed_workers = changed_workers or set()
    workers = _workers(payload)
    status = str(payload.get("status", "UNKNOWN")).upper()
    run_id = str(payload.get("run_id", "-"))

    header_lines = _watch_header_lines(
        run_id=run_id,
        status=status,
        width=content_width,
        age_seconds=age_seconds,
        stale=stale,
    )

    raw_plan = payload.get("execution_plan")
    plan = raw_plan if isinstance(raw_plan, dict) else {}
    plan_lines: list[WatchLine] = []
    plan_text = _run_summary_text(payload, plan, content_width)
    if plan_text is not None:
        plan_lines.append(_plain_line(plan_text))
    metric_lines = _metric_lines(payload, metric_deltas, content_width)
    optional_summary = [*plan_lines, *metric_lines]

    source_lines: list[WatchLine] = []
    if not source_available and source_message:
        source_lines.append(
            _plain_line(
                f"SOURCE: {source_message}",
                "source_error",
                emphasize=True,
            )
        )

    # A source diagnostic is a three-row block: blank, bright-red message, blank.
    # It is rendered after all worker rows and before the footer. On the smallest
    # screens, state/run/age, aggregate workers, and exit remain readable rather
    # than being displaced by a truncated diagnostic.
    source_rows: list[WatchLine] = []
    if source_lines and height >= _WATCH_TOP_BORDER_ROWS + len(header_lines) + 5:
        source_rows = [
            *_blank_lines(1),
            *_center_block(source_lines, content_width),
            *_blank_lines(1),
        ]
    reserved_spacing = (1 if height >= 6 else 0) + (2 if height >= 8 else 0)
    fixed_rows = (
        _WATCH_TOP_BORDER_ROWS
        + len(header_lines)
        + len(source_rows)
        + 1  # worker headline
        + 1  # footer
        + reserved_spacing
    )
    optional_count, effective_view, worker_lines, abbreviated = _select_worker_layout(
        workers=workers,
        requested_worker_view=requested_worker_view,
        width=content_width,
        height=height,
        fixed_rows=fixed_rows,
        optional_line_count=len(optional_summary),
        changed_workers=changed_workers,
    )

    worker_header = _worker_header_text(
        workers,
        width=content_width,
        abbreviated=abbreviated,
    )
    worker_head_line = _center_line(
        worker_header,
        content_width,
        role="warning" if abbreviated else "heading",
        emphasize=abbreviated,
    )

    selected_plan_count = min(len(plan_lines), optional_count)
    selected_metric_count = max(0, optional_count - selected_plan_count)
    selected_plan = _center_block(plan_lines[:selected_plan_count], content_width)
    selected_metrics = metric_lines[:selected_metric_count]
    if effective_view == "summary":
        worker_lines = _center_block(worker_lines, content_width)

    footer = _watch_footer(
        requested_worker_view=requested_worker_view,
        effective_worker_view=effective_view,
        abbreviated=abbreviated,
        width=content_width,
        terminal_width=terminal_width,
        height=height,
    )

    minimal_rows = (
        _WATCH_TOP_BORDER_ROWS
        + len(header_lines)
        + len(selected_plan)
        + len(selected_metrics)
        + len(source_rows)
        + 1  # worker headline
        + len(worker_lines)
        + 1  # footer
    )
    (
        after_header,
        after_plan,
        metric_gaps,
        before_worker,
        after_worker,
        worker_gaps,
        before_footer,
    ) = _layout_spacing(
        max(0, height - minimal_rows),
        len(selected_plan),
        len(selected_metrics),
        len(worker_lines),
    )

    has_pre_worker_content = bool(selected_plan or selected_metrics)
    if not has_pre_worker_content:
        before_footer += before_worker
        before_worker = 0

    lines: list[WatchLine] = _blank_lines(_WATCH_TOP_BORDER_ROWS)
    lines.extend(header_lines)
    lines.extend(_blank_lines(after_header))
    lines.extend(selected_plan)
    lines.extend(_blank_lines(after_plan))
    lines.extend(_with_worker_row_spacing(selected_metrics, metric_gaps))
    lines.extend(_blank_lines(before_worker))
    lines.append(worker_head_line)
    lines.extend(_blank_lines(after_worker))
    lines.extend(_with_worker_row_spacing(worker_lines, worker_gaps))
    lines.extend(source_rows)
    lines.extend(_blank_lines(before_footer))
    lines.append(footer)

    if len(lines) > height:
        # Selection math should make this unreachable, but retaining the footer
        # is more useful than clipping exit guidance if future layout work errs.
        lines = [*lines[: max(0, height - 1)], footer]
    elif len(lines) < height:
        lines[-1:-1] = _blank_lines(height - len(lines))

    bordered_lines = [
        _inset_watch_line(line, content_width) if line.text else line for line in lines[:height]
    ]

    return WatchFrame(
        lines=tuple(bordered_lines),
        worker_view=effective_view,
        abbreviated=abbreviated,
        stale=stale,
    )


def render_watch_frame(
    payload: dict[str, Any],
    *,
    width: int,
    height: int,
    requested_worker_view: str,
    metric_deltas: dict[str, int] | None = None,
    changed_workers: set[int] | None = None,
    age_seconds: float = 0.0,
    stale: bool = False,
    source_available: bool = True,
    source_message: str | None = None,
) -> WatchFrame:
    """Render the responsive watch dashboard for the physical terminal size."""

    return _render_watch_frame_core(
        payload,
        width=max(20, int(width)),
        height=max(4, int(height)),
        requested_worker_view=requested_worker_view,
        metric_deltas=metric_deltas,
        changed_workers=changed_workers,
        age_seconds=age_seconds,
        stale=stale,
        source_available=source_available,
        source_message=source_message,
    )


# xterm-256 foregrounds selected for readability on the named background class.
_WATCH_256: dict[str, dict[str, int]] = {
    "dark": {
        "heading": 51,
        "busy": 39,
        "idle": 250,
        "dead": 196,
        "unknown": 214,
        "success": 82,
        "metric": 51,
        "warning": 226,
        "source_error": 196,
        "stale": 214,
        "muted": 245,
        "error": 196,
        "america_red": 196,
        "america_white": 231,
        "america_blue": 39,
    },
    "light": {
        "heading": 24,
        "busy": 25,
        "idle": 238,
        "dead": 124,
        "unknown": 130,
        "success": 28,
        "metric": 30,
        "warning": 130,
        "source_error": 196,
        "stale": 130,
        "muted": 242,
        "error": 124,
        "america_red": 160,
        "america_white": 255,
        "america_blue": 25,
    },
}

_WATCH_BASIC: dict[str, dict[str, int]] = {
    "dark": {
        "heading": curses.COLOR_CYAN,
        "busy": curses.COLOR_BLUE,
        "idle": curses.COLOR_WHITE,
        "dead": curses.COLOR_RED,
        "unknown": curses.COLOR_YELLOW,
        "success": curses.COLOR_GREEN,
        "metric": curses.COLOR_CYAN,
        "warning": curses.COLOR_YELLOW,
        "source_error": curses.COLOR_RED,
        "stale": curses.COLOR_YELLOW,
        "muted": curses.COLOR_WHITE,
        "error": curses.COLOR_RED,
        "america_red": curses.COLOR_RED,
        "america_white": curses.COLOR_WHITE,
        "america_blue": curses.COLOR_BLUE,
    },
    "light": {
        "heading": curses.COLOR_CYAN,
        "busy": curses.COLOR_BLUE,
        "idle": curses.COLOR_BLACK,
        "dead": curses.COLOR_RED,
        "unknown": curses.COLOR_YELLOW,
        "success": curses.COLOR_GREEN,
        "metric": curses.COLOR_CYAN,
        "warning": curses.COLOR_YELLOW,
        "source_error": curses.COLOR_RED,
        "stale": curses.COLOR_YELLOW,
        "muted": curses.COLOR_BLACK,
        "error": curses.COLOR_RED,
        "america_red": curses.COLOR_RED,
        "america_white": curses.COLOR_WHITE,
        "america_blue": curses.COLOR_BLUE,
    },
}


def _curses_roles(palette: str, color_enabled: bool) -> dict[str, int]:
    """Initialize curses color pairs for one built-in dark/light watch palette."""

    roles = {"default": 0}
    if not color_enabled or not curses.has_colors():
        return roles
    curses.start_color()
    try:
        curses.use_default_colors()
        background = -1
    except curses.error:
        background = curses.COLOR_BLACK if palette == "dark" else curses.COLOR_WHITE

    selected = _WATCH_256[palette] if curses.COLORS >= 256 else _WATCH_BASIC[palette]
    for pair_id, (role, foreground) in enumerate(selected.items(), start=1):
        try:
            curses.init_pair(pair_id, foreground, background)
            roles[role] = curses.color_pair(pair_id)
        except curses.error:
            roles[role] = 0
    return roles


def _span_attr(
    span: WatchSpan,
    *,
    roles: dict[str, int],
    color_enabled: bool,
    stale: bool,
) -> int:
    """Map semantic span metadata to curses attributes for the current freshness."""

    if not color_enabled:
        return 0
    role = span.role
    if stale and role not in {"stale", "default", "source_error"}:
        role = "muted"
    attr = roles.get(role, roles.get("default", 0))
    if span.emphasize and not (stale and span.role not in {"stale", "source_error"}):
        attr |= curses.A_BOLD
    if span.role == "stale":
        attr |= curses.A_BOLD | curses.A_REVERSE
    return attr


def _draw_frame(
    screen: Any,
    frame: WatchFrame,
    *,
    roles: dict[str, int],
    color_enabled: bool,
) -> None:
    """Draw one complete frame without allowing curses to scroll the terminal."""

    screen.erase()
    height, width = screen.getmaxyx()
    for row, line in enumerate(frame.lines[:height]):
        column = 0
        for span in line.spans:
            if column >= width:
                break
            text = span.text[: max(0, width - column)]
            if not text:
                continue
            attr = _span_attr(
                span,
                roles=roles,
                color_enabled=color_enabled,
                stale=frame.stale,
            )
            try:
                screen.addstr(row, column, text, attr)
            except curses.error:
                # Some curses implementations reject writing the final cell. The
                # frame remains useful; never enable terminal scrolling to compensate.
                pass
            column += len(text)
    screen.refresh()


def _clear_exit_line(screen: Any) -> None:
    """Erase the final dashboard row before returning control to the shell.

    Some terminals (notably certain SSH sessions) keep the curses screen visible
    after ``endwin``. Clearing the footer row and leaving the cursor at column zero
    prevents the next shell prompt from sharing a line with stale watch controls.
    """

    try:
        height, _width = screen.getmaxyx()
        if height <= 0:
            return
        screen.move(height - 1, 0)
        screen.clrtoeol()
        screen.refresh()
        screen.move(height - 1, 0)
    except (curses.error, AttributeError):
        # Terminal teardown should never turn a successful watch exit into an error.
        pass


def _watch_loop(
    screen: Any,
    config: AppConfig,
    *,
    interval: float,
    worker_view: str,
    palette: str,
    color_enabled: bool,
) -> None:
    """Run the interactive refresh/read/render loop inside ``curses.wrapper``."""

    screen.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    # A terminal that cannot report color support is treated exactly like an
    # explicit no-color session: no bold/reverse attributes are emitted either.
    styling_enabled = color_enabled and curses.has_colors()
    roles = _curses_roles(palette, styling_enabled)
    session = WatchSession()
    selected_worker_view = worker_view
    modal_view: str | None = None
    threshold = stale_threshold(config.output.scoreboard_interval_seconds)
    next_refresh = 0.0
    force = True

    try:
        while True:
            now_mono = time.monotonic()
            if force or now_mono >= next_refresh:
                try:
                    source = load_current_scoreboard(cast(Path, config.paths.scratch_root))
                except WatchError as exc:
                    session.observe(
                        None,
                        now_monotonic=now_mono,
                        now_epoch=time.time(),
                        source_message=str(exc),
                    )
                else:
                    session.observe(
                        source,
                        now_monotonic=now_mono,
                        now_epoch=time.time(),
                    )

                height, width = screen.getmaxyx()
                if modal_view == "help":
                    frame = render_watch_help_frame(width=width, height=height)
                elif modal_view == "america":
                    frame = render_watch_america_frame(width=width, height=height)
                elif session.payload is None:
                    message = session.source_message or "waiting for current scoreboard"
                    frame = render_watch_frame(
                        {
                            "scoreboard_schema": SCOREBOARD_SCHEMA,
                            "run_id": "-",
                            "started": "-",
                            "status": "WAITING",
                            "elapsed_seconds": 0,
                            "workers": {},
                        },
                        width=width,
                        height=height,
                        requested_worker_view="summary",
                        age_seconds=0.0,
                        stale=False,
                        source_available=False,
                        source_message=message,
                    )
                else:
                    age = session.age_seconds(now_mono)
                    stale = is_stale(session.payload, age, threshold)
                    frame = render_watch_frame(
                        session.payload,
                        width=width,
                        height=height,
                        requested_worker_view=selected_worker_view,
                        metric_deltas=session.metric_deltas,
                        changed_workers=session.changed_workers,
                        age_seconds=age,
                        stale=stale,
                        source_available=session.source_available,
                        source_message=session.source_message,
                    )
                _draw_frame(screen, frame, roles=roles, color_enabled=styling_enabled)
                next_refresh = now_mono + interval
                force = False

            remaining = max(0.05, next_refresh - time.monotonic())
            screen.timeout(max(50, min(1000, int(remaining * 1000))))
            key = screen.getch()
            if key == -1:
                continue
            if modal_view is not None:
                if key == curses.KEY_RESIZE:
                    force = True
                    continue
                modal_view = None
                force = True
                continue
            if key in (ord("q"), ord("Q")):
                return
            if key in (ord("a"), ord("A")):
                modal_view = "america"
                force = True
                continue
            if key in (ord("h"), ord("H")):
                modal_view = "help"
                force = True
                continue
            if key in (ord("m"), ord("M")):
                selected_worker_view = cycle_worker_view(selected_worker_view)
                force = True
                continue
            if key == curses.KEY_RESIZE:
                force = True
    finally:
        _clear_exit_line(screen)


def run_watch(
    config: AppConfig,
    *,
    interval: float = 1.0,
    worker_view: str = "auto",
    palette: str | None = None,
    no_color: bool = False,
) -> None:
    """Start the built-in interactive scoreboard monitor.

    ``watch`` intentionally requires a TTY. Scripts and redirected consumers should
    continue to use ``lldp-runner status`` or ``lldp-runner status --json``.
    """

    if worker_view not in WORKER_VIEWS:
        raise WatchError(f"invalid worker view: {worker_view}")
    if interval <= 0:
        raise WatchError("watch interval must be > 0")
    selected_palette = palette or config.terminal.palette
    if selected_palette not in {"dark", "light"}:
        raise WatchError(f"invalid terminal palette: {selected_palette}")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise WatchError(
            "watch requires an interactive terminal; use 'lldp-runner status' "
            "or 'lldp-runner status --json' for redirected output"
        )

    color_enabled = (
        not no_color and config.terminal.color != "never" and "NO_COLOR" not in os.environ
    )
    try:
        curses.wrapper(
            _watch_loop,
            config,
            interval=float(interval),
            worker_view=worker_view,
            palette=selected_palette,
            color_enabled=color_enabled,
        )
    except KeyboardInterrupt:
        return
    except curses.error as exc:
        raise WatchError(f"terminal initialization failed: {exc}") from exc
