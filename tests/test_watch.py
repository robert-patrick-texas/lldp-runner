"""Regression coverage for the built-in interactive scoreboard watcher."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from lldp_runner.scoreboard import SCOREBOARD_SCHEMA, write_scoreboard
from lldp_runner.state import StateStore
from lldp_runner.watch import (
    ScoreboardSource,
    WatchError,
    WatchSession,
    cycle_worker_view,
    is_stale,
    load_current_scoreboard,
    render_watch_frame,
    render_watch_help_frame,
    stale_threshold,
)


def _payload(worker_count: int = 64) -> dict[str, object]:
    """Build a representative schema-1 scoreboard for layout/delta tests."""

    return {
        "scoreboard_schema": SCOREBOARD_SCHEMA,
        "run_id": "20260103-215200-00",
        "started": "2026-08-25 21:52:00 MDT",
        "status": "RUNNING",
        "elapsed_seconds": 123.0,
        "last_update": "2026-08-25T21:54:03.000-06:00",
        "hosts_discovered": 100,
        "managed_devices": 80,
        "managed_endpoints": 10,
        "unmanaged_devices": 5,
        "unknown_devices": 5,
        "ready": 12,
        "active": 8,
        "complete": 58,
        "failed": 2,
        "primary_successes": 55,
        "fallback_successes": 3,
        "errors": 4,
        "execution_plan": {
            "effective_workers": worker_count,
            "effective_batch_size": 8,
        },
        "workers": {
            str(worker_id): {
                "status": "DEAD" if worker_id == 17 else "IDLE" if worker_id % 9 == 0 else "BUSY",
                "batch": worker_id,
                "size": 8,
            }
            for worker_id in range(worker_count)
        },
    }


def test_scoreboard_json_declares_schema(tmp_path: Path) -> None:
    """The watch machine interface is explicitly versioned from v0.25.0 onward."""

    state = StateStore(tmp_path / "state.sqlite")
    scratch = tmp_path / "scratch"
    write_scoreboard(
        state,
        scratch,
        run_id="test-run",
        started="2026-08-25 21:52:00 MDT",
        status="RUNNING",
        elapsed_seconds=1.0,
        worker_status={0: {"status": "IDLE", "batch": "-", "size": 0}},
    )
    payload = json.loads((scratch / "scoreboard.json").read_text(encoding="utf-8"))
    assert payload["scoreboard_schema"] == 1
    state.close()


def test_load_current_scoreboard_uses_stable_live_directory_and_schema(
    tmp_path: Path,
) -> None:
    """The watcher follows the stable live-scoreboard namespace used by status."""

    live = tmp_path / "scoreboard"
    live.mkdir()
    payload = _payload(2)
    (live / "scoreboard.json").write_text(json.dumps(payload), encoding="utf-8")

    source = load_current_scoreboard(tmp_path)

    assert source.payload["run_id"] == payload["run_id"]
    assert source.path == tmp_path / "scoreboard" / "scoreboard.json"


def test_watch_session_keeps_deltas_highlighted_until_next_snapshot() -> None:
    """A delta remains visible across refreshes until another scoreboard is published."""

    first = _payload(2)
    second = _payload(2)
    second["hosts_discovered"] = 137
    second["last_update"] = "2026-08-25T21:54:06.000-06:00"
    workers = cast(dict[str, object], second["workers"])
    assert isinstance(workers, dict)
    worker = cast(dict[str, object], workers["1"])
    assert isinstance(worker, dict)
    worker["status"] = "IDLE"

    session = WatchSession()
    session.observe(
        ScoreboardSource(Path("scoreboard.json"), first, 1_000_000_000),
        now_monotonic=10.0,
        now_epoch=1.0,
    )
    session.observe(
        ScoreboardSource(Path("scoreboard.json"), second, 2_000_000_000),
        now_monotonic=13.0,
        now_epoch=2.0,
    )
    assert session.metric_deltas["hosts_discovered"] == 37
    assert session.changed_workers == {1}

    session.observe(
        ScoreboardSource(Path("scoreboard.json"), second, 2_000_000_000),
        now_monotonic=14.0,
        now_epoch=3.0,
    )
    assert session.metric_deltas["hosts_discovered"] == 37
    assert session.changed_workers == {1}


def test_stale_applies_only_to_active_run_states() -> None:
    """Old completed snapshots remain final records rather than becoming stale alarms."""

    threshold = stale_threshold(3.0)
    assert threshold == 15.0
    payload = _payload(1)
    assert not is_stale(payload, 15.0, threshold)
    assert is_stale(payload, 16.0, threshold)
    payload["status"] = "COMPLETED"
    assert not is_stale(payload, 999.0, threshold)


def test_auto_worker_view_responds_to_terminal_geometry() -> None:
    """Auto mode chooses the richest individual-worker view that fits the screen."""

    payload = _payload(64)
    large = render_watch_frame(
        payload,
        width=160,
        height=40,
        requested_worker_view="auto",
    )
    medium = render_watch_frame(
        payload,
        width=80,
        height=24,
        requested_worker_view="auto",
    )

    assert large.worker_view == "full"
    # The permanent one-column side borders reduce the 80-column interior just
    # enough that auto mode selects heatmap rather than sacrificing worker rows.
    assert medium.worker_view == "heatmap"
    assert "BUSY" in "\n".join(line.text for line in medium.lines)
    assert "IDLE" in "\n".join(line.text for line in medium.lines)
    assert "DEAD" in "\n".join(line.text for line in medium.lines)


def test_explicit_worker_view_is_preserved_when_space_is_available() -> None:
    """A fixed density does not automatically upgrade merely because the screen is large."""

    payload = _payload(16)
    heatmap = render_watch_frame(
        payload,
        width=180,
        height=40,
        requested_worker_view="heatmap",
    )
    compact = render_watch_frame(
        payload,
        width=180,
        height=40,
        requested_worker_view="compact",
    )

    assert heatmap.worker_view == "heatmap"
    assert compact.worker_view == "compact"
    heatmap_text = "\n".join(line.text for line in heatmap.lines)
    compact_text = "\n".join(line.text for line in compact.lines)
    assert "[01 BUSY]" in heatmap_text
    assert "[01 BUSY sz=.8]" in compact_text


def test_fixed_worker_view_abbreviates_with_visible_warning_when_too_small() -> None:
    """Forced views never scroll; a too-small terminal explicitly reports abbreviation."""

    frame = render_watch_frame(
        _payload(64),
        width=80,
        height=12,
        requested_worker_view="full",
    )
    text = "\n".join(line.text for line in frame.lines)

    assert frame.abbreviated
    assert frame.worker_view == "summary"
    assert "ABBREVIATED" in text


def test_stale_frame_has_literal_non_color_alarm() -> None:
    """STALE remains unmistakable even when terminal color/styling is unavailable."""

    frame = render_watch_frame(
        _payload(4),
        width=100,
        height=24,
        requested_worker_view="auto",
        age_seconds=14.0,
        stale=True,
    )
    assert "*** STALE ***" in "\n".join(line.text for line in frame.lines)


def test_no_color_mode_emits_no_curses_attributes() -> None:
    """Disabling color also disables bold/reverse styling for accessibility."""

    from lldp_runner.watch import WatchSpan, _span_attr

    span = WatchSpan("*** STALE ***", role="stale", emphasize=True)
    assert _span_attr(span, roles={}, color_enabled=False, stale=True) == 0


def test_stale_alarm_survives_narrow_header() -> None:
    """A narrow title keeps recognizable state, age, run identity, and stale alarm."""

    payload = _payload(1)
    payload["run_id"] = "20260103-215200-very-long-run-identifier"
    frame = render_watch_frame(
        payload,
        width=32,
        height=12,
        requested_worker_view="summary",
        age_seconds=30.0,
        stale=True,
    )
    header_text = frame.lines[1].text
    assert "R!" in header_text
    assert "00:30" in header_text
    assert "20260103" in header_text
    assert "entifier" in header_text
    assert any(span.role == "stale" for line in frame.lines[:2] for span in line.spans)


def test_auto_heatmap_keeps_128_workers_individual_on_practical_terminal() -> None:
    """A 100x24 terminal can still identify 128 workers with full state words."""

    frame = render_watch_frame(
        _payload(128),
        width=100,
        height=24,
        requested_worker_view="auto",
    )
    text = "\n".join(line.text for line in frame.lines)
    assert frame.worker_view == "heatmap"
    assert not frame.abbreviated
    assert "[127 BUSY]" in text


def test_summary_view_reports_changed_workers_without_transition_text() -> None:
    """Abbreviated mode still identifies changed workers by current full state."""

    frame = render_watch_frame(
        _payload(64),
        width=100,
        height=24,
        requested_worker_view="summary",
        changed_workers={1, 9},
    )
    text = "\n".join(line.text for line in frame.lines)
    assert "Changed workers: 01 BUSY, 09 IDLE" in text
    assert "->" not in text


def test_watch_rejects_unversioned_scoreboard_instead_of_guessing_legacy_format(
    tmp_path: Path,
) -> None:
    """The new live-monitoring contract is strict rather than silently legacy-aware."""

    current = tmp_path / "scoreboard"
    current.mkdir()
    payload = _payload(1)
    payload.pop("scoreboard_schema")
    (current / "scoreboard.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(WatchError, match="unsupported scoreboard schema"):
        load_current_scoreboard(tmp_path)


def test_worker_grid_uses_stable_padded_column_starts() -> None:
    """Worker cells align vertically even when IDs/batches have different widths."""

    frame = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="full",
    )
    worker_rows = [
        line.text.lstrip() for line in frame.lines if line.text.lstrip().startswith("[Worker ")
    ]
    assert len(worker_rows) > 2

    starts = []
    for row in worker_rows[:-1]:
        positions = []
        offset = 0
        while True:
            position = row.find("[Worker ", offset)
            if position < 0:
                break
            positions.append(position)
            offset = position + 1
        if len(positions) > 1:
            starts.append(positions)
    assert starts
    assert all(positions == starts[0] for positions in starts)
    assert starts[0][1] - starts[0][0] > len("[Worker 00 IDLE batch=0 size=8]")


def test_roomy_watch_frame_adds_section_spacing_and_reports_geometry() -> None:
    """Large terminals trade spare rows for breathing room and a bottom status bar."""

    frame = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="auto",
    )
    text_lines = [line.text for line in frame.lines]

    assert len(frame.lines) == 44
    assert text_lines.count("") >= 4
    assert text_lines[-1].rstrip().endswith("worker-view auto->full (120x44)")
    assert text_lines[-1].lstrip().startswith("a america   h help   m cycle view")


def test_worker_view_cycle_matches_interactive_m_key_order() -> None:
    """The m-key cycle is stable and returns to auto after summary."""

    view = "auto"
    observed = []
    for _ in range(5):
        view = cycle_worker_view(view)
        observed.append(view)
    assert observed == ["full", "compact", "heatmap", "summary", "auto"]


def test_busy_worker_palette_is_distinct_from_headers_and_metrics() -> None:
    """BUSY workers use a separate blue hue from dashboard headings/metrics."""

    from lldp_runner.watch import _WATCH_256

    for palette in ("dark", "light"):
        roles = _WATCH_256[palette]
        assert roles["busy"] != roles["heading"]
        assert roles["busy"] != roles["metric"]


def test_watch_loop_m_key_changes_requested_mode(monkeypatch, config) -> None:
    """The curses event loop applies an m keypress before the next redraw."""

    import lldp_runner.watch as watch_module

    class FakeScreen:
        def __init__(self) -> None:
            self.keys = iter((ord("m"), ord("q")))

        def keypad(self, enabled: bool) -> None:
            assert enabled

        def getmaxyx(self) -> tuple[int, int]:
            return 24, 80

        def timeout(self, milliseconds: int) -> None:
            assert milliseconds >= 50

        def getch(self) -> int:
            return next(self.keys)

    payload = _payload(64)
    source = ScoreboardSource(Path("scoreboard.json"), payload, 1_000_000_000)
    drawn = []

    monkeypatch.setattr(watch_module.curses, "curs_set", lambda _value: None)
    monkeypatch.setattr(watch_module.curses, "has_colors", lambda: False)
    monkeypatch.setattr(watch_module, "load_current_scoreboard", lambda _root: source)
    monkeypatch.setattr(
        watch_module,
        "_draw_frame",
        lambda _screen, frame, **_kwargs: drawn.append(frame),
    )

    watch_module._watch_loop(
        FakeScreen(),
        config,
        interval=1.0,
        worker_view="auto",
        palette="dark",
        color_enabled=False,
    )

    assert len(drawn) == 2
    assert "worker-view auto->" in drawn[0].lines[-1].text
    assert "worker-view full" in drawn[1].lines[-1].text


@pytest.mark.parametrize("exit_mode", ["q", "ctrl_c"])
def test_watch_loop_clears_footer_row_before_terminal_restore(
    monkeypatch, config, exit_mode: str
) -> None:
    """Normal and interrupt exits erase the footer before returning to the shell."""

    import lldp_runner.watch as watch_module

    class FakeScreen:
        def __init__(self) -> None:
            self.operations: list[tuple[object, ...]] = []

        def keypad(self, enabled: bool) -> None:
            assert enabled

        def getmaxyx(self) -> tuple[int, int]:
            return 49, 158

        def timeout(self, milliseconds: int) -> None:
            assert milliseconds >= 50

        def getch(self) -> int:
            if exit_mode == "ctrl_c":
                raise KeyboardInterrupt
            return ord("q")

        def move(self, row: int, column: int) -> None:
            self.operations.append(("move", row, column))

        def clrtoeol(self) -> None:
            self.operations.append(("clrtoeol",))

        def refresh(self) -> None:
            self.operations.append(("refresh",))

    payload = _payload(32)
    source = ScoreboardSource(Path("scoreboard.json"), payload, 1_000_000_000)
    screen = FakeScreen()

    monkeypatch.setattr(watch_module.curses, "curs_set", lambda _value: None)
    monkeypatch.setattr(watch_module.curses, "has_colors", lambda: False)
    monkeypatch.setattr(watch_module, "load_current_scoreboard", lambda _root: source)
    monkeypatch.setattr(watch_module, "_draw_frame", lambda *_args, **_kwargs: None)

    kwargs = {
        "interval": 1.0,
        "worker_view": "auto",
        "palette": "dark",
        "color_enabled": False,
    }
    if exit_mode == "ctrl_c":
        with pytest.raises(KeyboardInterrupt):
            watch_module._watch_loop(screen, config, **kwargs)
    else:
        watch_module._watch_loop(screen, config, **kwargs)

    assert screen.operations[-4:] == [
        ("move", 48, 0),
        ("clrtoeol",),
        ("refresh",),
        ("move", 48, 0),
    ]


def test_wide_header_uses_one_justified_four_section_title_line() -> None:
    """Normal title sections are evenly spaced and use semantic color roles."""

    from lldp_runner import APP_NAME, __version__

    payload = _payload(8)
    payload["status"] = "COMPLETED"
    frame = render_watch_frame(
        payload,
        width=126,
        height=30,
        requested_worker_view="auto",
        age_seconds=7.0,
    )

    assert frame.lines[0].text == ""
    title_line = frame.lines[1]
    title_text = f"{APP_NAME} {__version__}"
    run_text = f"Run ID = {payload['run_id']}"
    state_text = "STATE = COMPLETED"
    age_text = "updated 00:07 ago"
    assert title_line.text.startswith(f" {title_text}")
    assert len(title_line.text) == 125
    starts = [
        title_line.text.index(title_text),
        title_line.text.index(run_text),
        title_line.text.index(state_text),
        title_line.text.index(age_text),
    ]
    gaps = [
        starts[1] - (starts[0] + len(title_text)),
        starts[2] - (starts[1] + len(run_text)),
        starts[3] - (starts[2] + len(state_text)),
    ]
    assert max(gaps) - min(gaps) <= 1
    assert any(
        span.text == title_text and span.role == "heading" and span.emphasize
        for span in title_line.spans
    )
    assert any(
        span.text == state_text and span.role == "success" and span.emphasize
        for span in title_line.spans
    )
    run_span = next(span for span in title_line.spans if span.text == run_text)
    assert run_span.role == "muted"
    assert any(span.role == run_span.role and span.text.strip() for span in frame.lines[-1].spans)


def test_roomy_header_has_top_border_and_blank_line_before_summary() -> None:
    """The title sits below a blank top border and above a summary separator."""

    frame = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="auto",
    )
    assert frame.lines[0].text == ""
    assert frame.lines[1].text.startswith(" LLDP-Runner ")
    assert frame.lines[2].text == ""
    assert frame.lines[3].text.lstrip().startswith("Started ")


def test_normal_watch_adds_one_blank_after_started_and_around_workers() -> None:
    """A normal-height frame separates summary rows without wasting grid space."""

    frame = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="auto",
    )
    started_index = next(
        index for index, line in enumerate(frame.lines) if line.text.lstrip().startswith("Started ")
    )
    worker_index = next(
        index
        for index, line in enumerate(frame.lines)
        if line.text.lstrip().startswith("Workers 64:")
    )

    assert frame.lines[started_index + 1].text == ""
    assert frame.lines[started_index + 2].text != ""
    assert frame.lines[worker_index - 1].text == ""
    assert frame.lines[worker_index - 2].text != ""
    assert frame.lines[worker_index + 1].text == ""
    assert frame.lines[worker_index + 2].text != ""


def test_roomy_watch_adds_second_blank_after_started_and_around_workers() -> None:
    """Large residual footer space is redistributed around all summary blocks."""

    frame = render_watch_frame(
        _payload(48),
        width=223,
        height=69,
        requested_worker_view="auto",
    )
    started_index = next(
        index for index, line in enumerate(frame.lines) if line.text.lstrip().startswith("Started ")
    )
    worker_index = next(
        index
        for index, line in enumerate(frame.lines)
        if line.text.lstrip().startswith("Workers 48:")
    )

    assert [frame.lines[started_index - offset].text for offset in (1, 2)] == [
        "",
        "",
    ]
    assert frame.lines[started_index - 3].text.lstrip().startswith("LLDP-Runner ")
    assert [frame.lines[started_index + offset].text for offset in (1, 2)] == [
        "",
        "",
    ]
    assert frame.lines[started_index + 3].text != ""
    assert [frame.lines[worker_index - offset].text for offset in (1, 2)] == [
        "",
        "",
    ]
    assert frame.lines[worker_index - 3].text != ""
    assert [frame.lines[worker_index + offset].text for offset in (1, 2)] == [
        "",
        "",
    ]
    assert frame.lines[worker_index + 3].text != ""


def test_extra_summary_spacing_requires_more_than_ten_footer_rows() -> None:
    """The roomy-layout threshold is strict rather than triggering at ten rows."""

    from lldp_runner.watch import _layout_spacing

    at_threshold = _layout_spacing(
        20,
        plan_line_count=1,
        metric_line_count=4,
        worker_line_count=4,
    )
    over_threshold = _layout_spacing(
        21,
        plan_line_count=1,
        metric_line_count=4,
        worker_line_count=4,
    )

    (
        at_after_header,
        at_after_plan,
        at_metric_gaps,
        at_before_worker,
        at_after_worker,
        _at_worker_gaps,
        at_before_footer,
    ) = at_threshold
    (
        over_after_header,
        over_after_plan,
        over_metric_gaps,
        over_before_worker,
        over_after_worker,
        _over_worker_gaps,
        over_before_footer,
    ) = over_threshold

    assert (at_after_header, at_after_plan, at_metric_gaps, at_before_worker, at_after_worker) == (
        1,
        1,
        {0, 1, 2},
        1,
        1,
    )
    assert at_before_footer == 10
    assert (
        over_after_header,
        over_after_plan,
        over_metric_gaps,
        over_before_worker,
        over_after_worker,
    ) == (2, 2, {0, 1, 2}, 2, 2)
    assert over_before_footer == 7


def test_compact_and_heatmap_views_share_the_same_bordered_title_line() -> None:
    """Worker density never changes the title geometry or outer blank borders."""

    frames = [
        render_watch_frame(
            _payload(16),
            width=100,
            height=30,
            requested_worker_view=view,
            age_seconds=3.0,
        )
        for view in ("full", "compact", "heatmap")
    ]

    assert len({frame.lines[1].text for frame in frames}) == 1
    for frame in frames:
        assert frame.lines[0].text == ""
        assert all(line.text.startswith(" ") for line in frame.lines if line.text)
        assert all(len(line.text) <= 99 for line in frame.lines)


def test_title_drops_version_before_required_run_state_and_age_sections() -> None:
    """An 80-column title removes app_version first and keeps all four concepts."""

    from lldp_runner import APP_NAME, __version__

    payload = _payload(8)
    frame = render_watch_frame(
        payload,
        width=80,
        height=24,
        requested_worker_view="heatmap",
        age_seconds=3.0,
    )
    title = frame.lines[1].text

    assert APP_NAME in title
    assert __version__ not in title
    assert f"Run ID = {payload['run_id']}" in title
    assert "STATE = RUNNING" in title
    assert "updated 00:03 ago" in title


@pytest.mark.parametrize("width", (100, 80, 63, 42, 30, 20))
def test_run_id_keeps_footer_muted_role_as_title_compacts(width: int) -> None:
    """Every responsive title form keeps the run identity in the footer role."""

    frame = render_watch_frame(
        _payload(8),
        width=width,
        height=24,
        requested_worker_view="summary",
        age_seconds=3.0,
    )
    run_spans = [span for span in frame.lines[1].spans if span.role == "muted"]

    assert len(run_spans) == 1
    assert any(character.isdigit() for character in run_spans[0].text)


def test_roomy_metrics_have_blank_rows_and_data_independent_column_starts() -> None:
    """Metric rows breathe vertically and do not move as counter digits increase."""

    first_payload = _payload(48)
    second_payload = _payload(48)
    second_payload.update(
        {
            "hosts_discovered": 12_345_678,
            "managed_devices": 1_234_567,
            "managed_endpoints": 123_456,
        }
    )
    first = render_watch_frame(
        first_payload,
        width=223,
        height=69,
        requested_worker_view="auto",
    )
    second = render_watch_frame(
        second_payload,
        width=223,
        height=69,
        requested_worker_view="auto",
    )

    labels = ("Hosts", "Managed", "Endpoints")
    first_row_index = next(index for index, line in enumerate(first.lines) if "Hosts" in line.text)
    second_row_index = next(
        index for index, line in enumerate(second.lines) if "Hosts" in line.text
    )
    assert first.lines[first_row_index + 1].text == ""
    assert second.lines[second_row_index + 1].text == ""
    assert [first.lines[first_row_index].text.index(label) for label in labels] == [
        second.lines[second_row_index].text.index(label) for label in labels
    ]
    starts = [first.lines[first_row_index].text.index(label) for label in labels]
    assert starts[1] - starts[0] >= 55
    assert starts[2] - starts[1] >= 55


def test_worker_headline_is_centered_with_blank_line_above_and_below() -> None:
    """The aggregate worker line remains horizontally centered."""

    frame = render_watch_frame(
        _payload(48),
        width=223,
        height=69,
        requested_worker_view="auto",
    )
    index = next(
        index
        for index, line in enumerate(frame.lines)
        if line.text.lstrip().startswith("Workers 48:")
    )
    line = frame.lines[index]
    visible = line.text.strip()
    left = line.text.index(visible)
    right = 223 - (left + len(visible))

    assert frame.lines[index - 1].text == ""
    assert frame.lines[index + 1].text == ""
    assert abs(left - right) <= 1


def test_summary_uses_worker_headline_without_duplicate_summary_line() -> None:
    """Summary mode relies on the existing worker counts headline instead of repeating it."""

    frame = render_watch_frame(
        _payload(64),
        width=100,
        height=24,
        requested_worker_view="summary",
    )
    text = "\n".join(line.text for line in frame.lines)
    assert "Workers 64:  BUSY" in text
    assert "Worker summary:" not in text


def test_tall_worker_grid_can_put_blank_line_between_every_row() -> None:
    """A sufficiently tall terminal retains the existing airy worker-row layout."""

    frame = render_watch_frame(
        _payload(64),
        width=126,
        height=60,
        requested_worker_view="auto",
    )
    assert frame.worker_view == "full"
    worker_indexes = [
        index for index, line in enumerate(frame.lines) if line.text.lstrip().startswith("[Worker ")
    ]
    assert len(worker_indexes) > 1
    assert all(frame.lines[index + 1].text == "" for index in worker_indexes[:-1])


def test_worker_cells_keep_same_width_when_batch_and_size_gain_digits() -> None:
    """Batch/size changes never resize worker cells or move following columns."""

    from lldp_runner.watch import _pack_worker_cells

    workers = {
        0: {"status": "BUSY", "batch": 9, "size": 8},
        1: {"status": "IDLE", "batch": 99, "size": 8},
        2: {"status": "BUSY", "batch": 99999, "size": 99},
    }
    before = _pack_worker_cells(workers, "full", 126, set())
    assert before is not None
    starts_before = [before[0].text.find("[Worker 01"), before[0].text.find("[Worker 02")]

    workers[0]["batch"] = 10000
    workers[0]["size"] = 999
    workers[1]["batch"] = 100000  # deliberately overflows the fixed field budget
    after = _pack_worker_cells(workers, "full", 126, set())
    assert after is not None
    starts_after = [after[0].text.find("[Worker 01"), after[0].text.find("[Worker 02")]

    assert starts_after == starts_before
    assert "batch=#####" in after[0].text
    assert "batch=10000 size=999" in after[0].text


def test_worker_numeric_fields_use_visible_dot_fill() -> None:
    """Fixed batch/size budgets show unused positions rather than blank padding."""

    from lldp_runner.watch import _worker_cell

    full = _worker_cell(1, {"status": "BUSY", "batch": 184, "size": 8}, "full", id_width=2)
    compact = _worker_cell(1, {"status": "BUSY", "batch": 184, "size": 8}, "compact", id_width=2)

    assert "batch=..184" in full
    assert "size=..8" in full
    assert "sz=.8" in compact


def test_run_summary_uses_centered_lines_and_wide_fixed_metric_columns() -> None:
    """Started/worker lines center while metric columns use a stable wide grid."""

    frame = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="auto",
    )
    started = next(line for line in frame.lines if line.text.lstrip().startswith("Started "))
    worker = next(line for line in frame.lines if line.text.lstrip().startswith("Workers 64:"))
    metric = next(line for line in frame.lines if "Hosts" in line.text)

    for line in (started, worker):
        visible = line.text.strip()
        left = line.text.index(visible)
        right = 120 - (left + len(visible))
        assert abs(left - right) <= 1
    assert metric.text.index("Managed") > metric.text.index("Hosts") + 25
    assert metric.text.index("Endpoints") > metric.text.index("Managed") + 25
    assert len(metric.text) == 119
    assert frame.worker_view == "full"
    assert frame.lines[-1].text.rstrip().endswith("worker-view auto->full (120x44)")


def test_wide_run_summary_doubles_spacing_between_three_sections() -> None:
    """A wide screen uses six blanks between Started, Elapsed, and Plan."""

    frame = render_watch_frame(
        _payload(8),
        width=140,
        height=30,
        requested_worker_view="auto",
    )
    started = next(
        line.text.strip() for line in frame.lines if line.text.lstrip().startswith("Started ")
    )

    assert "      Elapsed " in started
    assert "      Plan " in started


def test_watch_keeps_side_borders_at_layout_boundary() -> None:
    """Every visible row keeps a blank left and far-right terminal cell."""

    frame = render_watch_frame(
        _payload(16),
        width=64,
        height=24,
        requested_worker_view="auto",
    )

    assert frame.lines[0].text == ""
    assert all(
        line.text.startswith(" ") and len(line.text) <= 63 for line in frame.lines if line.text
    )


def test_stale_floor_allows_five_default_seconds_more_than_previous_release() -> None:
    """Default three-second publication cadence receives a less sensitive 15s floor."""

    assert stale_threshold(3.0) == 15.0
    assert stale_threshold(10.0) == 30.0


def test_help_frame_defines_metrics_and_worker_plan_terms() -> None:
    """The h-key help screen explains every displayed metric plus worker plan vocabulary."""

    frame = render_watch_help_frame(width=100, height=30)
    text = "\n".join(line.text for line in frame.lines)
    for label in (
        "Hosts",
        "Managed",
        "Endpoints",
        "Unmanaged",
        "Unknown",
        "Queued",
        "Active",
        "Complete",
        "Failed",
        "Primary",
        "Fallback",
        "Errors",
    ):
        assert label in text
    assert "Batch" in text
    assert "Size" in text
    assert "Plan workers" in text
    assert "Effective" in text
    assert frame.lines[-1].text.startswith("Press any key to return")


def test_watch_loop_h_key_opens_help_and_any_key_returns(monkeypatch, config) -> None:
    """Help is modal: h opens it and the next ordinary key only returns to status."""

    import lldp_runner.watch as watch_module

    class FakeScreen:
        def __init__(self) -> None:
            self.keys = iter((ord("h"), ord("q"), ord("q")))

        def keypad(self, enabled: bool) -> None:
            assert enabled

        def getmaxyx(self) -> tuple[int, int]:
            return 30, 100

        def timeout(self, milliseconds: int) -> None:
            assert milliseconds >= 50

        def getch(self) -> int:
            return next(self.keys)

    payload = _payload(16)
    source = ScoreboardSource(Path("scoreboard.json"), payload, 1_000_000_000)
    drawn = []

    monkeypatch.setattr(watch_module.curses, "curs_set", lambda _value: None)
    monkeypatch.setattr(watch_module.curses, "has_colors", lambda: False)
    monkeypatch.setattr(watch_module, "load_current_scoreboard", lambda _root: source)
    monkeypatch.setattr(
        watch_module,
        "_draw_frame",
        lambda _screen, frame, **_kwargs: drawn.append(frame),
    )

    watch_module._watch_loop(
        FakeScreen(),
        config,
        interval=1.0,
        worker_view="auto",
        palette="dark",
        color_enabled=False,
    )

    assert len(drawn) == 3
    assert drawn[0].worker_view != "help"
    assert drawn[1].worker_view == "help"
    assert drawn[2].worker_view != "help"


def test_complete_worker_rows_are_centered_to_one_column() -> None:
    """Worker capacity is selected first, then complete rows receive balanced margins."""

    frame = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="auto",
    )
    rows = [line.text for line in frame.lines if line.text.lstrip().startswith("[Worker ")]
    complete_cell_count = max(row.count("[Worker ") for row in rows)
    complete_rows = [row for row in rows if row.count("[Worker ") == complete_cell_count]

    assert complete_rows
    for row in complete_rows:
        left = len(row) - len(row.lstrip())
        right = 120 - len(row)
        assert abs(left - right) <= 1


def test_watch_footer_shows_america_hint_only_when_width_allows() -> None:
    """The optional America key hint disappears before critical controls on narrow views."""

    wide = render_watch_frame(
        _payload(64),
        width=120,
        height=44,
        requested_worker_view="auto",
    )
    narrow = render_watch_frame(
        _payload(64),
        width=80,
        height=24,
        requested_worker_view="auto",
    )

    assert wide.lines[-1].text.lstrip().startswith("a america   h help")
    assert "a america" not in narrow.lines[-1].text
    assert "h help" in narrow.lines[-1].text


def test_america_overlay_colors_letters_and_keeps_requested_taglines() -> None:
    """Large terminals show centered red/white/blue USA art above the three taglines."""

    from lldp_runner.watch import render_watch_america_frame

    frame = render_watch_america_frame(width=80, height=24)
    text = "\n".join(line.text for line in frame.lines)
    roles = [span.role for line in frame.lines for span in line.spans]

    assert frame.worker_view == "america"
    assert not frame.abbreviated
    assert "america_red" in roles
    assert "america_white" in roles
    assert "america_blue" in roles
    assert "United States of America" in text
    assert "1776-2026" in text
    assert "250 years and the best has yet to come!" in text

    tagline_indices = [
        next(index for index, line in enumerate(frame.lines) if tagline in line.text)
        for tagline in (
            "United States of America",
            "1776-2026",
            "250 years and the best has yet to come!",
        )
    ]
    assert frame.lines[tagline_indices[0] - 1].text == ""
    assert tagline_indices[1] == tagline_indices[0] + 2
    assert tagline_indices[2] == tagline_indices[1] + 2
    assert frame.lines[tagline_indices[0] + 1].text == ""
    assert frame.lines[tagline_indices[1] + 1].text == ""


def test_america_overlay_uses_centered_taglines_only_when_art_does_not_fit() -> None:
    """A constrained screen drops decorative art before dropping the supplied statements."""

    from lldp_runner.watch import render_watch_america_frame

    frame = render_watch_america_frame(width=42, height=10)
    nonblank = [line for line in frame.lines if line.text]
    roles = {span.role for line in frame.lines for span in line.spans}

    assert frame.abbreviated
    assert not {"america_red", "america_white", "america_blue"} & roles
    assert [line.text.strip() for line in nonblank] == [
        "United States of America",
        "1776-2026",
        "250 years and the best has yet to come!",
    ]
    assert all(
        len(line.text) - len(line.text.lstrip()) == (42 - len(line.text.strip())) // 2
        for line in nonblank
    )
    tagline_indices = [frame.lines.index(line) for line in nonblank]
    assert tagline_indices[1] == tagline_indices[0] + 2
    assert tagline_indices[2] == tagline_indices[1] + 2


def test_watch_loop_a_key_opens_america_and_any_key_returns(monkeypatch, config) -> None:
    """America is modal: a opens it and the next ordinary key only returns to status."""

    import lldp_runner.watch as watch_module

    class FakeScreen:
        def __init__(self) -> None:
            self.keys = iter((ord("a"), ord("q"), ord("q")))

        def keypad(self, enabled: bool) -> None:
            assert enabled

        def getmaxyx(self) -> tuple[int, int]:
            return 30, 100

        def timeout(self, milliseconds: int) -> None:
            assert milliseconds >= 50

        def getch(self) -> int:
            return next(self.keys)

    payload = _payload(16)
    source = ScoreboardSource(Path("scoreboard.json"), payload, 1_000_000_000)
    drawn = []

    monkeypatch.setattr(watch_module.curses, "curs_set", lambda _value: None)
    monkeypatch.setattr(watch_module.curses, "has_colors", lambda: False)
    monkeypatch.setattr(watch_module, "load_current_scoreboard", lambda _root: source)
    monkeypatch.setattr(
        watch_module,
        "_draw_frame",
        lambda _screen, frame, **_kwargs: drawn.append(frame),
    )

    watch_module._watch_loop(
        FakeScreen(),
        config,
        interval=1.0,
        worker_view="auto",
        palette="dark",
        color_enabled=False,
    )

    assert len(drawn) == 3
    assert drawn[0].worker_view != "america"
    assert drawn[1].worker_view == "america"
    assert drawn[2].worker_view != "america"


@pytest.mark.parametrize(
    ("width", "height"),
    [
        (20, 4),
        (30, 8),
        (42, 10),
        (63, 24),
        (64, 24),
        (80, 24),
        (100, 30),
        (120, 44),
        (126, 55),
    ],
)
def test_representative_terminal_sizes_preserve_essential_information(
    width: int,
    height: int,
) -> None:
    """Every supported fallback is bounded, useful, and free of wrapped rows."""

    payload = _payload(64)
    frame = render_watch_frame(
        payload,
        width=width,
        height=height,
        requested_worker_view="auto",
        age_seconds=4029.0,
    )
    text = "\n".join(line.text for line in frame.lines)

    assert len(frame.lines) == height
    assert frame.lines[0].text == ""
    assert all(len(line.text) <= width - 1 for line in frame.lines)
    assert all(line.text.startswith(" ") for line in frame.lines if line.text)
    title = frame.lines[1].text
    assert any(token in title for token in ("STATE = RUNNING", "RUNNING", "RUN", " R "))
    if width >= 30:
        assert str(payload["run_id"]) in title
    else:
        assert "202" in title and "00" in title
    assert "67:09" in text
    assert ("Workers 64:" in text) or ("W64 " in text)
    assert ("BUSY" in text and "IDLE" in text and "DEAD" in text) or (
        "B55" in text and "I8" in text and "D1" in text
    )
    assert "q/Ctrl-C exit" in frame.lines[-1].text
    if frame.worker_view == "summary" and frame.abbreviated:
        assert any(marker in text for marker in ("SMALL", "ABBREVIATED", " SM", "*"))


def test_age_uses_total_minutes_instead_of_switching_to_hours() -> None:
    """Long scoreboard age remains mm:ss with unbounded total minutes."""

    frame = render_watch_frame(
        _payload(1),
        width=100,
        height=24,
        requested_worker_view="summary",
        age_seconds=4029.0,
    )
    assert frame.lines[1].text.endswith("updated 67:09 ago")


def test_partial_worker_row_keeps_first_table_column_offset() -> None:
    """A short final row is not independently re-centered."""

    from lldp_runner.watch import _pack_worker_cells

    workers = {
        worker_id: {"status": "BUSY", "batch": worker_id, "size": 8} for worker_id in range(10)
    }
    rows = _pack_worker_cells(workers, "full", 120, set())
    assert rows is not None and len(rows) > 1
    left_offsets = [len(row.text) - len(row.text.lstrip()) for row in rows]
    assert len(set(left_offsets)) == 1
    assert rows[-1].text.count("[Worker ") < rows[0].text.count("[Worker ")


def test_source_error_is_below_workers_bright_red_and_surrounded_by_blanks() -> None:
    """A source error occupies its requested location and dedicated red role."""

    frame = render_watch_frame(
        _payload(8),
        width=120,
        height=30,
        requested_worker_view="auto",
        source_available=False,
        source_message="scoreboard read failed",
    )
    warning_index = next(
        index
        for index, line in enumerate(frame.lines)
        if "SOURCE: scoreboard read failed" in line.text
    )
    warning = frame.lines[warning_index]
    visible = warning.text.strip()
    left = warning.text.index(visible)
    right = 120 - (left + len(visible))
    worker_indexes = [
        index for index, line in enumerate(frame.lines) if line.text.lstrip().startswith("[Worker ")
    ]

    assert abs(left - right) <= 1
    assert worker_indexes and warning_index > max(worker_indexes)
    assert frame.lines[warning_index - 1].text == ""
    assert frame.lines[warning_index + 1].text == ""
    assert any(span.role == "source_error" and span.emphasize for span in warning.spans)
