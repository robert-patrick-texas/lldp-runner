"""Regression coverage for operator and JSON scoreboard rendering."""

from __future__ import annotations

import json
from pathlib import Path

from lldp_runner.scoreboard import (
    ScoreboardSnapshot,
    archive_scoreboard,
    current_scoreboard_path,
    write_scoreboard,
)
from lldp_runner.state import StateStore


def test_scoreboard_displays_seed_only_execution_plan(tmp_path: Path) -> None:
    """Configured/effective seed scheduler values appear in both scoreboard forms."""

    state = StateStore(tmp_path / "state.sqlite")
    scratch = tmp_path / "scratch"
    plan = {
        "mode": "seed_only",
        "configured_workers": 64,
        "effective_workers": 2,
        "configured_batch_size": 9,
        "effective_batch_size": 5,
        "max_outstanding_devices_per_worker": 24,
        "per_worker_first_wave_capacity": 9,
        "ready_seeds": 10,
    }

    snapshot = write_scoreboard(
        state,
        scratch,
        run_id="test-run",
        started="2026-08-24 23:00:00 EDT",
        status="RUNNING",
        elapsed_seconds=3.2,
        worker_status={},
        execution_plan=plan,
    )

    text = (scratch / "scoreboard.txt").read_text(encoding="utf-8")
    assert "Execution plan:" in text
    assert "workers:          64 configured -> 2 effective" in text
    assert "batch size:       9 configured -> 5 effective" in text
    assert "READY seeds:      10" in text

    text_path = scratch / "scoreboard.txt"
    json_path = scratch / "scoreboard.json"
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["execution_plan"] == plan
    assert snapshot.text == text_path.read_text(encoding="utf-8")
    assert snapshot.json == json_path.read_text(encoding="utf-8")
    state.close()


def test_current_scoreboard_path_uses_reserved_live_directory(tmp_path: Path) -> None:
    """Status and Watch paths never depend on the per-run current symlink."""

    assert current_scoreboard_path(tmp_path) == tmp_path / "scoreboard" / "scoreboard.txt"
    assert current_scoreboard_path(tmp_path, json_output=True) == (
        tmp_path / "scoreboard" / "scoreboard.json"
    )


def test_archive_scoreboard_writes_exact_terminal_snapshot(tmp_path: Path) -> None:
    """Completed-run archival preserves the producer's exact rendered bytes."""

    snapshot = ScoreboardSnapshot(
        text="Status: COMPLETED\n",
        json='{"status": "COMPLETED"}\n',
    )
    text_path, json_path = archive_scoreboard(snapshot, tmp_path / "run")

    assert text_path.read_text(encoding="utf-8") == snapshot.text
    assert json_path.read_text(encoding="utf-8") == snapshot.json
