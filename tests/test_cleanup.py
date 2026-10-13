"""Regression tests for credential-free historical run cleanup."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lldp_runner.cli import main


def _config(tmp_path: Path) -> tuple[Path, Path, Path]:
    persistent = tmp_path / "persistent"
    scratch = tmp_path / "scratch"
    persistent.mkdir()
    scratch.mkdir()
    config = tmp_path / "config.toml"
    config.write_text(
        "\n".join(
            (
                "[paths]",
                f'persistent_root = "{persistent}"',
                f'scratch_root = "{scratch}"',
                'runs_dirname = "runs"',
                'output_dirname = "outputs"',
                "",
                # This intentionally lacks credentials. ``clean`` must never
                # enter the credential subsystem merely to resolve storage.
                "[logging]",
                "file = false",
                "",
            )
        ),
        encoding="utf-8",
    )
    return config, persistent, scratch


def _run_dir(root: Path, name: str, *, marker: str | None = None) -> Path:
    path = root / name
    path.mkdir(parents=True)
    if marker is not None:
        (path / marker).write_text("marker\n", encoding="utf-8")
    return path


def _set_age(path: Path, seconds: int) -> None:
    os.utime(path, (seconds, seconds))


def _populate_history(tmp_path: Path) -> tuple[Path, Path, Path]:
    config, persistent, scratch = _config(tmp_path)
    runs = persistent / "runs"
    output = persistent / "outputs"
    runs.mkdir()
    output.mkdir()

    for index, name in enumerate(
        ("run-old", "run-current", "run-latest", "run-newest"), start=1
    ):
        durable = _run_dir(runs, name, marker="discovery-state.sqlite")
        transient = _run_dir(scratch, name, marker="scoreboard.json")
        _set_age(durable, index)
        _set_age(transient, index)

    # ``latest`` and ``current`` deliberately select different older runs while
    # run-newest is newer. Cleanup therefore has to preserve all three
    # operator-significant retention cases independently.
    (output / "run-latest").mkdir()
    (output / "latest").symlink_to("run-latest")
    (runs / "latest").symlink_to("run-latest")
    (scratch / "current").symlink_to("run-current")
    return config, persistent, scratch


def test_clean_default_preserves_newest_latest_and_current(tmp_path: Path, capsys) -> None:
    config, persistent, scratch = _populate_history(tmp_path)
    runs = persistent / "runs"

    # Dedicated persistent run roots may contain stale files as well as run
    # directories; those are historical artifacts and should be removed.
    (runs / "orphan.tmp").write_text("old\n", encoding="utf-8")
    # An unrelated scratch directory must not be deleted merely because an
    # operator configured scratch_root to a shared filesystem location.
    unrelated = _run_dir(scratch, "not-lldp-data", marker="notes.txt")

    main(["--config", str(config), "clean"])

    assert not (runs / "run-old").exists()
    assert not (runs / "orphan.tmp").exists()
    assert (runs / "run-current").is_dir()
    assert (runs / "run-latest").is_dir()
    assert (runs / "run-newest").is_dir()

    assert not (scratch / "run-old").exists()
    assert (scratch / "run-current").is_dir()
    assert (scratch / "run-latest").is_dir()
    assert (scratch / "run-newest").is_dir()
    assert (scratch / "current").is_symlink()
    assert unrelated.is_dir()

    assert (persistent / "outputs" / "latest").is_symlink()
    assert (persistent / "outputs" / "run-latest").is_dir()
    assert (persistent / "runs" / "latest").is_symlink()
    assert (persistent / "runs" / "latest").resolve() == (
        persistent / "runs" / "run-latest"
    ).resolve()

    output = capsys.readouterr().out
    assert "Persistent: removed 2" in output
    assert "Scratch: removed 1" in output
    assert "Clean complete: removed 3 LLDP-Runner artifact(s)" in output


def test_clean_preserves_distinct_runs_latest_target(tmp_path: Path) -> None:
    """Run-state retention honors ``runs/latest`` even if output latest differs."""

    config, persistent, scratch = _config(tmp_path)
    runs = persistent / "runs"
    outputs = persistent / "outputs"
    runs.mkdir()
    outputs.mkdir()
    for index, run_id in enumerate(("run-state-latest", "run-output-latest", "run-newest")):
        durable = _run_dir(runs, run_id, marker="discovery-state.sqlite")
        transient = _run_dir(scratch, run_id, marker="scoreboard.json")
        _set_age(durable, index + 1)
        _set_age(transient, index + 1)
    (runs / "latest").symlink_to("run-state-latest")
    (outputs / "run-output-latest").mkdir()
    (outputs / "latest").symlink_to("run-output-latest")

    main(["--config", str(config), "clean"])

    assert (runs / "run-state-latest").is_dir()
    assert (runs / "run-output-latest").is_dir()
    assert (runs / "run-newest").is_dir()
    assert (scratch / "run-state-latest").is_dir()


@pytest.mark.parametrize("flags", [["--all"], ["--scratch", "--all"]])
def test_clean_all_and_scratch_all_have_all_area_semantics(
    flags: list[str], tmp_path: Path, capsys
) -> None:
    config, persistent, scratch = _populate_history(tmp_path)

    main(["--config", str(config), "clean", *flags])

    assert not (persistent / "runs" / "run-old").exists()
    assert not (scratch / "run-old").exists()
    output = capsys.readouterr().out
    assert "Persistent:" in output
    assert "Scratch:" in output


def test_clean_scratch_does_not_modify_persistent_history(tmp_path: Path, capsys) -> None:
    config, persistent, scratch = _populate_history(tmp_path)

    main(["--config", str(config), "clean", "--scratch"])

    assert (persistent / "runs" / "run-old").is_dir()
    assert not (scratch / "run-old").exists()
    output = capsys.readouterr().out
    assert "Persistent:" not in output
    assert "Scratch: removed 1" in output


def test_clean_preserves_current_target_even_when_not_newest(tmp_path: Path) -> None:
    config, persistent, scratch = _populate_history(tmp_path)

    # Make the current run oldest after initial population. It still must be
    # protected in both scratch and persistent history.
    _set_age(persistent / "runs" / "run-current", 0)
    _set_age(scratch / "run-current", 0)

    main(["--config", str(config), "clean"])

    assert (persistent / "runs" / "run-current").is_dir()
    assert (scratch / "run-current").is_dir()


def test_clean_scratch_ignores_unrecognized_children(tmp_path: Path) -> None:
    config, _, scratch = _config(tmp_path)
    current_run = _run_dir(scratch, "current-run", marker="scoreboard.json")
    old_run = _run_dir(scratch, "old-run", marker="scoreboard.txt")
    unrelated_dir = _run_dir(scratch, "shared-cache", marker="cache.dat")
    unrelated_file = scratch / "operator-note.txt"
    unrelated_file.write_text("keep\n", encoding="utf-8")
    (scratch / "current").symlink_to(current_run.name)
    _set_age(old_run, 1)
    _set_age(current_run, 2)

    main(["--config", str(config), "clean", "--scratch"])

    assert not old_run.exists()
    assert current_run.is_dir()
    assert unrelated_dir.is_dir()
    assert unrelated_file.is_file()


def test_clean_disables_credential_profile_validation(tmp_path: Path, capsys) -> None:
    """Local cleanup must not parse or validate network credential policy."""

    config, persistent, scratch = _config(tmp_path)
    with config.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n[credential_profiles.broken]\n"
            'primary = "profile-that-does-not-exist"\n'
            "\n[credential_rules]\n"
            'default_profile = "broken"\n'
        )

    main(["--config", str(config), "clean", "--scratch"])

    assert persistent.is_dir()
    assert scratch.is_dir()
    assert "Clean complete" in capsys.readouterr().out


def test_clean_dry_run_reports_without_removing(tmp_path: Path, capsys) -> None:
    config, persistent, scratch = _populate_history(tmp_path)

    main(["--config", str(config), "clean", "--dry-run"])

    assert (persistent / "runs" / "run-old").is_dir()
    assert (scratch / "run-old").is_dir()
    output = capsys.readouterr().out
    assert "Clean dry-run: would remove" in output


def test_clean_scratch_removes_stable_live_scoreboard_directory(
    tmp_path: Path, capsys
) -> None:
    """The reserved live publication directory is removed independently of runs."""

    config, _, scratch = _config(tmp_path)
    scoreboard = scratch / "scoreboard"
    scoreboard.mkdir()
    (scoreboard / "scoreboard.txt").write_text("Status: COMPLETED\n", encoding="utf-8")
    (scoreboard / "scoreboard.json").write_text("{}\n", encoding="utf-8")

    main(["--config", str(config), "clean", "--scratch"])

    assert not scoreboard.exists()
    output = capsys.readouterr().out
    assert "Scratch: removed 1" in output
    assert "Clean complete: removed 1 LLDP-Runner artifact(s)" in output


def test_clean_dry_run_reports_live_scoreboard_without_removing_it(
    tmp_path: Path, capsys
) -> None:
    """Dry-run includes the stable scoreboard but leaves its files untouched."""

    config, _, scratch = _config(tmp_path)
    scoreboard = scratch / "scoreboard"
    scoreboard.mkdir()
    snapshot = scoreboard / "scoreboard.json"
    snapshot.write_text("{}\n", encoding="utf-8")

    main(["--config", str(config), "clean", "--scratch", "--dry-run"])

    assert snapshot.is_file()
    assert "Scratch: would remove 1" in capsys.readouterr().out
