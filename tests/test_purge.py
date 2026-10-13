"""Regression tests for finalized-output purge retention."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from lldp_runner.cli import main


def _config(tmp_path: Path, *, keep: int = 0) -> tuple[Path, Path, Path]:
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
                'output_dirname = "outputs"',
                "",
                "[output]",
                f"purge_keep = {keep}",
                "",
                "[logging]",
                "file = false",
                "",
            )
        ),
        encoding="utf-8",
    )
    return config, persistent, scratch


def _output(root: Path, run_id: str) -> Path:
    path = root / "outputs" / run_id
    path.mkdir(parents=True)
    return path


def _run_json(path: Path, completed: str | None) -> None:
    payload = {"schema_version": 1, "run_id": path.name, "completed": completed}
    (path / "run.json").write_text(json.dumps(payload), encoding="utf-8")


def _discovery(path: Path, *, completed: str | None, generated: str | None) -> None:
    payload = {
        "schema_version": 4,
        "discovery": {"completed": completed, "generated": generated},
        "hosts": [],
        "errors": [],
    }
    (path / "discovery.json").write_text(json.dumps(payload), encoding="utf-8")


def test_purge_uses_configured_keep_as_default_and_preserves_latest(tmp_path: Path, capsys) -> None:
    config, persistent, _ = _config(tmp_path, keep=1)
    output_root = persistent / "outputs"
    old = _output(persistent, "run-old")
    latest = _output(persistent, "run-latest")
    newest = _output(persistent, "run-newest")
    _run_json(old, "2026-08-20T10:00:00-04:00")
    _run_json(latest, "2026-08-21T10:00:00-04:00")
    _run_json(newest, "2026-08-22T10:00:00-04:00")
    (output_root / "latest").symlink_to(latest.name)

    main(["--config", str(config), "purge"])

    assert not old.exists()
    assert latest.exists()
    assert newest.exists()
    text = capsys.readouterr().out
    assert "keep=1" in text
    assert "run-old" in text


def test_purge_keep_cli_overrides_configured_default(tmp_path: Path) -> None:
    config, persistent, _ = _config(tmp_path, keep=3)
    output_root = persistent / "outputs"
    runs = [_output(persistent, f"run-{index}") for index in range(4)]
    for index, path in enumerate(runs):
        _run_json(path, f"2026-08-{20 + index:02d}T10:00:00-04:00")
    (output_root / "latest").symlink_to(runs[-1].name)

    main(["--config", str(config), "purge", "--keep", "0"])

    assert runs[-1].exists()
    assert all(not path.exists() for path in runs[:-1])


def test_purge_dry_run_reports_without_deleting(tmp_path: Path, capsys) -> None:
    config, persistent, _ = _config(tmp_path)
    output_root = persistent / "outputs"
    old = _output(persistent, "run-old")
    latest = _output(persistent, "run-latest")
    _run_json(old, "2026-08-20T10:00:00-04:00")
    _run_json(latest, "2026-08-21T10:00:00-04:00")
    (output_root / "latest").symlink_to(latest.name)

    main(["--config", str(config), "purge", "--dry-run"])

    assert old.exists()
    assert latest.exists()
    assert "Purge dry-run: would remove 1" in capsys.readouterr().out


def test_purge_timestamp_fallback_chain_and_oldest_mtime(tmp_path: Path) -> None:
    config, persistent, _ = _config(tmp_path, keep=2)
    output_root = persistent / "outputs"
    latest = _output(persistent, "run-latest")
    by_discovery_completed = _output(persistent, "run-discovery-completed")
    by_discovery_generated = _output(persistent, "run-discovery-generated")
    by_mtime = _output(persistent, "run-mtime")

    _run_json(latest, "2026-08-24T10:00:00-04:00")
    # Missing run completion falls through to discovery.completed.
    _run_json(by_discovery_completed, None)
    _discovery(
        by_discovery_completed,
        completed="2026-08-23T10:00:00-04:00",
        generated="2026-08-25T10:00:00-04:00",
    )
    # Missing completion then falls through to discovery.generated.
    _run_json(by_discovery_generated, None)
    _discovery(
        by_discovery_generated,
        completed=None,
        generated="2026-08-22T10:00:00-04:00",
    )
    # Invalid JSON metadata falls back to the OLDEST available mtime.
    (by_mtime / "run.json").write_text("not-json", encoding="utf-8")
    (by_mtime / "discovery.json").write_text("not-json", encoding="utf-8")
    os.utime(by_mtime / "run.json", (300, 300))
    os.utime(by_mtime / "discovery.json", (200, 200))
    os.utime(by_mtime, (100, 100))
    (output_root / "latest").symlink_to(latest.name)

    main(["--config", str(config), "purge"])

    # latest + keep=2 retain latest and the two JSON-ranked recent directories.
    assert latest.exists()
    assert by_discovery_completed.exists()
    assert by_discovery_generated.exists()
    assert not by_mtime.exists()


def test_purge_rejects_malformed_latest_symlink(tmp_path: Path) -> None:
    config, persistent, _ = _config(tmp_path)
    output_root = persistent / "outputs"
    _output(persistent, "run-one")
    outside = tmp_path / "outside"
    outside.mkdir()
    (output_root / "latest").symlink_to(outside)

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "purge", "--dry-run"])

    assert exc.value.code == 2


def test_purge_is_credential_free(tmp_path: Path, capsys) -> None:
    config, _, _ = _config(tmp_path)
    with config.open("a", encoding="utf-8") as handle:
        handle.write(
            "\n[credential_profiles.broken]\n"
            'primary = "does-not-exist"\n'
            "\n[credential_rules]\n"
            'default_profile = "broken"\n'
        )

    main(["--config", str(config), "purge", "--dry-run"])

    assert "Purge dry-run" in capsys.readouterr().out
