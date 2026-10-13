from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner.cli import _print_discovery_outcome, main
from lldp_runner.coordinator import DiscoveryOutcome


def _included_operational_config(config_file: Path, tmp_path: Path) -> tuple[Path, Path]:
    scratch = tmp_path / "included-shm"
    ops = tmp_path / "ops.toml"
    ops.write_text(
        f'''[paths]
scratch_root = "{scratch}"

[resume]
pause_indicator = "hold.request"

[credentials.default-v3]
username_env = "LLDP_RUNNER_TEST_MISSING_USER"
auth_password_env = "LLDP_RUNNER_TEST_MISSING_AUTH"
priv_password_env = "LLDP_RUNNER_TEST_MISSING_PRIV"
''',
        encoding="utf-8",
    )
    root = tmp_path / "root.toml"
    root.write_text(
        f'''@include "{config_file.name}"
@include "{ops.name}"
''',
        encoding="utf-8",
    )
    return root, scratch


def test_status_uses_include_aware_config_loader(
    config_file: Path, tmp_path: Path, capsys
) -> None:
    root, scratch = _included_operational_config(config_file, tmp_path)
    scoreboard = scratch / "scoreboard"
    scoreboard.mkdir(parents=True)
    (scoreboard / "scoreboard.txt").write_text("Status: RUNNING\n", encoding="utf-8")

    main(["--config", str(root), "status"])

    assert capsys.readouterr().out == "Status: RUNNING\n"


def test_pause_uses_included_scratch_root_and_indicator(
    config_file: Path, tmp_path: Path, capsys
) -> None:
    root, scratch = _included_operational_config(config_file, tmp_path)
    current = scratch / "current"
    current.mkdir(parents=True)

    main(["--config", str(root), "pause"])

    indicator = current / "hold.request"
    assert indicator.exists()
    assert f"Pause requested: {indicator}" in capsys.readouterr().out


def test_run_summary_prints_runtime_immediately_after_status(tmp_path: Path, capsys) -> None:
    """The standard run summary keeps the requested Runtime line ordering."""

    outcome = DiscoveryOutcome(
        run_id="20260102-135700-EDT",
        status="COMPLETED",
        started_timestamp="2026-08-24 13:57:00 EDT",
        ended_timestamp="2026-08-24 13:58:30 EDT",
        duration_seconds=90,
        output_directory=tmp_path / "outputs",
        state_path=tmp_path / "state.sqlite",
        activity_log=tmp_path / "activity.log",
    )

    _print_discovery_outcome(outcome)

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "Run: 20260102-135700-EDT"
    assert lines[1] == "Status: COMPLETED"
    assert lines[2] == (
        "Runtime: 2026-08-24 13:57:00 EDT to 2026-08-24 13:58:30 EDT "
        "(duration: 90s)"
    )


def test_run_summary_reports_disabled_activity_log(tmp_path: Path, capsys) -> None:
    """File logging disabled is explicit rather than printing a fictitious path."""

    outcome = DiscoveryOutcome(
        run_id="20260102-145100-EDT",
        status="COMPLETED",
        started_timestamp="2026-08-24 14:51:00 EDT",
        ended_timestamp="2026-08-24 14:51:01 EDT",
        duration_seconds=1,
        output_directory=tmp_path / "outputs",
        state_path=tmp_path / "state.sqlite",
        activity_log=None,
    )

    _print_discovery_outcome(outcome)

    assert "Activity log: disabled" in capsys.readouterr().out.splitlines()


def test_run_storage_preflight_failure_is_reported_on_stderr(
    config_file: Path, monkeypatch, capsys
) -> None:
    """Storage preflight errors stop the run before worker discovery begins."""

    def fail_preflight(_paths) -> None:
        """Stand in for an OS error encountered by the constructor preflight."""

        raise OSError("persistent output preflight failed: simulated permission error")

    monkeypatch.setattr(
        "lldp_runner.runtime.preflight_run_storage",
        fail_preflight,
    )

    # Coordinator imports ensure_run_directories, which resolves the helper from
    # the runtime module at call time. No DNS/SNMP work occurs before this failure.
    with pytest.raises(SystemExit) as exc:
        main([
            "--config",
            str(config_file),
            "run",
            "--new-run",
            "--seed",
            "198.18.0.1",
        ])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "persistent output preflight failed" in captured.err
    assert "simulated permission error" in captured.err


def test_run_activity_log_append_failure_is_reported_on_stderr(
    config_file: Path, tmp_path: Path, capsys
) -> None:
    """A real file-handler open failure is terminal before worker startup."""

    log_path = tmp_path / "central-lldprunner.log"
    log_path.mkdir()
    config_text = config_file.read_text(encoding="utf-8")
    config_text = config_text.replace(
        "console = false\n",
        f'console = false\nfilename = "{log_path}"\n',
        1,
    )
    config_file.write_text(config_text, encoding="utf-8")

    with pytest.raises(SystemExit) as exc:
        main([
            "--config",
            str(config_file),
            "run",
            "--new-run",
            "--seed",
            "198.18.0.1",
        ])

    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "unable to open activity log for append" in captured.err
    assert str(log_path) in captured.err


def test_run_id_counter_exhaustion_is_reported_on_stderr_before_discovery(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    """Counter exhaustion is a CLI usage/runtime error, never an uncaught traceback."""

    from lldp_runner.cli import main

    persistent = tmp_path / "persistent"
    scratch = tmp_path / "scratch"
    runs = persistent / "runs"
    runs.mkdir(parents=True)
    (runs / "run-99").mkdir()
    monkeypatch.setenv("SNMPCOMM", "public")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'''[paths]\npersistent_root = "{persistent}"\nscratch_root = "{scratch}"\nrun_id_format = "run-{{counter}}"\n\n[logging]\nconsole = false\nfile = false\n''',
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config_path), "run", "--new-run", "--seed", "192.0.2.1"])
    assert exc.value.code == 2
    error = capsys.readouterr().err
    assert "next counter would exceed 99" in error
    assert "paths.run_id_format" in error


def test_watch_uses_include_aware_config_with_credentials_disabled(
    config_file: Path, tmp_path: Path, monkeypatch
) -> None:
    """Watch resolves the deployed scratch root without touching SNMP credentials."""

    scratch = tmp_path / "watch-shm"
    root = tmp_path / "watch.toml"
    root.write_text(
        f'''@include "{config_file.name}"

[paths]
scratch_root = "{scratch}"

[credentials.invalid]
this_setting_does_not_exist = "ignored-by-disabled-mode"
''',
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    def fake_watch(config, **kwargs) -> None:
        captured["scratch_root"] = config.paths.scratch_root
        captured.update(kwargs)

    monkeypatch.setattr("lldp_runner.cli.run_watch", fake_watch)

    main(
        [
            "--config",
            str(root),
            "watch",
            "--interval",
            "2",
            "--worker-view",
            "heatmap",
            "--palette",
            "light",
            "--no-color",
        ]
    )

    assert captured["scratch_root"] == scratch
    assert captured["interval"] == 2.0
    assert captured["worker_view"] == "heatmap"
    assert captured["palette"] == "light"
    assert captured["no_color"] is True


def test_status_disables_credential_parsing_entirely(
    config_file: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    """Status must bypass credentials plus runtime SNMP selection and factory."""

    scratch = tmp_path / "status-shm"
    scoreboard = scratch / "scoreboard"
    scoreboard.mkdir(parents=True)
    (scoreboard / "scoreboard.txt").write_text("Status: RUNNING\n", encoding="utf-8")
    root = tmp_path / "status-disabled-creds.toml"
    root.write_text(
        f'''@include "{config_file.name}"

[paths]
scratch_root = "{scratch}"

[credentials.invalid]
this_setting_does_not_exist = "ignored-by-disabled-mode"
''',
        encoding="utf-8",
    )

    def fail_backend_boundary(*_args, **_kwargs):
        raise AssertionError("read-only status entered the runtime SNMP subsystem")

    monkeypatch.setattr(
        "lldp_runner.snmp.selection.select_snmp_backend",
        fail_backend_boundary,
    )
    monkeypatch.setattr(
        "lldp_runner.snmp.create_snmp_client",
        fail_backend_boundary,
    )
    monkeypatch.setattr(
        "lldp_runner.cli.preflight_snmp_backend",
        fail_backend_boundary,
    )

    main(["--config", str(root), "status"])

    assert capsys.readouterr().out == "Status: RUNNING\n"


def test_status_does_not_write_probe_runtime_paths(
    config_file: Path, tmp_path: Path, monkeypatch, capsys
) -> None:
    """A read-only scoreboard observer must not require filesystem write access."""

    scratch = tmp_path / "readonly-shm"
    scoreboard = scratch / "scoreboard"
    scoreboard.mkdir(parents=True)
    (scoreboard / "scoreboard.txt").write_text("Status: RUNNING\n", encoding="utf-8")
    root = tmp_path / "readonly-status.toml"
    root.write_text(
        f'''@include "{config_file.name}"

[paths]
scratch_root = "{scratch}"
''',
        encoding="utf-8",
    )

    def fail_probe(*_args, **_kwargs):
        raise AssertionError("read-only status attempted a writable path probe")

    monkeypatch.setattr("lldp_runner.config._probe_writable_directory", fail_probe)

    main(["--config", str(root), "status"])

    assert capsys.readouterr().out == "Status: RUNNING\n"


def test_explain_target_is_read_only_and_does_not_require_secrets(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    """Policy explanation should not require writable roots or resolved secrets."""

    config_path = tmp_path / "explain.toml"
    config_path.write_text(
        '''[paths]
persistent_root = "/proc/lldp-runner-unwritable"
scratch_root = "/proc/lldp-runner-scratch-unwritable"

[credentials.site-v3]
version = "v3"
username_env = "MISSING_EXPLAIN_USER"
auth_password_env = "MISSING_EXPLAIN_AUTH"
priv_password_env = "MISSING_EXPLAIN_PRIV"

[credential_profiles.site]
primary = "site-v3"

[credential_rules]
default_profile = "site"
''',
        encoding="utf-8",
    )

    def fake_explain(config, target):
        """Verify policy is present while avoiding DNS in this CLI-mode test."""

        assert config.credential_profiles["site"].primary == "site-v3"
        return {"target": target, "credential_profile": "site"}

    monkeypatch.setattr("lldp_runner.cli.explain_target", fake_explain)

    main(["--config", str(config_path), "explain-target", "198.18.0.10"])

    assert '"credential_profile": "site"' in capsys.readouterr().out
