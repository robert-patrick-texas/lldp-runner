"""Regression tests for run.json launch provenance and redaction."""

from __future__ import annotations

import json
import queue
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from lldp_runner import APP_NAME, __version__
from lldp_runner.config import CredentialMode, load_config
from lldp_runner.coordinator import Coordinator
from lldp_runner.models import SeedInput
from lldp_runner.run_manifest import (
    REDACTED,
    build_invocation_provenance,
)
from lldp_runner.runtime import make_run_paths


def test_config_loader_records_effective_file_merge_order(tmp_path: Path) -> None:
    include = tmp_path / "explicit.toml"
    include.write_text("[logging]\nconsole = false\n", encoding="utf-8")
    conf_d = tmp_path / "conf.d"
    conf_d.mkdir()
    fragment = conf_d / "20-site.toml"
    fragment.write_text("[output]\npurge_keep = 2\n", encoding="utf-8")
    primary = tmp_path / "config.toml"
    primary.write_text(
        '@include "explicit.toml"\n[logging]\nfile = false\n', encoding="utf-8"
    )

    config = load_config(
        primary,
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )

    assert config.config_files == (
        include.resolve(),
        fragment.resolve(),
        primary.resolve(),
    )


def test_run_provenance_redacts_secrets_before_persistence(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text("[logging]\nfile = false\n", encoding="utf-8")
    config = load_config(
        config_path,
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )
    arguments = {
        "command": "run",
        "seed": ["198.18.0.1"],
        "snmp_community": "private-community",
        "snmp_auth": "auth-secret",
        "snmp_priv": "priv-secret",
        "set": [
            'credentials.site.community="another-secret"',
            'credentials.inline={ version = "2c", community = "table-secret" }',
            'logging.level="DEBUG"',
        ],
    }
    argv = [
        "--community",
        "private-community",
        "--snmp-auth=auth-secret",
        "--set",
        'credentials.site.priv_password="priv-secret"',
        "--set=credentials.inline={ version = \"2c\", community = \"argv-table-secret\" }",
        "run",
        "--seed",
        "198.18.0.1",
    ]

    provenance = build_invocation_provenance(
        config,
        argv=argv,
        arguments=arguments,
        seeds=[],
        stdin_seeds=["198.18.0.2", "198.18.0.2"],
        env={"LLDP_RUNNER_WORKERS": "8"},
    )
    serialized = json.dumps(
        {
            "argv": provenance.argv,
            "arguments": provenance.arguments,
            "stdin_seeds": provenance.stdin_seeds,
            "config_files": provenance.config_files,
        }
    )

    assert "private-community" not in serialized
    assert "auth-secret" not in serialized
    assert "priv-secret" not in serialized
    assert "table-secret" not in serialized
    assert "argv-table-secret" not in serialized
    assert REDACTED in serialized
    assert provenance.stdin_seeds == ("198.18.0.2", "198.18.0.2")
    assert provenance.config_files == (str(config_path.resolve()),)


def test_run_json_config_log_false_omits_config_file_detail(tmp_path: Path) -> None:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        "[output]\nrun_json_config_log = false\n[logging]\nfile = false\n",
        encoding="utf-8",
    )
    config = load_config(
        config_path,
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )

    provenance = build_invocation_provenance(
        config,
        argv=["run", "--seed", "198.18.0.1"],
        arguments={"command": "run", "seed": ["198.18.0.1"]},
        seeds=[],
        env={},
    )

    assert provenance.config_files_logged is False
    assert provenance.config_files == ()


def test_run_provenance_retains_prior_seed_state_for_dns_policy(tmp_path: Path) -> None:
    """run.json records the seed state that can authorize skip-addressed DNS."""

    config_path = tmp_path / "config.toml"
    config_path.write_text("[logging]\nfile = false\n", encoding="utf-8")
    config = load_config(
        config_path,
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )

    provenance = build_invocation_provenance(
        config,
        argv=["run", "--seed-file", "seeds.csv"],
        arguments={"command": "run", "seed_file": ["seeds.csv"]},
        seeds=[
            SeedInput(
                seed="switch1.net.example.com",
                query_target="198.18.20.17",
                prior_state="complete",
                source="seeds.csv",
            )
        ],
        env={},
    )

    assert provenance.seed_inputs[0]["prior_state"] == "complete"


def test_completed_run_publishes_run_json_with_discovery_times(
    config, tmp_path: Path, monkeypatch
) -> None:
    """A real coordinator finalization publishes run.json beside discovery.json."""

    config.paths.persistent_root = tmp_path / "persistent"
    config.paths.scratch_root = tmp_path / "scratch"
    config.logging.file = False
    paths = make_run_paths(config)
    provenance = build_invocation_provenance(
        config,
        argv=["run", "--new-run", "--seed", "198.18.0.1"],
        arguments={
            "command": "run",
            "new_run": True,
            "seed": ["198.18.0.1"],
        },
        seeds=[],
        env={},
    )
    coordinator = Coordinator(
        config,
        paths,
        # Resume mode permits a focused empty-state finalization without DNS/SNMP.
        resume=True,
        invocation_provenance=provenance,
    )
    coordinator.initialize([])

    class EmptyQueue:
        def get(self, timeout: float):
            raise queue.Empty

    coordinator.result_queue = EmptyQueue()
    monkeypatch.setattr(coordinator, "_register_signals", lambda: None)
    monkeypatch.setattr(coordinator, "_restore_signals", lambda: None)
    monkeypatch.setattr(coordinator, "_start_workers", lambda: None)
    monkeypatch.setattr(coordinator, "_stop_workers", lambda: None)
    monkeypatch.setattr(coordinator, "_check_pause_indicator", lambda: None)
    monkeypatch.setattr(coordinator, "_check_worker_health", lambda: None)
    monkeypatch.setattr(coordinator, "_dispatch", lambda: None)
    monkeypatch.setattr(coordinator, "_all_workers_idle", lambda: True)

    outcome = coordinator.run()

    assert outcome.status == "COMPLETED"
    run_document = json.loads(
        (paths.output_run_dir / "run.json").read_text(encoding="utf-8")
    )
    discovery = json.loads(
        (paths.output_run_dir / "discovery.json").read_text(encoding="utf-8")
    )
    assert list(run_document)[:3] == ["schema_version", "app_name", "app_version"]
    assert run_document["app_name"] == APP_NAME == "LLDP-Runner"
    assert run_document["app_version"] == __version__ == "0.37.0"
    assert run_document["run_id"] == paths.run_id
    assert run_document["snmp_backend"]["name"] == "gufo"
    assert run_document["snmp_backend"]["version"]
    assert run_document["invocations"][0]["snmp_backend"] == run_document[
        "snmp_backend"
    ]
    assert run_document["started"] == discovery["discovery"]["started"]
    assert run_document["completed"] == discovery["discovery"]["completed"]
    assert run_document["status"] == "COMPLETED"
    assert list(run_document)[4:9] == [
        "snmp_backend",
        "status",
        "started",
        "completed",
        "duration",
    ]
    started = datetime.fromisoformat(run_document["started"])
    completed = datetime.fromisoformat(run_document["completed"])
    assert started.utcoffset() is not None
    assert completed.utcoffset() is not None
    assert run_document["duration"] == round(
        (completed - started).total_seconds(), 3
    )
    assert run_document["started_by"]["username"]
    invocation_ended = datetime.fromisoformat(
        run_document["invocations"][0]["ended"]
    )
    assert invocation_ended >= completed
    for field in (
        "discovery_duration",
        "graph_resolution_duration",
        "graph_serialization_duration",
        "output_publication_duration",
        "finalization_duration",
        "total_wall_clock_duration",
    ):
        assert isinstance(run_document[field], float)
        assert run_document[field] >= 0.0
    assert run_document["total_wall_clock_duration"] == pytest.approx(
        run_document["discovery_duration"]
        + run_document["finalization_duration"],
        abs=0.002,
    )
    assert run_document["finalization_duration"] >= run_document[
        "graph_resolution_duration"
    ]
    assert run_document["finalization_duration"] >= run_document[
        "graph_serialization_duration"
    ]
    assert run_document["invocations"][0]["argv"][0] == "run"
    assert paths.latest_link.is_symlink()
    assert paths.latest_link.resolve() == paths.output_run_dir.resolve()
    assert paths.run_latest_link.is_symlink()
    assert paths.run_latest_link.resolve() == paths.run_dir.resolve()
    assert not paths.scratch_dir.exists()
    assert not (paths.scratch_dir.parent / "current").exists()
    assert paths.scoreboard_dir.is_dir()
    for filename in ("scoreboard.txt", "scoreboard.json"):
        live = paths.scoreboard_dir / filename
        archived = paths.run_dir / filename
        assert live.is_file()
        assert archived.read_bytes() == live.read_bytes()
    assert not (paths.run_dir / "run.json.draft").exists()


def test_resume_manifest_appends_invocations_without_losing_started_by(tmp_path: Path) -> None:
    from lldp_runner.run_manifest import (
        InvocationProvenance,
        begin_run_manifest,
        update_run_manifest,
    )

    path = tmp_path / "run.json.draft"
    first = InvocationProvenance(
        username="operator",
        uid=1000,
        effective_uid=1000,
        started="2026-08-26T01:00:00-04:00",
        argv=("run", "--seed", "one"),
        arguments={"command": "run", "seed": ["one"]},
        environment={},
        seed_inputs=(),
        stdin_seeds=(),
        config_files_logged=True,
        config_files=("/etc/lldp-runner/config.toml",),
    )
    first_sequence = begin_run_manifest(
        path,
        run_id="run-1",
        started="2026-08-26T01:00:00-04:00",
        status="RUNNING",
        invocation=first,
        indent=2,
    )
    update_run_manifest(
        path,
        sequence=first_sequence,
        status="PAUSED",
        started="2026-08-26T01:00:00-04:00",
        completed=None,
        invocation_ended="2026-08-26T01:05:00-04:00",
        indent=2,
    )
    second = InvocationProvenance(
        username="root",
        uid=0,
        effective_uid=0,
        started="2026-08-26T02:00:00-04:00",
        argv=("run",),
        arguments={"command": "run"},
        environment={},
        seed_inputs=(),
        stdin_seeds=(),
        config_files_logged=False,
        config_files=(),
    )
    second_sequence = begin_run_manifest(
        path,
        run_id="run-1",
        started="2026-08-26T01:00:00-04:00",
        status="RUNNING",
        invocation=second,
        indent=2,
    )
    update_run_manifest(
        path,
        sequence=second_sequence,
        status="COMPLETED",
        started="2026-08-26T01:00:00-04:00",
        completed="2026-08-26T02:10:00-04:00",
        invocation_ended="2026-08-26T02:10:00-04:00",
        indent=2,
    )

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["snmp_backend"]["name"] == "pysnmp"
    assert document["started_by"]["username"] == "operator"
    assert [item["username"] for item in document["invocations"]] == [
        "operator",
        "root",
    ]
    assert document["started"] == "2026-08-26T01:00:00-04:00"
    assert document["completed"] == "2026-08-26T02:10:00-04:00"
    assert document["duration"] == 4200.0


def test_legacy_resume_does_not_misidentify_current_user_as_original_starter(
    tmp_path: Path,
) -> None:
    from lldp_runner.run_manifest import InvocationProvenance, begin_run_manifest

    path = tmp_path / "run.json.draft"
    invocation = InvocationProvenance(
        username="root",
        uid=0,
        effective_uid=0,
        started="2026-08-26T03:00:00-04:00",
        argv=("run",),
        arguments={"command": "run"},
        environment={},
        seed_inputs=(),
        stdin_seeds=(),
        config_files_logged=False,
        config_files=(),
    )
    begin_run_manifest(
        path,
        run_id="legacy-run",
        started="2026-08-25 22:00:00 EDT",
        status="RUNNING",
        invocation=invocation,
        indent=2,
        resuming_existing=True,
    )

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["started_by"]["username"] == "unknown"
    assert document["invocations"][0]["username"] == "root"
