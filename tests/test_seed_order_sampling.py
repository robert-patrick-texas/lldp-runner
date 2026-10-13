from __future__ import annotations

from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from lldp_runner.classify import Classifier
from lldp_runner.coordinator import Coordinator
from lldp_runner.models import Candidate, NeighborObservation, SeedInput
from lldp_runner.policy import PolicyEngine
from lldp_runner.state import StateStore


def _coordinator(config, tmp_path: Path, *, resume: bool = False) -> Coordinator:
    """Build a coordinator focused on seed ranking and limit policy, without workers."""

    scratch = tmp_path / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.paths = SimpleNamespace(run_id="test-run", scratch_dir=scratch)
    coordinator.resume = resume
    coordinator.state = StateStore(tmp_path / "state.sqlite")
    coordinator.policy = PolicyEngine(config)
    coordinator.classifier = Classifier(config)
    coordinator.seed_only = isinstance(config.discovery.max_devices, str) and (
        config.discovery.max_devices.lower() == "auto"
    )
    coordinator.effective_max_devices = None
    coordinator.pause_event = Event()
    coordinator.limit_reached = False
    coordinator.limit_reason = None
    coordinator.started_text = "test"
    return coordinator


def _ranked_names(coordinator: Coordinator) -> list[str]:
    rows = coordinator.state.conn.execute(
        "SELECT preferred_name FROM hosts WHERE is_seed=1 ORDER BY seed_rank, id"
    ).fetchall()
    return [str(row["preferred_name"]) for row in rows]


def _neighbor(address: str) -> NeighborObservation:
    return NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name=f"host-{address.rsplit('.', 1)[-1]}",
        remote_interface="eth0",
        remote_interface_raw="eth0",
        remote_addresses=[address],
        remote_description="endpoint",
        remote_platform="endpoint",
        capabilities=["station"],
        chassis_id=f"00:11:22:33:44:{int(address.rsplit('.', 1)[-1]):02x}",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
    )


def test_input_order_survives_duplicate_seed_identity(config, tmp_path: Path) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 0
    config.discovery.seed_order = "input"
    coordinator = _coordinator(config, tmp_path)

    coordinator.initialize(
        [SeedInput("198.18.20.3"), SeedInput("198.18.20.1"), SeedInput("198.18.20.3")]
    )

    assert _ranked_names(coordinator) == ["198.18.20.3", "198.18.20.1"]
    coordinator.state.close()


def test_sorted_seed_order_is_lexical_after_consolidation(config, tmp_path: Path) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 0
    config.discovery.seed_order = "sorted"
    coordinator = _coordinator(config, tmp_path)

    coordinator.initialize(
        [SeedInput("198.18.20.20"), SeedInput("198.18.20.3"), SeedInput("198.18.20.11")]
    )

    assert _ranked_names(coordinator) == [
        "198.18.20.11",
        "198.18.20.20",
        "198.18.20.3",
    ]
    coordinator.state.close()


def test_random_seed_order_is_reproducible_with_explicit_key(config, tmp_path: Path) -> None:
    seeds = [SeedInput(f"198.18.20.{value}") for value in range(1, 12)]
    orders: list[list[str]] = []
    for index in range(2):
        case = tmp_path / str(index)
        case.mkdir()
        config.discovery.max_devices = "auto"
        config.discovery.max_hosts = 0
        config.discovery.seed_order = "random"
        config.discovery.shuffle_key = "sample-20260820"
        coordinator = _coordinator(config, case)
        coordinator.initialize(seeds)
        orders.append(_ranked_names(coordinator))
        assert coordinator.state.get_meta("seed_shuffle_key") == "sample-20260820"
        coordinator.state.close()

    assert orders[0] == orders[1]
    assert orders[0] != [seed.seed for seed in seeds]


def test_random_seed_order_generates_and_reuses_key_on_resume(
    config, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 0
    config.discovery.seed_order = "random"
    config.discovery.shuffle_key = ""
    coordinator = _coordinator(config, tmp_path)
    monkeypatch.setattr("lldp_runner.coordinator.secrets.token_hex", lambda size: "generated-key")

    coordinator.initialize([SeedInput("198.18.20.2"), SeedInput("198.18.20.1")])
    first_order = _ranked_names(coordinator)
    assert coordinator.state.get_meta("seed_shuffle_key") == "generated-key"

    coordinator.resume = True
    monkeypatch.setattr(
        "lldp_runner.coordinator.secrets.token_hex",
        lambda size: (_ for _ in ()).throw(AssertionError("resume should reuse key")),
    )
    coordinator.initialize([])
    assert _ranked_names(coordinator) == first_order
    coordinator.state.close()


def test_claim_batch_uses_seed_rank_before_cohort(config, tmp_path: Path) -> None:
    state = StateStore(tmp_path / "state.sqlite")
    ids: list[int] = []
    for rank, address in enumerate(["198.18.20.3", "198.18.20.1", "198.18.20.2"]):
        host_id = state.upsert_candidate(
            Candidate(names=[], addresses=[address], category="managed_device"),
            is_seed=True,
            seed_rank=rank,
        )
        state.set_host_ready(host_id, cohort=99 - rank)
        ids.append(host_id)

    claimed = state.claim_batch(worker_id=0, batch_size=2, lease_seconds=60, allow_steal=False)
    assert claimed == ids[:2]
    state.close()


def test_seed_only_max_hosts_counts_discovered_nonseeds_not_large_seed_inventory(
    config, tmp_path: Path
) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 1
    coordinator = _coordinator(config, tmp_path)
    seeds = [SeedInput(f"198.18.20.{value}") for value in range(1, 6)]
    coordinator.initialize(seeds)

    coordinator._check_limits()
    assert coordinator.limit_reached is False

    seed = next(row for row in coordinator.state.all_hosts() if row["is_seed"] == 1)
    coordinator._process_neighbor(int(seed["id"]), _neighbor("198.18.30.1"))
    coordinator._check_limits()

    assert coordinator.limit_reached is True
    assert coordinator.limit_reason == "max_hosts"
    coordinator.state.close()


def test_limit_behavior_selects_resumable_or_completed_limit(config, tmp_path: Path) -> None:
    coordinator = _coordinator(config, tmp_path)
    config.discovery.limit_behavior = "pause"
    assert coordinator._limit_stop_status() == "LIMIT_REACHED"
    config.discovery.limit_behavior = "complete"
    assert coordinator._limit_stop_status() == "COMPLETED_LIMIT"
    coordinator.state.close()


@pytest.mark.parametrize("clean_scratch", [True, False])
def test_completed_limit_run_finalizes_persistent_output(
    config,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    clean_scratch: bool,
) -> None:
    """limit_behavior=complete uses the normal final-output path, not a draft pause."""

    import queue
    import time

    import lldp_runner.coordinator as coordinator_module

    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 1
    config.discovery.limit_behavior = "complete"
    config.paths.clean_scratch_when_completed = clean_scratch
    coordinator = _coordinator(config, tmp_path)
    coordinator.paths = SimpleNamespace(  # ty: ignore[invalid-assignment]
        run_id="sample-run",
        scratch_dir=tmp_path / "scratch",
        scoreboard_dir=tmp_path / "live-scoreboard",
        run_dir=tmp_path / "run",
        output_run_dir=tmp_path / "outputs" / "sample-run",
        latest_link=tmp_path / "outputs" / "latest",
        run_latest_link=tmp_path / "runs" / "latest",
        state_path=tmp_path / "state.sqlite",
        activity_log=tmp_path / "activity.log",
    )
    coordinator.paths.run_dir.mkdir(parents=True)
    coordinator.paths.scratch_dir.mkdir(parents=True, exist_ok=True)
    coordinator.paths.scoreboard_dir.mkdir(parents=True)
    coordinator.started_monotonic = time.monotonic()
    coordinator.worker_status = {}
    coordinator.workers = []
    coordinator.work_queues = []
    coordinator.batch_hosts = {}
    coordinator.pause_requested = False
    coordinator._closed = False
    coordinator.state.set_meta("started", "test")
    coordinator.state.set_meta("status", "RUNNING")
    host_id = coordinator.state.upsert_candidate(
        Candidate(names=["sample-host"], addresses=["198.18.30.1"], category="managed_endpoint")
    )
    assert host_id > 0

    class EmptyQueue:
        def get(self, timeout: float):
            raise queue.Empty

    coordinator.result_queue = EmptyQueue()  # ty: ignore[invalid-assignment]
    monkeypatch.setattr(coordinator, "_register_signals", lambda: None)
    monkeypatch.setattr(coordinator, "_restore_signals", lambda: None)
    monkeypatch.setattr(coordinator, "_start_workers", lambda: None)
    monkeypatch.setattr(coordinator, "_stop_workers", lambda: None)
    monkeypatch.setattr(coordinator, "_check_pause_indicator", lambda: None)
    monkeypatch.setattr(coordinator, "_check_worker_health", lambda: None)
    monkeypatch.setattr(coordinator, "_dispatch", lambda: None)
    monkeypatch.setattr(coordinator, "_all_workers_idle", lambda: True)
    completion_events: list[str] = []

    def close_coordinator() -> None:
        completion_events.append("closed")
        coordinator.state.close()

    monkeypatch.setattr(coordinator, "close", close_coordinator)

    output_calls: list[tuple[str, bool]] = []
    finalized: list[tuple[Path, Path]] = []
    monkeypatch.setattr(
        coordinator_module,
        "write_outputs",
        lambda state, cfg, directory, *, run_id, status, draft: (
            output_calls.append((status, draft)) or [Path(directory) / "discovery.json"]
        ),
    )
    from lldp_runner.scoreboard import ScoreboardSnapshot

    terminal_scoreboard = ScoreboardSnapshot(
        text="Status: COMPLETED_LIMIT\n",
        json='{"status": "COMPLETED_LIMIT"}\n',
    )
    monkeypatch.setattr(
        coordinator_module,
        "write_scoreboard",
        lambda *args, **kwargs: terminal_scoreboard,
    )
    monkeypatch.setattr(
        coordinator_module,
        "finalize_to_persistent",
        lambda staging, output, latest, **kwargs: finalized.append((output, latest)),
    )
    monkeypatch.setattr(
        coordinator_module,
        "publish_latest_symlink",
        lambda latest, target: completion_events.append(f"run-latest:{latest.name}:{target.name}"),
    )
    monkeypatch.setattr(
        coordinator_module,
        "clean_completed_scratch",
        lambda paths: completion_events.append("scratch-cleaned"),
    )

    outcome = coordinator.run()

    assert outcome.status == "COMPLETED_LIMIT"
    assert outcome.output_directory == coordinator.paths.output_run_dir
    assert ("COMPLETED_LIMIT", False) in output_calls
    assert finalized == [(coordinator.paths.output_run_dir, coordinator.paths.latest_link)]
    expected_events = [
        "closed",
        "run-latest:latest:run",
    ]
    if clean_scratch:
        expected_events.append("scratch-cleaned")
    assert completion_events == expected_events
    assert (coordinator.paths.run_dir / "scoreboard.txt").read_text(
        encoding="utf-8"
    ) == terminal_scoreboard.text
    assert (coordinator.paths.run_dir / "scoreboard.json").read_text(
        encoding="utf-8"
    ) == terminal_scoreboard.json
    retained_scratch_scoreboard = coordinator.paths.scratch_dir / "scoreboard.json"
    assert retained_scratch_scoreboard.exists() is (not clean_scratch)


def test_state_store_migrates_pre_seed_rank_checkpoint(tmp_path: Path) -> None:
    """Internal v0.9 checkpoint state gains seed_rank without external format support."""

    import sqlite3

    path = tmp_path / "old-state.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE hosts (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "state TEXT NOT NULL, is_seed INTEGER NOT NULL DEFAULT 0, cohort INTEGER NOT NULL DEFAULT 0)"
    )
    conn.commit()
    conn.close()

    state = StateStore(path)
    columns = {str(row[1]) for row in state.conn.execute("PRAGMA table_info(hosts)")}
    assert "seed_rank" in columns
    state.close()


def test_resume_clears_old_limit_metadata_but_keeps_random_key(config, tmp_path: Path) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 0
    config.discovery.seed_order = "random"
    config.discovery.shuffle_key = ""
    coordinator = _coordinator(config, tmp_path, resume=True)
    coordinator.state.set_meta("limit_reason", "max_hosts")
    coordinator.state.set_meta("completion_reason", "max_hosts")
    coordinator.state.set_meta("completed", "old-time")
    coordinator.state.set_meta("seed_shuffle_key", "keep-this-key")

    coordinator.initialize([])

    assert coordinator.state.get_meta("limit_reason") is None
    assert coordinator.state.get_meta("completion_reason") is None
    assert coordinator.state.get_meta("completed") is None
    assert coordinator.state.get_meta("seed_shuffle_key") == "keep-this-key"
    coordinator.state.close()
