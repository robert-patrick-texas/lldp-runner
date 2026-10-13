from __future__ import annotations

import logging
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
    """Construct a coordinator without multiprocessing/log-listener side effects.

    These tests exercise initialization, state admission, and guardrail decisions;
    worker processes are intentionally outside their scope.  Using the real
    StateStore/PolicyEngine keeps identity de-duplication and state transitions
    representative of production behavior.
    """

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


def _managed_neighbor(address: str = "198.18.20.2") -> NeighborObservation:
    return NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name="neighbor-sw",
        remote_interface="Gi1/0/48",
        remote_interface_raw="GigabitEthernet1/0/48",
        remote_addresses=[address],
        remote_description="Cisco IOS Software",
        remote_platform="Cisco Catalyst",
        capabilities=["bridge", "router"],
        chassis_id="00:11:22:33:44:55",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
    )


def test_finite_max_devices_fails_before_workers_when_unique_seeds_exceed_limit(
    config, tmp_path: Path
) -> None:
    config.discovery.max_devices = 1
    coordinator = _coordinator(config, tmp_path)

    with pytest.raises(ValueError, match="2 unique managed seed devices"):
        coordinator.initialize([SeedInput("198.18.20.1"), SeedInput("198.18.20.2")])

    assert coordinator.state.get_meta("status") == "SEED_LIMIT_EXCEEDED"
    assert coordinator.state.seed_device_count() == 2
    error = coordinator.state.conn.execute(
        "SELECT category FROM errors WHERE host_id IS NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    assert error is not None
    assert error["category"] == "seed_count_exceeds_max_devices"
    coordinator.state.close()


def test_initialize_announces_run_config_seed_resolution_and_counts(
    config, tmp_path: Path, caplog
) -> None:
    """Startup logging makes slow pre-worker seed resolution visible to operators."""

    coordinator = _coordinator(config, tmp_path)
    caplog.set_level(logging.INFO, logger="lldp_runner.coordinator")

    coordinator.initialize([SeedInput("198.18.20.1")], raw_seed_count=3)

    assert "LLDP-Runner run test-run started: recursive discovery" in caplog.text
    assert f"Configuration loaded: {config.config_path}" in caplog.text
    assert "Seeds loaded: 3 raw seeds" in caplog.text
    assert "Seed resolution started:" in caplog.text
    assert "Seed resolution complete: 3 raw seeds -> 1 unique seeds" in caplog.text
    assert "seed resolution completed: raw=3 input_identities=1" in caplog.text
    coordinator.state.close()


def test_seed_resolution_progress_heartbeat_does_not_require_state_access(
    monkeypatch, caplog
) -> None:
    """The timer heartbeat can report progress while the resolver thread is blocked."""

    import time

    from lldp_runner import coordinator as coordinator_module

    monkeypatch.setattr(coordinator_module, "SEED_RESOLUTION_PROGRESS_SECONDS", 0.01)
    caplog.set_level(logging.INFO, logger="lldp_runner.coordinator")
    progress = coordinator_module._SeedResolutionProgress(
        total=10,
        raw=12,
        started=time.monotonic(),
    )
    progress.start()
    progress.update("resolved")
    time.sleep(0.03)
    progress.stop()

    assert "Seed resolution in progress: 1/10 input identities processed" in caplog.text
    assert "seed resolution progress: processed=1 total=10 raw=12" in caplog.text


def test_finite_limit_counts_deduplicated_seed_identities(config, tmp_path: Path) -> None:
    config.discovery.max_devices = 1
    coordinator = _coordinator(config, tmp_path)

    coordinator.initialize([SeedInput("198.18.20.1"), SeedInput("198.18.20.1")])

    assert coordinator.state.seed_device_count() == 1
    assert coordinator.effective_max_devices == 1
    coordinator.state.close()


def test_auto_queries_seed_but_records_managed_neighbor_without_scheduling_it(
    config, tmp_path: Path
) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 0
    coordinator = _coordinator(config, tmp_path)
    coordinator.initialize([SeedInput("198.18.20.1")])

    seed = next(row for row in coordinator.state.all_hosts() if row["is_seed"] == 1)
    assert seed["state"] == "READY"
    assert coordinator.effective_max_devices == 1

    coordinator._process_neighbor(int(seed["id"]), _managed_neighbor())

    neighbor = next(row for row in coordinator.state.all_hosts() if row["is_seed"] == 0)
    assert neighbor["classification"] == "managed_device"
    assert neighbor["state"] == "NO_QUERY"
    assert len(coordinator.state.neighbors_from(int(seed["id"]))) == 1
    assert coordinator.state.ready_count() == 1

    # The identified managed-neighbor population may exceed the effective seed
    # count without tripping max_devices in auto mode; scheduler admission is the
    # recursion control and max_hosts remains independent.
    coordinator._check_limits()
    assert coordinator.limit_reached is False
    assert coordinator.pause_event.is_set() is False
    coordinator.state.close()


def test_auto_resume_suppresses_pending_nonseed_ready_work(config, tmp_path: Path) -> None:
    config.discovery.max_devices = "auto"
    coordinator = _coordinator(config, tmp_path)
    coordinator.initialize([SeedInput("198.18.20.1")])

    host_id = coordinator.state.upsert_candidate(
        Candidate(
            names=["old-recursive-neighbor"],
            addresses=["198.18.20.9"],
            category="managed_device",
        )
    )
    coordinator.state.set_host_ready(host_id, 0)
    assert coordinator.state.host_row(host_id)["state"] == "READY"

    coordinator._resolve_seed_device_limit()

    assert coordinator.state.host_row(host_id)["state"] == "NO_QUERY"
    coordinator.state.close()


def test_zero_limits_disable_both_guardrails(config, tmp_path: Path) -> None:
    config.discovery.max_devices = 0
    config.discovery.max_hosts = 0
    coordinator = _coordinator(config, tmp_path)
    coordinator.initialize([SeedInput("198.18.20.1")])

    for offset in range(2, 8):
        host_id = coordinator.state.upsert_candidate(
            Candidate(
                names=[f"managed-{offset}"],
                addresses=[f"198.18.20.{offset}"],
                category="managed_device",
            )
        )
        coordinator._schedule_if_queryable(host_id)

    assert coordinator.state.managed_device_count() > 1
    coordinator._check_limits()
    assert coordinator.limit_reached is False
    assert coordinator.pause_event.is_set() is False
    coordinator.state.close()


def test_auto_still_honors_finite_max_hosts(config, tmp_path: Path) -> None:
    config.discovery.max_devices = "auto"
    config.discovery.max_hosts = 1
    coordinator = _coordinator(config, tmp_path)
    coordinator.initialize([SeedInput("198.18.20.1")])
    seed = next(row for row in coordinator.state.all_hosts() if row["is_seed"] == 1)

    coordinator._process_neighbor(int(seed["id"]), _managed_neighbor())
    coordinator._check_limits()

    assert coordinator.limit_reached is True
    assert coordinator.pause_event.is_set() is True
    coordinator.state.close()


def _seed_inputs(count: int) -> list[SeedInput]:
    """Return unique in-boundary IPv4 seed inputs for scheduler sizing tests."""

    return [SeedInput(f"198.18.20.{index}") for index in range(1, count + 1)]


def test_auto_right_sizes_small_seed_only_execution_plan(config, tmp_path: Path, caplog) -> None:
    """Nine READY seeds fit in one async worker batch despite high worker capacity."""

    import logging

    config.discovery.max_devices = "auto"
    config.discovery.workers = 64
    config.discovery.batch_size = 9
    config.snmp.max_outstanding_devices_per_worker = 24
    coordinator = _coordinator(config, tmp_path)
    caplog.set_level(logging.INFO, logger="lldp_runner.coordinator")

    coordinator.initialize(_seed_inputs(9))

    assert coordinator.effective_workers == 1
    assert coordinator.effective_batch_size == 9
    assert coordinator.execution_plan_ready_seeds == 9
    assert coordinator.state.get_meta("configured_workers") == "64"
    assert coordinator.state.get_meta("effective_workers") == "1"
    assert coordinator.state.get_meta("configured_batch_size") == "9"
    assert coordinator.state.get_meta("effective_batch_size") == "9"
    assert "seed-only execution plan: 9 READY seeds; workers 64 -> 1" in caplog.text
    coordinator.state.close()


def test_auto_balances_ten_seeds_across_two_workers(config, tmp_path: Path) -> None:
    """Ten seeds use two five-device batches instead of an uneven 9+1 claim."""

    config.discovery.max_devices = "auto"
    config.discovery.workers = 64
    config.discovery.batch_size = 9
    config.snmp.max_outstanding_devices_per_worker = 24
    coordinator = _coordinator(config, tmp_path)

    coordinator.initialize(_seed_inputs(10))

    assert coordinator.effective_workers == 2
    assert coordinator.effective_batch_size == 5
    coordinator.state.close()


def test_auto_caps_batch_by_per_worker_async_capacity(config, tmp_path: Path) -> None:
    """A large configured batch cannot let one worker hoard more than async capacity."""

    config.discovery.max_devices = "auto"
    config.discovery.workers = 32
    config.discovery.batch_size = 100
    config.snmp.max_outstanding_devices_per_worker = 24
    coordinator = _coordinator(config, tmp_path)

    coordinator.initialize(_seed_inputs(40))

    assert coordinator.effective_workers == 2
    assert coordinator.effective_batch_size == 20
    assert coordinator.execution_plan_per_worker_capacity == 24
    coordinator.state.close()


def test_recursive_discovery_keeps_configured_execution_plan(config, tmp_path: Path) -> None:
    """Runtime right-sizing does not constrain runs that may discover recursive work."""

    config.discovery.max_devices = 100
    config.discovery.workers = 64
    config.discovery.batch_size = 9
    coordinator = _coordinator(config, tmp_path)

    coordinator.initialize(_seed_inputs(9))

    assert coordinator.effective_workers == 64
    assert coordinator.effective_batch_size == 9
    assert coordinator.execution_plan_ready_seeds is None
    coordinator.state.close()


def test_dispatch_uses_balanced_seed_only_batch_size(config, tmp_path: Path) -> None:
    """The coordinator claims the calculated five-device batches for ten seeds."""

    config.discovery.max_devices = "auto"
    config.discovery.workers = 64
    config.discovery.batch_size = 9
    config.snmp.max_outstanding_devices_per_worker = 24
    coordinator = _coordinator(config, tmp_path)
    coordinator.initialize(_seed_inputs(10))

    class AliveProcess:
        """Minimal worker stand-in whose process is always considered alive."""

        @staticmethod
        def is_alive() -> bool:
            """Return true so the coordinator may dispatch to this fake worker."""

            return True

    class WorkQueue:
        """Capture one queued batch without starting multiprocessing workers."""

        def __init__(self) -> None:
            """Initialize the list of queued coordinator messages."""

            self.messages: list[object] = []

        def put(self, message: object) -> None:
            """Record one batch message supplied by ``Coordinator._dispatch``."""

            self.messages.append(message)

    coordinator.workers = [AliveProcess(), AliveProcess()]
    coordinator.work_queues = [WorkQueue(), WorkQueue()]
    coordinator.worker_status = {
        0: {"status": "IDLE", "batch": "-", "size": 0},
        1: {"status": "IDLE", "batch": "-", "size": 0},
    }
    coordinator.batch_hosts = {}
    coordinator.batch_counter = 0

    coordinator._dispatch()

    assert coordinator.worker_status[0]["size"] == 5
    assert coordinator.worker_status[1]["size"] == 5
    assert coordinator.state.active_count() == 10
    coordinator.state.close()


def test_start_workers_spawns_only_effective_seed_only_count(config, tmp_path: Path) -> None:
    """A nine-seed run configured for 64 workers starts only one process."""

    config.discovery.max_devices = "auto"
    config.discovery.workers = 64
    config.discovery.batch_size = 9
    coordinator = _coordinator(config, tmp_path)
    coordinator.initialize(_seed_inputs(9))

    class FakeProcess:
        """Record process startup without creating an operating-system process."""

        def __init__(self, name: str) -> None:
            """Remember the requested worker process name."""

            self.name = name
            self.started = False

        def start(self) -> None:
            """Mark this fake process as started."""

            self.started = True

    class FakeContext:
        """Provide the Queue/Process subset consumed by ``_start_workers``."""

        def __init__(self) -> None:
            """Initialize captured process objects."""

            self.processes: list[FakeProcess] = []

        @staticmethod
        def Queue() -> object:
            """Return an opaque fake work queue."""

            return object()

        def Process(self, *, target, name: str, args) -> FakeProcess:
            """Capture one requested process while ignoring its unexecuted target."""

            del target, args
            process = FakeProcess(name)
            self.processes.append(process)
            return process

    fake_context = FakeContext()
    coordinator.ctx = fake_context
    coordinator.result_queue = object()
    coordinator.log_queue = object()
    coordinator.work_queues = []
    coordinator.workers = []
    coordinator.worker_status = {}

    coordinator._start_workers()

    assert len(fake_context.processes) == 1
    assert fake_context.processes[0].name == "lldp-worker-0"
    assert fake_context.processes[0].started is True
    assert len(coordinator.worker_status) == 1
    coordinator.state.close()


def test_dispatch_serializes_duplicate_management_target_across_workers(config) -> None:
    """Two projections for one target are never polled concurrently."""

    from lldp_runner.models import DeviceTask, TargetAttempt

    class AliveProcess:
        @staticmethod
        def is_alive() -> bool:
            return True

    class WorkQueue:
        def __init__(self) -> None:
            self.messages: list[object] = []

        def put(self, message: object) -> None:
            self.messages.append(message)

    class FakeState:
        def __init__(self) -> None:
            self.claims = [[1], [2]]
            self.deferred: list[int] = []

        def claim_batch(self, *args, **kwargs):
            del args, kwargs
            return self.claims.pop(0)

        def defer_host(self, host_id: int) -> None:
            self.deferred.append(host_id)

    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.pause_event = Event()
    coordinator.workers = [AliveProcess(), AliveProcess()]
    coordinator.work_queues = [WorkQueue(), WorkQueue()]
    coordinator.worker_status = {
        0: {"status": "IDLE", "batch": "-", "size": 0},
        1: {"status": "IDLE", "batch": "-", "size": 0},
    }
    coordinator.state = FakeState()
    coordinator.batch_hosts = {}
    coordinator.batch_target_keys = {}
    coordinator.target_waiting_hosts = {}
    coordinator.batch_counter = 0

    def build_task(host_id: int) -> DeviceTask:
        return DeviceTask(
            host_id=host_id,
            preferred_name=f"projection-{host_id}.example.com",
            names=[f"projection-{host_id}.example.com"],
            addresses=["198.18.20.10"],
            attempts=[
                TargetAttempt(
                    address="198.18.20.10",
                    credential_profile="default",
                )
            ],
            cohort=host_id - 1,
        )

    coordinator._build_task = build_task

    coordinator._dispatch()

    assert len(coordinator.work_queues[0].messages) == 1
    assert coordinator.work_queues[1].messages == []
    assert coordinator.batch_hosts == {"0-1": [1]}
    assert coordinator.batch_target_keys == {"0-1": frozenset({"198.18.20.10"})}
    assert coordinator.state.deferred == [2]
    assert coordinator.target_waiting_hosts == {2: frozenset({"198.18.20.10"})}
