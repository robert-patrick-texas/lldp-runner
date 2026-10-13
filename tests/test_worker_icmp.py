from __future__ import annotations

import asyncio
import contextlib
import logging
from contextlib import AbstractAsyncContextManager
from types import SimpleNamespace
from typing import Any, ClassVar

from lldp_runner import worker
from lldp_runner.collectors.cdp import CdpSnapshotIncompleteError
from lldp_runner.collectors.lldp import collect_lldp
from lldp_runner.models import (
    CollectionCoverage,
    CollectionMetric,
    DeviceResult,
    DeviceTask,
    NeighborObservation,
    PingProbe,
    SystemDetails,
    TargetAttempt,
)
from lldp_runner.worker import _basic_wavefront


class _PauseEvent:
    def is_set(self) -> bool:
        return False


class _FakePinger:
    events: ClassVar[list[tuple[str, str, int]]] = []

    def __init__(self, _config: Any) -> None:
        pass

    async def probe(self, address: str, sequence: int) -> PingProbe:
        self.events.append(("ping", address, sequence))
        return PingProbe(
            status="reply",
            timestamp="2026-08-18T23:30:00-04:00",
            address=address,
            rtt_ms=1.0,
        )


class _FakeSnmpContext(AbstractAsyncContextManager[object]):
    def __init__(self, address: str, events: list[tuple[str, str, int]]) -> None:
        self.address = address
        self.events = events

    async def __aenter__(self) -> object:
        self.events.append(("snmp", self.address, 0))
        if self.address == "198.18.0.10":
            raise TimeoutError("test timeout")
        return object()

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        return None


def _task() -> DeviceTask:
    return DeviceTask(
        host_id=1,
        preferred_name="switch1.example.com",
        names=["switch1.example.com"],
        addresses=["198.18.0.10", "2001:db8::10"],
        attempts=[
            TargetAttempt(address="198.18.0.10", credential_profile="specific"),
            TargetAttempt(address="2001:db8::10", credential_profile="specific"),
        ],
        cohort=0,
    )


def test_each_new_snmp_address_is_pinged_first(config, monkeypatch) -> None:
    import lldp_runner.worker as worker

    config.icmp.enabled = True
    config.icmp.backend = "auto"
    config.icmp.inter_probe_delay_seconds = 0
    config.snmp.inter_wave_delay_seconds = 0
    _FakePinger.events = []

    monkeypatch.setattr(worker, "AsyncIcmpPinger", _FakePinger)
    monkeypatch.setattr(
        worker,
        "create_snmp_client",
        lambda _config, address, _credential, **_kwargs: _FakeSnmpContext(
            address, _FakePinger.events
        ),
    )

    async def fake_collect_basic_system(_client: object) -> SystemDetails:
        return SystemDetails(sys_name="switch1")

    monkeypatch.setattr(worker, "collect_basic_system", fake_collect_basic_system)

    results = {1: DeviceResult(host_id=1, status="deferred")}
    successful = asyncio.run(_basic_wavefront(config, [_task()], results, _PauseEvent()))

    assert [event[:2] for event in _FakePinger.events] == [
        ("ping", "198.18.0.10"),
        ("ping", "198.18.0.10"),
        ("snmp", "198.18.0.10"),
        ("ping", "2001:db8::10"),
        ("ping", "2001:db8::10"),
        ("snmp", "2001:db8::10"),
    ]
    assert [probe.address for probe in results[1].ping_probes] == [
        "198.18.0.10",
        "198.18.0.10",
        "2001:db8::10",
        "2001:db8::10",
    ]
    assert successful[0][1].address == "2001:db8::10"


def test_icmp_disabled_does_not_probe_before_snmp(config, monkeypatch) -> None:
    import lldp_runner.worker as worker

    config.icmp.enabled = False
    config.icmp.backend = "auto"
    config.snmp.inter_wave_delay_seconds = 0
    _FakePinger.events = []

    monkeypatch.setattr(worker, "AsyncIcmpPinger", _FakePinger)
    monkeypatch.setattr(
        worker,
        "create_snmp_client",
        lambda _config, address, _credential, **_kwargs: _FakeSnmpContext(
            address, _FakePinger.events
        ),
    )

    async def fake_collect_basic_system(_client: object) -> SystemDetails:
        return SystemDetails(sys_name="switch1")

    monkeypatch.setattr(worker, "collect_basic_system", fake_collect_basic_system)

    results = {1: DeviceResult(host_id=1, status="deferred")}
    successful = asyncio.run(_basic_wavefront(config, [_task()], results, _PauseEvent()))

    assert [event[:2] for event in _FakePinger.events] == [
        ("snmp", "198.18.0.10"),
        ("snmp", "2001:db8::10"),
    ]
    assert results[1].ping_probes == []
    assert successful[0][1].address == "2001:db8::10"


def test_process_single_device_system_only_skips_detail_collectors(monkeypatch, config) -> None:
    """System-only inspection must not open the detail ENTITY/IF/neighbor path."""

    from lldp_runner import worker

    task = DeviceTask(
        host_id=1,
        preferred_name="switch1.net.example.com",
        names=["switch1.net.example.com"],
        addresses=["198.18.10.10"],
        attempts=[TargetAttempt(address="198.18.10.10", credential_profile="default")],
        cohort=0,
    )

    async def fake_basic(config_arg, tasks, results, pause_event, *, collect_metrics=False):
        assert collect_metrics is True
        results[1].collection_metrics["sys"] = CollectionMetric(
            objects=6, duration_ms=12.4
        )
        return [
            (
                tasks[0],
                worker._SuccessfulBasic(
                    address="198.18.10.10",
                    profile_name="default",
                    credential=config.credentials[config.credential_profiles["default"].primary],
                    credential_result="primary",
                    credential_source="policy-profile",
                    credential_label=None,
                    system=SystemDetails(sys_name="switch1.net.example.com"),
                ),
            )
        ]

    async def forbidden_detail(*args, **kwargs):
        raise AssertionError("system-only inspection must not collect detail MIBs")

    monkeypatch.setattr(worker, "_basic_wavefront", fake_basic)
    monkeypatch.setattr(worker, "_collect_detail", forbidden_detail)

    device, timings = asyncio.run(
        worker.process_single_device(
            config, task, _PauseEvent(), system_only=True
        )
    )

    assert device.status == "success"
    assert device.collection_metrics["sys"].objects == 6
    assert device.neighbors == []
    assert timings["detail_phase"] == 0.0


class _RetryEvent:
    """Small mutable event matching the worker's retry-result contract."""

    def __init__(self) -> None:
        self.final_outcome = "pending"
        self.outcome_type = None
        self.attempt = 2


class _AdaptiveCollectorStub:
    """Collector-restart stub without opening an SNMP backend session."""

    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[tuple[str, str]] = []
        self.state = type("State", (), {"events": []})()

    async def prepare_collection_retry(
        self,
        *,
        operation: str,
        category: str,
        root_oid: str | None = None,
    ) -> bool:
        self.calls.append((operation, category))
        if not self.allow:
            return False
        self.state.events.append(_RetryEvent())
        return True


def test_lldp_subtable_coverage_survives_structural_restart(config) -> None:
    """Whole-protocol retry accumulates work but finalizes each subtable."""

    from lldp_runner.collectors.lldp import (
        LldpCollection,
        LldpSnapshotIncompleteError,
    )
    from lldp_runner.worker import _collect_neighbor_outcome, _NeighborProtocolSpec

    calls = 0
    adaptive = _AdaptiveCollectorStub()

    async def collector(_client: object, _interfaces: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            error = LldpSnapshotIncompleteError("mandatory Port ID missing")
            error.lldp_subtable_coverage = {
                "local_port": CollectionCoverage(
                    status="complete", attempts=1, object_count=2, row_count=1
                ),
                "remote_neighbor": CollectionCoverage(
                    status="structurally_invalid",
                    attempts=1,
                    object_count=9,
                    row_count=1,
                    message="mandatory Port ID missing",
                ),
                "remote_management_address": CollectionCoverage(
                    status="not_attempted", attempts=1, object_count=0, row_count=None
                ),
            }
            raise error
        observation = NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="Gi1/0/1",
            remote_name="peer",
            remote_interface="Gi0/1",
            remote_interface_raw="Gi0/1",
        )
        return LldpCollection(
            [observation],
            subtable_coverage={
                "local_port": CollectionCoverage(
                    status="complete", attempts=1, object_count=2, row_count=1
                ),
                "remote_neighbor": CollectionCoverage(
                    status="complete", attempts=1, object_count=10, row_count=1
                ),
                "remote_management_address": CollectionCoverage(
                    status="complete",
                    attempts=1,
                    object_count=1,
                    row_count=1,
                    valid_address_count=1,
                    ipv4_address_count=1,
                ),
            },
        )

    outcome = asyncio.run(
        _collect_neighbor_outcome(
            config,
            "198.18.0.10",
            None,
            object(),
            {},
            _NeighborProtocolSpec(
                operation="lldp",
                collector=collector,
                display_name="LLDP",
                unresolved_identifier="lldpLocalPort",
            ),
            adaptive_client=adaptive,
        )
    )

    assert outcome.exc is None
    assert outcome.attempts == 2
    assert len(outcome.values) == 1
    assert outcome.subtable_coverage["local_port"].attempts == 2
    assert outcome.subtable_coverage["local_port"].object_count == 4
    assert outcome.subtable_coverage["remote_neighbor"].attempts == 2
    assert outcome.subtable_coverage["remote_neighbor"].object_count == 19
    assert outcome.subtable_coverage["remote_neighbor"].status == "complete"
    assert outcome.subtable_coverage["remote_management_address"].attempts == 2
    assert outcome.subtable_coverage["remote_management_address"].status == "complete"


def test_lldp_aggregate_coverage_is_partial_when_local_map_failed(config) -> None:
    """Remote topology can be retained while local-port loss remains explicit."""

    from lldp_runner import worker

    result = DeviceResult(host_id=1, status="success")
    observation = NeighborObservation(
        protocol="lldp",
        local_interface="lldpLocalPort:7",
        local_interface_raw="lldpLocalPort:7",
        remote_name="peer",
        remote_interface="Gi0/1",
        remote_interface_raw="Gi0/1",
        details={"local_interface_resolved": False},
    )
    outcome = worker._NeighborProtocolOutcome(
        spec=worker._NeighborProtocolSpec(
            operation="lldp",
            collector=collect_lldp,
            display_name="LLDP",
            unresolved_identifier="lldpLocalPort",
        ),
        values=[observation],
        exc=None,
        attempts=1,
        subtable_coverage={
            "local_port": CollectionCoverage(
                status="timeout", attempts=2, message="local map timeout"
            ),
            "remote_neighbor": CollectionCoverage(
                status="complete", attempts=1, object_count=8, row_count=1
            ),
            "remote_management_address": CollectionCoverage(
                status="complete", attempts=1, object_count=0, row_count=0
            ),
        },
    )
    credential = config.credentials[config.credential_profiles["default"].primary]
    basic = worker._SuccessfulBasic(
        address="198.18.0.10",
        profile_name="default",
        credential=credential,
        credential_result="primary",
        credential_source="policy-profile",
        credential_label=None,
        system=SystemDetails(sys_name="switch1"),
    )
    errors: list[object] = []
    observations: list[object] = []

    worker._record_neighbor_outcome(
        outcome,
        target="198.18.0.10",
        credential=credential,
        basic=basic,
        audit_result=result,
        errors=errors,  # type: ignore[arg-type]
        observations=observations,
    )

    aggregate = result.collection_coverage["lldp"]
    assert aggregate.status == "partial"
    assert aggregate.row_count == 1
    assert aggregate.resolution_status == "partial"
    assert aggregate.subtables["local_port"].status == "timeout"
    assert aggregate.subtables["remote_neighbor"].status == "complete"
    assert observations == [observation]
    assert any(getattr(error, "operation", "") == "lldp_interface_resolution" for error in errors)


def test_neighbor_protocol_timeout_is_not_retried_by_worker(config) -> None:
    """Timeout retry belongs to the adaptive SNMP operation boundary only."""

    from lldp_runner.worker import _collect_neighbor_protocol

    calls = 0

    async def collector(_client: object) -> list[str]:
        nonlocal calls
        calls += 1
        raise TimeoutError("table timeout surfaced after adaptive budget")

    values, error, attempts = asyncio.run(
        _collect_neighbor_protocol(
            config, "198.18.0.10", "cdp", None, object(), collector
        )
    )

    assert values == []
    assert isinstance(error, TimeoutError)
    assert attempts == 1
    assert calls == 1


def test_neighbor_protocol_retries_one_incomplete_snapshot(config, caplog) -> None:
    """A structural table defect may consume the shared target retry token."""

    from lldp_runner.collectors.lldp import LldpSnapshotIncompleteError
    from lldp_runner.worker import _collect_neighbor_protocol

    calls = 0
    adaptive = _AdaptiveCollectorStub()

    async def collector(_client: object) -> list[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise LldpSnapshotIncompleteError("mandatory port ID missing")
        return ["complete-neighbor"]

    with caplog.at_level(logging.INFO):
        values, error, attempts = asyncio.run(
            _collect_neighbor_protocol(
                config,
                "198.18.0.10",
                "lldp",
                None,
                object(),
                collector,
                adaptive_client=adaptive,
            )
        )

    assert values == ["complete-neighbor"]
    assert error is None
    assert attempts == 2
    assert calls == 2
    assert adaptive.calls == [("LLDP", "incomplete_table")]
    assert adaptive.state.events[0].final_outcome == "succeeded"
    assert (
        "SNMP target=198.18.0.10 neighbor collector restart "
        "operation=lldp category=incomplete_table attempt=2"
    ) in caplog.text


def test_neighbor_protocol_persists_second_incomplete_snapshot(config) -> None:
    """A repeated structural failure remains explicit collection coverage loss."""

    from lldp_runner.collectors.lldp import LldpSnapshotIncompleteError
    from lldp_runner.worker import _collect_neighbor_protocol, _error_category

    calls = 0
    adaptive = _AdaptiveCollectorStub()

    async def collector(_client: object) -> list[str]:
        nonlocal calls
        calls += 1
        raise LldpSnapshotIncompleteError("mandatory chassis ID missing")

    values, error, attempts = asyncio.run(
        _collect_neighbor_protocol(
            config,
            "198.18.0.10",
            "lldp",
            None,
            object(),
            collector,
            adaptive_client=adaptive,
        )
    )

    assert values == []
    assert isinstance(error, LldpSnapshotIncompleteError)
    assert _error_category(error) == "incomplete_table"
    assert attempts == 2
    assert calls == 2
    assert adaptive.state.events[0].final_outcome == "failed"
    assert adaptive.state.events[0].outcome_type == "LldpSnapshotIncompleteError"


def test_cdp_invalid_snapshot_retries_from_root_then_materializes(config) -> None:
    """A valid second CDP snapshot replaces, rather than extends, the invalid one."""

    from lldp_runner.collectors.cdp import CdpSnapshotIncompleteError
    from lldp_runner.worker import _collect_neighbor_protocol

    calls = 0
    adaptive = _AdaptiveCollectorStub()

    async def collector(_client: object) -> list[str]:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise CdpSnapshotIncompleteError(
                "cdp cache row 2006.2472 missing mandatory device_id, remote_port"
            )
        return ["validated-cdp-row"]

    values, error, attempts = asyncio.run(
        _collect_neighbor_protocol(
            config,
            "198.18.0.11",
            "cdp",
            None,
            object(),
            collector,
            adaptive_client=adaptive,
        )
    )

    assert values == ["validated-cdp-row"]
    assert error is None
    assert attempts == 2
    assert calls == 2
    assert adaptive.calls == [("CDP", "incomplete_table")]


def test_repeated_invalid_cdp_snapshot_records_structural_failure(config) -> None:
    """Two invalid CDP snapshots return no rows and a stable coverage category."""

    from lldp_runner.collectors.cdp import CdpSnapshotIncompleteError
    from lldp_runner.worker import _collect_neighbor_protocol, _error_category

    adaptive = _AdaptiveCollectorStub()

    async def collector(_client: object) -> list[str]:
        raise CdpSnapshotIncompleteError(
            "cdp cache row 2006.580 missing mandatory device_id, remote_port"
        )

    values, error, attempts = asyncio.run(
        _collect_neighbor_protocol(
            config,
            "198.18.0.12",
            "cdp",
            None,
            object(),
            collector,
            adaptive_client=adaptive,
        )
    )

    assert values == []
    assert isinstance(error, CdpSnapshotIncompleteError)
    assert _error_category(error) == "incomplete_table"
    assert attempts == 2
    assert adaptive.state.events[0].final_outcome == "failed"


def test_neighbor_protocol_transport_failure_is_not_performance_retry(config) -> None:
    """Socket failures are not mislabeled as slow-agent GETBULK behavior."""

    from lldp_runner.worker import _collect_neighbor_protocol

    calls = 0

    async def collector(_client: object) -> list[str]:
        nonlocal calls
        calls += 1
        raise OSError("socket route failed")

    values, error, attempts = asyncio.run(
        _collect_neighbor_protocol(
            config, "198.18.0.10", "lldp", None, object(), collector
        )
    )

    assert values == []
    assert isinstance(error, OSError)
    assert attempts == 1
    assert calls == 1


def test_interface_timeout_is_not_retried_by_worker(config, monkeypatch) -> None:
    """IF-MIB timeout handling is centralized in AdaptiveSnmpClient."""

    from lldp_runner import worker

    calls = 0

    async def fake_collect(_client: object):
        nonlocal calls
        calls += 1
        raise TimeoutError("IF-MIB timeout after adaptive budget")

    monkeypatch.setattr(worker, "collect_interfaces", fake_collect)
    values, error, attempts = asyncio.run(
        worker._collect_interface_map(config, "198.18.0.10", None, object())
    )

    assert values == {}
    assert isinstance(error, TimeoutError)
    assert attempts == 1
    assert calls == 1


def test_interface_map_retries_one_structural_failure(config, monkeypatch) -> None:
    """An incomplete IF-MIB naming snapshot restarts through shared policy."""

    from lldp_runner import worker
    from lldp_runner.collectors.interfaces import InterfaceCollectionError

    calls = 0
    adaptive = _AdaptiveCollectorStub()

    async def fake_collect(_client: object):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterfaceCollectionError("both naming tables incomplete")
        return {101: ("GigabitEthernet1/0/1", "Gi1/0/1")}

    monkeypatch.setattr(worker, "collect_interfaces", fake_collect)
    values, error, attempts = asyncio.run(
        worker._collect_interface_map(
            config,
            "198.18.0.10",
            None,
            object(),
            adaptive_client=adaptive,
        )
    )

    assert values == {101: ("GigabitEthernet1/0/1", "Gi1/0/1")}
    assert error is None
    assert attempts == 2
    assert calls == 2
    assert adaptive.calls == [("INTERFACES", "incomplete_table")]


def test_basic_route_reuses_adaptive_profile_across_outer_attempts(
    config, monkeypatch
) -> None:
    """Configured attempts on one route keep the target's degraded profile."""

    from lldp_runner import worker

    config.icmp.enabled = False
    config.snmp.inter_wave_delay_seconds = 0
    config.credential_profiles["specific"].primary_attempts = 2
    task = DeviceTask(
        host_id=1,
        preferred_name="switch1.example.com",
        names=["switch1.example.com"],
        addresses=["198.18.0.10"],
        attempts=[TargetAttempt(address="198.18.0.10", credential_profile="specific")],
        cohort=0,
    )
    states = []
    calls = 0

    class Context(AbstractAsyncContextManager[object]):
        def __init__(self, adaptive_state) -> None:
            self.adaptive_state = adaptive_state

        async def __aenter__(self) -> object:
            nonlocal calls
            calls += 1
            states.append(self.adaptive_state)
            if calls == 1:
                event = self.adaptive_state.consume_retry(
                    operation_key="basic-system-get",
                    retry_kind="transport",
                    collector="system",
                    logical_operation="GET",
                    table_name="SYSTEM-MIB",
                    root_oid=None,
                    collection_phase="basic",
                    category="timeout",
                    partial_rows_discarded=False,
                )
                assert event is not None
                event.final_outcome = "failed"
                raise TimeoutError("route remains slow after its internal retry")
            return object()

        async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
            return None

    monkeypatch.setattr(
        worker,
        "create_snmp_client",
        lambda _config, _address, _credential, *, adaptive_state: Context(
            adaptive_state
        ),
    )

    async def fake_collect_basic_system(_client: object) -> SystemDetails:
        return SystemDetails(sys_name="switch1.example.com")

    monkeypatch.setattr(worker, "collect_basic_system", fake_collect_basic_system)
    results = {1: DeviceResult(host_id=1, status="deferred")}
    successful = asyncio.run(
        _basic_wavefront(config, [task], results, _PauseEvent())
    )

    assert len(states) == 2
    assert states[0] is states[1]
    assert states[1].degraded is True
    assert states[1].timeout_seconds == 4.5
    assert states[1].max_repetitions == 10
    assert results[1].snmp_sessions == []
    assert successful[0][1].adaptive_state is states[1]


def test_adaptive_profile_resets_for_new_target_or_credential_route(config) -> None:
    """Slowdown evidence belongs only to one address and credential route."""

    from lldp_runner import worker

    task = DeviceTask(
        host_id=1,
        preferred_name="switch1.example.com",
        names=["switch1.example.com"],
        addresses=["198.18.0.10"],
        attempts=[TargetAttempt(address="198.18.0.10", credential_profile="specific")],
        cohort=0,
    )
    state = worker._BasicState(task=task, errors=[])
    credential = config.credentials[config.credential_profiles["specific"].primary]

    def route(
        address: str,
        *,
        stage: str = "primary",
        label: str = "site-primary",
    ) -> worker._ResolvedCredentialAttempt:
        return worker._ResolvedCredentialAttempt(
            address=address,
            profile_name="specific",
            credential=credential,
            credential_result=stage,
            credential_source="policy-profile",
            credential_label=label,
        )

    first = state.adaptive_state_for(config, route("198.18.0.10"))
    event = first.consume_retry(
        operation_key="system-get",
        retry_kind="transport",
        collector="system",
        logical_operation="GET",
        table_name="SYSTEM-MIB",
        root_oid=None,
        collection_phase="basic",
        category="timeout",
        partial_rows_discarded=False,
    )
    assert event is not None
    assert first.degraded is True

    second = state.adaptive_state_for(config, route("198.18.0.11"))
    assert second is not first
    assert second.degraded is False
    assert second.timeout_seconds == config.snmp.timeout_seconds

    third = state.adaptive_state_for(
        config,
        route("198.18.0.11", stage="fallback", label="site-fallback"),
    )
    assert third is not second
    assert third.degraded is False


def test_delayed_neighbor_stability_pass_shares_one_delay_and_is_bounded(
    monkeypatch,
    config,
) -> None:
    config.snmp.neighbor_stability_retry = True
    config.snmp.neighbor_stability_retry_delay_seconds = 1.25
    sleeps: list[float] = []
    calls: list[str] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    monkeypatch.setattr(worker.asyncio, "sleep", fake_sleep)

    class Adaptive:
        def __init__(self) -> None:
            self.state = SimpleNamespace(events=[])
            self.context: dict[str, Any] = {}
            self.suppressed = False

        @contextlib.contextmanager
        def collection_context(self, **kwargs):
            previous = self.context
            self.context = kwargs
            try:
                yield
            finally:
                self.context = previous

        async def prepare_stability_retry(self, **kwargs) -> bool:
            event = SimpleNamespace(
                collector=self.context["collector"],
                retry_allowed=True,
                final_outcome="pending",
                outcome_type=None,
            )
            self.state.events.append(event)
            return True

        @contextlib.contextmanager
        def suppress_normal_retries(self):
            assert not self.suppressed
            self.suppressed = True
            try:
                yield
            finally:
                self.suppressed = False

    adaptive = Adaptive()

    async def recovered_lldp(_client, _interfaces):
        assert adaptive.suppressed
        calls.append("lldp")
        return ["lldp-row"]

    async def still_failing_cdp(_client, _interfaces):
        assert adaptive.suppressed
        calls.append("cdp")
        raise TimeoutError("persistent packet loss")

    async def should_not_run(_client, _interfaces):
        calls.append("lldpv2")
        return []

    outcomes = [
        worker._NeighborProtocolOutcome(
            spec=worker._NeighborProtocolSpec(
                operation="lldp",
                collector=recovered_lldp,
                display_name="LLDP",
                unresolved_identifier="ifIndex",
            ),
            values=[],
            exc=TimeoutError("first timeout"),
            attempts=2,
        ),
        worker._NeighborProtocolOutcome(
            spec=worker._NeighborProtocolSpec(
                operation="cdp",
                collector=still_failing_cdp,
                display_name="CDP",
                unresolved_identifier="ifIndex",
            ),
            values=[],
            exc=CdpSnapshotIncompleteError(
                "cdp cache row 17.2 missing mandatory device_id"
            ),
            attempts=1,
        ),
        worker._NeighborProtocolOutcome(
            spec=worker._NeighborProtocolSpec(
                operation="lldpv2",
                collector=should_not_run,
                display_name="LLDPv2",
                unresolved_identifier="ifIndex",
            ),
            values=[],
            exc=RuntimeError("deterministic failure"),
            attempts=1,
        ),
    ]

    asyncio.run(
        worker._run_delayed_neighbor_stability_pass(
            config,
            "192.0.2.90",
            None,
            object(),
            {},
            outcomes,
            adaptive_client=adaptive,
        )
    )

    assert sleeps == [1.25]
    assert calls == ["lldp", "cdp"]
    assert outcomes[0].values == ["lldp-row"]
    assert outcomes[0].exc is None
    assert outcomes[0].attempts == 3
    assert isinstance(outcomes[1].exc, TimeoutError)
    assert outcomes[1].attempts == 2
    assert isinstance(outcomes[2].exc, RuntimeError)
    assert outcomes[2].attempts == 1
    assert [event.final_outcome for event in adaptive.state.events] == [
        "succeeded",
        "failed",
    ]


def test_delayed_neighbor_stability_pass_can_be_disabled(
    monkeypatch, config
) -> None:
    config.snmp.neighbor_stability_retry = False
    called = False

    async def forbidden_sleep(_seconds: float) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(worker.asyncio, "sleep", forbidden_sleep)
    outcome = worker._NeighborProtocolOutcome(
        spec=worker._NeighborProtocolSpec(
            operation="lldp",
            collector=collect_lldp,
            display_name="LLDP",
            unresolved_identifier="ifIndex",
        ),
        values=[],
        exc=TimeoutError("first timeout"),
        attempts=1,
    )

    asyncio.run(
        worker._run_delayed_neighbor_stability_pass(
            config,
            "192.0.2.91",
            None,
            object(),
            {},
            [outcome],
            adaptive_client=SimpleNamespace(),
        )
    )

    assert called is False
    assert isinstance(outcome.exc, TimeoutError)
    assert outcome.attempts == 1
