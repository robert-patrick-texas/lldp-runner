"""Bounded late-management-address recovery and route-history regression tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from lldp_runner.coordinator import Coordinator
from lldp_runner.models import Candidate, DeviceResult, SystemDetails, WorkerError
from lldp_runner.policy import PolicyEngine
from lldp_runner.state import StateStore


def _coordinator(config, state: StateStore) -> Coordinator:
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.state = state
    coordinator.policy = PolicyEngine(config)
    coordinator.seed_only = False
    coordinator.seed_credential_bindings = {}
    return coordinator


def _failed_result(host_id: int, target: str, *, attempt: int = 1) -> DeviceResult:
    family = "ipv6" if ":" in target else "ipv4"
    return DeviceResult(
        host_id=host_id,
        status="failed",
        query_target=target,
        credential_profile="specific",
        credential_source="policy-profile",
        credential_result="failed",
        errors=[
            WorkerError(
                operation="snmp_basic",
                category="timeout",
                message="builtins.TimeoutError: request timed out",
                timestamp="2026-08-31T01:00:00-04:00",
                attempted_target=target,
                address_family=family,
                phase="request",
                exception_type="builtins.TimeoutError",
                exception_args=[repr("request timed out")],
                credential_profile="specific",
                credential_stage="primary",
                credential_source="policy-profile",
                attempt=attempt,
                collector="system",
            )
        ],
    )


def _successful_result(host_id: int, target: str) -> DeviceResult:
    return DeviceResult(
        host_id=host_id,
        status="success",
        query_target=target,
        credential_profile="specific",
        credential_source="policy-profile",
        credential_result="primary",
        system=SystemDetails(sys_name="late-recovery-switch"),
        last_seen="2026-08-31T01:05:00-04:00",
        last_seen_source="snmp",
    )


@pytest.mark.parametrize(
    ("failed_target", "new_target"),
    [
        ("198.18.10.10", "2001:db8:8000:da02::10"),
        ("2001:db8:8000:da02::11", "198.18.10.11"),
    ],
)
def test_failed_host_can_use_one_later_cross_family_address(
    tmp_path: Path,
    config,
    failed_target: str,
    new_target: str,
) -> None:
    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=[failed_target],
            category="managed_device",
        )
    )
    state.apply_device_result(_failed_result(host_id, failed_target))
    assert state.host_row(host_id)["state"] == "FAILED"

    merged = state.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=[new_target],
            identity_addresses=[new_target],
            category="managed_device",
            protocol="lldp",
        )
    )
    assert merged == host_id

    coordinator = _coordinator(config, state)
    coordinator._schedule_if_queryable(host_id, evidence_source="lldp:neighbor")

    row = state.host_row(host_id)
    assert row["state"] == "READY"
    assert row["late_recovery_used"] == 1
    assert state.pending_late_recovery_addresses(host_id) == [new_target]
    task = coordinator._build_task(host_id)
    assert task is not None
    assert {attempt.address for attempt in task.attempts} == {new_target}
    assert failed_target not in {attempt.address for attempt in task.attempts}

    state.apply_device_result(_successful_result(host_id, new_target))
    assert state.host_row(host_id)["state"] == "COMPLETE"
    assert state.attempted_addresses(host_id) == {failed_target, new_target}
    events = state.scheduler_events_for_host(host_id)
    assert [event["event_type"] for event in events] == ["late_address_recovery_admitted"]
    assert events[0]["payload"]["new_addresses"] == [new_target]
    state.close()


def test_repeated_or_policy_rejected_address_does_not_requeue(tmp_path: Path, config) -> None:
    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=["198.18.10.20"],
            category="managed_device",
        )
    )
    state.apply_device_result(_failed_result(host_id, "198.18.10.20"))
    # One repeated route, one in-boundary address denied by the fixture's query
    # policy, and one address outside every configured discovery boundary.
    state.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=["198.18.10.20", "198.18.200.20", "203.0.113.20"],
            identity_addresses=[
                "198.18.10.20",
                "198.18.200.20",
                "203.0.113.20",
            ],
            category="managed_device",
            protocol="lldp",
        )
    )

    coordinator = _coordinator(config, state)
    coordinator._schedule_if_queryable(host_id, evidence_source="lldp:neighbor")

    row = state.host_row(host_id)
    assert row["state"] == "FAILED"
    assert row["late_recovery_used"] == 0
    assert state.scheduler_events_for_host(host_id) == []
    state.close()


def test_late_recovery_cap_survives_restart_and_same_address_evidence(
    tmp_path: Path, config
) -> None:
    path = tmp_path / "state.sqlite"
    state = StateStore(path)
    host_id = state.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=["198.18.10.30"],
            category="managed_device",
        )
    )
    state.apply_device_result(_failed_result(host_id, "198.18.10.30"))
    state.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=["2001:db8:8000:da02::30"],
            identity_addresses=["2001:db8:8000:da02::30"],
            category="managed_device",
            protocol="lldp",
        )
    )
    coordinator = _coordinator(config, state)
    coordinator._schedule_if_queryable(host_id, evidence_source="lldp:neighbor")
    assert state.host_row(host_id)["state"] == "READY"

    # The admitted address also fails. The one configured allowance has now
    # been consumed and must remain consumed after SQLite is reopened.
    state.apply_device_result(_failed_result(host_id, "2001:db8:8000:da02::30", attempt=2))
    state.close()

    resumed = StateStore(path)
    resumed.upsert_candidate(
        Candidate(
            names=["late-recovery-switch"],
            addresses=[
                "2001:db8:8000:da02::30",
                "198.18.10.31",
            ],
            identity_addresses=[
                "2001:db8:8000:da02::30",
                "198.18.10.31",
            ],
            category="managed_device",
            protocol="cdp",
        )
    )
    resumed_coordinator = _coordinator(config, resumed)
    resumed_coordinator._schedule_if_queryable(host_id, evidence_source="cdp:neighbor")

    row = resumed.host_row(host_id)
    assert row["state"] == "FAILED"
    assert row["late_recovery_used"] == 1
    assert len(resumed.scheduler_events_for_host(host_id)) == 1
    assert resumed.attempted_addresses(host_id) == {
        "198.18.10.30",
        "2001:db8:8000:da02::30",
    }
    resumed.close()


def test_host_merge_preserves_max_recovery_count_without_new_allowance(
    tmp_path: Path,
) -> None:
    state = StateStore(tmp_path / "state.sqlite")
    by_name = state.upsert_candidate(Candidate(names=["merge-switch"], category="managed_device"))
    by_address = state.upsert_candidate(
        Candidate(addresses=["198.18.44.40"], category="managed_device")
    )
    for host_id, attempted, admitted in (
        (by_name, "198.18.44.41", "198.18.44.42"),
        (by_address, "198.18.44.40", "198.18.44.43"),
    ):
        state.conn.execute("UPDATE hosts SET state='FAILED' WHERE id=?", (host_id,))
        state.conn.commit()
        state.record_route_attempt(
            host_id=host_id,
            attempted_target=attempted,
            outcome="failed",
            category="timeout",
        )
        assert state.admit_late_address_recovery(
            host_id,
            new_addresses=[admitted],
            evidence_source="test",
            allowance=1,
        ) == [admitted]

    merged = state.upsert_candidate(
        Candidate(
            names=["merge-switch"],
            addresses=["198.18.44.40"],
            category="managed_device",
        )
    )
    assert state.host_count() == 1
    assert state.host_row(merged)["late_recovery_used"] == 1
    assert len(state.scheduler_events_for_host(merged)) == 2

    state.conn.execute("UPDATE hosts SET state='FAILED' WHERE id=?", (merged,))
    state.conn.commit()
    assert (
        state.admit_late_address_recovery(
            merged,
            new_addresses=["198.18.44.44"],
            evidence_source="test-after-merge",
            allowance=1,
        )
        == []
    )
    assert state.host_row(merged)["state"] == "FAILED"
    state.close()
