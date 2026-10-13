"""Structured SNMP error persistence, output, recovery, and legacy migration."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from lldp_runner.models import Candidate, DeviceResult, SystemDetails, WorkerError
from lldp_runner.outputs import write_outputs
from lldp_runner.state import StateStore


def _structured_address_error(host_id: int, target: str) -> DeviceResult:
    return DeviceResult(
        host_id=host_id,
        status="failed",
        query_target=target,
        credential_profile="specific",
        credential_source="policy-profile",
        credential_label="site-v2",
        credential_result="failed",
        errors=[
            WorkerError(
                operation="snmp_basic",
                category="snmp_session_address_error",
                message="builtins.OSError: invalid address",
                timestamp="2026-08-31T02:00:00-04:00",
                attempted_target=target,
                address_family="ipv6",
                phase="session_construct",
                exception_type="builtins.OSError",
                exception_errno=22,
                exception_strerror="invalid address",
                exception_args=[repr("invalid address"), "<redacted>"],
                credential_profile="specific",
                credential_stage="primary",
                credential_source="policy-profile",
                credential_label="site-v2",
                attempt=1,
                collector="system",
            )
        ],
    )


def test_failed_route_fields_survive_later_success_and_csv_projection(
    tmp_path: Path, config
) -> None:
    state = StateStore(tmp_path / "state.sqlite")
    state.set_meta("started", "2026-08-31T02:00:00-04:00")
    failed_target = "2001:db8:8000:da02::50"
    recovered_target = "198.18.50.50"
    host_id = state.upsert_candidate(
        Candidate(
            names=["route-provenance-switch"],
            addresses=[failed_target, recovered_target],
            category="managed_device",
        ),
        is_seed=True,
    )
    state.apply_device_result(_structured_address_error(host_id, failed_target))
    state.apply_device_result(
        DeviceResult(
            host_id=host_id,
            status="success",
            query_target=recovered_target,
            credential_profile="specific",
            credential_source="policy-profile",
            credential_label="site-v2",
            credential_result="primary",
            system=SystemDetails(sys_name="route-provenance-switch"),
            last_seen="2026-08-31T02:01:00-04:00",
            last_seen_source="snmp",
        )
    )
    # A non-route warning on the recovered host must not be relabeled as a
    # recovery or have its target guessed from the host's successful route.
    state.add_error(
        host_id,
        "output_validation",
        "example_warning",
        "example host-level warning",
        final_device_status="COMPLETE",
    )

    output = tmp_path / "output"
    write_outputs(
        state,
        config,
        output,
        run_id="error-provenance",
        status="COMPLETED",
        draft=False,
    )
    document = json.loads((output / "discovery.json").read_text(encoding="utf-8"))
    route_error, host_warning = document["errors"]
    assert route_error == {
        "host_ref": host_id,
        "device": "route-provenance-switch",
        "query_target": recovered_target,
        "attempted_target": failed_target,
        "address_family": "ipv6",
        "phase": "session_construct",
        "timestamp": "2026-08-31T02:00:00-04:00",
        "operation": "snmp_basic",
        "collector": "system",
        "category": "snmp_session_address_error",
        "exception_type": "builtins.OSError",
        "exception_errno": 22,
        "exception_strerror": "invalid address",
        "exception_args": [repr("invalid address"), "<redacted>"],
        "credential_profile": "specific",
        "credential_stage": "primary",
        "credential_source": "policy-profile",
        "credential_label": "site-v2",
        "attempt": 1,
        "message": "builtins.OSError: invalid address",
        "recoverable": True,
        "final_state": "complete",
        "recovered": True,
        "recovered_by_target": recovered_target,
    }
    assert host_warning["query_target"] == recovered_target
    assert host_warning["attempted_target"] is None
    assert host_warning["recovered"] is False
    assert host_warning["recovered_by_target"] is None
    assert host_warning["final_state"] == "complete"

    with (output / "errors.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["query_target"] == recovered_target
    assert rows[0]["attempted_target"] == failed_target
    assert rows[0]["address_family"] == "ipv6"
    assert rows[0]["phase"] == "session_construct"
    assert rows[0]["exception_type"] == "builtins.OSError"
    assert rows[0]["exception_errno"] == "22"
    assert rows[0]["credential_source"] == "policy-profile"
    assert rows[0]["collector"] == "system"
    assert rows[0]["final_state"] == "complete"
    assert rows[0]["recovered"] == "True"
    assert rows[0]["recovered_by_target"] == recovered_target
    assert rows[1]["attempted_target"] == ""
    assert rows[1]["recovered"] == "False"
    state.close()


def test_legacy_gufo_ipv6_error_backfill_requires_unique_session_route(
    tmp_path: Path,
) -> None:
    path = tmp_path / "state.sqlite"
    state = StateStore(path)
    target = "2001:db8:8000:da02::51"
    host_id = state.upsert_candidate(
        Candidate(
            names=["legacy-gufo-switch"],
            addresses=[target],
            category="managed_device",
        )
    )
    state.conn.execute(
        "UPDATE hosts SET state='FAILED', snmp_sessions_json=? WHERE id=?",
        (
            json.dumps(
                [
                    {
                        "target": target,
                        "credential_profile": "specific",
                        "credential_route": (f"{target}|policy-profile|primary|specific-v2"),
                    }
                ]
            ),
            host_id,
        ),
    )
    state.conn.execute(
        """
        INSERT INTO errors(
            host_id, timestamp, operation, category, message,
            credential_profile, credential_stage, credential_source,
            credential_label, attempt, recoverable, final_device_status
        ) VALUES(?, ?, 'snmp_basic', 'transport', 'OSError: invalid address',
                 'specific', 'primary', 'policy-profile', 'specific-v2', 1, 1,
                 'FAILED')
        """,
        (host_id, "2026-08-30T19:00:00-04:00"),
    )
    state.conn.commit()
    state.close()

    migrated = StateStore(path)
    error = migrated.errors_for_host(host_id)[0]
    assert error["attempted_target"] == target
    assert error["address_family"] == "ipv6"
    assert error["phase"] == "session_construct"
    assert error["exception_type"] == "builtins.OSError"
    assert error["category"] == "snmp_session_address_error"
    assert error["collector"] == "system"
    assert migrated.attempted_addresses(host_id) == {target}
    migrated.close()


def test_legacy_gufo_backfill_pairs_equal_ordered_route_groups(
    tmp_path: Path,
) -> None:
    """Multiple exact routes may be paired only by matching stage order."""

    path = tmp_path / "ordered.sqlite"
    state = StateStore(path)
    first = "2001:db8:33d:1220::1000:198"
    second = "2001:db8:8000:da02::1"
    host_id = state.upsert_candidate(
        Candidate(
            names=["ordered-gufo-switch"],
            addresses=[first, second],
            category="managed_device",
        )
    )
    sessions = []
    for target in (first, second):
        for stage, credential in (
            ("primary", "specific-v2"),
            ("fallback", "fallback-v2"),
        ):
            sessions.append(
                {
                    "target": target,
                    "credential_profile": "specific",
                    "credential_route": (f"{target}|policy-profile|{stage}|{credential}"),
                }
            )
    state.conn.execute(
        "UPDATE hosts SET state='FAILED', snmp_sessions_json=? WHERE id=?",
        (json.dumps(sessions), host_id),
    )
    for sequence, stage in enumerate(
        ("primary", "fallback", "primary", "fallback"),
        start=1,
    ):
        state.conn.execute(
            """
            INSERT INTO errors(
                host_id, timestamp, operation, category, message,
                credential_profile, credential_stage, credential_source,
                attempt, recoverable, final_device_status
            ) VALUES(?, ?, 'snmp_basic', 'transport',
                     'OSError: invalid address', 'specific', ?,
                     'policy-profile', 1, 1, 'FAILED')
            """,
            (host_id, f"2026-08-30T19:00:0{sequence}-04:00", stage),
        )
    state.conn.commit()
    state.close()

    migrated = StateStore(path)
    errors = migrated.errors_for_host(host_id)
    assert [row["attempted_target"] for row in errors] == [
        first,
        first,
        second,
        second,
    ]
    assert migrated.attempted_addresses(host_id) == {first, second}
    migrated.close()


def test_legacy_error_target_is_not_inferred_when_sessions_are_ambiguous(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ambiguous.sqlite"
    state = StateStore(path)
    host_id = state.upsert_candidate(
        Candidate(
            names=["ambiguous-gufo-switch"],
            addresses=[
                "2001:db8:8000:da02::61",
                "2001:db8:8000:da02::62",
            ],
            category="managed_device",
        )
    )
    state.conn.execute(
        "UPDATE hosts SET state='FAILED', query_target=?, snmp_sessions_json=? WHERE id=?",
        (
            "2001:db8:8000:da02::61",
            json.dumps(
                [
                    {
                        "target": value,
                        "credential_profile": "specific",
                        "credential_route": (f"{value}|policy-profile|primary|specific-v2"),
                    }
                    for value in (
                        "2001:db8:8000:da02::61",
                        "2001:db8:8000:da02::62",
                    )
                ]
            ),
            host_id,
        ),
    )
    state.conn.execute(
        """
        INSERT INTO errors(
            host_id, timestamp, operation, category, message,
            credential_profile, credential_stage, credential_source,
            credential_label, attempt, recoverable, final_device_status
        ) VALUES(?, ?, 'snmp_basic', 'transport', 'OSError: invalid address',
                 'specific', 'primary', 'policy-profile', 'specific-v2', 1, 1,
                 'FAILED')
        """,
        (host_id, "2026-08-30T19:00:00-04:00"),
    )
    state.conn.commit()
    state.close()

    migrated = StateStore(path)
    error = migrated.errors_for_host(host_id)[0]
    assert error["attempted_target"] is None
    assert error["category"] == "transport"
    assert migrated.attempted_addresses(host_id) == set()
    migrated.close()
