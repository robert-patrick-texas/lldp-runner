"""Immutable claim-ledger and deferred-resolution regression coverage."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from lldp_runner.claims import candidate_claims
from lldp_runner.models import Candidate, DeviceResult, StackMemberDetails, SystemDetails
from lldp_runner.state import StateStore


def _edge_candidate(
    *,
    name: str | None = None,
    chassis_id: str | None = None,
    chassis_subtype: str | None = None,
    chassis_subtype_id: int | None = None,
    source_host_id: int = 10,
    local_interface: str = "Gi1/0/1",
    port_id: str | None = None,
) -> Candidate:
    details: dict[str, object] = {}
    if port_id is not None:
        details.update(
            {
                "port_id": port_id,
                "port_id_subtype": "mac_address",
                "port_id_subtype_id": 3,
            }
        )
    return Candidate(
        names=[name] if name else [],
        identity_names=[name] if name else [],
        source_host_id=source_host_id,
        protocol="lldp",
        local_interface=local_interface,
        local_interface_raw=local_interface,
        remote_interface="P1",
        remote_interface_raw="P1",
        chassis_id=chassis_id,
        chassis_id_subtype=chassis_subtype,
        chassis_id_subtype_id=chassis_subtype_id,
        details=details,
        category="managed_endpoint",
    )


def test_candidate_claims_separate_strong_and_weak_evidence() -> None:
    """Strict hardware identity is strong while network chassis data stays weak."""

    candidate = _edge_candidate(
        name="SEP001122334455.voice-a.example.com",
        chassis_id="198.51.100.3",
        chassis_subtype="network_address",
        chassis_subtype_id=5,
        port_id="00:11:22:33:44:55",
    )
    candidate.names.append("phone-service.example.com")
    candidate.addresses = ["198.18.0.55"]
    candidate.identity_addresses = []

    claims = candidate_claims(candidate)

    sep = next(claim for claim in claims if claim.claim_subtype == "cisco_sep_mac")
    assert sep.normalized_value == "00:11:22:33:44:55"
    assert sep.strength == "strong"
    assert sep.scope == "global"
    assert sep.identity_eligible is True

    chassis = next(
        claim
        for claim in claims
        if claim.claim_type == "chassis" and claim.claim_subtype == "network_address"
    )
    assert chassis.normalized_value == "198.51.100.3"
    assert chassis.strength == "weak"
    assert chassis.scope == "edge"
    assert chassis.identity_eligible is False

    dns = next(
        claim
        for claim in claims
        if claim.claim_type == "name" and claim.normalized_value == "phone-service.example.com"
    )
    assert dns.provenance == "dns_enrichment"
    assert dns.scope == "diagnostic"
    assert dns.identity_eligible is False

    # A strong claim is only globally verified when its scope permits.  The
    # exact remote Port-ID MAC is strong within this edge, not a universal host
    # identity by itself.
    edge_only = [claim for claim in claims if claim.claim_type == "remote_port"]
    assert StateStore._claim_confidence(edge_only) == "high"
    assert StateStore._claim_confidence([sep]) == "verified"


def test_anonymous_local_chassis_port_mac_becomes_bounded_hardware_claim() -> None:
    """Subtype-7 stays edge-scoped while a typed anonymous Port ID is global."""

    candidate = _edge_candidate(
        chassis_id="hex:a1:00:00:00:00:00",
        chassis_subtype="local",
        chassis_subtype_id=7,
        port_id="10:98:19:4d:2f:97",
    )

    claims = candidate_claims(candidate)
    chassis = next(claim for claim in claims if claim.claim_type == "chassis")
    endpoint = next(claim for claim in claims if claim.claim_subtype == "anonymous_lldp_port_mac")

    assert chassis.normalized_value == "hex:a1:00:00:00:00:00"
    assert chassis.scope == "edge"
    assert chassis.identity_eligible is False
    assert endpoint.normalized_value == "10:98:19:4d:2f:97"
    assert endpoint.provenance == "derived_strict"
    assert endpoint.scope == "global"
    assert endpoint.strength == "strong"
    assert endpoint.identity_eligible is True


def test_named_endpoint_does_not_promote_port_mac_to_device_identity() -> None:
    """A named multi-interface device continues to use device-level evidence."""

    claims = candidate_claims(
        _edge_candidate(
            name="switch.example.com",
            chassis_id="local-label",
            chassis_subtype="local",
            chassis_subtype_id=7,
            port_id="10:98:19:4d:2f:97",
        )
    )

    assert not any(claim.claim_subtype == "anonymous_lldp_port_mac" for claim in claims)


def test_replaying_candidate_is_idempotent_in_claim_ledger(tmp_path: Path) -> None:
    """The same normalized observation creates one observation and decision."""

    state = StateStore(tmp_path / "state.sqlite")
    candidate = _edge_candidate(
        name="SEP001122334455",
        chassis_id="00:11:22:33:44:55",
        chassis_subtype="mac_address",
        chassis_subtype_id=4,
        port_id="00:11:22:33:44:55",
    )

    first = state.upsert_candidate(candidate, synthetic_alias="edge:10:Gi1/0/1")
    second = state.upsert_candidate(candidate, synthetic_alias="edge:10:Gi1/0/1")

    assert first == second
    observations = state.observations()
    assert len(observations) == 1
    observation_id = int(observations[0]["id"])
    assert len(state.claims_for_observation(observation_id)) >= 4
    assert len(state.resolution_decisions_for_observation(observation_id)) == 1
    state.close()


def test_claim_ledger_preserves_distinct_raw_forms_with_one_normalized_value(
    tmp_path: Path,
) -> None:
    """Normalization must not erase separately reported immutable evidence."""

    state = StateStore(tmp_path / "state.sqlite")
    candidate = Candidate(
        names=["Switch1.Example.Com", "switch1.example.com"],
        identity_names=["Switch1.Example.Com", "switch1.example.com"],
        category="managed_device",
    )

    state.upsert_candidate(candidate)

    observation_id = int(state.observations()[0]["id"])
    rows = state.conn.execute(
        "SELECT raw_value_json FROM claims "
        "WHERE observation_id=? AND claim_type='name' "
        "AND normalized_value='switch1.example.com' ORDER BY id",
        (observation_id,),
    ).fetchall()
    assert [json.loads(str(row["raw_value_json"])) for row in rows] == [
        "Switch1.Example.Com",
        "switch1.example.com",
    ]
    state.close()


def test_observations_claims_and_decisions_reject_mutation(tmp_path: Path) -> None:
    """Audit evidence and resolver history are append-only at the SQL boundary."""

    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(
        _edge_candidate(name="SEP001122334455"),
        synthetic_alias="edge:10:Gi1/0/1",
    )
    observation_id = int(state.observations()[0]["id"])
    claim_id = int(state.claims_for_observation(observation_id)[0]["id"])
    decision_id = int(state.resolution_decisions_for_observation(observation_id)[0]["id"])

    with pytest.raises(sqlite3.IntegrityError, match="observations are immutable"):
        state.conn.execute("UPDATE observations SET protocol='cdp' WHERE id=?", (observation_id,))
    state.conn.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="claims are immutable"):
        state.conn.execute("UPDATE claims SET strength='weak' WHERE id=?", (claim_id,))
    state.conn.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="resolution decisions are immutable"):
        state.conn.execute(
            "UPDATE resolution_decisions SET confidence='low' WHERE id=?",
            (decision_id,),
        )
    state.conn.rollback()
    with pytest.raises(sqlite3.IntegrityError, match="decision claim links are immutable"):
        state.conn.execute("DELETE FROM decision_claims WHERE decision_id=?", (decision_id,))
    state.conn.rollback()
    state.close()


def test_changed_resolution_supersedes_without_overwriting_history(
    tmp_path: Path,
) -> None:
    """New evidence can append a different decision while preserving the old one."""

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        _edge_candidate(name="SEP001122334455"),
        synthetic_alias="edge:10:Gi1/0/1",
    )
    observation_id = int(state.observations()[0]["id"])
    first = state.resolution_decisions_for_observation(observation_id)[0]

    repeated = state.record_resolution_decision(
        observation_id,
        decision_type=str(first["decision_type"]),
        projected_host_id=host_id,
        candidate_host_ids=json.loads(str(first["candidate_host_ids_json"])),
        confidence=str(first["confidence"]),
        rationale=json.loads(str(first["rationale_json"])),
    )
    assert repeated == int(first["id"])

    reassessed = state.record_resolution_decision(
        observation_id,
        decision_type="projected_host",
        projected_host_id=host_id,
        candidate_host_ids=[host_id],
        confidence=str(first["confidence"]),
        rationale=["same host retained after a materially different analysis"],
    )
    assert reassessed != int(first["id"])

    replacement = state.record_resolution_decision(
        observation_id,
        decision_type="cluster_quarantined",
        projected_host_id=None,
        candidate_host_ids=[host_id],
        confidence="low",
        rationale=["new strong evidence conflicts with the original cluster"],
    )

    decisions = state.resolution_decisions_for_observation(observation_id)
    assert [int(row["sequence"]) for row in decisions] == [1, 2, 3]
    assert replacement == int(decisions[2]["id"])
    assert int(decisions[1]["supersedes_decision_id"]) == int(decisions[0]["id"])
    assert int(decisions[2]["supersedes_decision_id"]) == int(decisions[1]["id"])
    assert json.loads(str(decisions[2]["rationale_json"])) == [
        "new strong evidence conflicts with the original cluster"
    ]
    state.close()


def test_device_result_records_self_observed_strong_claims(tmp_path: Path) -> None:
    """SNMP engine and ENTITY-MIB serial evidence remain independently auditable."""

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(names=["switch1.example.com"], category="managed_device")
    )
    state.apply_device_result(
        DeviceResult(
            host_id=host_id,
            status="success",
            query_target="198.18.0.10",
            system=SystemDetails(
                sys_name="switch1.example.com",
                snmp_engine_id="800000090300001122334455",
                serial_number="FCW12345678",
                stack_members=[
                    StackMemberDetails(
                        entity_index=1001,
                        member_number=1,
                        serial_number="FOC87654321",
                    )
                ],
            ),
        )
    )

    observations = state.observations()
    result_observation = next(
        row for row in observations if row["observation_type"] == "snmp_device_result"
    )
    claims = state.claims_for_observation(int(result_observation["id"]))
    by_subtype = {str(row["claim_subtype"]): row for row in claims}

    assert by_subtype["snmp_engine_id"]["strength"] == "strong"
    assert by_subtype["snmp_engine_id"]["scope"] == "snmp_agent"
    assert by_subtype["entity_serial"]["scope"] == "physical_container"
    assert by_subtype["stack_member_serial"]["scope"] == "physical_container"
    state.close()


def test_reused_network_address_chassis_does_not_merge_unrelated_edges(
    tmp_path: Path,
) -> None:
    """A default LLDP network-address chassis value is not a global equality key."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        _edge_candidate(
            chassis_id="198.51.100.3",
            chassis_subtype="network_address",
            chassis_subtype_id=5,
            source_host_id=10,
            local_interface="Gi1/0/1",
            port_id="00:11:22:33:44:55",
        ),
        synthetic_alias="edge:10:Gi1/0/1:00:11:22:33:44:55",
    )
    second = state.upsert_candidate(
        _edge_candidate(
            chassis_id="198.51.100.3",
            chassis_subtype="network_address",
            chassis_subtype_id=5,
            source_host_id=20,
            local_interface="Gi1/0/24",
            port_id="66:77:88:99:aa:bb",
        ),
        synthetic_alias="edge:20:Gi1/0/24:66:77:88:99:aa:bb",
    )

    assert first != second
    assert state.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 2
    network_claims = state.conn.execute(
        "SELECT COUNT(*) FROM claims "
        "WHERE claim_type='chassis' AND claim_subtype='network_address' "
        "AND normalized_value='198.51.100.3' AND identity_eligible=0"
    ).fetchone()[0]
    assert network_claims == 2
    state.close()


def test_strict_cisco_ap_name_reconciles_with_lldp_chassis_mac(
    tmp_path: Path,
) -> None:
    """CDP AP hardware names and LLDP chassis MACs resolve to one endpoint."""

    state = StateStore(tmp_path / "state.sqlite")
    lldp = state.upsert_candidate(
        _edge_candidate(
            chassis_id="00:12:34:56:a0:01",
            chassis_subtype="mac_address",
            chassis_subtype_id=4,
            source_host_id=10,
            local_interface="Gi4/0/37",
            port_id="00:12:34:56:a0:01",
        ),
        synthetic_alias="edge:10:Gi4/0/37:00:12:34:56:a0:01",
    )
    cdp = state.upsert_candidate(
        Candidate(
            names=["AP0012.3456.A001"],
            identity_names=["AP0012.3456.A001"],
            source_host_id=10,
            protocol="cdp",
            local_interface="Gi4/0/37",
            local_interface_raw="Gi4/0/37",
            remote_interface="Gi0",
            remote_interface_raw="Gi0",
            category="managed_endpoint",
        ),
        synthetic_alias="edge:10:Gi4/0/37:00:12:34:56:a0:01",
    )

    assert cdp == lldp
    assert state.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1
    state.close()


def test_opening_pre_claim_ledger_state_adds_tables_without_rebuilding_hosts(
    tmp_path: Path,
) -> None:
    """A 0.31.4-shaped database receives the additive evidence schema in place."""

    path = tmp_path / "state.sqlite"
    state = StateStore(path)
    host_id = state.upsert_candidate(
        Candidate(names=["switch1.example.com"], category="managed_device")
    )
    for trigger in (
        "observations_immutable_update",
        "observations_immutable_delete",
        "claims_immutable_update",
        "claims_immutable_delete",
        "resolution_decisions_immutable_update",
        "resolution_decisions_immutable_delete",
    ):
        state.conn.execute(f"DROP TRIGGER {trigger}")
    state.conn.execute("DROP TABLE decision_claims")
    state.conn.execute("DROP TABLE resolution_decisions")
    state.conn.execute("DROP TABLE claims")
    state.conn.execute("DROP TABLE observations")
    state.conn.commit()
    state.close()

    resumed = StateStore(path)

    assert int(resumed.host_row(host_id)["id"]) == host_id
    tables = {
        str(row[0])
        for row in resumed.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {
        "observations",
        "claims",
        "resolution_decisions",
        "decision_claims",
    } <= tables
    resumed.upsert_candidate(Candidate(names=["switch2.example.com"], category="managed_device"))
    assert len(resumed.observations()) == 1
    resumed.close()


def test_decorated_name_yields_base_and_non_merging_serial_hint_claims() -> None:
    """Raw name, logical name, and physical serial hint retain separate roles."""

    candidate = Candidate(
        names=["hq-vdc2-7nx1.net.example.com(SERIAL000001)"],
        identity_names=["hq-vdc2-7nx1.net.example.com(SERIAL000001)"],
        category="managed_device",
        source_host_id=10,
        protocol="cdp",
        local_interface="Gi1/0/1",
    )

    claims = candidate_claims(candidate)

    raw = next(
        claim
        for claim in claims
        if claim.claim_type == "name" and claim.claim_subtype == "dns_name"
    )
    base = next(claim for claim in claims if claim.claim_subtype == "decorated_base_name")
    serial = next(claim for claim in claims if claim.claim_subtype == "advertised_serial_hint")
    assert raw.raw_value == "hq-vdc2-7nx1.net.example.com(SERIAL000001)"
    assert base.normalized_value == "hq-vdc2-7nx1.net.example.com"
    assert base.identity_eligible is True
    assert serial.normalized_value == "serial000001"
    assert serial.scope == "physical_container"
    assert serial.strength == "moderate"
    assert serial.identity_eligible is False
