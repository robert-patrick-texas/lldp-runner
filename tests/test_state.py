import json
from pathlib import Path

from lldp_runner.identity import cisco_sep_mac
from lldp_runner.models import Candidate, DeviceResult, NeighborObservation, SystemDetails
from lldp_runner.state import StateStore
from lldp_runner.timeutil import iso_now


def test_identity_dedup_and_no_requery(tmp_path: Path):
    state = StateStore(tmp_path / "state.sqlite")
    a = Candidate(
        names=["switch1.net.example.com"],
        addresses=["198.18.10.1"],
        category="managed_device",
        reason=["seed"],
    )
    aid = state.upsert_candidate(a, is_seed=True)
    aid_again = state.upsert_candidate(
        Candidate(addresses=["198.18.10.1"], category="managed_device")
    )
    assert aid_again == aid

    state.set_host_ready(aid, 0)
    assert state.claim_batch(0, 10, 300, allow_steal=False) == [aid]
    state.apply_device_result(
        DeviceResult(
            host_id=aid,
            status="success",
            query_target="198.18.10.1",
            credential_profile="default",
            credential_result="primary",
            system=SystemDetails(sys_name="switch1"),
            last_seen=iso_now(),
        )
    )
    address_row = state.conn.execute(
        "SELECT identity_eligible FROM host_addresses "
        "WHERE host_id=? AND address_type='ipv4' AND value='198.18.10.1'",
        (aid,),
    ).fetchone()
    assert address_row is not None and int(address_row[0]) == 1
    state.set_host_ready(aid, 0)
    assert state.ready_count() == 0
    state.close()


def test_unspecified_cdp_address_does_not_merge_distinct_esxi_hosts(tmp_path: Path):
    """VMware CDP 0.0.0.0 placeholders must not become a shared host alias."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["ashprdesxphy026"],
            addresses=["0.0.0.0"],
            category="managed_endpoint",
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["ashprdesxphy027"],
            addresses=["0.0.0.0"],
            category="managed_endpoint",
        )
    )
    first_again = state.upsert_candidate(
        Candidate(
            names=["ashprdesxphy026"],
            addresses=["0.0.0.0"],
            category="managed_endpoint",
        )
    )

    assert first != second
    assert first_again == first
    assert state.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 2
    assert (
        state.conn.execute(
            "SELECT COUNT(*) FROM aliases WHERE alias_type='ipv4' AND value='0.0.0.0'"
        ).fetchone()[0]
        == 0
    )
    state.close()


def test_neighbor_cycle_is_graph_not_recursive_copy(tmp_path: Path):
    state = StateStore(tmp_path / "state.sqlite")
    a = state.upsert_candidate(Candidate(names=["a"], category="managed_device"), is_seed=True)
    b = state.upsert_candidate(Candidate(names=["b"], category="managed_device"), is_seed=True)
    state.add_neighbor(
        a,
        b,
        NeighborObservation("lldp", "Gi1/0/1", None, "b", "Gi1/0/2", None),
    )
    state.add_neighbor(
        b,
        a,
        NeighborObservation("lldp", "Gi1/0/2", None, "a", "Gi1/0/1", None),
    )
    assert len(state.neighbors_from(a)) == 1
    assert len(state.neighbors_from(b)) == 1
    assert state.host_count() == 2
    state.close()


def test_explicit_classification_can_override_prior_inference(tmp_path: Path):
    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(names=["server1"], category="unmanaged_device", reason=["inferred"])
    )
    state.update_classification(
        host_id,
        "managed_device",
        ["explicit name rule ^server1$"],
    )
    assert state.host_row(host_id)["classification"] == "managed_device"
    state.close()


def test_neighbor_edge_retains_discovery_evidence(tmp_path: Path):
    import json

    state = StateStore(tmp_path / "state.sqlite")
    source = state.upsert_candidate(
        Candidate(names=["source"], category="managed_device"), is_seed=True
    )
    remote = state.upsert_candidate(Candidate(names=["remote"], category="unknown_device"))
    state.add_neighbor(
        source,
        remote,
        NeighborObservation(
            protocol="lldp",
            local_interface="Gi1/0/1",
            local_interface_raw="GigabitEthernet1/0/1",
            remote_name="remote",
            remote_interface="Eth1",
            remote_interface_raw="Ethernet1",
            remote_description="example description",
            remote_platform="example platform",
            capabilities=["bridge"],
            chassis_id="00:11:22:33:44:55",
        ),
    )
    edge = state.neighbors_from(source)[0]
    details = json.loads(edge["details_json"])
    assert details["remote_description"] == "example description"
    assert details["remote_platform"] == "example platform"
    assert details["capabilities"] == ["bridge"]
    assert details["chassis_id"] == "00:11:22:33:44:55"
    state.close()


def test_out_of_scope_state_can_be_reconsidered_before_query(tmp_path: Path):
    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(names=["switch1"], addresses=["203.0.113.10"], category="managed_device")
    )
    state.set_host_no_query(host_id, "OUT_OF_SCOPE")
    state.set_host_ready(host_id, 0)
    assert state.host_row(host_id)["state"] == "READY"
    state.close()


def test_ready_does_not_reset_active_claim(tmp_path: Path):
    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(names=["switch1"], addresses=["198.18.10.1"], category="managed_device"),
        is_seed=True,
    )
    state.set_host_ready(host_id, 0)
    assert state.claim_batch(0, 1, 300, allow_steal=False) == [host_id]
    state.set_host_ready(host_id, 0)
    assert state.host_row(host_id)["state"] == "CLAIMED"
    state.close()


def test_identity_correlation_does_not_delete_inflight_host(tmp_path: Path):
    state = StateStore(tmp_path / "state.sqlite")
    by_name = state.upsert_candidate(Candidate(names=["switch1"], category="managed_device"))
    by_ip = state.upsert_candidate(Candidate(addresses=["198.18.10.1"], category="managed_device"))
    state.set_host_ready(by_name, 0)
    assert state.claim_batch(0, 1, 300, allow_steal=False) == [by_name]
    chosen = state.upsert_candidate(
        Candidate(
            names=["switch1"],
            addresses=["198.18.10.1"],
            category="managed_device",
        )
    )
    assert chosen == by_name
    assert state.host_row(by_name)["state"] == "CLAIMED"
    assert state.host_row(by_ip)["id"] == by_ip
    state.close()


def test_tags_survive_identity_merge(tmp_path):
    from lldp_runner.models import Candidate
    from lldp_runner.state import StateStore

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(names=["phone-01"], category="managed_endpoint", tags=["service:voice"])
    )
    second = state.upsert_candidate(
        Candidate(
            addresses=["198.18.20.50"],
            chassis_id="phone-01-chassis",
            category="managed_endpoint",
            tags=["tenant:a"],
        )
    )
    assert first != second

    merged = state.upsert_candidate(
        Candidate(
            names=["phone-01"],
            addresses=["198.18.20.50"],
            chassis_id="phone-01-chassis",
            category="managed_endpoint",
        )
    )
    assert state.tags_for_host(merged) == ["service:voice", "tenant:a"]
    state.close()


def test_identity_merge_preserves_complete_query_target(tmp_path: Path):
    """Merging two COMPLETE identities must not discard the successful target."""

    state = StateStore(tmp_path / "state.sqlite")
    by_name = state.upsert_candidate(
        Candidate(names=["switch1.net.example.com"], category="managed_device")
    )
    by_ip = state.upsert_candidate(Candidate(addresses=["198.18.10.1"], category="managed_device"))
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', query_target=NULL WHERE id=?",
        (by_name,),
    )
    state.conn.execute(
        """
        UPDATE hosts SET state='COMPLETE', query_target='198.18.10.1',
            credential_profile='default', credential_result='primary'
        WHERE id=?
        """,
        (by_ip,),
    )
    state.conn.commit()

    merged = state.upsert_candidate(
        Candidate(
            names=["switch1.net.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        )
    )

    row = state.host_row(merged)
    assert row["state"] == "COMPLETE"
    assert row["query_target"] == "198.18.10.1"
    assert row["credential_profile"] == "default"
    assert row["credential_result"] == "primary"
    state.close()


def test_state_migrates_optional_collection_metrics_column(tmp_path):
    """A v0.12-style hosts table remains resumable after metrics are introduced."""

    import sqlite3

    path = tmp_path / "legacy-state.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            preferred_name TEXT NOT NULL,
            snmp_sysname TEXT,
            classification TEXT NOT NULL DEFAULT 'unknown_device',
            classification_reason_json TEXT NOT NULL DEFAULT '[]',
            state TEXT NOT NULL DEFAULT 'DISCOVERED',
            cohort INTEGER NOT NULL DEFAULT 0,
            worker_id INTEGER,
            lease_until TEXT,
            query_target TEXT,
            credential_profile TEXT,
            credential_result TEXT,
            is_seed INTEGER NOT NULL DEFAULT 0,
            seed_rank INTEGER,
            first_seen TEXT NOT NULL,
            last_seen TEXT,
            last_seen_source TEXT,
            ping_json TEXT NOT NULL DEFAULT '[]',
            system_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()

    state = StateStore(path)
    columns = {str(row[1]) for row in state.conn.execute("PRAGMA table_info(hosts)").fetchall()}
    assert "metrics_json" in columns
    assert "snmp_sessions_json" in columns
    assert "interface_groups_json" in columns
    state.close()


def test_malformed_network_chassis_id_does_not_merge_distinct_neighbors(tmp_path: Path):
    """Malformed subtype-5 chassis evidence must not collapse unrelated phones."""

    state = StateStore(tmp_path / "state.sqlite")
    host_ids = []
    for name, address in (
        ("SEP00123456000D.voice.example.net", "192.0.2.191"),
        ("SEP001234560011.voice.example.net", "192.0.2.206"),
        ("SEP001234560009.voice.example.net", "192.0.2.115"),
    ):
        host_ids.append(
            state.upsert_candidate(
                Candidate(
                    names=[name],
                    addresses=[address],
                    category="managed_endpoint",
                    chassis_id="hex:15:00:00:00:00:00",
                    chassis_id_subtype="network_address",
                    chassis_id_subtype_id=5,
                )
            )
        )

    assert len(set(host_ids)) == 3
    assert state.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 3
    assert (
        state.conn.execute("SELECT COUNT(*) FROM aliases WHERE alias_type='chassis_id'").fetchone()[
            0
        ]
        == 0
    )
    state.close()


def test_conflicting_trusted_chassis_ids_keep_duplicate_name_hosts_separate(
    tmp_path: Path,
):
    """A duplicate name cannot override contradictory physical identity evidence."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["phone-01.example.com"],
            addresses=["198.18.20.10"],
            chassis_id="00:11:22:33:44:55",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_endpoint",
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["phone-01.example.com"],
            addresses=["198.18.20.11"],
            chassis_id="00:11:22:33:44:66",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_endpoint",
        ),
        synthetic_alias="edge:1:lldp:Gi1/0/2:phone-01",
    )

    assert first != second
    assert state.host_row(first)["preferred_name"] == "phone-01.example.com"
    assert state.host_row(second)["preferred_name"] == "phone-01.example.com"
    state.close()


def test_shared_chassis_only_match_rejects_conflicting_name_and_address(tmp_path: Path):
    """A reused chassis value needs corroboration when other identity data conflicts."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["phone-a.example.com"],
            addresses=["198.18.20.20"],
            chassis_id="00:11:22:33:44:77",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_endpoint",
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["phone-b.example.com"],
            addresses=["198.18.20.21"],
            chassis_id="00:11:22:33:44:77",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_endpoint",
        ),
        synthetic_alias="edge:1:lldp:Gi1/0/3:phone-b",
    )

    assert first != second
    assert state.conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 2
    state.close()


def test_shared_chassis_with_matching_name_still_folds_one_device(tmp_path: Path):
    """Conflict protection must preserve normal multi-address device folding."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["dist-1.example.com"],
            addresses=["198.18.30.10"],
            chassis_id="00:11:22:33:44:88",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["dist-1.example.com"],
            addresses=["198.18.30.11"],
            chassis_id="00:11:22:33:44:88",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        )
    )

    assert first == second
    _names, addresses, _chassis = state.aliases_for_host(first)
    assert addresses == ["198.18.30.10", "198.18.30.11"]
    state.close()


def test_device_local_chassis_subtype_is_not_a_global_identity(tmp_path: Path):
    """A local chassis value stays scoped while a typed Port-ID identifies an endpoint."""

    state = StateStore(tmp_path / "state.sqlite")
    local_id = state.upsert_candidate(
        Candidate(
            chassis_id="rack-a",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            details={
                "port_id": "10:98:19:4d:2f:97",
                "port_id_subtype": "mac_address",
                "port_id_subtype_id": 3,
            },
        )
    )
    interface_id = state.upsert_candidate(
        Candidate(
            chassis_id="rack-a",
            chassis_id_subtype="interface_name",
            chassis_id_subtype_id=6,
        ),
        synthetic_alias="edge:observer:Gi1/0/1:rack-a",
    )

    assert local_id != interface_id
    assert (
        state.conn.execute(
            "SELECT 1 FROM aliases WHERE host_id=? AND alias_type='chassis_id'",
            (local_id,),
        ).fetchone()
        is None
    )
    assert (
        state.conn.execute(
            "SELECT value FROM aliases WHERE host_id=? AND alias_type='mac'",
            (local_id,),
        ).fetchone()["value"]
        == "10:98:19:4d:2f:97"
    )
    assert (
        state.conn.execute(
            "SELECT 1 FROM aliases WHERE host_id=? AND alias_type='chassis_id'",
            (interface_id,),
        ).fetchone()
        is None
    )
    state.close()


def test_repeated_local_chassis_uses_distinct_anonymous_port_macs(tmp_path: Path):
    """Production-shaped subtype-7 endpoints must not collapse into one host."""

    state = StateStore(tmp_path / "state.sqlite")

    def endpoint(mac: str, *, name: str | None = None) -> Candidate:
        return Candidate(
            names=[name] if name else [],
            identity_names=[name] if name else [],
            chassis_id="hex:a1:00:00:00:00:00",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            protocol="lldp",
            details={
                "port_id": mac,
                "port_id_subtype": "mac_address",
                "port_id_subtype_id": 3,
            },
        )

    first = state.upsert_candidate(endpoint("10:98:19:4d:2f:97"))
    second = state.upsert_candidate(endpoint("08:92:04:f6:d6:f4"))
    repeated = state.upsert_candidate(endpoint("10:98:19:4d:2f:97"))
    named = state.upsert_candidate(endpoint("ac:b4:80:44:52:de", name="endpoint.example.com"))
    named_other_port = state.upsert_candidate(
        endpoint("20:88:10:f1:52:c2", name="endpoint.example.com")
    )

    assert first != second
    assert repeated == first
    assert named not in {first, second}
    assert named_other_port == named
    aliases = {
        (int(row["host_id"]), str(row["alias_type"]), str(row["value"]))
        for row in state.conn.execute(
            "SELECT host_id, alias_type, value FROM aliases ORDER BY host_id, alias_type"
        )
    }
    assert (first, "mac", "10:98:19:4d:2f:97") in aliases
    assert (second, "mac", "08:92:04:f6:d6:f4") in aliases
    assert (named, "name", "endpoint.example.com") in aliases
    assert all(alias_type != "chassis_id" for _, alias_type, _ in aliases)
    assert (named, "mac", "ac:b4:80:44:52:de") not in aliases
    assert (named, "mac", "20:88:10:f1:52:c2") not in aliases
    state.close()


def test_matching_name_and_address_override_link_specific_chassis_conflict(
    tmp_path: Path,
):
    """Strong logical identity may fold Nexus links with different chassis MACs."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["hq-vdc2-7nx1.net.example.com"],
            addresses=["203.0.113.24", "2001:db8:113d:61::1000:46"],
            chassis_id="00:12:34:56:b0:01",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["hq-vdc2-7nx1.net.example.com"],
            addresses=["203.0.113.24", "2001:db8:113d:61::1000:46"],
            chassis_id="00:12:34:56:b0:02",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        )
    )

    assert first == second
    rows = state.conn.execute(
        "SELECT value FROM aliases WHERE host_id=? AND alias_type='chassis_id'",
        (first,),
    ).fetchall()
    assert len(rows) == 2
    state.close()


def test_bridge_observation_repairs_order_dependent_shared_name_split(tmp_path: Path) -> None:
    """A later name+address bridge must merge split Nexus logical-host evidence."""

    state = StateStore(tmp_path / "state.sqlite")
    name = "hq-fabric-leaf-02.fabric.example.com"
    main = state.upsert_candidate(
        Candidate(
            names=[name],
            addresses=["203.0.113.27"],
            chassis_id="d0:09:c8:ca:bf:36",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        ),
        preferred_name=name,
    )
    split = state.upsert_candidate(
        Candidate(
            names=[name],
            addresses=["198.51.100.134", "10.1.1.2"],
            chassis_id="d0:09:c8:ca:bf:44",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        ),
        preferred_name=name,
        synthetic_alias="edge:1:lldp:Eth1/52:Eth1/52:d0:09:c8:ca:bf:44",
    )
    assert split != main
    source = state.upsert_candidate(
        Candidate(names=["observer.example.com"], addresses=["198.18.200.1"])
    )
    state.add_neighbor(
        source,
        split,
        NeighborObservation(
            protocol="lldp",
            local_interface="Eth1/52",
            local_interface_raw="Ethernet1/52",
            remote_interface="Eth1/52",
            remote_interface_raw="Ethernet1/52",
            remote_name=name,
            remote_addresses=["198.51.100.134", "10.1.1.2"],
            chassis_id="d0:09:c8:ca:bf:44",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
    )

    # A second link can carry the same logical name/address while exposing a
    # third link-specific chassis MAC.  It must fold into the existing split
    # record rather than creating the production run's third duplicate host.
    third = state.upsert_candidate(
        Candidate(
            names=[name],
            addresses=["198.51.100.134"],
            chassis_id="d0:09:c8:ca:bf:00",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        ),
        preferred_name=name,
        synthetic_alias="edge:2:lldp:Gi1/0/2:mgmt0:d0:09:c8:ca:bf:00",
    )
    assert third == split

    bridged = state.upsert_candidate(
        Candidate(
            names=[name],
            addresses=["198.51.100.134", "203.0.113.27"],
            chassis_id="d0:09:c8:ca:bf:48",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        ),
        preferred_name=name,
    )

    assert bridged == main
    rows = state.conn.execute(
        "SELECT id FROM hosts WHERE preferred_name=? COLLATE NOCASE", (name,)
    ).fetchall()
    assert [int(row["id"]) for row in rows] == [main]
    assert state.conn.execute(
        "SELECT 1 FROM host_addresses "
        "WHERE host_id=? AND address_type='ipv4' AND value='198.51.100.134'",
        (main,),
    ).fetchone()
    state.close()


def test_placeholder_preferred_name_does_not_become_identity_evidence(tmp_path: Path) -> None:
    """Repeated literal null names must not correlate otherwise unrelated hosts."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["null"],
            chassis_id="00:11:22:33:44:55",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        preferred_name="null",
    )
    second = state.upsert_candidate(
        Candidate(
            names=["null"],
            chassis_id="00:11:22:33:44:66",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
        ),
        preferred_name="null",
    )

    assert first != second
    assert (
        state.conn.execute(
            "SELECT COUNT(*) FROM aliases WHERE alias_type='name' AND value='null'"
        ).fetchone()[0]
        == 0
    )
    state.close()


def test_sep_short_and_fqdn_candidates_merge_without_management_address(tmp_path: Path):
    """Embedded SEP MAC identity prevents protocol-order-dependent phone splits."""

    state = StateStore(tmp_path / "state.sqlite")
    cdp_id = state.upsert_candidate(
        Candidate(
            names=["SEP001234560004"],
            addresses=["198.51.100.173"],
            category="managed_endpoint",
        )
    )
    lldp_id = state.upsert_candidate(
        Candidate(
            names=["SEP001234560004.voice-a.example.com"],
            addresses=[],
            chassis_id="198.51.100.173",
            chassis_id_subtype="network_address",
            chassis_id_subtype_id=5,
            category="managed_endpoint",
        )
    )

    assert lldp_id == cdp_id
    assert state.host_count() == 1
    mac_owner = state.conn.execute(
        "SELECT host_id FROM aliases WHERE alias_type='mac' AND value=?",
        ("00:12:34:56:00:04",),
    ).fetchone()
    assert mac_owner is not None and int(mac_owner[0]) == cdp_id
    state.close()


def test_sep_mac_allows_suffix_and_network_chassis_transition(tmp_path: Path):
    """The embedded hardware MAC remains stronger than changing DNS/IP evidence."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["SEP001234560004.voice-a.example.com"],
            chassis_id="198.51.100.173",
            chassis_id_subtype="network_address",
            chassis_id_subtype_id=5,
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["SEP001234560004.voice-b.example.net"],
            chassis_id="198.51.100.80",
            chassis_id_subtype="network_address",
            chassis_id_subtype_id=5,
        )
    )

    assert second == first
    assert state.host_count() == 1
    state.close()


def test_distinct_sep_macs_do_not_merge_through_shared_phone_address(tmp_path: Path):
    """A repeated endpoint address cannot override contradictory SEP hardware IDs.

    Production Cisco phones at unrelated sites were observed with distinct
    ``SEP<MAC>`` names and Port IDs while all advertising ``198.51.100.29`` as a
    network-address chassis/management value. Before this guard, the first phone
    to claim that address became the host for every later phone, and diff then
    reported encounter-order-dependent neighbor name changes across many routers.
    """

    state = StateStore(tmp_path / "state.sqlite")
    phone_names = [
        "SEP001234560001",
        "SEP001234560007",
        "SEP001234560012",
        "SEP001234560010",
        "SEP00123456000E",
        "SEP001234560005",
        "SEP00123456000A",
        "SEP001234560008",
        "SEP001234560006",
    ]

    host_ids: list[int] = []
    for index, name in enumerate(phone_names):
        host_ids.append(
            state.upsert_candidate(
                Candidate(
                    names=[name],
                    addresses=["198.51.100.29"],
                    category="managed_endpoint",
                    chassis_id="198.51.100.29",
                    chassis_id_subtype="network_address",
                    chassis_id_subtype_id=5,
                ),
                synthetic_alias=f"edge:{index}:lldp:Gi0/1/{index}:phone",
            )
        )

    assert len(set(host_ids)) == len(phone_names)
    assert state.host_count() == len(phone_names)

    for host_id, name in zip(host_ids, phone_names, strict=True):
        expected_mac = cisco_sep_mac(name)
        assert expected_mac is not None
        row = state.conn.execute(
            "SELECT host_id FROM aliases WHERE alias_type='mac' AND value=?",
            (expected_mac,),
        ).fetchone()
        assert row is not None and int(row[0]) == host_id

    # Re-observing one phone must still resolve to its own host even though the
    # globally unique address/chassis aliases remain owned by the first phone.
    repeated = state.upsert_candidate(
        Candidate(
            names=["SEP001234560006.voice-a.example.com"],
            addresses=["198.51.100.29"],
            category="managed_endpoint",
            chassis_id="198.51.100.29",
            chassis_id_subtype="network_address",
            chassis_id_subtype_id=5,
        ),
        synthetic_alias="edge:99:lldp:Gi0/1/2:phone",
    )
    assert repeated == host_ids[-1]
    assert state.host_count() == len(phone_names)
    state.close()


def test_incompatible_direct_names_can_share_one_contested_address(tmp_path: Path) -> None:
    """A common/default address is a many-to-many claim, not forced equality."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(names=["router-a.example.com"], addresses=["10.10.10.1"])
    )
    second = state.upsert_candidate(
        Candidate(names=["router-b.example.com"], addresses=["10.10.10.1"])
    )

    assert first != second
    rows = state.conn.execute(
        "SELECT host_id FROM host_addresses "
        "WHERE address_type='ipv4' AND value='10.10.10.1' ORDER BY host_id"
    ).fetchall()
    assert [int(row[0]) for row in rows] == [first, second]
    assert (
        state.upsert_candidate(Candidate(names=["router-a.example.com"], addresses=["10.10.10.1"]))
        == first
    )
    assert (
        state.upsert_candidate(Candidate(names=["router-b.example.com"], addresses=["10.10.10.1"]))
        == second
    )
    state.close()


def test_contested_address_grouping_is_independent_of_ingest_order(
    tmp_path: Path,
) -> None:
    """Common-address claimants produce the same clusters in either order."""

    names = [
        "router-a.example.com",
        "router-b.example.com",
        "router-c.example.com",
    ]
    projections: list[tuple[list[str], list[tuple[str, int]]]] = []
    for label, ordered_names in (
        ("forward", names),
        ("reverse", list(reversed(names))),
    ):
        state = StateStore(tmp_path / f"{label}.sqlite")
        for name in ordered_names:
            state.upsert_candidate(Candidate(names=[name], addresses=["10.10.10.1"]))
        host_names = [
            str(row[0])
            for row in state.conn.execute(
                "SELECT preferred_name FROM hosts ORDER BY preferred_name"
            ).fetchall()
        ]
        claims = [
            (str(row[0]), int(row[1]))
            for row in state.conn.execute(
                "SELECT h.preferred_name, ha.identity_eligible "
                "FROM host_addresses AS ha "
                "JOIN hosts AS h ON h.id=ha.host_id "
                "WHERE ha.address_type='ipv4' AND ha.value='10.10.10.1' "
                "ORDER BY h.preferred_name"
            ).fetchall()
        ]
        projections.append((host_names, claims))
        state.close()

    assert projections[0] == projections[1]
    assert projections[0][0] == names
    assert projections[0][1] == [(name, 1) for name in names]


def test_contested_address_reuses_same_edge_observation_when_name_is_missing(
    tmp_path: Path,
) -> None:
    """A transiently absent name must not create a third contested claimant."""

    state = StateStore(tmp_path / "state.sqlite")
    state.upsert_candidate(Candidate(names=["router-a.example.com"], addresses=["10.10.10.1"]))
    edge = "edge:7:lldp:Gi1/0/7:mgmt0:shared-address"
    router_b = state.upsert_candidate(
        Candidate(names=["router-b.example.com"], addresses=["10.10.10.1"]),
        synthetic_alias=edge,
    )

    repeated = state.upsert_candidate(
        Candidate(addresses=["10.10.10.1"]),
        synthetic_alias=edge,
    )

    assert repeated == router_b
    assert state.host_count() == 2
    state.close()


def test_dns_enrichment_names_do_not_become_global_identity_aliases(tmp_path: Path) -> None:
    """A shared DNS frontend can classify devices without merging their identities."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["edge-a.example.com", "shared-frontend.example.net"],
            identity_names=["edge-a.example.com"],
            addresses=["198.18.44.20"],
            identity_addresses=[],
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["edge-b.example.com", "shared-frontend.example.net"],
            identity_names=["edge-b.example.com"],
            addresses=["198.18.44.20"],
            identity_addresses=[],
        )
    )

    assert first != second
    assert (
        state.conn.execute(
            "SELECT 1 FROM aliases WHERE alias_type='name' AND value='shared-frontend.example.net'"
        ).fetchone()
        is None
    )
    rows = state.conn.execute(
        "SELECT host_id, identity_eligible FROM host_addresses "
        "WHERE address_type='ipv4' AND value='198.18.44.20' ORDER BY host_id"
    ).fetchall()
    assert [(int(row[0]), int(row[1])) for row in rows] == [
        (first, 0),
        (second, 0),
    ]

    state.apply_device_result(
        DeviceResult(
            host_id=first,
            status="success",
            query_target="198.18.44.20",
            system=SystemDetails(sys_name="edge-a.example.com"),
            last_seen=iso_now(),
        )
    )
    rows = state.conn.execute(
        "SELECT host_id, identity_eligible FROM host_addresses "
        "WHERE address_type='ipv4' AND value='198.18.44.20' ORDER BY host_id"
    ).fetchall()
    assert [(int(row[0]), int(row[1])) for row in rows] == [
        (first, 1),
        (second, 0),
    ]
    state.close()


def test_interface_name_chassis_does_not_merge_distinct_vmware_hosts(tmp_path: Path) -> None:
    """Repeated vmnic names are local to each ESXi agent, never global chassis IDs."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["lab-vm-01.lab.example.org"],
            chassis_id="vmnic2",
            chassis_id_subtype="interface_name",
            chassis_id_subtype_id=6,
        )
    )
    second = state.upsert_candidate(
        Candidate(
            names=["lab-vm-02.lab.example.org"],
            chassis_id="vmnic2",
            chassis_id_subtype="interface_name",
            chassis_id_subtype_id=6,
        )
    )

    assert first != second
    assert state.host_count() == 2
    assert (
        state.conn.execute("SELECT COUNT(*) FROM aliases WHERE alias_type='chassis_id'").fetchone()[
            0
        ]
        == 0
    )
    state.close()


def test_opening_0313_state_migrates_address_aliases_to_claims(tmp_path: Path) -> None:
    """A resumed 0.31.3 database moves one-owner IP aliases without data loss."""

    path = tmp_path / "state.sqlite"
    state = StateStore(path)
    host_id = state.upsert_candidate(
        Candidate(names=["seed.example.com"], addresses=["198.18.60.10"]),
        is_seed=True,
    )
    state.conn.execute(
        "INSERT INTO aliases(alias_type, value, host_id) VALUES('ipv4', ?, ?)",
        ("198.18.60.10", host_id),
    )
    state.conn.execute("DELETE FROM host_addresses")
    state.conn.execute("DROP TABLE host_addresses")
    state.close()

    resumed = StateStore(path)

    assert resumed.conn.execute("SELECT 1 FROM aliases WHERE alias_type='ipv4'").fetchone() is None
    row = resumed.conn.execute(
        "SELECT host_id, identity_eligible FROM host_addresses "
        "WHERE address_type='ipv4' AND value='198.18.60.10'"
    ).fetchone()
    assert row is not None and int(row[0]) == host_id
    assert int(row[1]) == 1
    assert resumed.seed_resolution_counts()["unresolved"] == 0
    resumed.close()


def test_device_result_persists_adaptive_session_and_shadow_groups(
    tmp_path: Path,
) -> None:
    """Operational transport evidence and shadow topology survive restart."""

    import json

    from lldp_runner.models import SnmpRetryEvent, SnmpSessionTelemetry

    state = StateStore(tmp_path / "state.sqlite")
    host_id = state.upsert_candidate(
        Candidate(
            names=["switch1.example.com"],
            addresses=["198.18.0.10"],
            category="managed_device",
        )
    )
    retry = SnmpRetryEvent(
        sequence=1,
        target="198.18.0.10",
        collector="lldp",
        logical_operation="WALK",
        table_name="lldp",
        root_oid="1.0",
        credential_route="198.18.0.10|policy-profile|primary|default",
        credential_profile="default",
        collection_phase="detail",
        category="timeout",
        retry_kind="transport",
        retry_allowed=True,
        attempt=2,
        per_operation_retry_count=1,
        total_target_retry_count=1,
        timeout_before_seconds=2.0,
        timeout_after_seconds=3.0,
        max_repetitions_before=25,
        max_repetitions_after=13,
        inter_pdu_delay_before_ms=0.0,
        inter_pdu_delay_after_ms=100.0,
        per_device_rps_before=5.0,
        per_device_rps_after=3.333333,
        partial_rows_discarded=True,
        final_outcome="succeeded",
    )
    session = SnmpSessionTelemetry(
        target="198.18.0.10",
        credential_route="198.18.0.10|policy-profile|primary|default",
        credential_profile="default",
        initial_timeout_seconds=2.0,
        effective_timeout_seconds=3.0,
        initial_max_repetitions=25,
        effective_max_repetitions=13,
        initial_per_device_rps=5.0,
        effective_per_device_rps=3.333333,
        effective_inter_pdu_delay_ms=100.0,
        retry_per_operation=1,
        structural_table_retry=1,
        retry_total_cap=3,
        total_retries_used=1,
        degraded=True,
        operation_retry_counts={"lldp:WALK": 1},
        events=[retry],
    )
    group = {
        "group_fingerprint": "sha256:test",
        "analysis_status": "shadow",
        "source_host_id": host_id,
        "local_interface": "Gi0/0/3",
        "local_interface_namespace": "resolved",
        "cardinality": "many",
        "member_count": 2,
        "members": [],
    }

    state.apply_device_result(
        DeviceResult(
            host_id=host_id,
            status="success",
            query_target="198.18.0.10",
            system=SystemDetails(sys_name="switch1.example.com"),
            snmp_sessions=[session],
            interface_observation_groups=[group],
            last_seen=iso_now(),
        )
    )

    row = state.host_row(host_id)
    sessions = json.loads(str(row["snmp_sessions_json"]))
    groups = json.loads(str(row["interface_groups_json"]))
    assert sessions[0]["target"] == "198.18.0.10"
    assert sessions[0]["effective_max_repetitions"] == 13
    assert sessions[0]["events"][0]["partial_rows_discarded"] is True
    assert groups == [group]
    observation = next(row for row in reversed(state.observations()) if row["protocol"] == "snmp")
    payload = json.loads(str(observation["payload_json"]))
    assert payload["snmp_sessions"][0]["degraded"] is True
    assert payload["interface_observation_groups"] == [group]
    state.close()


def test_raw_protocol_advertisements_are_idempotent_and_graph_decisions_supersede(
    tmp_path: Path,
) -> None:
    """Raw rows remain immutable while later evidence revises graph conclusions."""

    state = StateStore(tmp_path / "state.sqlite")
    source_id = state.upsert_candidate(
        Candidate(
            names=["source.example.com"],
            addresses=["192.0.2.10"],
            category="managed_device",
        ),
        is_seed=True,
    )
    cdp = NeighborObservation(
        protocol="cdp",
        local_interface="Gi1/0/1",
        local_interface_raw="Gi1/0/1",
        remote_name="remote.example.com",
        remote_interface="Gi0",
        remote_interface_raw="Gi0",
        remote_addresses=["192.0.2.20"],
        chassis_id="00:11:22:33:44:55",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
        details={"protocols": ["cdp"]},
    )
    first = DeviceResult(
        host_id=source_id,
        status="success",
        query_target="192.0.2.10",
        system=SystemDetails(
            sys_name="source.example.com",
            serial_number="SOURCE-SERIAL",
        ),
        raw_neighbors=[cdp],
        neighbors=[cdp],
        last_seen=iso_now(),
    )
    state.apply_device_result(first)
    initial_advertisements = int(
        state.conn.execute("SELECT COUNT(*) FROM protocol_advertisements").fetchone()[0]
    )
    assert initial_advertisements == 1

    # Exact replay is idempotent even though the mutable compatibility projection
    # is refreshed with a new last_seen value.
    state.apply_device_result(first)
    assert (
        int(state.conn.execute("SELECT COUNT(*) FROM protocol_advertisements").fetchone()[0])
        == initial_advertisements
    )
    first_graph = state.materialize_topology_graph()
    assert first_graph.document["authority"]["observation_projection"] == "authoritative"
    assert state.current_topology_graph() == first_graph.document
    projection_row = state.conn.execute(
        "SELECT payload_json, payload_codec, payload_blob, summary_json "
        "FROM graph_projection WHERE singleton=1"
    ).fetchone()
    assert projection_row is not None
    assert projection_row["payload_json"] == "{}"
    assert projection_row["payload_codec"] == "zlib-json"
    assert bytes(projection_row["payload_blob"])
    assert json.loads(str(projection_row["summary_json"])) == first_graph.document["summary"]
    initial_global_history = [
        item
        for item in state.graph_decision_history()
        if item["component_key"] == "graph:observation_projection"
    ]
    assert [item["sequence"] for item in initial_global_history] == [1]

    # An unchanged rebuild is idempotent and does not append a decision.
    state.materialize_topology_graph()
    unchanged_global_history = [
        item
        for item in state.graph_decision_history()
        if item["component_key"] == "graph:observation_projection"
    ]
    assert [item["sequence"] for item in unchanged_global_history] == [1]

    lldp = NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="Gi1/0/1",
        remote_name="remote.example.com",
        remote_interface="Gi0",
        remote_interface_raw="Gi0",
        remote_addresses=["192.0.2.20"],
        chassis_id="00:11:22:33:44:55",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
        details={"protocols": ["lldp"]},
    )
    second = DeviceResult(
        host_id=source_id,
        status="success",
        query_target="192.0.2.10",
        system=SystemDetails(
            sys_name="source.example.com",
            serial_number="SOURCE-SERIAL",
        ),
        raw_neighbors=[cdp, lldp],
        neighbors=[cdp, lldp],
        last_seen=iso_now(),
    )
    state.apply_device_result(second)
    second_graph = state.materialize_topology_graph()
    assert len(second_graph.document["advertisements"]) == 2

    history = state.graph_decision_history()
    group_history = [
        item for item in history if item["component_key"].startswith("relationship_group:")
    ]
    assert max(item["sequence"] for item in group_history) == 2
    latest = max(group_history, key=lambda item: item["sequence"])
    assert latest["supersedes_decision_id"] is not None
    global_history = [
        item for item in history if item["component_key"] == "graph:observation_projection"
    ]
    assert [item["sequence"] for item in global_history] == [1, 2]
    assert global_history[-1]["supersedes_decision_id"] == global_history[0]["id"]
    state.close()


def test_graph_retains_advertisements_after_provisional_source_host_is_removed(
    tmp_path: Path,
) -> None:
    """Immutable source-result facts survive compatibility-host retirement."""

    state = StateStore(tmp_path / "state.sqlite")
    source_id = state.upsert_candidate(
        Candidate(
            names=["hq-vdc2-7nx1.example.com"],
            addresses=["203.0.113.24"],
            category="managed_device",
        ),
        is_seed=True,
    )
    observation = NeighborObservation(
        protocol="lldp",
        local_interface="mgmt0",
        local_interface_raw="mgmt0",
        remote_name="peer.example.com",
        remote_interface="mgmt0",
        remote_interface_raw="mgmt0",
        details={"protocols": ["lldp"], "time_mark": 42},
    )
    result = DeviceResult(
        host_id=source_id,
        status="success",
        query_target="203.0.113.24",
        system=SystemDetails(
            sys_name="hq-vdc2-7nx1",
            serial_number="SERIAL000001",
            snmp_engine_id="800000090300001122334455",
        ),
        raw_neighbors=[observation],
        neighbors=[observation],
        last_seen=iso_now(),
    )
    state.apply_device_result(result)
    source_row = state.conn.execute(
        "SELECT source_observation_id, source_context_json FROM protocol_advertisements"
    ).fetchone()
    assert source_row is not None
    assert source_row["source_observation_id"] is not None
    assert len(str(source_row["source_context_json"])) < 300

    state.conn.execute("DELETE FROM hosts WHERE id=?", (source_id,))
    state.conn.commit()
    graph = state.materialize_topology_graph().document

    assert graph["summary"]["input_advertisements"] == 1
    assert graph["summary"]["raw_advertisements"] == 1
    assert graph["summary"]["excluded_advertisements"] == 0
    assert graph["summary"]["unaccounted_advertisements"] == 0
    assert graph["authority"]["observation_completeness"] == "complete"
    assert any(
        "hq-vdc2-7nx1" in item["identity"]["names"]
        for item in graph["entities"]
        if item["entity_type"] == "logical_system"
    )
    state.close()


def _make_split_managed_projection(
    state: StateStore,
    *,
    name: str,
    addresses: list[str],
    serial: str | None = None,
) -> int:
    """Create a test-only shadow row without claiming a globally unique name."""

    host_id = state.upsert_candidate(
        Candidate(names=[], addresses=[], category="managed_device"),
        synthetic_alias=(
            f"test-shadow:{name}:{serial or 'none'}:"
            f"{state.conn.execute('SELECT COUNT(*) FROM hosts').fetchone()[0]}"
        ),
    )
    system = {"sys_name": name}
    if serial is not None:
        system["serial_number"] = serial
    state.conn.execute(
        "UPDATE hosts SET preferred_name=?, system_json=? WHERE id=?",
        (name, json.dumps(system), host_id),
    )
    for address in addresses:
        state.conn.execute(
            "INSERT INTO host_addresses(address_type, value, host_id, "
            "identity_eligible) VALUES('ipv4', ?, ?, 1)",
            (address, host_id),
        )
    state.conn.commit()
    return host_id


def test_claim_batch_reconciles_inactive_duplicate_query_projections(
    tmp_path: Path,
) -> None:
    """Two ready rows for one name/address become one claim, not two queries."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["switch1.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        ),
        is_seed=True,
    )
    second = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1"],
    )
    state.set_host_ready(first, 0)
    state.set_host_ready(second, 0)

    claimed = state.claim_batch(0, 10, 300, allow_steal=False)

    assert claimed == [first]
    assert state.host_count() == 1
    assert state.host_row(first)["state"] == "CLAIMED"
    state.close()


def test_projection_reconciliation_uses_direct_sysname_not_shadow_alias(
    tmp_path: Path,
) -> None:
    """A shadow VDC presentation cannot defeat direct SNMP corroboration."""

    state = StateStore(tmp_path / "state.sqlite")
    canonical = state.upsert_candidate(
        Candidate(
            names=["switch-vdc2.example.com"],
            addresses=["198.18.10.1"],
            chassis_id="00:11:22:33:44:55",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            category="managed_device",
        )
    )
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', query_target='198.18.10.1', "
        "snmp_sysname='switch-vdc2', system_json=? WHERE id=?",
        (
            json.dumps(
                {
                    "sys_name": "switch-vdc2.example.com",
                    "serial_number": "SERIAL-1",
                }
            ),
            canonical,
        ),
    )
    state.conn.commit()

    shadow = _make_split_managed_projection(
        state,
        name="switch-vdc3.example.com",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', query_target='198.18.10.1', "
        "snmp_sysname='switch-vdc2', system_json=? WHERE id=?",
        (
            json.dumps(
                {
                    "sys_name": "switch-vdc2.example.com",
                    "serial_number": "SERIAL-1",
                }
            ),
            shadow,
        ),
    )
    state.conn.execute(
        "INSERT INTO aliases(alias_type, value, host_id) "
        "VALUES('chassis_id', '4:00:11:22:33:44:66', ?)",
        (shadow,),
    )
    state.conn.commit()

    canonical_alias_names = {
        value for kind, value in state._identity_aliases_for_host(canonical) if kind == "name"
    }
    shadow_alias_names = {
        value for kind, value in state._identity_aliases_for_host(shadow) if kind == "name"
    }
    assert canonical_alias_names.isdisjoint(shadow_alias_names)
    canonical_direct_names = state._query_projection_logical_names(state.host_row(canonical))
    shadow_direct_names = state._query_projection_logical_names(state.host_row(shadow))
    assert canonical_direct_names & shadow_direct_names

    assert state.reconcile_duplicate_query_projections() == {shadow: canonical}
    assert state.host_count() == 1
    state.close()


def test_claim_batch_defers_projection_equivalent_to_active_worker(
    tmp_path: Path,
) -> None:
    """An active equivalent row remains unclaimed until final reconciliation."""

    state = StateStore(tmp_path / "state.sqlite")
    active = state.upsert_candidate(
        Candidate(
            names=["switch1.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        ),
        is_seed=True,
    )
    state.set_host_ready(active, 0)
    assert state.claim_batch(0, 1, 300, allow_steal=False) == [active]
    shadow = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1"],
    )
    state.set_host_ready(shadow, 1)

    assert state.claim_batch(1, 1, 300, allow_steal=True) == []
    assert state.host_row(shadow)["state"] == "READY"

    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', worker_id=NULL, lease_until=NULL WHERE id=?",
        (active,),
    )
    state.conn.commit()
    assert state.reconcile_duplicate_query_projections() == {shadow: active}
    assert state.host_count() == 1
    state.close()


def test_projection_reconciliation_prefers_complete_over_failed_seed(
    tmp_path: Path,
) -> None:
    """A failed seed may be absorbed without losing seed rank or completion."""

    state = StateStore(tmp_path / "state.sqlite")
    failed_seed = state.upsert_candidate(
        Candidate(
            names=["switch1.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        ),
        is_seed=True,
        seed_rank=7,
    )
    state.conn.execute(
        "UPDATE hosts SET state='FAILED', system_json=? WHERE id=?",
        (json.dumps({"sys_name": "switch1", "serial_number": "SERIAL-1"}), failed_seed),
    )
    state.conn.commit()
    complete = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', query_target='198.18.10.1' WHERE id=?",
        (complete,),
    )
    state.conn.commit()

    assert state.reconcile_duplicate_query_projections() == {failed_seed: complete}
    row = state.host_row(complete)
    assert row["state"] == "COMPLETE"
    assert bool(row["is_seed"]) is True
    assert row["seed_rank"] == 7
    state.close()


def test_projection_reconciliation_preserves_ready_alternate_after_failure(
    tmp_path: Path,
) -> None:
    """A failed projection cannot consume an equivalent route still awaiting work."""

    state = StateStore(tmp_path / "state.sqlite")
    failed = state.upsert_candidate(
        Candidate(
            names=["switch1.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        )
    )
    state.conn.execute(
        "UPDATE hosts SET state='FAILED', system_json=? WHERE id=?",
        (json.dumps({"sys_name": "switch1", "serial_number": "SERIAL-1"}), failed),
    )
    state.conn.commit()
    ready = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1", "198.18.10.2"],
        serial="SERIAL-1",
    )
    state.set_host_ready(ready, 0)

    assert state.reconcile_duplicate_query_projections() == {failed: ready}
    assert state.host_row(ready)["state"] == "READY"
    assert state.claim_batch(0, 1, 300, allow_steal=False) == [ready]
    state.close()


def test_projection_reconciliation_rejects_transitive_serial_conflict(
    tmp_path: Path,
) -> None:
    """An identity-poor bridge cannot merge contradictory managed systems."""

    state = StateStore(tmp_path / "state.sqlite")
    left = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1"],
        serial="SERIAL-A",
    )
    bridge = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1", "198.18.10.2"],
    )
    right = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.2"],
        serial="SERIAL-B",
    )

    assert state.reconcile_duplicate_query_projections() == {}
    assert {int(row["id"]) for row in state.conn.execute("SELECT id FROM hosts")} == {
        left,
        bridge,
        right,
    }
    state.close()


def test_duplicate_projection_reconciliation_preserves_raw_graph_advertisements(
    tmp_path: Path,
) -> None:
    """Absorbing compatibility rows must not erase immutable protocol evidence."""

    state = StateStore(tmp_path / "state.sqlite")
    first = state.upsert_candidate(
        Candidate(
            names=["switch1.example.com"],
            addresses=["198.18.10.1"],
            category="managed_device",
        ),
        is_seed=True,
    )
    second = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )
    observation = NeighborObservation(
        protocol="lldp",
        local_interface="Gi1/0/1",
        local_interface_raw="GigabitEthernet1/0/1",
        remote_name="peer.example.com",
        remote_interface="Gi0/1",
        remote_interface_raw="GigabitEthernet0/1",
        chassis_id="00:11:22:33:44:55",
        chassis_id_subtype="mac_address",
        chassis_id_subtype_id=4,
        details={"protocols": ["lldp"]},
    )
    for host_id in (first, second):
        state.apply_device_result(
            DeviceResult(
                host_id=host_id,
                status="success",
                query_target="198.18.10.1",
                system=SystemDetails(
                    sys_name="switch1.example.com",
                    serial_number="SERIAL-1",
                ),
                raw_neighbors=[observation],
                neighbors=[],
                last_seen=iso_now(),
            )
        )

    assert state.conn.execute("SELECT COUNT(*) FROM protocol_advertisements").fetchone()[0] == 2
    assert state.reconcile_duplicate_query_projections() == {second: first}
    assert state.host_count() == 1

    graph = state.materialize_topology_graph().document
    assert graph["summary"]["input_advertisements"] == 2
    assert graph["summary"]["raw_advertisements"] == 2
    assert graph["summary"]["unique_advertisement_keys"] == 2
    assert graph["summary"]["excluded_advertisements"] == 0
    assert graph["summary"]["unaccounted_advertisements"] == 0
    state.close()


def test_projection_reconciliation_accepts_direct_short_name_and_fqdn(
    tmp_path: Path,
) -> None:
    """A direct short sysName may absorb its exact FQDN projection."""

    state = StateStore(tmp_path / "state.sqlite")
    complete = _make_split_managed_projection(
        state,
        name="switch1",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )
    state.conn.execute(
        "UPDATE hosts SET state='COMPLETE', snmp_sysname='switch1' WHERE id=?",
        (complete,),
    )
    state.conn.commit()
    ready = _make_split_managed_projection(
        state,
        name="switch1.example.com",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )
    state.set_host_ready(ready, 0)

    assert state.reconcile_duplicate_query_projections() == {ready: complete}
    assert state.host_count() == 1
    state.close()


def test_projection_reconciliation_does_not_strip_two_fqdn_suffixes(
    tmp_path: Path,
) -> None:
    """Two FQDNs with one left-most label remain distinct logical systems."""

    state = StateStore(tmp_path / "state.sqlite")
    left = _make_split_managed_projection(
        state,
        name="switch1.site-a.example",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )
    right = _make_split_managed_projection(
        state,
        name="switch1.site-b.example",
        addresses=["198.18.10.1"],
        serial="SERIAL-1",
    )

    assert state.reconcile_duplicate_query_projections() == {}
    assert {int(row["id"]) for row in state.conn.execute("SELECT id FROM hosts")} == {
        left,
        right,
    }
    state.close()
