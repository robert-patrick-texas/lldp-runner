"""Regression coverage for finalized discovery-to-discovery comparison."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import lldp_runner.discovery_diff as discovery_diff
from lldp_runner.cli import main
from lldp_runner.config import CredentialMode, load_config
from lldp_runner.discovery_diff import (
    DiffSourceSpec,
    DiscoveryDiffUnavailable,
    host_diff,
    macro_diff,
    pair_hosts,
    resolve_diff_sources,
)
from lldp_runner.discovery_diff_output import render_diff
from lldp_runner.discovery_query import build_query_criteria


def _neighbor(
    host_ref: int,
    name: str,
    *,
    local: str = "Gi1/0/1",
    remote: str = "Gi1/0/48",
    address: str = "192.0.2.2",
) -> dict[str, object]:
    """Build one schema-v5 learned-neighbor fixture."""

    return {
        "host_ref": host_ref,
        "name": name,
        "classification": "managed_device",
        "local_interface": local,
        "local_interface_raw": local,
        "remote_interface": remote,
        "remote_interface_raw": remote,
        "protocols": ["lldp"],
        "protocol_tag": "[lldp]",
        "observed_name": name,
        "observed_addresses": [address],
        "details": {"chassis_id": f"chassis-{name}"},
        "last_seen": "2026-08-27 10:00:00 EDT",
    }


def _host(
    host_id: int,
    name: str,
    *,
    address: str | None = None,
    serial: str | None = None,
    chassis: str | None = None,
    engine: str | None = None,
    version: str = "17.12",
    uptime: int = 1000,
    learned: list[dict[str, object]] | None = None,
    observed_by: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    """Build a compact canonical host record with durable identity evidence."""

    addresses = [address] if address else []
    return {
        "id": host_id,
        "preferred_name": name,
        "queried_as": address,
        "snmp_sysname": name,
        "classification": "managed_device",
        "classification_reason": ["fixture"],
        "tags": ["site:lab"],
        "state": "complete",
        "is_seed": True,
        "first_seen": "2026-08-27 09:00:00 EDT",
        "last_seen": "2026-08-27 10:00:00 EDT",
        "last_seen_source": "snmp",
        "names": [name],
        "addresses": {"ipv4": addresses, "ipv6": []},
        "chassis_id": chassis,
        "icmp": [
            {
                "status": "reply",
                "timestamp": "2026-08-27T10:00:00-04:00",
                "address": address,
                "rtt_ms": 1.25,
                "error": None,
            }
        ]
        if address
        else [],
        "system": {
            "sys_name": name,
            "sys_descr": "fixture switch",
            "sys_object_id": "1.3.6.1.4.1.9.1.1234",
            "sys_uptime_ticks": uptime,
            "manufacturer": "Cisco",
            "model": "C9300",
            "version": version,
            "serial_number": serial,
            "snmp_engine_id": engine,
            "stack_members": [],
        },
        "snmp": {
            "credential_profile": "site",
            "credential_result": "primary",
            "collection_metrics": {"duration_ms": 10},
        },
        "learned_neighbors": learned or [],
        "observed_by_neighbors": observed_by or [],
    }


def _write_config(root: Path) -> Path:
    config = root / "config.toml"
    config.write_text(
        f'''[paths]\npersistent_root = "{root}"\n\n[logging]\nconsole = false\nfile = false\n''',
        encoding="utf-8",
    )
    return config


def _write_run(
    root: Path,
    run_id: str,
    completed: str,
    hosts: list[dict[str, object]],
    *,
    discovery_completed: str | None = None,
    boundaries: list[str] | None = None,
    seeds: list[str] | None = None,
    config_files: list[str] | None = None,
    errors: list[dict[str, object]] | None = None,
    schema_version: int = 8,
) -> Path:
    directory = root / "outputs" / run_id
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "schema_version": schema_version,
        "discovery": {
            "run_id": run_id,
            "status": "COMPLETED",
            "started": completed,
            "completed": discovery_completed or completed,
            "generated": completed,
            "boundaries": boundaries or [],
            "discovery_mode": "recursive",
            "effective_max_devices": 0,
            "configured_max_devices": 0,
            "configured_max_hosts": 0,
            "seed_order": "input",
            "shuffle_key": None,
            "limit_behavior": "pause",
            "limit_reason": None,
            "completion_reason": "completed",
            "snmp_report_metrics": True,
            "counts": {},
        },
        "hosts": hosts,
        "errors": errors if errors is not None else [{"ignored": "no host coverage effect"}],
    }
    (directory / "discovery.json").write_text(json.dumps(document), encoding="utf-8")
    run_json = {
        "schema_version": 1,
        "run_id": run_id,
        "status": "COMPLETED",
        "started": completed,
        "completed": completed,
        "config_files_logged": config_files is not None,
        "config_files": config_files or [],
        "invocations": [
            {
                "sequence": 1,
                "seed_inputs": [{"seed": seed} for seed in seeds or []],
            }
        ],
    }
    (directory / "run.json").write_text(json.dumps(run_json), encoding="utf-8")
    return directory / "discovery.json"


def _config(root: Path):
    return load_config(
        _write_config(root),
        credential_mode=CredentialMode.DISABLED,
        resolve_paths=False,
    )


def test_history_aliases_use_run_json_completed_not_runid_or_discovery_size(tmp_path: Path) -> None:
    """History ranking prefers small run.json completion metadata over run-ID text."""

    _write_run(
        tmp_path,
        "zzz-old",
        "2026-08-27T08:00:00-04:00",
        [_host(1, "old", serial="S1")],
        discovery_completed="2026-08-27T23:00:00-04:00",
    )
    _write_run(
        tmp_path,
        "aaa-new",
        "2026-08-27T09:00:00-04:00",
        [_host(1, "new", serial="S2")],
        discovery_completed="2026-08-27T01:00:00-04:00",
    )
    sources = resolve_diff_sources(_config(tmp_path), [])
    assert sources[0].run_id == "aaa-new"
    assert sources[1].run_id == "zzz-old"

    oldest = resolve_diff_sources(_config(tmp_path), [DiffSourceSpec("oldest")])
    assert oldest[0].run_id == "aaa-new"
    assert oldest[1].run_id == "zzz-old"


def test_default_comparison_without_prior_run_is_unavailable(tmp_path: Path) -> None:
    _write_run(
        tmp_path,
        "only-run",
        "2026-08-27T09:00:00-04:00",
        [_host(1, "one", serial="S1")],
    )
    with pytest.raises(DiscoveryDiffUnavailable, match="no prior"):
        resolve_diff_sources(_config(tmp_path), [])


def test_pairing_uses_physical_then_address_then_name_and_refuses_conflict() -> None:
    a = [
        _host(1, "renamed-a", address="192.0.2.1", serial="SER1", chassis="C1"),
        _host(2, "addr-name", address="192.0.2.2"),
        _host(3, "name-only"),
        _host(4, "duplicate", address="192.0.2.40", serial="SER-A", chassis="CHA"),
    ]
    b = [
        _host(11, "renamed-b", address="198.51.100.1", serial="SER1", chassis="C1"),
        _host(12, "addr-name", address="192.0.2.2"),
        _host(13, "name-only"),
        _host(14, "duplicate", address="198.51.100.40", serial="SER-B", chassis="CHB"),
    ]
    result = pair_hosts(a, b)
    assert [(pair.a["id"], pair.b["id"], pair.tier) for pair in result.pairs] == [
        (1, 11, "physical"),
        (2, 12, "address"),
        (3, 13, "name"),
    ]
    assert len(result.ambiguous) == 1
    assert result.ambiguous[0].a["id"] == 4
    assert result.ambiguous[0].conflicting_identity is True



def test_pairing_disambiguates_nexus_vdcs_that_share_one_physical_serial() -> None:
    """Shared chassis serials must not make logical Nexus VDCs ambiguous."""

    a = [
        _host(10, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001", chassis="C-VDC1-A"),
        _host(20, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001", chassis="C-VDC2-A"),
        _host(30, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001", chassis="C-VDC3-A"),
    ]
    b = [
        _host(103, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001", chassis="C-VDC3-B"),
        _host(101, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001", chassis="C-VDC1-B"),
        _host(102, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001", chassis="C-VDC2-B"),
    ]

    result = pair_hosts(a, b)

    assert [(pair.a["id"], pair.b["id"], pair.tier) for pair in result.pairs] == [
        (10, 101, "physical"),
        (20, 102, "physical"),
        (30, 103, "physical"),
    ]
    assert not result.ambiguous
    assert not result.a_only
    assert not result.b_only
    # The serial is shared container evidence; name and address explain which VDC
    # was selected, while the differing per-link chassis value is not a hard conflict.
    assert "serial:serial000001" in result.pairs[0].evidence
    assert "name:hq-vdc1-7nx1" in result.pairs[0].evidence
    assert "ipv4:203.0.113.23" in result.pairs[0].evidence


def test_pairing_keeps_shared_serial_vdcs_ambiguous_without_logical_corroboration() -> None:
    """A shared physical container alone must not collapse discrete VDCs."""

    a = [
        _host(1, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001"),
        _host(2, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001"),
    ]
    b = [
        _host(11, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001"),
        _host(12, "hq-storage-7nx1", address="203.0.113.25", serial="SERIAL000001"),
    ]

    result = pair_hosts(a, b)

    assert not result.pairs
    assert len(result.ambiguous) == 2
    assert all(item.tier == "physical" for item in result.ambiguous)


def test_pairing_name_and_address_do_not_override_serial_or_engine_conflict() -> None:
    """VDC chassis tolerance must not weaken durable serial/engine safeguards."""

    a = [_host(1, "vdc1", address="192.0.2.10", serial="SER-A", chassis="CHA", engine="ENG-A")]
    b = [_host(2, "vdc1", address="192.0.2.10", serial="SER-B", chassis="CHB", engine="ENG-B")]

    result = pair_hosts(a, b)

    assert not result.pairs
    assert len(result.ambiguous) == 1
    assert result.ambiguous[0].conflicting_identity is True


def test_host_diff_treats_vdc_neighbor_edges_as_same_across_run_local_ids(tmp_path: Path) -> None:
    """Full diff must translate Nexus VDC host_refs after VDC-aware host pairing."""

    a_neighbors = [
        _neighbor(176, "hq-vdc1-7nx1", local="Hu1/0/21", remote="Eth6/22", address="203.0.113.23"),
        _neighbor(27, "hq-vdc2-7nx1", local="Hu1/0/25", remote="Eth1/2", address="203.0.113.24"),
        _neighbor(197, "hq-vdc3-7nx1", local="Hu1/0/29", remote="Eth4/22", address="203.0.113.22"),
    ]
    b_neighbors = [
        _neighbor(501, "hq-vdc1-7nx1", local="Hu1/0/21", remote="Eth6/22", address="203.0.113.23"),
        _neighbor(502, "hq-vdc2-7nx1", local="Hu1/0/25", remote="Eth1/2", address="203.0.113.24"),
        _neighbor(503, "hq-vdc3-7nx1", local="Hu1/0/29", remote="Eth4/22", address="203.0.113.22"),
    ]
    a_hosts = [
        _host(111, "hq-core-9500-1", address="203.0.113.101", serial="SERIAL000002", chassis="CORE", learned=a_neighbors, observed_by=a_neighbors),
        _host(176, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001", chassis="VDC1-A"),
        _host(27, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001", chassis="VDC2-A"),
        _host(197, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001", chassis="VDC3-A"),
    ]
    b_hosts = [
        _host(900, "hq-core-9500-1", address="203.0.113.101", serial="SERIAL000002", chassis="CORE", learned=b_neighbors, observed_by=b_neighbors),
        _host(501, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001", chassis="VDC1-B"),
        _host(502, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001", chassis="VDC2-B"),
        _host(503, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001", chassis="VDC3-B"),
    ]
    a_path = _write_run(tmp_path, "a", "2026-08-28T02:11:31-04:00", a_hosts)
    b_path = _write_run(tmp_path, "b", "2026-08-28T01:54:28-04:00", b_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )
    criteria = build_query_criteria(
        host_id=None, name="hq-core-9500-1", key_expressions=[], ipv4_values=[], ipv6_values=[]
    )

    outcome = host_diff(config, source_a, source_b, criteria, changes_only=False)

    assert outcome.status == "no_differences"
    assert outcome.exit_code == 0
    assert outcome.data["host"]["learned_neighbor_difference_count"] == 0
    assert outcome.data["host"]["observed_by_neighbor_difference_count"] == 0
    assert all(item["status"] == "same" for item in outcome.data["host"]["learned_neighbors"])
    assert all(item["status"] == "same" for item in outcome.data["host"]["observed_by_neighbors"])


def test_pairing_ignores_non_host_addresses_and_falls_back_to_names() -> None:
    """Placeholder IP values must not outrank unique logical-name evidence."""

    a = [
        _host(1, "ashprdesxphy026", address="0.0.0.0"),
        _host(2, "ashprdesxphy027", address="0.0.0.0"),
    ]
    b = [
        _host(12, "ashprdesxphy027", address="0.0.0.0"),
        _host(11, "ashprdesxphy026", address="0.0.0.0"),
    ]
    # Include the IPv6 unspecified sentinel as a second historical address.
    for host in [*a, *b]:
        host["addresses"]["ipv6"] = ["::"]

    result = pair_hosts(a, b)

    assert [(pair.a["id"], pair.b["id"], pair.tier) for pair in result.pairs] == [
        (1, 11, "name"),
        (2, 12, "name"),
    ]
    assert not result.ambiguous
    assert not result.a_only
    assert not result.b_only



def test_pairing_does_not_reclassify_rejected_ip_literal_as_name() -> None:
    """A rejected address sentinel cannot re-enter pairing through name tokens."""

    a = [_host(1, "0.0.0.0")]
    b = [_host(2, "0.0.0.0")]

    result = pair_hosts(a, b)

    assert not result.pairs
    assert not result.ambiguous
    assert [host["id"] for host in result.a_only] == [1]
    assert [host["id"] for host in result.b_only] == [2]

def test_macro_diff_pairs_shared_serial_vdcs_without_false_topology_churn(
    tmp_path: Path,
) -> None:
    """Macro/mass diff must translate VDC host refs without a_only/b_only churn."""

    old_neighbors = [
        _neighbor(501, "hq-vdc1-7nx1", local="Hu1/0/21", remote="Eth6/22", address="203.0.113.23"),
        _neighbor(502, "hq-vdc2-7nx1", local="Hu1/0/25", remote="Eth1/2", address="203.0.113.24"),
        _neighbor(503, "hq-vdc3-7nx1", local="Hu1/0/29", remote="Eth4/22", address="203.0.113.22"),
    ]
    new_neighbors = [
        _neighbor(176, "hq-vdc1-7nx1", local="Hu1/0/21", remote="Eth6/22", address="203.0.113.23"),
        _neighbor(27, "hq-vdc2-7nx1", local="Hu1/0/25", remote="Eth1/2", address="203.0.113.24"),
        _neighbor(197, "hq-vdc3-7nx1", local="Hu1/0/29", remote="Eth4/22", address="203.0.113.22"),
    ]
    old_hosts = [
        _host(900, "hq-core-9500-1", address="203.0.113.101", serial="SERIAL000002", chassis="CORE", learned=old_neighbors),
        _host(501, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001", chassis="VDC1-B"),
        _host(502, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001", chassis="VDC2-B"),
        _host(503, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001", chassis="VDC3-B"),
    ]
    new_hosts = [
        _host(111, "hq-core-9500-1", address="203.0.113.101", serial="SERIAL000002", chassis="CORE", learned=new_neighbors),
        _host(176, "hq-vdc1-7nx1", address="203.0.113.23", serial="SERIAL000001", chassis="VDC1-A"),
        _host(27, "hq-vdc2-7nx1", address="203.0.113.24", serial="SERIAL000001", chassis="VDC2-A"),
        _host(197, "hq-vdc3-7nx1", address="203.0.113.22", serial="SERIAL000001", chassis="VDC3-A"),
    ]
    old = _write_run(tmp_path, "old", "2026-08-28T01:54:28-04:00", old_hosts)
    new = _write_run(tmp_path, "new", "2026-08-28T02:11:31-04:00", new_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(new)), DiffSourceSpec("file", str(old))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    # The three representative VDC chassis IDs intentionally differ between
    # runs, so host-field comparison can report those diagnostic changes.  The
    # regression target is the prior macro-diff failure: VDCs must pair
    # one-to-one and unchanged topology must not become a_only/b_only churn.
    assert outcome.status == "differences_found"
    assert outcome.exit_code == 1
    assert outcome.data["summary"]["hosts"] == {
        "same": 1,
        "changed": 3,
        "a_only": 0,
        "b_only": 0,
        "coverage_uncertain": 0,
        "invalid_source_evidence": 0,
        "identity_ambiguous": 0,
        "attribute_uncertain": 0,
        "uncertain": 0,
    }
    assert outcome.data["summary"]["learned_neighbors"] == {
        "same": 3,
        "changed": 0,
        "moved": 0,
        "protocol_changed": 0,
        "management_address_changed": 0,
        "relationship_evidence_changed": 0,
        "a_only": 0,
        "b_only": 0,
        "uncertain": 0,
    }
    core = next(
        item
        for item in outcome.data["hosts"]
        if item["a"]["preferred_name"] == "hq-core-9500-1"
    )
    assert core["status"] == "same"
    assert core["learned_neighbor_difference_count"] == 0
    for item in outcome.data["hosts"]:
        if (
            item["a"]["preferred_name"].startswith("hq-vdc")
            and "7nx1" in item["a"]["preferred_name"]
        ):
            assert [difference["path"] for difference in item["host_differences"]] == [
                "chassis_id"
            ]

def test_pairing_normalizes_identity_once_per_host(monkeypatch) -> None:
    """Large unique inventories must not reconstruct identity for every A/B pair."""

    host_count = 250
    a = [
        _host(
            index,
            f"sw-{index}",
            address=f"10.0.{index // 250}.{index % 250 + 1}",
            serial=f"SER-{index}",
            chassis=f"CH-{index}",
        )
        for index in range(host_count)
    ]
    b = [
        _host(
            index + 10_000,
            f"sw-{index}",
            address=f"10.0.{index // 250}.{index % 250 + 1}",
            serial=f"SER-{index}",
            chassis=f"CH-{index}",
        )
        for index in range(host_count)
    ]

    original = discovery_diff._physical_groups
    calls = 0

    def counted(host):
        nonlocal calls
        calls += 1
        return original(host)

    monkeypatch.setattr(discovery_diff, "_physical_groups", counted)
    result = pair_hosts(a, b)

    assert len(result.pairs) == host_count
    assert not result.ambiguous
    assert calls == host_count * 2


def test_macro_diff_normalizes_volatile_fields_and_detects_reboot_and_neighbor_change(
    tmp_path: Path,
) -> None:
    old_hosts = [
        _host(
            10,
            "sw1",
            address="192.0.2.1",
            serial="SER1",
            chassis="C1",
            engine="E1",
            version="17.9",
            uptime=9000,
            learned=[_neighbor(20, "sw2", remote="Gi1/0/47")],
        ),
        _host(20, "sw2", address="192.0.2.2", serial="SER2", chassis="C2"),
    ]
    new_hosts = [
        _host(
            1,
            "sw1",
            address="192.0.2.1",
            serial="SER1",
            chassis="C1",
            engine="E1",
            version="17.12",
            uptime=1000,
            learned=[_neighbor(2, "sw2", remote="Gi1/0/48")],
        ),
        _host(2, "sw2", address="192.0.2.2", serial="SER2", chassis="C2"),
    ]
    old = _write_run(tmp_path, "old", "2026-08-27T09:00:00-04:00", old_hosts)
    new = _write_run(tmp_path, "new", "2026-08-27T10:00:00-04:00", new_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(new)), DiffSourceSpec("file", str(old))],
    )
    outcome = macro_diff(config, source_a, source_b, changes_only=False)
    assert outcome.exit_code == 1
    first = outcome.data["hosts"][0]
    paths = {item["path"] for item in first["host_differences"]}
    assert "system.version" in paths
    assert "system.sys_uptime_ticks (possible reboot)" in paths
    assert all("rtt_ms" not in path and "timestamp" not in path for path in paths)
    assert first["learned_neighbor_difference_count"] == 1
    assert outcome.data["summary"]["hosts"] == {
        "same": 1,
        "changed": 1,
        "a_only": 0,
        "b_only": 0,
        "coverage_uncertain": 0,
        "invalid_source_evidence": 0,
        "identity_ambiguous": 0,
        "attribute_uncertain": 0,
        "uncertain": 0,
    }


def test_neighbor_diff_ignores_volatile_snmp_table_indexes(tmp_path: Path) -> None:
    """Changing collector row indexes alone must not create a topology delta."""

    old_neighbor = _neighbor(20, "endpoint-02", local="Gi0/2", remote="d4:a2:cd:b6:cf:d3")
    old_neighbor["details"] = {
        "chassis_id": "chassis-endpoint-02",
        "remote_index": 91,
        "lldp.remote_index": 91,
        "time_mark": 100,
        "lldp.time_mark": 100,
        "local_port_num": 2,
        "lldp.local_port_num": 2,
        "ifindex": 10002,
        "cdp.ifindex": 10002,
        "device_index": 7,
        "cdp.device_index": 7,
        "local_ifindex": 10002,
        "lldpv2.local_ifindex": 10002,
        "port_id_subtype_id": 3,
    }
    new_neighbor = _neighbor(2, "endpoint-02", local="Gi0/2", remote="d4:a2:cd:b6:cf:d3")
    new_neighbor["details"] = {
        "chassis_id": "chassis-endpoint-02",
        "remote_index": 94,
        "lldp.remote_index": 94,
        "time_mark": 200,
        "lldp.time_mark": 200,
        "local_port_num": 200,
        "lldp.local_port_num": 200,
        "ifindex": 20002,
        "cdp.ifindex": 20002,
        "device_index": 9,
        "cdp.device_index": 9,
        "local_ifindex": 20002,
        "lldpv2.local_ifindex": 20002,
        "port_id_subtype_id": 3,
    }

    old_hosts = [
        _host(10, "endpoint-kiosk-01", serial="SER1", learned=[old_neighbor]),
        _host(20, "endpoint-02", serial="SER2"),
    ]
    new_hosts = [
        _host(1, "endpoint-kiosk-01", serial="SER1", learned=[new_neighbor]),
        _host(2, "endpoint-02", serial="SER2"),
    ]
    old = _write_run(tmp_path, "old", "2026-08-27T09:00:00-04:00", old_hosts)
    new = _write_run(tmp_path, "new", "2026-08-27T10:00:00-04:00", new_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(new)), DiffSourceSpec("file", str(old))],
    )

    outcome = host_diff(
        config,
        source_a,
        source_b,
        build_query_criteria(
            host_id=None,
            name="endpoint-kiosk-01",
            key_expressions=[],
            ipv4_values=[],
            ipv6_values=[],
        ),
        changes_only=False,
    )

    assert outcome.exit_code == 0
    assert outcome.status == "no_differences"
    assert outcome.message == "No differences"
    assert outcome.data is not None
    learned = outcome.data["host"]["learned_neighbors"]
    assert learned[0]["status"] == "same"
    assert learned[0]["differences"] == []


def test_neighbor_diff_still_compares_semantic_subtype_ids(tmp_path: Path) -> None:
    """Do not suppress protocol enum IDs merely because their names end in ID."""

    old_neighbor = _neighbor(20, "peer")
    old_neighbor["details"] = {"port_id_subtype_id": 3}
    new_neighbor = _neighbor(2, "peer")
    new_neighbor["details"] = {"port_id_subtype_id": 5}
    old_hosts = [
        _host(10, "sw1", serial="SER1", learned=[old_neighbor]),
        _host(20, "peer", serial="SER2"),
    ]
    new_hosts = [
        _host(1, "sw1", serial="SER1", learned=[new_neighbor]),
        _host(2, "peer", serial="SER2"),
    ]
    old = _write_run(tmp_path, "old", "2026-08-27T09:00:00-04:00", old_hosts)
    new = _write_run(tmp_path, "new", "2026-08-27T10:00:00-04:00", new_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(new)), DiffSourceSpec("file", str(old))],
    )

    outcome = host_diff(
        config,
        source_a,
        source_b,
        build_query_criteria(
            host_id=None,
            name="sw1",
            key_expressions=[],
            ipv4_values=[],
            ipv6_values=[],
        ),
        changes_only=False,
    )

    assert outcome.exit_code == 1
    assert outcome.data is not None
    changes = outcome.data["host"]["learned_neighbors"]
    assert changes[0]["differences"] == [
        {"path": "details.port_id_subtype_id", "a": 5, "b": 3, "kind": "changed"}
    ]


def test_changes_only_hides_same_rows_without_changing_summary(tmp_path: Path) -> None:
    hosts_a = [
        _host(1, "same", serial="S1"),
        _host(2, "changed", serial="S2", version="2"),
    ]
    hosts_b = [
        _host(11, "same", serial="S1"),
        _host(12, "changed", serial="S2", version="1"),
    ]
    a = _write_run(tmp_path, "a", "2026-08-27T10:00:00-04:00", hosts_a)
    b = _write_run(tmp_path, "b", "2026-08-27T09:00:00-04:00", hosts_b)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a)), DiffSourceSpec("file", str(b))],
    )
    outcome = macro_diff(config, source_a, source_b, changes_only=True)
    assert [item["a"]["preferred_name"] for item in outcome.data["hosts"]] == ["changed"]
    assert outcome.data["summary"]["hosts"]["same"] == 1
    assert outcome.data["summary"]["hosts"]["changed"] == 1


def test_scope_warning_uses_discovery_and_run_json_metadata(tmp_path: Path) -> None:
    a = _write_run(
        tmp_path,
        "a",
        "2026-08-27T10:00:00-04:00",
        [_host(1, "sw", serial="S1")],
        boundaries=["10.0.0.0/8"],
        seeds=["sw1"],
        config_files=["/etc/lldp/a.toml"],
    )
    b = _write_run(
        tmp_path,
        "b",
        "2026-08-27T09:00:00-04:00",
        [_host(2, "sw", serial="S1")],
        boundaries=["192.168.0.0/16"],
        seeds=["sw2"],
        config_files=["/etc/lldp/b.toml"],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a)), DiffSourceSpec("file", str(b))],
    )
    outcome = macro_diff(config, source_a, source_b, changes_only=False)
    assert outcome.warnings
    warning = outcome.warnings[0]
    assert "discovery.boundaries" in warning
    assert "run.json config_files" in warning
    assert "run.json seed_inputs" in warning


def test_host_diff_id_selects_a_but_pairs_b_by_cross_run_identity(tmp_path: Path) -> None:
    a = _write_run(
        tmp_path,
        "a",
        "2026-08-27T10:00:00-04:00",
        [_host(5, "new-name", serial="SER1", version="2")],
    )
    b = _write_run(
        tmp_path,
        "b",
        "2026-08-27T09:00:00-04:00",
        [_host(99, "old-name", serial="SER1", version="1")],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a)), DiffSourceSpec("file", str(b))],
    )
    criteria = build_query_criteria(
        host_id=5, name=None, key_expressions=[], ipv4_values=[], ipv6_values=[]
    )
    outcome = host_diff(config, source_a, source_b, criteria, changes_only=False)
    assert outcome.data["host"]["b"]["id"] == 99
    assert outcome.data["host"]["match"]["tier"] == "physical"


def test_cli_multiple_matches_in_b_resolves_alias_to_runid(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    _write_run(
        tmp_path,
        "old",
        "2026-08-27T09:00:00-04:00",
        [_host(10, "dup"), _host(11, "dup")],
    )
    _write_run(
        tmp_path,
        "new",
        "2026-08-27T10:00:00-04:00",
        [_host(1, "dup")],
    )
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff", "--id", "1"])
    assert exc.value.code == 3
    output = capsys.readouterr().out
    assert "Result: Multiple records matched in the second data set" in output
    assert "Multiple records matched in --runid old:" in output
    assert "10  dup" in output
    assert "11  dup" in output


def test_cli_multiple_matches_in_a_matches_show_neighbors_style(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    _write_run(
        tmp_path,
        "old",
        "2026-08-27T09:00:00-04:00",
        [_host(10, "alpha", serial="S1")],
    )
    _write_run(
        tmp_path,
        "new",
        "2026-08-27T10:00:00-04:00",
        [_host(1, "alpha-one", serial="S1"), _host(2, "alpha-two", serial="S2")],
    )
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff", "alpha"])
    assert exc.value.code == 3
    output = capsys.readouterr().out
    assert "Multiple records matched:" in output
    assert "1  alpha-one" in output
    assert "2  alpha-two" in output


def test_cli_no_match_outcomes_use_exit_four_and_result_line(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    _write_run(tmp_path, "old", "2026-08-27T09:00:00-04:00", [_host(10, "old", serial="S9")])
    _write_run(tmp_path, "new", "2026-08-27T10:00:00-04:00", [_host(1, "new", serial="S1")])

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff", "missing"])
    assert exc.value.code == 4
    output = capsys.readouterr().out
    assert "Result: No match in the first data set was found to compare" in output

    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff", "--id", "1"])
    assert exc.value.code == 4
    output = capsys.readouterr().out
    assert "Result: No match in the second data set was found to compare" in output


def test_cli_latest_alone_is_usage_error_with_result_line(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    _write_run(tmp_path, "old", "2026-08-27T09:00:00-04:00", [_host(1, "old", serial="S1")])
    _write_run(tmp_path, "new", "2026-08-27T10:00:00-04:00", [_host(2, "new", serial="S2")])
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff", "--latest"])
    assert exc.value.code == 2
    output = capsys.readouterr().out
    assert output.startswith("Result: Error - two different run references are necessary")
    assert "Host comparison" not in output


def test_cli_json_is_valid_machine_output_and_reports_exit_code(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    _write_run(tmp_path, "old", "2026-08-27T09:00:00-04:00", [_host(1, "sw", serial="S1", version="1")])
    _write_run(tmp_path, "new", "2026-08-27T10:00:00-04:00", [_host(2, "sw", serial="S1", version="2")])
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff", "--json"])
    assert exc.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema_version"] == 12
    assert payload["result"]["status"] == "differences_found"
    assert payload["result"]["exit_code"] == 1
    assert payload["sources"]["a"]["label"] == "--runid new"
    assert payload["sources"]["b"]["label"] == "--runid old"


def test_cli_default_no_prior_reports_no_comparison_possible(tmp_path: Path, capsys) -> None:
    config = _write_config(tmp_path)
    _write_run(tmp_path, "only", "2026-08-27T10:00:00-04:00", [_host(1, "sw", serial="S1")])
    with pytest.raises(SystemExit) as exc:
        main(["--config", str(config), "diff"])
    assert exc.value.code == 4
    output = capsys.readouterr().out
    assert output.strip() == "Result: No comparison possible: no prior finalized discovery run is available."


def test_cli_parser_usage_error_also_has_result_line(capsys) -> None:
    """Keep the diff Result line present even for argparse-level failures."""

    with pytest.raises(SystemExit) as exc:
        main(["diff", "--id", "not-an-integer"])
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out.startswith("Result: Error - ")
    assert "invalid int value" in captured.out
    assert "usage: lldp-runner diff" in captured.err


def test_neighbor_diff_pairs_anonymous_same_mac_edge_without_remote_host_map() -> None:
    """Same local port plus exact remote MAC can pair anonymous run-local hosts."""

    a = _neighbor(100, "unknown", local="1/1/36", remote="a0:b4:37:01:19:6e")
    b = _neighbor(200, "unknown", local="1/1/36", remote="a0:b4:37:01:19:6e")

    result = discovery_diff.compare_neighbors(
        [a],
        [b],
        a_to_b_host_ids={},
        b_to_a_host_ids={},
    )

    assert len(result) == 1
    assert result[0].status == "same"


def test_neighbor_diff_pairs_exact_modified_eui64_with_mac_on_same_port() -> None:
    """A reversible EUI-64/MAC representation change is one edge, not two."""

    a = _neighbor(
        100,
        "fe80::c65a:b1ff:fed5:ecfa",
        local="Gi3/0/27",
        remote="",
        address="fe80::c65a:b1ff:fed5:ecfa",
    )
    a["remote_interface"] = None
    a["remote_interface_raw"] = None
    a["observed_name"] = None
    a["details"] = {"remote_description": "DellThinOS"}
    b = _neighbor(
        200,
        "WTC45AB1D5ECFA",
        local="Gi3/0/27",
        remote="c4:5a:b1:d5:ec:fa",
        address="203.0.113.12",
    )
    b["details"] = {
        "port_id": "c4:5a:b1:d5:ec:fa",
        "port_id_subtype": "mac_address",
        "chassis_id": "c4:5a:b1:d5:ec:fa",
        "chassis_id_subtype": "mac_address",
        "remote_description": "DellThinOS",
    }

    result = discovery_diff.compare_neighbors(
        [a],
        [b],
        a_to_b_host_ids={},
        b_to_a_host_ids={},
    )

    assert len(result) == 1
    assert result[0].status == "changed"
    assert result[0].a is a
    assert result[0].b is b


def test_macro_diff_marks_missing_cdp_evidence_uncertain_after_collector_failure(
    tmp_path: Path,
) -> None:
    """A failed CDP walk must not masquerade as dozens of definite topology changes."""

    a_neighbor = _neighbor(2, "peer", local="Eth1/1", remote="Eth1/1")
    a_neighbor["protocols"] = ["cdp", "lldp"]
    a_neighbor["details"] = {
        "protocols": ["cdp", "lldp"],
        "cdp.device_id": "peer",
        "lldp.remote_name": "peer",
    }
    b_neighbor = _neighbor(20, "peer", local="Eth1/1", remote="Eth1/1")
    b_neighbor["protocols"] = ["lldp"]
    b_neighbor["details"] = {
        "protocols": ["lldp"],
        "lldp.remote_name": "peer",
    }
    a_hosts = [
        _host(1, "nexus", address="192.0.2.1", serial="N1", learned=[a_neighbor]),
        _host(2, "peer", address="192.0.2.2", serial="P1"),
    ]
    b_hosts = [
        _host(10, "nexus", address="192.0.2.1", serial="N1", learned=[b_neighbor]),
        _host(20, "peer", address="192.0.2.2", serial="P1"),
    ]
    a_path = _write_run(tmp_path, "a", "2026-08-28T04:00:00-04:00", a_hosts)
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-28T03:50:00-04:00",
        b_hosts,
        errors=[
            {
                "host_ref": 10,
                "operation": "cdp",
                "category": "timeout",
                "recoverable": True,
                "final_state": "complete",
            }
        ],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    nexus = next(item for item in outcome.data["hosts"] if item["a"]["preferred_name"] == "nexus")
    assert nexus["status"] == "uncertain"
    assert nexus["learned_neighbors"][0]["status"] == "uncertain"
    assert nexus["learned_neighbors"][0]["uncertainty_reasons"] == [
        "B cdp collection failed"
    ]
    assert nexus["collection_coverage"]["b"]["failed_protocols"] == ["cdp"]
    assert outcome.data["summary"]["learned_neighbors"]["uncertain"] == 1
    assert outcome.data["summary"]["learned_neighbors"]["changed"] == 0
    assert outcome.data["summary"]["collection_coverage"]["a"][
        "affected_host_count"
    ] == 0
    assert outcome.data["summary"]["collection_coverage"]["b"][
        "affected_host_count"
    ] == 1
    assert outcome.data["summary"]["collection_coverage"]["b"][
        "failed_protocols"
    ] == {"cdp": 1}
    assert any("Collection coverage is incomplete" in item for item in outcome.warnings)


def test_macro_diff_marks_neighbors_uncertain_when_one_host_collection_failed(
    tmp_path: Path,
) -> None:
    """A failed source host makes absent neighbors uncertain, not definite removals."""

    peer = _neighbor(20, "peer", local="Gi1/0/10", remote="Gi0/1")
    a_host = _host(1, "access", address="192.0.2.1", serial="A1", learned=[])
    a_host["state"] = "failed"
    b_hosts = [
        _host(10, "access", address="192.0.2.1", serial="A1", learned=[peer]),
        _host(20, "peer", address="192.0.2.2", serial="P1"),
    ]
    a_hosts = [a_host, _host(2, "peer", address="192.0.2.2", serial="P1")]
    a_path = _write_run(tmp_path, "a", "2026-08-28T04:00:00-04:00", a_hosts)
    b_path = _write_run(tmp_path, "b", "2026-08-28T03:50:00-04:00", b_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    access = next(item for item in outcome.data["hosts"] if item["a"]["preferred_name"] == "access")
    neighbor = access["learned_neighbors"][0]
    assert neighbor["status"] == "uncertain"
    assert neighbor["uncertainty_reasons"] == ["A host neighbor collection incomplete"]


def test_pair_hosts_uses_strict_sep_mac_across_short_fqdn_and_suffix_change() -> None:
    """SEP host components are physical identity, not generic DNS suffix aliases."""

    a = _host(1, "SEP001234560004.voice-b.example.net")
    b = _host(20, "SEP001234560004.voice-a.example.com")

    pairing = pair_hosts([a], [b])

    assert len(pairing.pairs) == 1
    assert pairing.pairs[0].tier == "physical"
    assert "sep_mac:00:12:34:56:00:04" in pairing.pairs[0].evidence


def test_pair_hosts_rejects_shared_address_with_disjoint_sep_macs() -> None:
    """A repeated phone address cannot override contradictory SEP hardware."""

    a = _host(1, "SEP001234560001", address="198.51.100.29")
    b = _host(20, "SEP001234560006", address="198.51.100.29")

    pairing = pair_hosts([a], [b])

    assert pairing.pairs == ()
    assert len(pairing.ambiguous) == 1
    assert pairing.ambiguous[0].tier == "address"
    assert pairing.ambiguous[0].conflicting_identity is True


def test_neighbor_diff_reports_protocol_transition_as_specific_change() -> None:
    """Same physical edge gaining LLDP is evidence change, not generic topology churn."""

    new = _neighbor(
        2,
        "SEP001234560004.voice-a.example.com",
        local="Gi1/0/1",
        remote="001234560004:P1",
        address="198.51.100.173",
    )
    new["protocols"] = ["cdp", "lldp"]
    new["protocol_tag"] = "[cdp,lldp]"
    new["details"] = {
        "protocols": ["cdp", "lldp"],
        "cdp.remote_name": "SEP001234560004",
        "cdp.remote_interface": "Port 1",
        "lldp.remote_name": "SEP001234560004.voice-a.example.com",
        "lldp.remote_interface": "001234560004:P1",
        "lldp.chassis_id": "198.51.100.173",
    }
    old = _neighbor(
        20,
        "SEP001234560004",
        local="Gi1/0/1",
        remote="Port 1",
        address="198.51.100.173",
    )
    old["protocols"] = ["cdp"]
    old["protocol_tag"] = "[cdp]"
    old["details"] = {
        "protocols": ["cdp"],
        "cdp.remote_name": "SEP001234560004",
        "cdp.remote_interface": "Port 1",
    }

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "protocol_changed"
    assert result[0].protocol_change == (("cdp", "lldp"), ("cdp",))


def test_neighbor_diff_classifies_management_address_evidence_separately() -> None:
    """IPv6 advertisement churn on one stable edge is not topology churn."""

    new = _neighbor(2, "SEP00123456000B.voice-b.example", address="198.51.100.60")
    new["observed_addresses"] = [
        "198.51.100.60",
        "2001:db8:8201:297::8021:b5b3",
    ]
    new["details"] = {
        "chassis_id": "00:12:34:56:00:0b",
        "lldp": {
            "remote_addresses": [
                "198.51.100.60",
                "2001:db8:8201:297::8021:b5b3",
            ]
        },
    }
    old = _neighbor(20, "SEP00123456000B.voice-b.example", address="198.51.100.60")
    old["details"] = {
        "chassis_id": "00:12:34:56:00:0b",
        "lldp": {"remote_addresses": ["198.51.100.60"]},
    }

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
        a_coverage=discovery_diff._HostCollectionCoverage(
            host_state="complete",
            table_statuses=(("lldp", "complete"),),
            management_address_statuses=(("lldp", "complete"),),
            management_address_sources=(("lldp", "subtable"),),
        ),
        b_coverage=discovery_diff._HostCollectionCoverage(
            host_state="complete",
            table_statuses=(("lldp", "complete"),),
            management_address_statuses=(("lldp", "complete"),),
            management_address_sources=(("lldp", "subtable"),),
        ),
    )

    assert len(result) == 1
    change = result[0]
    assert change.status == "management_address_changed"
    assert change.presence_status == "same"
    assert change.management_address_change == {
        "a": ["198.51.100.60", "2001:db8:8201:297::8021:b5b3"],
        "b": ["198.51.100.60"],
        "before": ["198.51.100.60"],
        "after": ["198.51.100.60", "2001:db8:8201:297::8021:b5b3"],
        "added": ["2001:db8:8201:297::8021:b5b3"],
        "removed": [],
        "added_by_family": {
            "ipv4": [],
            "ipv6": ["2001:db8:8201:297::8021:b5b3"],
        },
        "removed_by_family": {"ipv4": [], "ipv6": []},
        "confidence": "confirmed",
        "rationale": (
            "paired relationship is unchanged and both relevant management-address "
            "collection boundaries are complete"
        ),
        "protocol_coverage": {
            "lldp": {
                "a": {"status": "complete", "source": "subtable", "message": None},
                "b": {"status": "complete", "source": "subtable", "message": None},
            }
        },
    }
    payload = discovery_diff._neighbor_json(change)
    assert payload["physical_topology_effect"] == "none"


def test_neighbor_diff_management_address_removal_is_uncertain_when_subtable_failed() -> None:
    """Incomplete management-table coverage cannot establish a removal."""

    new = _neighbor(2, "phone", address="10.0.0.2")
    old = _neighbor(20, "phone", address="10.0.0.2")
    old["observed_addresses"] = ["10.0.0.2", "2001:db8::2"]
    new["details"] = {"chassis_id": "phone", "lldp": {"remote_addresses": ["10.0.0.2"]}}
    old["details"] = {
        "chassis_id": "phone",
        "lldp": {"remote_addresses": ["10.0.0.2", "2001:db8::2"]},
    }
    a_observer = _host(1, "source-a", address="192.0.2.1")
    b_observer = _host(10, "source-b", address="192.0.2.1")

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
        a_coverage=discovery_diff._HostCollectionCoverage(
            host_state="complete",
            table_statuses=(("lldp", "complete"),),
            management_address_statuses=(("lldp", "timeout"),),
            management_address_messages=(("lldp", "management walk timed out"),),
            management_address_sources=(("lldp", "subtable"),),
        ),
        b_coverage=discovery_diff._HostCollectionCoverage(
            host_state="complete",
            table_statuses=(("lldp", "complete"),),
            management_address_statuses=(("lldp", "complete"),),
            management_address_sources=(("lldp", "subtable"),),
        ),
        a_observer=a_observer,
        b_observer=b_observer,
    )

    assert result[0].status == "uncertain"
    assert result[0].presence_status == "same"
    assert result[0].management_address_change is not None
    assert result[0].management_address_change["confidence"] == "coverage_uncertain"
    assert result[0].coverage_sources[0].table == "lldp.remote_management_address"
    assert result[0].coverage_sources[0].status == "timeout"


def test_neighbor_move_precedes_management_address_change() -> None:
    """A physical local-port move remains a move even when addresses also vary."""

    new = _neighbor(2, "peer", local="Gi1/0/2", address="10.0.0.2")
    new["observed_addresses"] = ["10.0.0.2", "2001:db8::2"]
    new["details"] = {"chassis_id": "00:12:34:56:00:0b"}
    old = _neighbor(20, "peer", local="Gi1/0/1", address="10.0.0.2")
    old["details"] = {"chassis_id": "00:12:34:56:00:0b"}

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert result[0].status == "moved"
    assert result[0].management_address_change is None


def test_neighbor_diff_collection_uncertainty_precedes_protocol_transition() -> None:
    """Missing protocol evidence stays uncertain when that collector failed."""

    complete = _neighbor(2, "peer", local="Eth1/1", remote="Eth1/1")
    complete["protocols"] = ["cdp", "lldp"]
    complete["details"] = {"protocols": ["cdp", "lldp"]}
    partial = _neighbor(20, "peer", local="Eth1/1", remote="Eth1/1")
    partial["protocols"] = ["lldp"]
    partial["details"] = {"protocols": ["lldp"]}

    result = discovery_diff.compare_neighbors(
        [complete],
        [partial],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
        b_coverage=discovery_diff._HostCollectionCoverage(
            host_state="complete", failed_protocols=frozenset({"cdp"})
        ),
    )

    assert result[0].status == "uncertain"
    assert result[0].protocol_change == (("cdp", "lldp"), ("lldp",))
    assert result[0].uncertainty_reasons == ("B cdp collection failed",)


def test_macro_diff_counts_protocol_change_separately(tmp_path: Path) -> None:
    """Macro summary separates protocol evidence transitions from topology changes."""

    new_phone = _host(2, "SEP001234560004.voice-a.example.com")
    old_phone = _host(20, "SEP001234560004")
    new_edge = _neighbor(
        2,
        "SEP001234560004.voice-a.example.com",
        local="Gi1/0/1",
        remote="001234560004:P1",
        address="198.51.100.173",
    )
    new_edge["protocols"] = ["cdp", "lldp"]
    new_edge["protocol_tag"] = "[cdp,lldp]"
    new_edge["details"] = {
        "protocols": ["cdp", "lldp"],
        "cdp.remote_name": "SEP001234560004",
        "lldp.remote_name": "SEP001234560004.voice-a.example.com",
        "lldp.remote_interface": "001234560004:P1",
    }
    old_edge = _neighbor(
        20,
        "SEP001234560004",
        local="Gi1/0/1",
        remote="Port 1",
        address="198.51.100.173",
    )
    old_edge["protocols"] = ["cdp"]
    old_edge["protocol_tag"] = "[cdp]"
    old_edge["details"] = {"protocols": ["cdp"], "cdp.remote_name": "SEP001234560004"}
    new_switch = _host(1, "access-switch", serial="SW1", learned=[new_edge])
    old_switch = _host(10, "access-switch", serial="SW1", learned=[old_edge])

    new = _write_run(
        tmp_path,
        "new",
        "2026-08-28T12:00:00-04:00",
        [new_switch, new_phone],
    )
    old = _write_run(
        tmp_path,
        "old",
        "2026-08-28T11:50:00-04:00",
        [old_switch, old_phone],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(new)), DiffSourceSpec("file", str(old))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    summary = outcome.data["summary"]["learned_neighbors"]
    assert summary["protocol_changed"] == 1
    assert summary["changed"] == 0
    switch = next(
        item for item in outcome.data["hosts"] if item["a"]["preferred_name"] == "access-switch"
    )
    assert switch["learned_neighbors"][0]["status"] == "protocol_changed"
    assert switch["learned_neighbors"][0]["protocol_change"] == {
        "a": ["cdp", "lldp"],
        "b": ["cdp"],
    }

    macro_text = render_diff(
        config,
        outcome,
        json_output=False,
        json_indent=2,
    )
    assert "Protocol" in macro_text
    assert "protocols: cdp,lldp -> cdp" in macro_text

    criteria = build_query_criteria(
        host_id=None,
        name="access-switch",
        key_expressions=[],
        ipv4_values=[],
        ipv6_values=[],
    )
    host_outcome = host_diff(
        config,
        source_a,
        source_b,
        criteria,
        changes_only=False,
    )
    host_text = render_diff(
        config,
        host_outcome,
        json_output=False,
        json_indent=2,
    )
    assert "protocols: cdp,lldp -> cdp" in host_text


def test_host_pairing_uses_unique_edge_context_for_anonymous_endpoint() -> None:
    """A paired observer, local port, and endpoint MAC can pair anonymous hosts."""

    a_remote = _host(2, "unknown")
    b_remote = _host(20, "unknown")
    a_observer = _host(
        1,
        "access-a.example.com",
        serial="ACCESS-1",
        learned=[
            _neighbor(
                2,
                "unknown",
                local="Gi1/0/27",
                remote="a0:b4:37:00:10:30",
                address="",
            )
        ],
    )
    b_observer = _host(
        10,
        "access-a.example.com",
        serial="ACCESS-1",
        learned=[
            _neighbor(
                20,
                "unknown",
                local="Gi1/0/27",
                remote="a0:b4:37:00:10:30",
                address="",
            )
        ],
    )

    pairing = pair_hosts([a_observer, a_remote], [b_observer, b_remote])

    remote_pair = next(pair for pair in pairing.pairs if pair.a["id"] == 2)
    assert remote_pair.b["id"] == 20
    assert remote_pair.tier == "edge_context"
    assert "mac:a0:b4:37:00:10:30" in remote_pair.evidence
    assert pairing.a_only == ()
    assert pairing.b_only == ()


def test_edge_context_pairing_refuses_same_mac_on_different_local_ports() -> None:
    """Topology-scoped MAC evidence cannot follow an endpoint to another port."""

    a_remote = _host(2, "unknown")
    b_remote = _host(20, "unknown")
    a_observer = _host(
        1,
        "access-a.example.com",
        serial="ACCESS-1",
        learned=[_neighbor(2, "unknown", local="Gi1/0/27", remote="a0:b4:37:00:10:30")],
    )
    b_observer = _host(
        10,
        "access-a.example.com",
        serial="ACCESS-1",
        learned=[_neighbor(20, "unknown", local="Gi1/0/28", remote="a0:b4:37:00:10:30")],
    )

    pairing = pair_hosts([a_observer, a_remote], [b_observer, b_remote])

    assert all(pair.a["id"] != 2 for pair in pairing.pairs)
    assert [host["id"] for host in pairing.a_only] == [2]
    assert [host["id"] for host in pairing.b_only] == [20]


def test_repeated_address_candidates_are_narrowed_by_exact_name() -> None:
    """A contested address remains useful only with unique name corroboration."""

    a = [
        _host(1, "edge-a.example.com", address="10.10.10.1"),
        _host(2, "edge-b.example.com", address="10.10.10.1"),
    ]
    b = [
        _host(10, "edge-b.example.com", address="10.10.10.1"),
        _host(20, "edge-a.example.com", address="10.10.10.1"),
    ]

    pairing = pair_hosts(a, b)

    assert {(pair.a["id"], pair.b["id"]) for pair in pairing.pairs} == {
        (1, 20),
        (2, 10),
    }
    assert all(pair.tier == "address" for pair in pairing.pairs)


def test_unique_shared_address_cannot_pair_incompatible_named_hosts() -> None:
    """A DNS/default address alone cannot link two differently named devices."""

    a = _host(1, "edge-a.example.com", address="198.18.44.20")
    b = _host(20, "edge-b.example.com", address="198.18.44.20")

    pairing = pair_hosts([a], [b])

    assert pairing.pairs == ()
    assert len(pairing.ambiguous) == 1
    assert pairing.ambiguous[0].tier == "address"
    assert pairing.ambiguous[0].conflicting_identity is True


def test_neighbor_diff_reports_unique_resolved_port_change_as_move() -> None:
    """One stable endpoint changing resolved switch ports is a move event."""

    new = _neighbor(
        2,
        "ABQ-P591908",
        local="Gi1/0/10",
        remote="fc:4c:ea:c6:b4:2d",
    )
    old = _neighbor(
        20,
        "ABQ-P591908",
        local="Gi1/0/12",
        remote="fc:4c:ea:c6:b4:2d",
    )

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "moved"
    assert any(diff.path == "local_interface" for diff in result[0].differences)


def test_neighbor_diff_does_not_confirm_move_from_low_entropy_virtual_token() -> None:
    """A repeated virtual-appliance token is correlation, not move proof."""

    new = _neighbor(
        2,
        "unknown",
        local="Te3/0/48",
        remote="00:00:00:00:01:03",
    )
    old = _neighbor(
        20,
        "unknown",
        local="Te4/0/47",
        remote="00:00:00:00:01:03",
    )

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "uncertain"
    assert result[0].uncertainty_reasons == (
        "remote identity is insufficient to confirm a physical port move",
    )


def test_host_comparison_ignores_collection_route_selection() -> None:
    """Choosing another known address is not a physical-host field change."""

    a = _host(1, "router.example.com", address="192.0.2.10", serial="R1")
    b = _host(2, "router.example.com", address="192.0.2.10", serial="R1")
    a["addresses"] = {"ipv4": ["192.0.2.10", "192.0.2.11"], "ipv6": []}
    b["addresses"] = {"ipv4": ["192.0.2.10", "192.0.2.11"], "ipv6": []}
    a["queried_as"] = "192.0.2.10"
    b["queried_as"] = "192.0.2.11"
    a["icmp"][0]["address"] = "192.0.2.10"
    b["icmp"][0]["address"] = "192.0.2.11"

    differences = discovery_diff.compare_host_fields(
        a,
        b,
        a_completed=None,
        b_completed=None,
    )

    assert differences == ()


def test_missing_entity_rows_are_not_confirmed_removed_without_complete_coverage() -> None:
    """An incomplete ENTITY-MIB query cannot prove that a member disappeared."""

    a = _host(1, "nexus.example.com", serial="N1")
    b = _host(2, "nexus.example.com", serial="N1")
    a["system"]["stack_members"] = [
        {
            "member_number": 1,
            "name": "module-1",
            "serial_number": "MODULE1",
        }
    ]
    b["system"]["stack_members"] = []
    complete = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("entity", "complete"),),
    )
    timeout = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("entity", "timeout"),),
    )

    differences = discovery_diff.compare_host_fields(
        a,
        b,
        a_completed=None,
        b_completed=None,
        a_coverage=complete,
        b_coverage=timeout,
    )

    assert differences
    assert {item.kind for item in differences} == {"not_observed"}



def test_snmp_collection_row_count_does_not_change_host_attributes() -> None:
    """Collection inventory size belongs to coverage, not device attributes."""

    a = _host(1, "switch.example.com", address="192.0.2.1", serial="S1")
    b = _host(2, "switch.example.com", address="192.0.2.1", serial="S1")
    a["snmp"]["collection_coverage"] = {
        "lldp": {"status": "complete", "row_count": 19}
    }
    b["snmp"]["collection_coverage"] = {
        "lldp": {"status": "complete", "row_count": 20}
    }

    assert discovery_diff.compare_host_fields(
        a,
        b,
        a_completed=None,
        b_completed=None,
    ) == ()


def test_empty_complete_entity_snapshot_is_not_authoritative_removal() -> None:
    """A successful but empty optional ENTITY-MIB walk cannot prove removal."""

    a = _host(1, "nexus.example.com", serial="N1")
    b = _host(2, "nexus.example.com", serial="N1")
    a["system"]["stack_members"] = []
    b["system"]["stack_members"] = [
        {
            "member_number": 1,
            "name": "chassis",
            "serial_number": "N1",
        }
    ]
    empty = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("entity", "complete"),),
        table_row_counts=(("entity", 0),),
    )
    nonempty = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("entity", "complete"),),
        table_row_counts=(("entity", 1),),
    )

    differences = discovery_diff.compare_host_fields(
        a,
        b,
        a_completed=None,
        b_completed=None,
        a_coverage=empty,
        b_coverage=nonempty,
    )

    assert differences
    assert {item.kind for item in differences} == {"not_observed"}


def test_macro_diff_reconciles_duplicate_complete_managed_projections(
    tmp_path: Path,
) -> None:
    """A duplicate queried row must not duplicate hosts or neighbor deltas."""

    endpoint_a = _host(3, "endpoint.example.com", serial="END")
    endpoint_a["state"] = "no_query"
    endpoint_b = {**endpoint_a, "id": 30}
    a_first = _host(
        1,
        "switch.example.com",
        address="192.0.2.1",
        serial="SW1",
        learned=[_neighbor(3, "endpoint.example.com")],
    )
    a_second = _host(
        2,
        "switch.example.com",
        address="192.0.2.1",
        serial="SW1",
        learned=[_neighbor(3, "endpoint.example.com")],
    )
    b_switch = _host(
        10,
        "switch.example.com",
        address="192.0.2.1",
        serial="SW1",
        learned=[_neighbor(30, "endpoint.example.com")],
    )
    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-30T02:00:00-04:00",
        [a_first, a_second, endpoint_a],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-30T01:00:00-04:00",
        [b_switch, endpoint_b],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    projection = outcome.data["summary"]["compatibility_projection"]
    assert projection["a"] == {
        "raw_host_count": 3,
        "canonical_host_count": 2,
        "duplicate_group_count": 1,
        "absorbed_host_count": 1,
    }
    assert projection["b"]["absorbed_host_count"] == 0
    assert outcome.data["summary"]["hosts"] == {
        "same": 2,
        "changed": 0,
        "a_only": 0,
        "b_only": 0,
        "coverage_uncertain": 0,
        "invalid_source_evidence": 0,
        "identity_ambiguous": 0,
        "attribute_uncertain": 0,
        "uncertain": 0,
    }
    assert outcome.data["summary"]["learned_neighbors"]["same"] == 1
    assert outcome.data["summary"]["learned_neighbors"]["a_only"] == 0
    assert outcome.data["summary"]["learned_neighbors"]["b_only"] == 0


def test_projection_fold_accepts_direct_short_name_and_fqdn() -> None:
    """One short direct name may match the same left-most FQDN component."""

    short = _host(1, "switch1", address="192.0.2.1", serial="SW1")
    fqdn = _host(
        2,
        "switch1.example.com",
        address="192.0.2.1",
        serial="SW1",
    )

    components = discovery_diff._projection_duplicate_components([short, fqdn])

    assert components == [
        ("switch1.example.com", [1, 2], ["ipv4:192.0.2.1"])
    ]


def test_projection_fold_does_not_strip_two_fqdn_suffixes() -> None:
    """One shared address cannot merge two FQDNs by left-most label alone."""

    left = _host(
        1,
        "switch1.site-a.example",
        address="192.0.2.1",
        serial="SW1",
    )
    right = _host(
        2,
        "switch1.site-b.example",
        address="192.0.2.1",
        serial="SW1",
    )

    assert discovery_diff._projection_duplicate_components([left, right]) == []


def test_neighbor_diff_treats_identical_typed_unresolved_port_as_same() -> None:
    """A stable LLDP-local index is not topology uncertainty by itself."""

    a = _neighbor(
        2,
        "branch-access-3650-1.net.example.com",
        local="lldpLocalPort:13",
        remote="Te1/0/47",
        address="198.51.100.215",
    )
    b = _neighbor(
        20,
        "branch-access-3650-1.net.example.com",
        local="lldpLocalPort:13",
        remote="Te1/0/47",
        address="198.51.100.215",
    )
    for row in (a, b):
        row["protocols"] = ["lldp"]
        row["protocol_tag"] = "[lldp]"
        row["details"] = {
            "local_port_num": 13,
            "local_interface_resolved": False,
            "local_interface_namespace": "lldpLocalPort",
            "protocols": ["lldp"],
        }

    result = discovery_diff.compare_neighbors(
        [a],
        [b],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "same"
    assert result[0].differences == ()
    assert result[0].uncertainty_reasons == ()


def test_neighbor_diff_separates_resolved_unresolved_port_presentation() -> None:
    """A unique edge stays same when only the friendly local-port name is missing."""

    unresolved = _neighbor(
        2,
        "peer.example.com",
        local="ifIndex:1",
        remote="Gi0/1",
        address="192.0.2.20",
    )
    unresolved["protocols"] = ["cdp"]
    unresolved["protocol_tag"] = "[cdp]"
    unresolved["details"] = {
        "ifindex": 1,
        "local_interface_resolved": False,
        "local_interface_namespace": "ifIndex",
        "local_port_map_failed": True,
        "cdp.local_port_map_failed": True,
        "protocols": ["cdp"],
    }
    resolved = _neighbor(
        20,
        "peer.example.com",
        local="Fa0/0",
        remote="Gi0/1",
        address="192.0.2.20",
    )
    resolved["protocols"] = ["cdp"]
    resolved["protocol_tag"] = "[cdp]"
    resolved["details"] = {
        "ifindex": 1,
        "local_interface_resolved": True,
        "local_interface_namespace": "ifName",
        "local_port_map_failed": False,
        "cdp.local_port_map_failed": False,
        "protocols": ["cdp"],
    }

    result = discovery_diff.compare_neighbors(
        [unresolved],
        [resolved],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "same"
    assert result[0].differences == ()
    assert {item.path for item in result[0].presentation_differences} == {
        "details.local_interface_namespace",
        "details.local_interface_resolved",
        "details.local_port_map_failed",
        "details.cdp.local_port_map_failed",
        "local_interface",
        "local_interface_raw",
    }
    assert result[0].uncertainty_reasons == ()


def test_neighbor_diff_coalesces_unresolved_split_protocol_rows_as_uncertain() -> None:
    """A failed interface map must not turn one merged edge into add/remove churn."""

    lldp = _neighbor(
        2,
        "SEP001234560002.voice-a.example.com",
        local="16",
        remote="001234560002:P1",
    )
    lldp["protocols"] = ["lldp"]
    lldp["protocol_tag"] = "[lldp]"
    lldp["details"] = {
        "local_port_num": 16,
        "local_interface_resolved": False,
        "protocols": ["lldp"],
        "port_id": "001234560002:P1",
    }
    cdp = _neighbor(
        2,
        "SEP001234560002",
        local="23",
        remote="Port 1",
    )
    cdp["protocols"] = ["cdp"]
    cdp["protocol_tag"] = "[cdp]"
    cdp["details"] = {
        "ifindex": 23,
        "local_interface_resolved": False,
        "protocols": ["cdp"],
    }
    merged = _neighbor(
        20,
        "SEP001234560002.voice-a.example.com",
        local="Gi1/0/16",
        remote="001234560002:P1",
    )
    merged["protocols"] = ["cdp", "lldp"]
    merged["protocol_tag"] = "[cdp,lldp]"
    merged["details"] = {
        "local_port_num": 16,
        "cdp.ifindex": 23,
        "local_interface_resolved": True,
        "protocols": ["cdp", "lldp"],
        "port_id": "001234560002:P1",
    }

    result = discovery_diff.compare_neighbors(
        [lldp, cdp],
        [merged],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "uncertain"
    assert result[0].a is not None
    assert result[0].a["protocols"] == ["cdp", "lldp"]
    assert result[0].uncertainty_reasons == ("A local interface unresolved",)


def test_neighbor_diff_keeps_lldp_continuity_when_cdp_interface_map_failed() -> None:
    """A surviving exact LLDP edge keeps relationship presence stable.

    The failed IF-MIB map may leave a separate unresolved CDP row and change the
    generic merged capability/protocol detail fields.  Those are coverage-limited
    evidence differences, not a physical relationship add/remove/change.
    """

    merged = _neighbor(
        2,
        "peer.example.com",
        local="Gi1/0/24",
        remote="Gi1/0/28",
        address="192.0.2.20",
    )
    merged["protocols"] = ["cdp", "lldp"]
    merged["protocol_tag"] = "[cdp,lldp]"
    merged["details"] = {
        "capabilities": ["bridge", "router", "switch"],
        "protocols": ["cdp", "lldp"],
        "cdp.ifindex": 31,
        "lldp.local_port_num": 24,
        "local_interface_resolved": True,
    }
    lldp = _neighbor(
        20,
        "peer.example.com",
        local="Gi1/0/24",
        remote="Gi1/0/28",
        address="192.0.2.20",
    )
    lldp["protocols"] = ["lldp"]
    lldp["protocol_tag"] = "[lldp]"
    lldp["details"] = {
        "capabilities": ["bridge", "router"],
        "protocols": ["lldp"],
        "local_port_num": 24,
        "local_interface_resolved": True,
    }
    cdp = _neighbor(
        20,
        "peer.example.com",
        local="ifIndex:31",
        remote="Gi1/0/28",
        address="192.0.2.20",
    )
    cdp["protocols"] = ["cdp"]
    cdp["protocol_tag"] = "[cdp]"
    cdp["details"] = {
        "capabilities": ["router", "switch"],
        "protocols": ["cdp"],
        "ifindex": 31,
        "local_interface_resolved": False,
    }
    complete = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("cdp", "complete"), ("interfaces", "complete")),
    )
    degraded = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        unresolved_interface_protocols=frozenset({"cdp"}),
        table_statuses=(("cdp", "complete"), ("interfaces", "structurally_invalid")),
        table_messages=(("interfaces", "IF-MIB interface map incomplete"),),
    )

    result = discovery_diff.compare_neighbors(
        [merged],
        [lldp, cdp],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
        a_coverage=complete,
        b_coverage=degraded,
        a_observer={"id": 1, "preferred_name": "observer.example.com"},
        b_observer={"id": 10, "preferred_name": "observer.example.com"},
    )

    assert len(result) == 1
    assert result[0].status == "same"
    assert result[0].presence_status == "same"
    assert result[0].presence_confidence == "coverage_uncertain"
    assert result[0].semantic_qualification == "coverage_uncertain"
    assert {item.path for item in result[0].differences} == {
        "details.capabilities",
        "details.protocols",
    }
    assert result[0].coverage_sources[0].table == "interfaces"
    assert result[0].coverage_sources[0].protocol == "cdp"


def test_host_pairing_confidence_is_categorical_and_explainable(tmp_path: Path) -> None:
    """Diff exposes evidence categories without pretending they are probabilities."""

    a_hosts = [
        _host(1, "serial-a", serial="SER-1"),
        _host(2, "address-a", address="192.0.2.2"),
        _host(3, "name-a"),
    ]
    b_hosts = [
        _host(10, "serial-b", serial="SER-1"),
        _host(20, "address-a", address="192.0.2.2"),
        _host(30, "name-a"),
    ]
    a_path = _write_run(tmp_path, "a", "2026-08-28T04:00:00-04:00", a_hosts)
    b_path = _write_run(tmp_path, "b", "2026-08-28T03:50:00-04:00", b_hosts)
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    confidence = {
        item["a"]["id"]: item["match"]["confidence"]
        for item in outcome.data["hosts"]
    }
    assert confidence == {1: "verified", 2: "medium", 3: "low"}
    assert outcome.data["summary"]["host_pairing_confidence"] == {
        "verified": 1,
        "high": 0,
        "medium": 1,
        "low": 1,
    }


def _set_collection_coverage(
    host: dict[str, object],
    **tables: tuple[str, str],
) -> None:
    """Attach compact schema-8 table coverage to a host fixture."""

    snmp = host.setdefault("snmp", {})
    assert isinstance(snmp, dict)
    snmp["collection_coverage"] = {
        table: {
            "status": status,
            "resolution_status": resolution,
            "message": None,
        }
        for table, (status, resolution) in tables.items()
    }


def _set_schema8_lldp_coverage(
    host: dict[str, object],
    *,
    aggregate: str = "complete",
    remote_neighbor: str = "complete",
    local_port: str = "complete",
    remote_management_address: str = "complete",
) -> None:
    """Attach independent original-LLDP subtable coverage to one fixture."""

    snmp = host.setdefault("snmp", {})
    assert isinstance(snmp, dict)
    snmp["collection_coverage"] = {
        "interfaces": {
            "status": "complete",
            "resolution_status": "resolved",
            "message": None,
        },
        "lldp": {
            "status": aggregate,
            "resolution_status": (
                "resolved" if aggregate == "complete" else "partial"
            ),
            "message": None,
            "subtables": {
                "local_port": {
                    "status": local_port,
                    "resolution_status": (
                        "resolved" if local_port == "complete" else "partial"
                    ),
                    "message": None,
                },
                "remote_neighbor": {
                    "status": remote_neighbor,
                    "resolution_status": (
                        "resolved"
                        if remote_neighbor == "complete"
                        else "unresolved"
                    ),
                    "message": None,
                },
                "remote_management_address": {
                    "status": remote_management_address,
                    "resolution_status": (
                        "resolved"
                        if remote_management_address == "complete"
                        else "partial"
                    ),
                    "message": (
                        None
                        if remote_management_address == "complete"
                        else "fixture management-address walk was partial"
                    ),
                },
            },
        },
    }


def test_macro_diff_propagates_failed_observer_protocol_to_one_sided_entity(
    tmp_path: Path,
) -> None:
    """An endpoint hidden by failed LLDP coverage is uncertain, not A-only."""

    a_source = _host(1, "source", address="192.0.2.1", serial="SRC")
    b_source = _host(10, "source", address="192.0.2.1", serial="SRC")
    _set_collection_coverage(a_source, lldp=("complete", "resolved"))
    _set_collection_coverage(b_source, lldp=("timeout", "unresolved"))
    endpoint = _host(2, "endpoint", address="192.0.2.2", serial="END")
    endpoint["state"] = "no_query"
    endpoint["observed_by_neighbors"] = [_neighbor(1, "source")]

    a_path = _write_run(
        tmp_path, "a", "2026-08-30T02:00:00-04:00", [a_source, endpoint]
    )
    b_path = _write_run(
        tmp_path, "b", "2026-08-30T01:00:00-04:00", [b_source]
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    assert outcome.data["summary"]["hosts"]["a_only"] == 0
    assert outcome.data["summary"]["hosts"]["coverage_uncertain"] == 1
    result = outcome.data["presence_uncertain"][0]
    assert result["preferred_name"] == "endpoint"
    assert result["presence_confidence"] == "coverage_uncertain"
    assert result["coverage_source"]["protocol"] == "lldp"
    assert result["coverage_source"]["observer"]["b"]["id"] == 10
    assert outcome.data["collection_incidents"][0]["affected_remote_entity_count"] == 1
    rendered = render_diff(config, outcome, json_output=False, json_indent=2)
    assert "Collection coverage" in rendered
    assert "Health partial/failed" in rendered
    assert "Collection incidents" in rendered
    assert "source" in rendered
    assert "lldp" in rendered


def test_macro_diff_recursively_propagates_original_coverage_incident(
    tmp_path: Path,
) -> None:
    """A hidden managed switch and its endpoint retain one originating incident."""

    a_root = _host(1, "root", address="192.0.2.1", serial="ROOT")
    b_root = _host(10, "root", address="192.0.2.1", serial="ROOT")
    _set_collection_coverage(a_root, lldp=("complete", "resolved"))
    _set_collection_coverage(b_root, lldp=("timeout", "unresolved"))
    branch = _host(2, "branch", address="192.0.2.2", serial="BRANCH")
    branch["observed_by_neighbors"] = [_neighbor(1, "root")]
    endpoint = _host(3, "phone", address="192.0.2.3", serial="PHONE")
    endpoint["state"] = "no_query"
    endpoint["observed_by_neighbors"] = [_neighbor(2, "branch")]

    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-30T02:00:00-04:00",
        [a_root, branch, endpoint],
    )
    b_path = _write_run(
        tmp_path, "b", "2026-08-30T01:00:00-04:00", [b_root]
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    assert outcome.data["summary"]["hosts"]["coverage_uncertain"] == 2
    by_name = {
        item["preferred_name"]: item for item in outcome.data["presence_uncertain"]
    }
    assert by_name["branch"]["coverage_source"]["origin"] == "direct"
    assert by_name["phone"]["coverage_source"]["origin"] == "recursive"
    assert [
        item["preferred_name"]
        for item in by_name["phone"]["coverage_source"]["recursive_path"]
    ] == ["branch", "phone"]
    incident = outcome.data["collection_incidents"][0]
    assert incident["affected_remote_entity_count"] == 1
    assert incident["recursive_descendant_count"] == 1


def test_macro_diff_keeps_genuine_absence_confirmed_with_complete_coverage(
    tmp_path: Path,
) -> None:
    """Complete corresponding LLDP coverage preserves a confirmed A-only result."""

    a_source = _host(1, "source", address="192.0.2.1", serial="SRC")
    b_source = _host(10, "source", address="192.0.2.1", serial="SRC")
    _set_collection_coverage(a_source, lldp=("complete", "resolved"))
    _set_collection_coverage(b_source, lldp=("complete", "resolved"))
    endpoint = _host(2, "endpoint", address="192.0.2.2", serial="END")
    endpoint["state"] = "no_query"
    endpoint["observed_by_neighbors"] = [_neighbor(1, "source")]

    a_path = _write_run(
        tmp_path, "a", "2026-08-30T02:00:00-04:00", [a_source, endpoint]
    )
    b_path = _write_run(
        tmp_path, "b", "2026-08-30T01:00:00-04:00", [b_source]
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    assert outcome.data["summary"]["hosts"]["a_only"] == 1
    assert outcome.data["summary"]["hosts"]["coverage_uncertain"] == 0
    assert outcome.data["a_only"][0]["presence_confidence"] == "confirmed"
    assert outcome.data["presence_uncertain"] == []


def test_collection_summary_excludes_no_query_and_out_of_scope_from_failures(
    tmp_path: Path,
) -> None:
    """Intentional discovery boundaries do not inflate queried failure counts."""

    queried = _host(1, "switch", address="192.0.2.1", serial="SW")
    no_query = _host(2, "phone", address="192.0.2.2", serial="PHONE")
    no_query["state"] = "no_query"
    out_of_scope = _host(3, "remote", address="192.0.2.3", serial="REMOTE")
    out_of_scope["state"] = "out_of_scope"
    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-30T02:00:00-04:00",
        [queried, no_query, out_of_scope],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-30T01:00:00-04:00",
        [
            _host(10, "switch", address="192.0.2.1", serial="SW"),
            {**no_query, "id": 20},
            {**out_of_scope, "id": 30},
        ],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)
    coverage = outcome.data["summary"]["collection_coverage"]["a"]

    assert coverage["actively_queried_count"] == 1
    assert coverage["complete_queried_count"] == 1
    assert coverage["partial_or_failed_queried_count"] == 0
    assert coverage["no_query_count"] == 1
    assert coverage["out_of_scope_count"] == 1


def test_macro_diff_does_not_fold_conflicting_duplicate_projection_identity(
    tmp_path: Path,
) -> None:
    """Exact name/address cannot override contradictory physical serials."""

    a_first = _host(
        1,
        "switch.example.com",
        address="192.0.2.1",
        serial="SERIAL-A",
    )
    a_second = _host(
        2,
        "switch.example.com",
        address="192.0.2.1",
        serial="SERIAL-B",
    )
    b_first = _host(
        10,
        "switch.example.com",
        address="192.0.2.1",
        serial="SERIAL-A",
    )
    b_second = _host(
        20,
        "switch.example.com",
        address="192.0.2.1",
        serial="SERIAL-B",
    )
    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-30T02:00:00-04:00",
        [a_first, a_second],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-30T01:00:00-04:00",
        [b_first, b_second],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    projection = outcome.data["summary"]["compatibility_projection"]
    assert projection["a"]["absorbed_host_count"] == 0
    assert projection["b"]["absorbed_host_count"] == 0
    assert outcome.data["summary"]["hosts"]["same"] == 2
    assert outcome.data["summary"]["hosts"]["identity_ambiguous"] == 0


def test_collection_duration_is_volatile_by_default_and_opt_in() -> None:
    """Exact collector timings stay in discoveries without creating default churn."""

    a = _host(1, "switch", address="192.0.2.1", serial="SW")
    b = _host(10, "switch", address="192.0.2.1", serial="SW")
    for host, aggregate_duration, row_duration in (
        (a, 250.0, 175.0),
        (b, 100.0, 75.0),
    ):
        snmp = host["snmp"]
        assert isinstance(snmp, dict)
        snmp["collection_metrics"] = {
            "duration_ms": aggregate_duration,
            "collector_count": 5,
        }
        snmp["collection_coverage"] = {
            "lldp": {
                "status": "complete",
                "duration_ms": aggregate_duration,
                "subtables": {
                    "remote_neighbor": {
                        "status": "complete",
                        "duration_ms": row_duration,
                    }
                },
            }
        }

    assert discovery_diff.compare_host_collection_fields(a, b) == ()
    paths = {
        item.path
        for item in discovery_diff.compare_host_collection_fields(
            a,
            b,
            include_timing=True,
        )
    }
    assert paths == {
        "snmp.collection_coverage.lldp.duration_ms",
        "snmp.collection_coverage.lldp.subtables.remote_neighbor.duration_ms",
    }


def test_cli_collection_timing_config_can_be_explicitly_disabled(
    tmp_path: Path,
    capsys,
) -> None:
    """Dedicated BooleanOptionalAction flags override the read-only diff policy."""

    config = tmp_path / "config.toml"
    config.write_text(
        f'''[paths]\npersistent_root = "{tmp_path}"\n\n'''
        "[logging]\nconsole = false\nfile = false\n\n"
        "[diff]\ninclude_collection_timing = true\n",
        encoding="utf-8",
    )
    old = _host(1, "switch", address="192.0.2.1", serial="SW")
    new = _host(2, "switch", address="192.0.2.1", serial="SW")
    assert isinstance(old["snmp"], dict)
    assert isinstance(new["snmp"], dict)
    old["snmp"]["collection_coverage"] = {
        "lldp": {"status": "complete", "duration_ms": 10.0}
    }
    new["snmp"]["collection_coverage"] = {
        "lldp": {"status": "complete", "duration_ms": 20.0}
    }
    _write_run(tmp_path, "old", "2026-08-31T01:00:00-04:00", [old])
    _write_run(tmp_path, "new", "2026-08-31T02:00:00-04:00", [new])

    with pytest.raises(SystemExit) as enabled:
        main(["--config", str(config), "diff", "--json"])
    assert enabled.value.code == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["comparison"]["options"]["include_collection_timing"] is True
    assert payload["comparison"]["summary"]["host_dimensions"]["collection"] == {
        "same": 0,
        "changed": 1,
    }

    main(
        [
            "--config",
            str(config),
            "diff",
            "--no-include-collection-timing",
            "--json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["comparison"]["options"]["include_collection_timing"] is False
    assert payload["comparison"]["summary"]["host_dimensions"]["collection"] == {
        "same": 1,
        "changed": 0,
    }


def test_management_only_lldp_partial_does_not_obscure_neighbor_presence(
    tmp_path: Path,
) -> None:
    """A partial address subtable cannot invalidate a complete neighbor table."""

    a_source = _host(
        1,
        "source",
        address="192.0.2.1",
        serial="SRC",
        learned=[_neighbor(2, "endpoint")],
    )
    b_source = _host(10, "source", address="192.0.2.1", serial="SRC")
    _set_schema8_lldp_coverage(a_source)
    _set_schema8_lldp_coverage(
        b_source,
        aggregate="partial",
        remote_management_address="partial",
    )
    a_endpoint = _host(2, "endpoint", address="192.0.2.2", serial="END")
    b_endpoint = _host(20, "endpoint", address="192.0.2.2", serial="END")
    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-31T02:00:00-04:00",
        [a_source, a_endpoint],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-31T01:00:00-04:00",
        [b_source, b_endpoint],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    learned = outcome.data["summary"]["learned_neighbors"]
    assert learned["a_only"] == 1
    assert learned["uncertain"] == 0
    b_coverage = outcome.data["summary"]["collection_coverage"]["b"]
    assert b_coverage["aggregate_partial_or_failed_queried_count"] == 1
    assert b_coverage["topology_affected_queried_count"] == 0
    assert b_coverage["topology_complete_queried_count"] == 2
    assert b_coverage["management_address_only_incomplete_count"] == 1
    assert b_coverage["other_health_only_incomplete_count"] == 0
    assert outcome.data["collection_incidents"] == []
    assert not any("topology-sensitive" in warning for warning in outcome.warnings)


def test_stable_edge_evidence_changes_have_specific_conservative_status() -> None:
    """Display/sentinel evidence is separated without hiding two usable chassis IDs."""

    new = _neighbor(2, "SEP001122334455.example", address="192.0.2.44")
    old = _neighbor(20, "SEP001122334455", address="192.0.2.44")
    new["observed_name"] = "SEP001122334455.example"
    old["observed_name"] = "SEP001122334455"
    new["details"] = {
        "lldp": {
            "remote_name": "SEP001122334455.example",
            "chassis_id": "192.0.2.44",
        }
    }
    old["details"] = {
        "lldp": {
            "remote_name": "SEP001122334455",
            "chassis_id": "0.0.0.0",
        }
    }

    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )

    assert len(result) == 1
    assert result[0].status == "relationship_evidence_changed"
    assert result[0].semantic_qualification == "evidence_only"
    assert result[0].presence_status == "same"
    assert result[0].presence_confidence == "confirmed"

    new["details"] = {"lldp": {"chassis_id": "192.0.2.45"}}
    old["details"] = {"lldp": {"chassis_id": "192.0.2.46"}}
    result = discovery_diff.compare_neighbors(
        [new],
        [old],
        a_to_b_host_ids={2: 20},
        b_to_a_host_ids={20: 2},
    )
    assert result[0].status == "changed"


def test_missing_lldp_derived_chassis_attribute_retains_observer_provenance(
    tmp_path: Path,
) -> None:
    """A failed observer makes a missing endpoint chassis value not-observed."""

    a_observer = _host(1, "observer", address="192.0.2.1", serial="OBS")
    b_observer = _host(10, "observer", address="192.0.2.1", serial="OBS")
    _set_schema8_lldp_coverage(a_observer)
    _set_schema8_lldp_coverage(
        b_observer,
        aggregate="partial",
        remote_neighbor="incomplete_table",
    )
    a_endpoint = _host(
        2,
        "endpoint",
        address="192.0.2.2",
        serial="END",
        chassis="aa:bb:cc:dd:ee:ff",
    )
    b_endpoint = _host(
        20,
        "endpoint",
        address="192.0.2.2",
        serial="END",
        chassis=None,
    )
    observation = _neighbor(1, "observer", address="192.0.2.1")
    observation["details"] = {
        "lldp": {"chassis_id": "aa:bb:cc:dd:ee:ff"}
    }
    a_endpoint["observed_by_neighbors"] = [observation]
    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-31T02:00:00-04:00",
        [a_observer, a_endpoint],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-31T01:00:00-04:00",
        [b_observer, b_endpoint],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    endpoint = next(
        item
        for item in outcome.data["hosts"]
        if item["a"]["preferred_name"] == "endpoint"
    )
    difference = endpoint["host_differences"][0]
    assert difference["path"] == "chassis_id"
    assert difference["kind"] == "not_observed"
    assert difference["provenance"] == "neighbor_observation"
    assert difference["coverage_source"]["missing_side"] == "b"
    assert difference["coverage_source"]["protocol"] == "lldp"
    assert difference["coverage_source"]["table"] == "lldp.remote_neighbor"
    assert outcome.data["summary"]["hosts"]["changed"] == 0
    assert outcome.data["summary"]["hosts"]["attribute_uncertain"] == 1
    assert outcome.data["collection_incidents"][0]["affected_attribute_count"] == 1


def test_terminal_render_can_collapse_expand_or_emit_summary_only(
    tmp_path: Path,
) -> None:
    """Human output is compact by default while JSON-grade detail remains available."""

    a_source = _host(
        1,
        "source",
        address="192.0.2.1",
        serial="SRC",
        learned=[_neighbor(2, "endpoint")],
    )
    b_source = _host(10, "source", address="192.0.2.1", serial="SRC")
    _set_collection_coverage(a_source, lldp=("complete", "resolved"))
    _set_collection_coverage(b_source, lldp=("timeout", "unresolved"))
    a_endpoint = _host(2, "endpoint", address="192.0.2.2", serial="END")
    b_endpoint = _host(20, "endpoint", address="192.0.2.2", serial="END")
    a_path = _write_run(
        tmp_path,
        "a",
        "2026-08-31T02:00:00-04:00",
        [a_source, a_endpoint],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-08-31T01:00:00-04:00",
        [b_source, b_endpoint],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )
    outcome = macro_diff(config, source_a, source_b, changes_only=True)

    compact = render_diff(config, outcome, json_output=False, json_indent=2)
    expanded = render_diff(
        config,
        outcome,
        json_output=False,
        json_indent=2,
        expand_collection_incidents=True,
    )
    summary = render_diff(
        config,
        outcome,
        json_output=False,
        json_indent=2,
        summary_only=True,
    )

    assert "Collapsed derivative coverage-uncertain rows" in compact
    assert "Collapsed derivative coverage-uncertain rows" not in expanded
    assert len(expanded.splitlines()) > len(compact.splitlines())
    assert "Compatibility host comparison" in compact
    assert "Compatibility host comparison" not in summary
    assert "Collection incidents" in summary


def test_duplicate_projection_coverage_preserves_semantic_subtable_boundaries() -> None:
    """Coverage merging keeps independent dimensions and lets complete paths win."""

    first = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("lldp", "partial"),),
        neighbor_statuses=(("lldp", "complete"),),
        neighbor_sources=(("lldp", "lldp.remote_neighbor"),),
        interface_statuses=(("lldp", "complete"),),
        interface_sources=(("lldp", "lldp.local_port"),),
        management_address_statuses=(("lldp", "partial"),),
        management_address_messages=(("lldp", "first path partial"),),
        management_address_sources=(("lldp", "subtable"),),
    )
    second = discovery_diff._HostCollectionCoverage(
        host_state="complete",
        table_statuses=(("lldp", "complete"),),
        neighbor_statuses=(("lldp", "timeout"),),
        neighbor_messages=(("lldp", "second neighbor path timed out"),),
        neighbor_sources=(("lldp", "lldp.remote_neighbor"),),
        interface_statuses=(("lldp", "unresolved"),),
        interface_sources=(("lldp", "lldp.local_port"),),
        management_address_statuses=(("lldp", "complete"),),
        management_address_sources=(("lldp", "subtable"),),
    )

    merged = discovery_diff._merge_projection_coverage([first, second])

    assert merged.status_for("lldp") == "complete"
    assert merged.neighbor_status_for("lldp") == "complete"
    assert merged.neighbor_source_for("lldp") == "lldp.remote_neighbor"
    assert merged.interface_status_for("lldp") == "complete"
    assert merged.interface_source_for("lldp") == "lldp.local_port"
    assert merged.management_address_status_for("lldp") == "complete"
    assert merged.management_address_source_for("lldp") == "subtable"


def test_macro_diff_summarizes_management_health_persistence_and_recovery(
    tmp_path: Path,
) -> None:
    """Management-table health tracks persistence and recovery by cause."""

    a_persistent = _host(1, "persistent", address="192.0.2.1", serial="P")
    b_persistent = _host(10, "persistent", address="192.0.2.1", serial="P")
    a_recovered = _host(2, "recovered", address="192.0.2.2", serial="R")
    b_recovered = _host(20, "recovered", address="192.0.2.2", serial="R")
    for host in (a_persistent, b_persistent):
        _set_schema8_lldp_coverage(
            host,
            aggregate="partial",
            remote_management_address="partial",
        )
        coverage = host["snmp"]["collection_coverage"]["lldp"]
        coverage["subtables"]["remote_management_address"]["message"] = (
            "one malformed management-address index"
        )
    _set_schema8_lldp_coverage(a_recovered)
    _set_schema8_lldp_coverage(
        b_recovered,
        aggregate="partial",
        remote_management_address="timeout",
    )
    b_coverage = b_recovered["snmp"]["collection_coverage"]["lldp"]
    b_coverage["subtables"]["remote_management_address"]["message"] = (
        "management-address walk timeout"
    )

    a_path = _write_run(
        tmp_path,
        "a",
        "2026-09-01T02:00:00-04:00",
        [a_persistent, a_recovered],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-09-01T01:00:00-04:00",
        [b_persistent, b_recovered],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    health = outcome.data["management_address_health"]
    assert health["a_incomplete_count"] == 1
    assert health["b_incomplete_count"] == 2
    assert health["persistent_count"] == 1
    assert health["persistent_by_cause"] == {"malformed_index": 1}
    assert health["recovered_in_a_count"] == 1
    assert health["recovered_in_a_by_cause"] == {"timeout": 1}
    assert health["new_in_a_count"] == 0
    assert health["changed_count"] == 0
    assert health["transitions"][0]["classification"] == "recovered_in_a"
    assert health["transitions"][0]["host"]["a"]["preferred_name"] == "recovered"
    assert outcome.data["collection_incidents"] == []

    rendered = render_diff(config, outcome, json_output=False, json_indent=2, summary_only=True)
    assert "Management-address collection health" in rendered
    assert "malformed_index=1" in rendered
    assert "timeout=1" in rendered


def test_macro_diff_reports_topology_health_gap_without_claiming_diff_dependency(
    tmp_path: Path,
) -> None:
    """A stable failed table remains health-visible without qualifying a change."""

    a_host = _host(1, "switch", address="192.0.2.1", serial="SW")
    b_host = _host(10, "switch", address="192.0.2.1", serial="SW")
    for host in (a_host, b_host):
        _set_schema8_lldp_coverage(
            host,
            aggregate="partial",
            remote_neighbor="timeout",
        )
        coverage = host["snmp"]["collection_coverage"]["lldp"]
        coverage["subtables"]["remote_neighbor"]["message"] = (
            "remote-neighbor walk timeout"
        )

    a_path = _write_run(
        tmp_path,
        "a",
        "2026-09-01T02:00:00-04:00",
        [a_host],
    )
    b_path = _write_run(
        tmp_path,
        "b",
        "2026-09-01T01:00:00-04:00",
        [b_host],
    )
    config = _config(tmp_path)
    source_a, source_b = resolve_diff_sources(
        config,
        [DiffSourceSpec("file", str(a_path)), DiffSourceSpec("file", str(b_path))],
    )

    outcome = macro_diff(config, source_a, source_b, changes_only=False)

    incidents = outcome.data["collection_incidents"]
    assert len(incidents) == 2
    assert {item["missing_side"] for item in incidents} == {"a", "b"}
    assert {item["table"] for item in incidents} == {"lldp.remote_neighbor"}
    assert all(
        item["reported_difference_depends_on_gap"] is False
        for item in incidents
    )
    incident_summary = outcome.data["summary"]["collection_incidents"]
    assert incident_summary["reported_difference_dependent_incident_count"] == 0
    assert incident_summary["health_only_incident_count"] == 2
    assert incident_summary["topology_gap_observer_count"] == {"a": 1, "b": 1}
    assert any(
        "no reported difference depends on those gaps" in warning
        for warning in outcome.warnings
    )

    rendered = render_diff(config, outcome, json_output=False, json_indent=2, summary_only=True)
    assert "Collection incidents" in rendered
    assert "Affects diff" in rendered
    assert "lldp.remote_neighbor" in rendered
