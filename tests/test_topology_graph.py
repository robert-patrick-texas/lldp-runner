"""Claims-driven graph materialization and many-to-many correspondence tests."""

from __future__ import annotations

import json
from copy import deepcopy

from lldp_runner.models import NeighborObservation
from lldp_runner.topology_graph import (
    build_topology_graph,
    canonical_raw_advertisements,
)
from lldp_runner.topology_graph_diff import compare_topology_graphs


def _host(
    host_id: int,
    name: str,
    target: str | None,
    *,
    serial: str | None = None,
    engine: str | None = None,
) -> dict[str, object]:
    return {
        "id": host_id,
        "preferred_name": name,
        "snmp_sysname": name.split(".", 1)[0],
        "classification": "managed_device",
        "query_target": target,
        "system_json": json.dumps(
            {
                "sys_name": name.split(".", 1)[0],
                "serial_number": serial,
                "snmp_engine_id": engine,
            }
        ),
        "state": "COMPLETE",
        "collection_coverage_json": "{}",
    }


def _neighbor(
    protocol: str,
    local: str,
    remote: str,
    remote_port: str,
    *,
    address: str | None = None,
) -> NeighborObservation:
    return NeighborObservation(
        protocol=protocol,
        local_interface=local,
        local_interface_raw=local,
        remote_name=remote,
        remote_interface=remote_port,
        remote_interface_raw=remote_port,
        remote_addresses=[address] if address else [],
        details={"protocols": [protocol]},
    )


def _neighbor_with_namespace(
    protocol: str,
    local: str,
    remote: str,
    remote_port: str,
    *,
    namespace: str,
) -> NeighborObservation:
    observation = _neighbor(protocol, local, remote, remote_port)
    observation.details = {
        "protocols": [protocol],
        "local_interface_namespace": namespace,
        "local_interface_resolved": True,
    }
    return observation


def _build(hosts, advertisements, *, coverage_by_host=None):
    names = {int(host["id"]): [str(host["preferred_name"])] for host in hosts}
    addresses = {
        int(host["id"]): [str(host["query_target"])]
        for host in hosts
        if host.get("query_target")
    }
    return build_topology_graph(
        hosts=hosts,
        names_by_host=names,
        addresses_by_host=addresses,
        raw_advertisements=advertisements,
        coverage_by_host=coverage_by_host,
    ).document


def _table_coverage(
    *,
    lldp: str = "complete",
    cdp: str = "complete",
    lldpv2: str = "complete",
) -> dict[str, dict[str, object]]:
    """Build the graph-facing table coverage used by comparison fixtures."""

    return {
        protocol: {
            "status": status,
            "attempts": 1,
            "row_count": 0,
            "resolution_status": (
                "resolved" if status == "complete" else "unresolved"
            ),
            "message": (
                None
                if status == "complete"
                else f"{protocol} fixture collection {status}"
            ),
        }
        for protocol, status in {
            "lldp": lldp,
            "lldpv2": lldpv2,
            "cdp": cdp,
        }.items()
    }


def test_raw_advertisement_occurrences_are_order_independent_and_count_duplicates():
    first = _neighbor("lldp", "Gi1/0/1", "edge-a", "Gi0")
    second = _neighbor("cdp", "Gi1/0/2", "edge-b", "Gi0")
    forward = canonical_raw_advertisements(7, [first, second, first])
    reverse = canonical_raw_advertisements(7, [first, second, first][::-1])

    assert forward == reverse
    duplicates = [
        item for item in forward if item["observation"]["remote_name"] == "edge-a"
    ]
    assert [item["duplicate_ordinal"] for item in duplicates] == [0, 1]
    assert len({item["occurrence_fingerprint"] for item in duplicates}) == 2


def test_same_agent_duplicate_projections_are_absorbed_but_vdcs_remain_distinct():
    hosts = [
        _host(1, "hq-vdc1-7nx1.example.com", "203.0.113.23", serial="SERIAL000001"),
        _host(2, "hq-vdc1-7nx1", "203.0.113.23", serial="SERIAL000001"),
        _host(3, "hq-vdc3-7nx1.example.com", "203.0.113.22", serial="SERIAL000001"),
        _host(4, "hq-vdc2-7nx1.example.com", "203.0.113.21", serial="SERIAL000001"),
        _host(5, "hq-vdc2-7nx1", "203.0.113.24", serial="SERIAL000001"),
    ]
    graph = _build(hosts, [])
    logical = [item for item in graph["entities"] if item["entity_type"] == "logical_system"]
    physical = [item for item in graph["entities"] if item["entity_type"] == "physical_chassis"]

    assert len(logical) == 3
    vdc1 = next(item for item in logical if set(item["host_refs"]) == {1, 2})
    vdc2 = next(item for item in logical if set(item["host_refs"]) == {4, 5})
    assert vdc1["projection_status"] == "duplicate_projection"
    assert vdc2["projection_status"] == "duplicate_projection"
    assert {tuple(item["host_refs"]) for item in logical} >= {(3,)}
    assert vdc2["identity"]["query_targets"] == ["203.0.113.21", "203.0.113.24"]
    assert len(physical) == 1
    members = [
        item
        for item in graph["memberships"]
        if item["parent_entity_key"] == physical[0]["entity_key"]
    ]
    assert len(members) == 3


def test_duplicate_source_projections_get_unique_stable_advertisement_keys():
    """Duplicate compatibility hosts retain multiplicity without key collision."""

    observation = _neighbor("lldp", "Eth1/1", "peer.example.com", "Eth1/2")
    first_hosts = [
        _host(1, "hq-vdc1-7nx1.example.com", "203.0.113.23", serial="SERIAL000001"),
        _host(2, "hq-vdc1-7nx1", "203.0.113.23", serial="SERIAL000001"),
    ]
    second_hosts = [
        _host(101, "hq-vdc1-7nx1.example.com", "203.0.113.23", serial="SERIAL000001"),
        _host(202, "hq-vdc1-7nx1", "203.0.113.23", serial="SERIAL000001"),
    ]
    first = _build(
        first_hosts,
        [
            *canonical_raw_advertisements(1, [observation]),
            *canonical_raw_advertisements(2, [observation]),
        ],
    )
    second = _build(
        second_hosts,
        [
            *canonical_raw_advertisements(101, [observation]),
            *canonical_raw_advertisements(202, [observation]),
        ],
    )

    first_keys = [item["advertisement_key"] for item in first["advertisements"]]
    second_keys = [item["advertisement_key"] for item in second["advertisements"]]
    assert len(first_keys) == len(set(first_keys)) == 2
    assert first["summary"]["unique_advertisement_keys"] == 2
    assert first_keys == second_keys
    assert [item["duplicate_ordinal"] for item in first["advertisements"]] == [0, 1]


def test_multi_neighbor_interface_is_reported_without_directness_inference():
    hosts = [
        _host(1, "router.example.com", "192.0.2.1", serial="ROUTER1"),
        _host(2, "juniper.example.com", "192.0.2.2", serial="JUNIPER1"),
        _host(3, "nexus-a.example.com", "192.0.2.3", serial="NEXUSA"),
        _host(4, "nexus-b.example.com", "192.0.2.4", serial="NEXUSB"),
    ]
    rows = canonical_raw_advertisements(
        1,
        [
            _neighbor_with_namespace(
                "lldp",
                "Gi0/0/3",
                "juniper.example.com",
                "ge-0/0/0",
                namespace="lldpLocalPort",
            ),
            _neighbor_with_namespace(
                "cdp",
                "Gi0/0/3",
                "nexus-a.example.com",
                "mgmt0",
                namespace="ifIndex",
            ),
            _neighbor_with_namespace(
                "cdp",
                "Gi0/0/3",
                "nexus-b.example.com",
                "mgmt0",
                namespace="ifIndex",
            ),
        ],
    )
    graph = _build(hosts, rows)
    group = next(
        item for item in graph["relationship_groups"] if item["local_interface"] == "Gi0/0/3"
    )

    assert group["classification"] == "multiple_neighbor_observations"
    assert group["directness"] == "unresolved"
    assert group["relationship_scope"] == "observed"
    assert group["unique_member_count"] == 3
    assert group["discrepancies"] == ["multiple_neighbors_on_interface"]
    interface = next(
        item
        for item in graph["interfaces"]
        if item["interface_key"] == group["interface_key"]
    )
    assert interface["namespace"] == "resolved"
    assert interface["evidence_namespaces"] == ["ifIndex", "lldpLocalPort"]


def test_graph_diff_reports_duplicate_absorption_without_physical_topology_effect():
    hosts_a = [
        _host(1, "hq-vdc1-7nx1.example.com", "203.0.113.23", serial="SERIAL000001"),
        _host(2, "hq-vdc1-7nx1", "203.0.113.23", serial="SERIAL000001"),
    ]
    hosts_b = [
        _host(9, "hq-vdc1-7nx1.example.com", "203.0.113.23", serial="SERIAL000001")
    ]
    result = compare_topology_graphs(_build(hosts_a, []), _build(hosts_b, []))

    logical = [
        item
        for item in result["entity_correspondence"]
        if item["a_entities"]
        and item["a_entities"][0]["entity_type"] == "logical_system"
    ]
    assert len(logical) == 1
    assert logical[0]["status"] == "duplicate_projection_introduced"
    assert logical[0]["physical_topology_effect"] == "none"


def test_graph_diff_retains_one_to_many_cluster_correspondence():
    graph_a = _build(
        [_host(1, "vdc", "192.0.2.10", serial="CHASSIS0")], []
    )
    graph_b = _build(
        [
            _host(2, "vdc", "192.0.2.10", serial="CHASSIS1"),
            _host(3, "vdc", "192.0.2.11", serial="CHASSIS2"),
        ],
        [],
    )
    result = compare_topology_graphs(graph_a, graph_b)
    merged = [item for item in result["entity_correspondence"] if item["status"] == "cluster_merge"]

    assert len(merged) == 1
    assert merged[0]["cardinality"] == "1:2"
    assert merged[0]["physical_topology_effect"] == "not_inferred"


def test_graph_diff_reports_current_many_projection_as_cluster_split():
    graph_a = _build(
        [
            _host(2, "vdc", "192.0.2.10", serial="CHASSIS1"),
            _host(3, "vdc", "192.0.2.11", serial="CHASSIS2"),
        ],
        [],
    )
    graph_b = _build(
        [_host(1, "vdc", "192.0.2.10", serial="CHASSIS0")], []
    )

    result = compare_topology_graphs(graph_a, graph_b)
    split = [
        item
        for item in result["entity_correspondence"]
        if item["status"] == "cluster_split"
    ]

    assert len(split) == 1
    assert split[0]["cardinality"] == "2:1"
    assert split[0]["physical_topology_effect"] == "not_inferred"


def test_graph_diff_separates_projection_changes_from_observed_relationships():
    graph_a = _build(
        [
            _host(1, "device.example.com", "192.0.2.10", serial="SERIAL1"),
            _host(2, "device.example.com", "192.0.2.10", serial="SERIAL1"),
        ],
        [],
    )
    graph_b = _build(
        [_host(9, "device.example.com", "192.0.2.10", serial="SERIAL1")], []
    )

    result = compare_topology_graphs(graph_a, graph_b)

    assert result["has_differences"] is True
    assert result["has_resolution_differences"] is True
    assert result["has_observed_relationship_differences"] is False
    assert result["physical_topology_assessment"] == "no_change_indicated"


def test_graph_projection_is_stable_when_raw_row_order_changes():
    hosts = [
        _host(1, "source.example.com", "192.0.2.1", serial="SRC"),
        _host(2, "a.example.com", "192.0.2.2", serial="A"),
        _host(3, "b.example.com", "192.0.2.3", serial="B"),
    ]
    observations = [
        _neighbor("lldp", "Gi1", "a.example.com", "Gi0"),
        _neighbor("cdp", "Gi2", "b.example.com", "Gi0"),
    ]
    first = _build(hosts, canonical_raw_advertisements(1, observations))
    second = _build(hosts, canonical_raw_advertisements(1, list(reversed(observations))))

    assert first == second
    assert first["projection_fingerprint"] == second["projection_fingerprint"]


def test_local_chassis_label_is_displayed_without_becoming_global_identity():
    hosts = [_host(1, "switch.example.com", "192.0.2.1", serial="SWITCH1")]
    endpoint = NeighborObservation(
        protocol="lldp",
        local_interface="Gi0/1",
        local_interface_raw="Gi0/1",
        remote_name=None,
        remote_interface="c4:5a:b1:f2:d4:3e",
        remote_interface_raw="c4:5a:b1:f2:d4:3e",
        chassis_id="workstation-01",
        chassis_id_subtype="local",
        chassis_id_subtype_id=7,
        details={
            "protocols": ["lldp"],
            "port_id": "c4:5a:b1:f2:d4:3e",
            "port_id_subtype": "mac_address",
            "port_id_subtype_id": 3,
        },
    )

    graph = _build(hosts, canonical_raw_advertisements(1, [endpoint]))
    observed = next(
        item for item in graph["entities"] if item["entity_type"] == "observed_system"
    )
    relationship = graph["relationships"][0]

    assert observed["entity_key"] == "endpoint:mac:c4:5a:b1:f2:d4:3e"
    assert observed["display_name"] == "workstation-01"
    assert observed["identity"]["names"] == []
    assert observed["identity"]["strict_macs"] == ["c4:5a:b1:f2:d4:3e"]
    assert relationship["remote_name"] == "workstation-01"


def test_graph_warns_when_legacy_compatibility_host_spans_endpoint_macs():
    """A legacy flat-host aggregate is diagnosed without changing graph entities."""

    hosts = [_host(1, "switch.example.com", "192.0.2.1", serial="SWITCH1")]

    def endpoint(local_interface: str, mac: str) -> NeighborObservation:
        return NeighborObservation(
            protocol="lldp",
            local_interface=local_interface,
            local_interface_raw=local_interface,
            remote_name=None,
            remote_interface=mac,
            remote_interface_raw=mac,
            chassis_id="hex:a1:00:00:00:00:00",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            details={
                "protocols": ["lldp"],
                "port_id": mac,
                "port_id_subtype": "mac_address",
                "port_id_subtype_id": 3,
            },
        )

    raw = canonical_raw_advertisements(
        1,
        [
            endpoint("Gi0/1", "10:98:19:4d:2f:97"),
            endpoint("Gi0/2", "08:92:04:f6:d6:f4"),
        ],
    )
    legacy_projection = []
    for record in raw:
        projected = dict(record)
        projected["remote_host_id"] = 900
        legacy_projection.append(projected)

    result = build_topology_graph(
        hosts=hosts,
        names_by_host={1: ["switch.example.com"]},
        addresses_by_host={1: ["192.0.2.1"]},
        raw_advertisements=raw,
        compatibility_projection_advertisements=legacy_projection,
    )
    diagnostics = result.document["compatibility_projection_diagnostics"]

    assert result.document["summary"]["compatibility_projection_diagnostics"] == 1
    assert len(diagnostics) == 1
    assert diagnostics[0]["compatibility_host_ref"] == 900
    assert diagnostics[0]["endpoint_macs"] == [
        "08:92:04:f6:d6:f4",
        "10:98:19:4d:2f:97",
    ]
    assert diagnostics[0]["graph_entity_keys"] == [
        "endpoint:mac:08:92:04:f6:d6:f4",
        "endpoint:mac:10:98:19:4d:2f:97",
    ]
    assert diagnostics[0]["authoritative_graph_impact"] == "none"
    decision = next(
        item
        for item in result.decisions
        if item["component_key"] == "compatibility_host:900"
    )
    assert decision["decision_type"] == (
        "compatibility_host_spans_distinct_endpoint_macs"
    )


def test_graph_does_not_warn_for_named_multi_interface_port_macs():
    """Per-interface MACs on one named system are not an aggregate warning."""

    hosts = [_host(1, "switch.example.com", "192.0.2.1", serial="SWITCH1")]

    def endpoint(local_interface: str, mac: str) -> NeighborObservation:
        return NeighborObservation(
            protocol="lldp",
            local_interface=local_interface,
            local_interface_raw=local_interface,
            remote_name="named-appliance.example.com",
            remote_interface=mac,
            remote_interface_raw=mac,
            chassis_id="shared-local-label",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
            details={
                "protocols": ["lldp"],
                "port_id": mac,
                "port_id_subtype": "mac_address",
                "port_id_subtype_id": 3,
            },
        )

    raw = canonical_raw_advertisements(
        1,
        [
            endpoint("Gi0/1", "e0:9d:73:5e:19:ac"),
            endpoint("Gi0/2", "e0:9d:73:5e:19:ad"),
        ],
    )
    legacy_projection = [{**record, "remote_host_id": 900} for record in raw]

    graph = build_topology_graph(
        hosts=hosts,
        names_by_host={1: ["switch.example.com"]},
        addresses_by_host={1: ["192.0.2.1"]},
        raw_advertisements=raw,
        compatibility_projection_advertisements=legacy_projection,
    ).document

    assert graph["summary"]["compatibility_projection_diagnostics"] == 0
    assert graph["compatibility_projection_diagnostics"] == []


def test_semantic_graph_ids_survive_run_local_ids_routes_and_volatile_indexes():
    """Equivalent evidence keeps graph IDs when route and table indexes change."""

    source_a = _host(
        1,
        "hq-vdc2-7nx1.example.com",
        "203.0.113.21",
        serial="SERIAL000001",
        engine="800000090300001122334455",
    )
    remote_a = _host(2, "peer.example.com", "192.0.2.2", serial="PEER1")
    source_b = _host(
        91,
        "hq-vdc2-7nx1.example.com",
        "203.0.113.24",
        serial="SERIAL000001",
        engine="800000090300001122334455",
    )
    remote_b = _host(92, "peer.example.com", "192.0.2.2", serial="PEER1")

    def raw(source_id: int, target: str, time_mark: int) -> list[dict[str, object]]:
        observation = _neighbor("lldp", "mgmt0", "peer.example.com", "mgmt0")
        observation.details = {
            "protocols": ["lldp"],
            "time_mark": time_mark,
            "remote_index": time_mark + 1,
            "port_id": "00:11:22:33:44:55",
            "port_id_subtype": "mac_address",
            "port_id_subtype_id": 3,
        }
        record = canonical_raw_advertisements(source_id, [observation])[0]
        record["source_context"] = {
            "query_target": target,
            "snmp_sysname": "hq-vdc2-7nx1",
            "system": {
                "sys_name": "hq-vdc2-7nx1",
                "serial_number": "SERIAL000001",
                "snmp_engine_id": "800000090300001122334455",
            },
            "credential_route": {"profile": "site-a" if source_id == 1 else "site-b"},
        }
        return [record]

    first = build_topology_graph(
        hosts=[source_a, remote_a],
        names_by_host={
            1: ["hq-vdc2-7nx1", "hq-vdc2-7nx1.example.com"],
            2: ["peer.example.com"],
        },
        addresses_by_host={
            1: ["203.0.113.21", "203.0.113.24"],
            2: ["192.0.2.2"],
        },
        raw_advertisements=raw(1, "203.0.113.21", 100),
    ).document
    second = build_topology_graph(
        hosts=[source_b, remote_b],
        names_by_host={
            91: ["hq-vdc2-7nx1", "hq-vdc2-7nx1.example.com"],
            92: ["peer.example.com"],
        },
        addresses_by_host={
            91: ["203.0.113.24", "203.0.113.21"],
            92: ["192.0.2.2"],
        },
        raw_advertisements=raw(91, "203.0.113.24", 900),
    ).document

    assert {item["entity_key"] for item in first["entities"]} == {
        item["entity_key"] for item in second["entities"]
    }
    assert [item["advertisement_key"] for item in first["advertisements"]] == [
        item["advertisement_key"] for item in second["advertisements"]
    ]
    assert [item["relationship_key"] for item in first["relationships"]] == [
        item["relationship_key"] for item in second["relationships"]
    ]
    assert [item["group_key"] for item in first["relationship_groups"]] == [
        item["group_key"] for item in second["relationship_groups"]
    ]
    assert first["projection_fingerprint"] == second["projection_fingerprint"]


def test_graph_diff_retains_many_to_many_reassociation():
    """A 2:2 component remains explicit instead of forcing arbitrary pairs."""

    graph_a = _build(
        [
            _host(1, "shared", "192.0.2.1", serial="A1"),
            _host(2, "shared", "192.0.2.2", serial="A2"),
        ],
        [],
    )
    graph_b = _build(
        [
            _host(11, "shared", "192.0.2.11", serial="B1"),
            _host(12, "shared", "192.0.2.12", serial="B2"),
        ],
        [],
    )

    result = compare_topology_graphs(graph_a, graph_b)
    reassociated = [
        item
        for item in result["entity_correspondence"]
        if item["status"] == "cluster_reassociated"
        and item["a_entities"]
        and item["a_entities"][0]["entity_type"] == "logical_system"
    ]
    assert len(reassociated) == 1
    assert reassociated[0]["cardinality"] == "2:2"
    assert reassociated[0]["physical_topology_effect"] == "not_inferred"


def test_malformed_advertisement_is_explicitly_accounted_for():
    """Invalid evidence is excluded with a reason instead of disappearing."""

    graph = build_topology_graph(
        hosts=[_host(1, "source", "192.0.2.1", serial="SRC")],
        names_by_host={1: ["source"]},
        addresses_by_host={1: ["192.0.2.1"]},
        raw_advertisements=[{"source_host_id": 1, "protocol": "lldp"}],
    ).document

    assert graph["summary"]["input_advertisements"] == 1
    assert graph["summary"]["raw_advertisements"] == 0
    assert graph["summary"]["excluded_advertisements"] == 1
    assert graph["summary"]["unaccounted_advertisements"] == 0
    assert graph["advertisement_exclusions"][0]["reason"] == "observation_payload_invalid"


def test_graph_diff_reconciles_unique_resolved_and_typed_unresolved_lldp_port():
    """Port-name degradation remains presentation-only for one corroborated edge."""

    hosts_a = [
        _host(1, "source.example.com", "192.0.2.1", serial="SRC"),
        _host(2, "phone.example.com", "192.0.2.2", serial="PHONE"),
    ]
    hosts_b = [
        _host(10, "source.example.com", "192.0.2.1", serial="SRC"),
        _host(20, "phone.example.com", "192.0.2.2", serial="PHONE"),
    ]
    resolved = _neighbor("lldp", "1/1/1", "phone.example.com", "SEP000000000001:P1")
    resolved.details = {
        "protocols": ["lldp"],
        "local_port_num": 1,
        "local_interface_namespace": "lldpLocalPort",
        "local_interface_resolved": True,
    }
    unresolved = _neighbor(
        "lldp",
        "lldpLocalPort:1",
        "phone.example.com",
        "SEP000000000001:P1",
    )
    unresolved.details = {
        "protocols": ["lldp"],
        "local_port_num": 1,
        "local_interface_namespace": "lldpLocalPort",
        "local_interface_resolved": False,
    }
    graph_a = _build(hosts_a, canonical_raw_advertisements(1, [resolved]))
    graph_b = _build(hosts_b, canonical_raw_advertisements(10, [unresolved]))

    result = compare_topology_graphs(graph_a, graph_b, changes_only=True)

    relationship = next(
        item
        for item in result["relationship_groups"]
        if item["source_correspondence_key"].startswith("correspondence:")
    )
    assert relationship["status"] == "same"
    assert relationship["semantic_qualification"] == "presentation_only"
    assert relationship["physical_topology_effect"] == "none"
    assert relationship["port_resolution"]["degraded_side"] == "b"
    assert relationship["port_resolution"]["typed_local_port"] == "lldpLocalPort:1"
    assert result["has_observed_relationship_differences"] is False


def test_graph_diff_marks_failed_observer_table_as_coverage_uncertain():
    """One failed LLDP table qualifies both the edge and remote entity."""

    hosts_a = [_host(1, "source.example.com", "192.0.2.1", serial="SRC")]
    hosts_b = [_host(10, "source.example.com", "192.0.2.1", serial="SRC")]
    observation = _neighbor(
        "lldp", "Gi1/0/1", "endpoint.example.com", "eth0", address="192.0.2.2"
    )
    graph_a = _build(
        hosts_a,
        canonical_raw_advertisements(1, [observation]),
        coverage_by_host={1: _table_coverage()},
    )
    graph_b = _build(
        hosts_b,
        [],
        coverage_by_host={10: _table_coverage(lldp="structurally_invalid")},
    )

    result = compare_topology_graphs(graph_a, graph_b)

    relationship = next(
        item for item in result["relationship_groups"] if item["status"] == "a_only"
    )
    endpoint = next(
        item
        for item in result["entity_correspondence"]
        if item["status"] == "a_only"
        and any(
            entity["display_name"] == "endpoint.example.com"
            for entity in item["a_entities"]
        )
    )
    assert relationship["semantic_qualification"] == "coverage_uncertain"
    assert relationship["presence_confidence"] == "coverage_uncertain"
    assert relationship["coverage_source"]["protocol"] == "lldp"
    assert relationship["coverage_source"]["status"] == "structurally_invalid"
    assert endpoint["semantic_qualification"] == "coverage_uncertain"
    assert endpoint["coverage_source"]["incident_key"] == relationship[
        "coverage_source"
    ]["incident_key"]
    assert result["has_confirmed_observed_relationship_differences"] is False
    assert result["physical_topology_assessment"] == "not_inferred"


def test_graph_diff_keeps_genuine_absence_confirmed_with_complete_coverage():
    """A complete corresponding LLDP table is an authoritative negative."""

    hosts_a = [_host(1, "source.example.com", "192.0.2.1", serial="SRC")]
    hosts_b = [_host(10, "source.example.com", "192.0.2.1", serial="SRC")]
    observation = _neighbor("lldp", "Gi1/0/1", "endpoint", "eth0")
    graph_a = _build(
        hosts_a,
        canonical_raw_advertisements(1, [observation]),
        coverage_by_host={1: _table_coverage()},
    )
    graph_b = _build(
        hosts_b,
        [],
        coverage_by_host={10: _table_coverage()},
    )

    result = compare_topology_graphs(graph_a, graph_b)
    relationship = next(
        item for item in result["relationship_groups"] if item["status"] == "a_only"
    )
    endpoint = next(
        item
        for item in result["entity_correspondence"]
        if item["status"] == "a_only"
    )

    assert relationship["semantic_qualification"] == "confirmed"
    assert relationship["coverage_sources"] == []
    assert endpoint["semantic_qualification"] == "confirmed"
    assert result["has_confirmed_observed_relationship_differences"] is True


def test_graph_diff_protocol_transition_is_confirmed_when_collectors_completed():
    """CDP loss with retained LLDP changes evidence, not asserted topology."""

    hosts_a = [_host(1, "source.example.com", "192.0.2.1", serial="SRC")]
    hosts_b = [_host(10, "source.example.com", "192.0.2.1", serial="SRC")]
    lldp = _neighbor("lldp", "Hu1/0/21", "peer.example.com", "Ethernet1")
    cdp = _neighbor("cdp", "Hu1/0/21", "peer.example.com", "Ethernet1")
    graph_a = _build(
        hosts_a,
        canonical_raw_advertisements(1, [lldp]),
        coverage_by_host={1: _table_coverage()},
    )
    graph_b = _build(
        hosts_b,
        canonical_raw_advertisements(10, [lldp, cdp]),
        coverage_by_host={10: _table_coverage()},
    )

    result = compare_topology_graphs(graph_a, graph_b)
    relationship = next(
        item
        for item in result["relationship_groups"]
        if item["status"] == "protocol_evidence_changed"
    )

    assert relationship["semantic_qualification"] == "confirmed"
    assert relationship["physical_topology_effect"] == "none"
    assert relationship["coverage_sources"] == []
    assert relationship["change_dimensions"] == ["protocol_evidence"]
    assert relationship["member_presence_change"] is None
    assert relationship["member_protocol_changes"] == [
        {
            "remote_component_key": relationship["a_groups"][0][
                "members"
            ][0]["remote_component_key"],
            "remote_interface": "ethernet1",
            "a_protocols": ["lldp"],
            "b_protocols": ["cdp", "lldp"],
        }
    ]
    assert result["has_observed_relationship_differences"] is False


def test_graph_diff_preserves_protocol_dimension_inside_member_set_change():
    """One relationship record exposes concurrent membership and protocol changes."""

    hosts_a = [_host(1, "source.example.com", "192.0.2.1", serial="SRC")]
    hosts_b = [_host(10, "source.example.com", "192.0.2.1", serial="SRC")]
    phone_lldp = _neighbor(
        "lldp",
        "Gi1/0/6",
        "SEP00123456000F.voice-a.example.com",
        "00123456000F:P1",
        address="192.0.2.20",
    )
    phone_cdp = _neighbor(
        "cdp",
        "Gi1/0/6",
        "SEP00123456000F.voice-a.example.com",
        "00123456000F:P1",
        address="192.0.2.20",
    )
    extra_lldp = _neighbor(
        "lldp",
        "Gi1/0/6",
        "a0:b4:37:00:13:d4",
        "a0:b4:37:00:13:d4",
    )
    graph_a = _build(
        hosts_a,
        canonical_raw_advertisements(1, [phone_lldp, extra_lldp]),
        coverage_by_host={1: _table_coverage()},
    )
    graph_b = _build(
        hosts_b,
        canonical_raw_advertisements(10, [phone_lldp, phone_cdp]),
        coverage_by_host={10: _table_coverage()},
    )

    result = compare_topology_graphs(graph_a, graph_b)
    relationship = next(
        item
        for item in result["relationship_groups"]
        if item["status"] == "member_set_changed"
    )

    assert relationship["change_dimensions"] == [
        "member_presence",
        "protocol_evidence",
    ]
    assert len(relationship["member_presence_change"]["a_only"]) == 1
    assert relationship["member_presence_change"]["b_only"] == []
    phone_component = next(
        member["remote_component_key"]
        for member in relationship["a_groups"][0]["members"]
        if str(member["remote_display_name"]).casefold().startswith("sep00123456000f")
    )
    assert relationship["member_protocol_changes"] == [
        {
            "remote_component_key": phone_component,
            "remote_interface": "00123456000f:p1",
            "a_protocols": ["lldp"],
            "b_protocols": ["cdp", "lldp"],
        }
    ]


def test_graph_diff_protocol_transition_is_uncertain_when_missing_collector_failed():
    """An uncollected CDP table cannot prove that CDP evidence disappeared."""

    hosts_a = [_host(1, "source.example.com", "192.0.2.1", serial="SRC")]
    hosts_b = [_host(10, "source.example.com", "192.0.2.1", serial="SRC")]
    lldp = _neighbor("lldp", "Hu1/0/21", "peer.example.com", "Ethernet1")
    cdp = _neighbor("cdp", "Hu1/0/21", "peer.example.com", "Ethernet1")
    graph_a = _build(
        hosts_a,
        canonical_raw_advertisements(1, [lldp]),
        coverage_by_host={1: _table_coverage(cdp="timeout")},
    )
    graph_b = _build(
        hosts_b,
        canonical_raw_advertisements(10, [lldp, cdp]),
        coverage_by_host={10: _table_coverage()},
    )

    result = compare_topology_graphs(graph_a, graph_b)
    relationship = next(
        item
        for item in result["relationship_groups"]
        if item["status"] == "protocol_evidence_changed"
    )

    assert relationship["semantic_qualification"] == "coverage_uncertain"
    assert relationship["coverage_source"]["protocol"] == "cdp"
    assert relationship["coverage_source"]["missing_side"] == "a"
    assert relationship["physical_topology_effect"] == "none"


def test_graph_diff_propagates_originating_coverage_incident_recursively():
    """A hidden managed observer carries its upstream LLDP incident downstream."""

    hosts_a = [
        _host(1, "root.example.com", "192.0.2.1", serial="ROOT"),
        _host(2, "access.example.com", "192.0.2.2", serial="ACCESS"),
    ]
    hosts_b = [_host(10, "root.example.com", "192.0.2.1", serial="ROOT")]
    root_to_access = _neighbor(
        "lldp",
        "Gi1/0/48",
        "access.example.com",
        "Gi1/0/48",
        address="192.0.2.2",
    )
    access_to_endpoint = _neighbor(
        "lldp", "Gi1/0/1", "endpoint.example.com", "eth0", address="192.0.2.3"
    )
    graph_a = _build(
        hosts_a,
        [
            *canonical_raw_advertisements(1, [root_to_access]),
            *canonical_raw_advertisements(2, [access_to_endpoint]),
        ],
        coverage_by_host={1: _table_coverage(), 2: _table_coverage()},
    )
    graph_b = _build(
        hosts_b,
        [],
        coverage_by_host={10: _table_coverage(lldp="timeout")},
    )

    result = compare_topology_graphs(graph_a, graph_b)
    access_component = next(
        item
        for item in result["entity_correspondence"]
        if item["status"] == "a_only"
        and any(
            entity["display_name"] == "access.example.com"
            for entity in item["a_entities"]
        )
    )
    downstream = next(
        item
        for item in result["relationship_groups"]
        if item["source_correspondence_key"] == access_component["component_key"]
    )
    endpoint = next(
        item
        for item in result["entity_correspondence"]
        if item["status"] == "a_only"
        and any(
            entity["display_name"] == "endpoint.example.com"
            for entity in item["a_entities"]
        )
    )

    assert access_component["semantic_qualification"] == "coverage_uncertain"
    assert downstream["semantic_qualification"] == "coverage_uncertain"
    assert downstream["coverage_source"]["origin"] == "recursive"
    assert access_component["component_key"] in downstream["coverage_source"][
        "recursive_path"
    ]
    assert endpoint["semantic_qualification"] == "coverage_uncertain"
    assert endpoint["coverage_source"]["incident_key"] == access_component[
        "coverage_source"
    ]["incident_key"]


def test_graph_diff_qualifies_failed_observer_relationship_and_entity_presence():
    """A failed paired LLDP table cannot prove a graph endpoint is newly present."""

    source_a = _host(1, "source.example.com", "192.0.2.1", serial="SRC")
    endpoint_a = _host(2, "phone.example.com", "192.0.2.2", serial="PHONE")
    source_b = _host(10, "source.example.com", "192.0.2.1", serial="SRC")
    graph_a = _build(
        [source_a, endpoint_a],
        canonical_raw_advertisements(
            1,
            [_neighbor("lldp", "Gi1/0/1", "phone.example.com", "P1")],
        ),
        coverage_by_host={1: _table_coverage(), 2: _table_coverage()},
    )
    graph_b = _build(
        [source_b],
        [],
        coverage_by_host={
            10: _table_coverage(lldp="structurally_invalid"),
        },
    )

    result = compare_topology_graphs(graph_a, graph_b, changes_only=True)

    relationship = next(
        item for item in result["relationship_groups"] if item["status"] == "a_only"
    )
    assert relationship["semantic_qualification"] == "coverage_uncertain"
    assert relationship["presence_confidence"] == "coverage_uncertain"
    assert relationship["coverage_sources"][0]["protocol"] == "lldp"
    assert relationship["coverage_sources"][0]["status"] == "structurally_invalid"
    endpoint = next(
        item
        for item in result["entity_correspondence"]
        if item["status"] == "a_only"
        and any(
            entity["display_name"] == "phone.example.com"
            for entity in item["a_entities"]
        )
    )
    assert endpoint["semantic_qualification"] == "coverage_uncertain"
    assert result["has_confirmed_observed_relationship_differences"] is False


def test_graph_diff_protocol_transition_uses_collection_coverage():
    """Protocol-set change is confirmed only when the missing collector completed."""

    hosts_a = [
        _host(1, "source.example.com", "192.0.2.1", serial="SRC"),
        _host(2, "peer.example.com", "192.0.2.2", serial="PEER"),
    ]
    hosts_b = [
        _host(10, "source.example.com", "192.0.2.1", serial="SRC"),
        _host(20, "peer.example.com", "192.0.2.2", serial="PEER"),
    ]
    a_observations = canonical_raw_advertisements(
        1, [_neighbor("lldp", "Gi1/0/1", "peer.example.com", "Gi0")]
    )
    b_observations = canonical_raw_advertisements(
        10,
        [
            _neighbor("lldp", "Gi1/0/1", "peer.example.com", "Gi0"),
            _neighbor("cdp", "Gi1/0/1", "peer.example.com", "Gi0"),
        ],
    )
    graph_b = _build(
        hosts_b,
        b_observations,
        coverage_by_host={10: _table_coverage(), 20: _table_coverage()},
    )

    complete_a = _build(
        hosts_a,
        a_observations,
        coverage_by_host={1: _table_coverage(), 2: _table_coverage()},
    )
    confirmed = compare_topology_graphs(complete_a, graph_b, changes_only=True)
    confirmed_row = next(
        item
        for item in confirmed["relationship_groups"]
        if item["status"] == "protocol_evidence_changed"
    )
    assert confirmed_row["semantic_qualification"] == "confirmed"
    assert confirmed_row["physical_topology_effect"] == "none"

    failed_a = _build(
        hosts_a,
        a_observations,
        coverage_by_host={
            1: _table_coverage(cdp="timeout"),
            2: _table_coverage(),
        },
    )
    uncertain = compare_topology_graphs(failed_a, graph_b, changes_only=True)
    uncertain_row = next(
        item
        for item in uncertain["relationship_groups"]
        if item["status"] == "protocol_evidence_changed"
    )
    assert uncertain_row["semantic_qualification"] == "coverage_uncertain"
    assert uncertain_row["coverage_sources"][0]["protocol"] == "cdp"
    assert uncertain_row["physical_topology_effect"] == "none"


def test_graph_diff_recursively_propagates_originating_collection_incident():
    """A hidden managed observer carries one root incident to downstream edges."""

    root_a = _host(1, "root.example.com", "192.0.2.1", serial="ROOT")
    branch_a = _host(2, "branch.example.com", "192.0.2.2", serial="BRANCH")
    phone_a = _host(3, "phone.example.com", "192.0.2.3", serial="PHONE")
    root_b = _host(10, "root.example.com", "192.0.2.1", serial="ROOT")
    graph_a = _build(
        [root_a, branch_a, phone_a],
        [
            *canonical_raw_advertisements(
                1,
                [_neighbor("lldp", "Gi1/0/1", "branch.example.com", "Gi0")],
            ),
            *canonical_raw_advertisements(
                2,
                [_neighbor("lldp", "Gi1/0/2", "phone.example.com", "P1")],
            ),
        ],
        coverage_by_host={
            1: _table_coverage(),
            2: _table_coverage(),
            3: _table_coverage(),
        },
    )
    graph_b = _build(
        [root_b],
        [],
        coverage_by_host={10: _table_coverage(lldp="timeout")},
    )

    result = compare_topology_graphs(graph_a, graph_b, changes_only=True)

    one_sided = [
        item for item in result["relationship_groups"] if item["status"] == "a_only"
    ]
    assert len(one_sided) == 2
    assert {item["semantic_qualification"] for item in one_sided} == {
        "coverage_uncertain"
    }
    assert any(
        source["origin"] == "recursive"
        for item in one_sided
        for source in item["coverage_sources"]
    )
    uncertain_names = {
        entity["display_name"]
        for item in result["entity_correspondence"]
        if item.get("semantic_qualification") == "coverage_uncertain"
        for entity in item["a_entities"]
    }
    assert {"branch.example.com", "phone.example.com"} <= uncertain_names


def test_graph_diff_weak_mac_cross_port_change_is_ambiguous_candidate_move() -> None:
    """A low-entropy MAC cannot prove endpoint or cable movement."""

    def weak_observation(local_interface: str) -> NeighborObservation:
        return NeighborObservation(
            protocol="lldp",
            local_interface=local_interface,
            local_interface_raw=local_interface,
            remote_name=None,
            remote_interface="00:00:00:00:01:03",
            remote_interface_raw="00:00:00:00:01:03",
            chassis_id="00:00:00:00:01:03",
            chassis_id_subtype="mac_address",
            chassis_id_subtype_id=4,
            details={"protocols": ["lldp"]},
        )

    a_host = _host(1, "source.example.com", "192.0.2.1", serial="SRC")
    b_host = _host(10, "source.example.com", "192.0.2.1", serial="SRC")
    a_graph = _build(
        [a_host],
        canonical_raw_advertisements(1, [weak_observation("Te4/0/47")]),
    )
    b_graph = _build(
        [b_host],
        canonical_raw_advertisements(10, [weak_observation("Te3/0/48")]),
    )

    result = compare_topology_graphs(a_graph, b_graph, changes_only=True)

    assert result["summary"]["relationship_groups"] == {"candidate_move": 1}
    assert result["summary"]["relationship_qualifications"] == {"ambiguous": 1}
    assert result["has_confirmed_observed_relationship_differences"] is False
    assert len(result["relationship_groups"]) == 1
    relationship = result["relationship_groups"][0]
    assert relationship["status"] == "candidate_move"
    assert relationship["semantic_qualification"] == "ambiguous"
    assert relationship["presence_confidence"] == "ambiguous"
    assert relationship["mobility"]["identity_strength"] == "weak"
    assert relationship["physical_topology_effect"] == "not_inferred"


def test_graph_diff_qualifies_attribute_derived_components_with_provenance() -> None:
    """A missing collected identity field cannot become confirmed graph churn."""

    graph_a = _build(
        [_host(1, "device.example", "192.0.2.1", serial="SER1")],
        [],
    )
    graph_b = _build(
        [_host(10, "device.example", "192.0.2.1", serial=None)],
        [],
    )
    source = {
        "incident_key": "coverage:test",
        "missing_side": "b",
        "observer": {
            "a": {"id": 20, "preferred_name": "observer"},
            "b": {"id": 200, "preferred_name": "observer"},
        },
        "protocol": "lldp",
        "table": "lldp.remote_neighbor",
        "status": "incomplete_table",
        "message": "fixture",
        "origin": "direct",
        "recursive_path": [],
        "attribute_path": "chassis_id",
        "attribute_provenance": "neighbor_observation",
    }

    result = compare_topology_graphs(
        graph_a,
        graph_b,
        changes_only=True,
        a_attribute_uncertainty={1: [source]},
        b_attribute_uncertainty={10: [source]},
    )

    affected = [
        item
        for item in result["entity_correspondence"]
        if item["status"] in {"changed", "a_only", "b_only"}
    ]
    assert affected
    assert all(
        item["semantic_qualification"] == "coverage_uncertain"
        for item in affected
    )
    assert all(item["coverage_sources"] == [source] for item in affected)
    assert result["summary"]["entity_qualifications"]["coverage_uncertain"] == len(
        affected
    )


def test_graph_diff_uses_remote_neighbor_subtable_not_aggregate_lldp_health():
    """A management-only LLDP partial does not weaken a complete edge snapshot."""

    source_a = _host(1, "source.example.com", "192.0.2.1", serial="SRC")
    endpoint_a = _host(2, "phone.example.com", "192.0.2.2", serial="PHONE")
    source_b = _host(10, "source.example.com", "192.0.2.1", serial="SRC")
    graph_a = _build(
        [source_a, endpoint_a],
        canonical_raw_advertisements(
            1,
            [_neighbor("lldp", "Gi1/0/1", "phone.example.com", "P1")],
        ),
        coverage_by_host={1: _table_coverage(), 2: _table_coverage()},
    )
    coverage = _table_coverage()
    coverage["lldp"] = {
        "status": "partial",
        "attempts": 1,
        "row_count": 0,
        "resolution_status": "partial",
        "message": "remote management address was partial",
        "subtables": {
            "remote_neighbor": {
                "status": "complete",
                "attempts": 1,
                "row_count": 0,
                "resolution_status": "resolved",
                "message": None,
            },
            "remote_management_address": {
                "status": "partial",
                "attempts": 1,
                "row_count": 0,
                "resolution_status": "partial",
                "message": "one malformed management-address index",
            },
        },
    }
    graph_b = _build([source_b], [], coverage_by_host={10: coverage})

    result = compare_topology_graphs(graph_a, graph_b, changes_only=True)

    relationship = next(
        item for item in result["relationship_groups"] if item["status"] == "a_only"
    )
    assert relationship["semantic_qualification"] == "confirmed"
    assert relationship["coverage_sources"] == []


def test_graph_diff_reports_exact_remote_neighbor_subtable_failure():
    """A true LLDP neighbor failure remains uncertain with exact provenance."""

    source_a = _host(1, "source.example.com", "192.0.2.1", serial="SRC")
    endpoint_a = _host(2, "phone.example.com", "192.0.2.2", serial="PHONE")
    source_b = _host(10, "source.example.com", "192.0.2.1", serial="SRC")
    graph_a = _build(
        [source_a, endpoint_a],
        canonical_raw_advertisements(
            1,
            [_neighbor("lldp", "Gi1/0/1", "phone.example.com", "P1")],
        ),
        coverage_by_host={1: _table_coverage(), 2: _table_coverage()},
    )
    coverage = _table_coverage()
    coverage["lldp"] = {
        "status": "timeout",
        "attempts": 2,
        "row_count": None,
        "resolution_status": "unresolved",
        "message": "aggregate LLDP timeout",
        "subtables": {
            "remote_neighbor": {
                "status": "timeout",
                "attempts": 2,
                "row_count": None,
                "resolution_status": "unresolved",
                "message": "remote-neighbor timeout",
            },
            "remote_management_address": {
                "status": "not_attempted",
                "attempts": 0,
                "row_count": None,
                "resolution_status": "not_applicable",
                "message": "remote-neighbor table did not complete",
            },
        },
    }
    graph_b = _build([source_b], [], coverage_by_host={10: coverage})

    result = compare_topology_graphs(graph_a, graph_b, changes_only=True)

    relationship = next(
        item for item in result["relationship_groups"] if item["status"] == "a_only"
    )
    assert relationship["semantic_qualification"] == "coverage_uncertain"
    assert relationship["coverage_sources"][0]["protocol"] == "lldp"
    assert relationship["coverage_sources"][0]["table"] == "lldp.remote_neighbor"
    assert relationship["coverage_sources"][0]["message"] == "remote-neighbor timeout"
