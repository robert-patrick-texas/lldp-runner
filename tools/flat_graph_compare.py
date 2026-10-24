#!/usr/bin/env python3
"""Compare the flat ``hosts[]`` view of a discovery.json with its topology graph.

``discovery.json`` carries two models of one discovery: the flat compatibility
projection (``hosts[]`` with learned and observed-by neighbors) and the
claims-driven ``topology_graph``. This tool derives a flat host list from the
graph alone and reports where the two disagree, to measure how far the graph is
from being able to replace the flat view. It reads the file only; nothing is
written and LLDP-Runner itself is not imported.

Graph systems are ``logical_system`` and ``observed_system`` entities. A logical
system is paired with flat hosts through its ``host_refs``; an observed system is
paired by overlapping names, usable addresses, or MAC addresses. Pairs are grouped,
so a graph system that merges several flat hosts, or a flat host that the graph
splits into several systems, is reported once instead of as unrelated
differences. Neighbor edges are compared between those groups, keyed by local
interface and remote interface, using both the resolved and raw interface names.

The report also counts host data that exists only in the flat view, such as
SYSTEM-MIB details, ICMP results, and the SNMP credential route.

Examples:

    tools/flat_graph_compare.py /opt/lldp-runner/var/outputs/latest
    tools/flat_graph_compare.py outputs/20261024-120000-EDT/discovery.json --details
    tools/flat_graph_compare.py run-a/discovery.json run-b/discovery.json --json

Exit status: 0 when systems, host fields, and neighbors agree; 1 when they
disagree; 2 when an input cannot be read or has an unsupported schema. Host
data that only the flat view carries is counted but is not a disagreement.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SUPPORTED_DISCOVERY_SCHEMA = 8
SUPPORTED_GRAPH_SCHEMA = 2
REPORT_VERSION = 1
SYSTEM_ENTITY_TYPES = ("logical_system", "observed_system")
_MAC_HEX = re.compile(r"^[0-9a-f]{12}$")

# Host fields that only the flat view carries, with the test for "has a value".
FLAT_ONLY_DATA = (
    ("system_details", "SYSTEM-MIB and ENTITY-MIB details (sysDescr, model, version)"),
    ("icmp", "ICMP results"),
    ("snmp_credential_route", "SNMP credential route and result"),
    ("collection_metrics", "SNMP collection metrics and sessions"),
    ("tags", "tags"),
    ("classification_reason", "classification reasons"),
    ("seen_times", "first and last seen times"),
    ("seed_flag", "seed flag"),
    ("observed_classification", "classification of systems that were never queried"),
)


class InputError(Exception):
    """An input file cannot be compared."""


def _casefold_set(values: Iterable[Any]) -> set[str]:
    return {str(value).strip().casefold() for value in values if str(value or "").strip()}


def _usable_addresses(values: Iterable[Any]) -> set[str]:
    """Return normalized addresses that can identify a host."""

    result: set[str] = set()
    for value in values:
        try:
            address = ipaddress.ip_address(str(value).strip())
        except ValueError:
            continue
        if address.is_unspecified or address.is_loopback:
            continue
        result.add(address.compressed)
    return result


def _mac(value: Any) -> str | None:
    text = re.sub(r"[^0-9a-f]", "", str(value or "").casefold())
    return text if _MAC_HEX.match(text) else None


def _interface_names(*values: Any) -> set[str]:
    return _casefold_set(value for value in values if value)


def _flat_addresses(host: Mapping[str, Any]) -> set[str]:
    addresses = host.get("addresses") or {}
    if isinstance(addresses, Mapping):
        return _usable_addresses([*addresses.get("ipv4", []), *addresses.get("ipv6", [])])
    return _usable_addresses(addresses)


def _has_system_details(host: Mapping[str, Any]) -> bool:
    system = host.get("system") or {}
    return isinstance(system, Mapping) and any(
        value not in (None, "", [], {}) for value in system.values()
    )


def _flat_only_values(host: Mapping[str, Any]) -> dict[str, bool]:
    snmp = host.get("snmp") or {}
    credential = any(
        snmp.get(key) not in (None, "")
        for key in (
            "credential_source",
            "credential_profile",
            "credential_label",
            "credential_result",
        )
    )
    return {
        "system_details": _has_system_details(host),
        "icmp": bool(host.get("icmp")),
        "snmp_credential_route": credential,
        "collection_metrics": bool(snmp.get("collection_metrics") or snmp.get("adaptive_sessions")),
        "tags": bool(host.get("tags")),
        "classification_reason": bool(host.get("classification_reason")),
        "seen_times": bool(host.get("first_seen") or host.get("last_seen")),
        "seed_flag": bool(host.get("is_seed")),
    }


@dataclass
class _Group:
    """One system as both views see it: graph entities and flat hosts together."""

    graph_keys: set[str] = field(default_factory=set)
    flat_ids: set[int] = field(default_factory=set)


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, item: str) -> str:
        self.parent.setdefault(item, item)
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: str, right: str) -> None:
        root_left, root_right = self.find(left), self.find(right)
        if root_left != root_right:
            self.parent[max(root_left, root_right)] = min(root_left, root_right)


def load_discovery(path: Path) -> tuple[Path, dict[str, Any]]:
    """Read a discovery.json, given its path or the output directory holding it."""

    if path.is_dir():
        path = path / "discovery.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise InputError(f"{path}: file not found") from exc
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputError(f"{path}: cannot read discovery JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise InputError(f"{path}: discovery JSON root must be an object")
    if payload.get("schema_version") != SUPPORTED_DISCOVERY_SCHEMA:
        raise InputError(
            f"{path}: discovery schema {payload.get('schema_version')!r} is not supported "
            f"(expected {SUPPORTED_DISCOVERY_SCHEMA})"
        )
    graph = payload.get("topology_graph")
    if not isinstance(graph, dict) or graph.get("schema_version") != SUPPORTED_GRAPH_SCHEMA:
        found = graph.get("schema_version") if isinstance(graph, dict) else None
        raise InputError(
            f"{path}: topology graph schema {found!r} is not supported "
            f"(expected {SUPPORTED_GRAPH_SCHEMA})"
        )
    if not isinstance(payload.get("hosts"), list):
        raise InputError(f"{path}: discovery JSON has no hosts array")
    return path, payload


def _flat_label(host: Mapping[str, Any]) -> str:
    return f"{host.get('preferred_name')} (host {host.get('id')})"


def _graph_label(entity: Mapping[str, Any]) -> str:
    return f"{entity.get('display_name')} ({entity.get('entity_type')})"


def _match_observed(
    entity: Mapping[str, Any], flat_hosts: Sequence[Mapping[str, Any]]
) -> list[int]:
    """Return flat hosts whose identity overlaps an observed graph system."""

    identity = entity.get("identity") or {}
    names = _casefold_set(identity.get("names", []))
    if entity.get("display_name"):
        names.add(str(entity["display_name"]).strip().casefold())
    addresses = _usable_addresses(identity.get("addresses", []))
    macs = {mac for mac in (_mac(value) for value in identity.get("strict_macs", [])) if mac}
    matches = []
    for host in flat_hosts:
        host_names = _casefold_set([host.get("preferred_name"), *host.get("names", [])])
        host_mac = _mac(host.get("chassis_id"))
        host_name_macs = {mac for mac in (_mac(name) for name in host_names) if mac}
        if (
            names & host_names
            or addresses & _flat_addresses(host)
            or (host_mac is not None and host_mac in macs)
            or macs & host_name_macs
        ):
            matches.append(int(host["id"]))
    return matches


def _build_groups(
    flat_hosts: Sequence[Mapping[str, Any]], entities: Sequence[Mapping[str, Any]]
) -> tuple[list[_Group], dict[str, int], dict[int, int]]:
    union = _UnionFind()
    flat_ids = {int(host["id"]) for host in flat_hosts}
    for host_id in flat_ids:
        union.find(f"flat:{host_id}")
    for entity in entities:
        key = f"graph:{entity['entity_key']}"
        union.find(key)
        if entity["entity_type"] == "logical_system":
            refs = [int(ref) for ref in entity.get("host_refs", []) if int(ref) in flat_ids]
        else:
            refs = _match_observed(entity, flat_hosts)
        for ref in refs:
            union.union(key, f"flat:{ref}")

    by_root: dict[str, _Group] = defaultdict(_Group)
    for node in list(union.parent):
        group = by_root[union.find(node)]
        kind, _, value = node.partition(":")
        if kind == "flat":
            group.flat_ids.add(int(value))
        else:
            group.graph_keys.add(value)
    groups = sorted(
        by_root.values(),
        key=lambda item: (
            min(item.flat_ids) if item.flat_ids else 1 << 62,
            sorted(item.graph_keys),
        ),
    )
    graph_group = {key: index for index, group in enumerate(groups) for key in group.graph_keys}
    flat_group = {host: index for index, group in enumerate(groups) for host in group.flat_ids}
    return groups, graph_group, flat_group


@dataclass
class _Edge:
    source: int
    remote: int | None
    local_names: set[str]
    remote_names: set[str]
    protocols: tuple[str, ...]
    label: dict[str, Any]


def _flat_edges(
    flat_hosts: Sequence[Mapping[str, Any]], flat_group: Mapping[int, int]
) -> list[_Edge]:
    edges = []
    for host in flat_hosts:
        source = flat_group[int(host["id"])]
        for neighbor in host.get("learned_neighbors", []):
            ref = neighbor.get("host_ref")
            remote = flat_group.get(int(ref)) if ref is not None else None
            edges.append(
                _Edge(
                    source=source,
                    remote=remote,
                    local_names=_interface_names(
                        neighbor.get("local_interface"), neighbor.get("local_interface_raw")
                    ),
                    remote_names=_interface_names(
                        neighbor.get("remote_interface"), neighbor.get("remote_interface_raw")
                    ),
                    protocols=tuple(sorted(_casefold_set(neighbor.get("protocols", [])))),
                    label={
                        "host": _flat_label(host),
                        "local_interface": neighbor.get("local_interface"),
                        "neighbor": neighbor.get("name"),
                        "remote_interface": neighbor.get("remote_interface"),
                        "protocols": list(neighbor.get("protocols", [])),
                    },
                )
            )
    return edges


def _graph_edges(graph: Mapping[str, Any], graph_group: Mapping[str, int]) -> list[_Edge]:
    interfaces = {item["interface_key"]: item for item in graph.get("interfaces", [])}
    names = {item["entity_key"]: item.get("display_name") for item in graph.get("entities", [])}
    edges = []
    for relationship in graph.get("relationships", []):
        source_key = relationship.get("source_entity_key")
        if source_key not in graph_group:
            continue
        interface = interfaces.get(relationship.get("interface_key"), {})
        remote_key = relationship.get("remote_entity_key")
        edges.append(
            _Edge(
                source=graph_group[source_key],
                remote=graph_group.get(remote_key),
                local_names=_interface_names(
                    interface.get("name"), *interface.get("raw_identifiers", [])
                ),
                remote_names=_interface_names(relationship.get("remote_interface")),
                protocols=tuple(sorted(_casefold_set(relationship.get("protocols", [])))),
                label={
                    "system": names.get(source_key),
                    "local_interface": interface.get("name"),
                    "neighbor": names.get(remote_key) or relationship.get("remote_name"),
                    "remote_interface": relationship.get("remote_interface"),
                    "protocols": list(relationship.get("protocols", [])),
                },
            )
        )
    return edges


def _edge_matches(flat: _Edge, graph: _Edge) -> bool:
    if not graph.local_names & flat.local_names:
        return False
    if graph.remote_names or flat.remote_names:
        return bool(graph.remote_names & flat.remote_names)
    return True


def _compare_edges(flat: list[_Edge], graph: list[_Edge]) -> dict[str, Any]:
    """Pair flat neighbor rows with graph relationships between the same systems.

    A flat row that repeats an edge another flat row already matched, as happens
    when the flat view keeps two hosts for one graph system, is counted as a
    duplicate rather than as a neighbor the graph lacks.
    """

    pending: dict[tuple[int, int | None], list[_Edge]] = defaultdict(list)
    used: dict[tuple[int, int | None], list[_Edge]] = defaultdict(list)
    for edge in graph:
        pending[(edge.source, edge.remote)].append(edge)
    matched = 0
    protocols_differ: list[dict[str, Any]] = []
    flat_duplicates: list[dict[str, Any]] = []
    flat_only: list[dict[str, Any]] = []
    for edge in flat:
        key = (edge.source, edge.remote)
        found = next((item for item in pending.get(key, []) if _edge_matches(edge, item)), None)
        if found is None:
            if any(_edge_matches(edge, item) for item in used.get(key, [])):
                flat_duplicates.append(edge.label)
            else:
                flat_only.append(edge.label)
            continue
        pending[key].remove(found)
        used[key].append(found)
        matched += 1
        if found.protocols != edge.protocols:
            protocols_differ.append({"flat": edge.label, "graph": found.label})
    graph_only = [edge.label for edges in pending.values() for edge in edges]
    return {
        "flat_rows": len(flat),
        "graph_relationships": len(graph),
        "matched": matched,
        "protocols_differ": protocols_differ,
        "flat_duplicates": flat_duplicates,
        "flat_only": flat_only,
        "graph_only": graph_only,
    }


def _field_differences(
    host: Mapping[str, Any], entity: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    """Compare one flat host with the one graph system that represents it."""

    identity = entity.get("identity") or {}
    differences: dict[str, dict[str, Any]] = {}

    def record(name: str, flat_value: Any, graph_value: Any) -> None:
        differences[name] = {
            "host": _flat_label(host),
            "system": _graph_label(entity),
            "flat": flat_value,
            "graph": graph_value,
        }

    flat_names = _casefold_set(host.get("names", []))
    graph_names = _casefold_set(identity.get("names", []))
    if flat_names != graph_names:
        record("names", sorted(flat_names), sorted(graph_names))
    flat_addresses = _flat_addresses(host)
    graph_addresses = _usable_addresses(identity.get("addresses", []))
    if flat_addresses != graph_addresses:
        record("addresses", sorted(flat_addresses), sorted(graph_addresses))
    flat_target = _casefold_set([host.get("queried_as")])
    graph_targets = _casefold_set(identity.get("query_targets", []))
    if flat_target != graph_targets:
        record("query_target", sorted(flat_target), sorted(graph_targets))
    if (
        str(host.get("preferred_name") or "").casefold()
        != str(entity.get("display_name") or "").casefold()
    ):
        record("display_name", host.get("preferred_name"), entity.get("display_name"))

    # Observed systems carry no classification; that gap is counted with the
    # other flat-only data rather than as a disagreement.
    classifications = list(entity.get("classifications", []))
    flat_class = host.get("classification")
    if classifications and [flat_class] != classifications:
        record("classification", flat_class, classifications)

    states = [str(value).casefold() for value in entity.get("states", [])]
    flat_state = str(host.get("state") or "").casefold()
    if states:
        if [flat_state] != states:
            record("state", flat_state, states)
    elif entity.get("entity_type") == "observed_system" and flat_state not in (
        "no_query",
        "out_of_scope",
    ):
        # An observed system was never queried, so its flat host should not be.
        record("state", flat_state, "observed only (never queried)")
    return differences


HOST_FIELD_KEYS = (
    "names",
    "addresses",
    "query_target",
    "display_name",
    "classification",
    "state",
)


def compare(payload: Mapping[str, Any], source: str = "") -> dict[str, Any]:
    """Return the comparison report for one discovery.json payload."""

    graph = payload["topology_graph"]
    flat_hosts = [host for host in payload["hosts"] if isinstance(host, Mapping)]
    flat_by_id = {int(host["id"]): host for host in flat_hosts}
    all_entities = [item for item in graph.get("entities", []) if isinstance(item, Mapping)]
    entities = [item for item in all_entities if item.get("entity_type") in SYSTEM_ENTITY_TYPES]
    entity_by_key = {item["entity_key"]: item for item in entities}

    groups, graph_group, flat_group = _build_groups(flat_hosts, entities)
    observed_classification = 0

    systems: dict[str, Any] = {
        "flat_hosts": len(flat_hosts),
        "graph_systems": len(entities),
        "logical_systems": sum(item["entity_type"] == "logical_system" for item in entities),
        "observed_systems": sum(item["entity_type"] == "observed_system" for item in entities),
        "physical_chassis": sum(
            item.get("entity_type") == "physical_chassis" for item in all_entities
        ),
        "matched_one_to_one": 0,
        "merged_in_graph": [],
        "split_in_graph": [],
        "many_to_many": [],
        "flat_only": [],
        "graph_only": [],
    }
    host_fields: dict[str, list[dict[str, Any]]] = {key: [] for key in HOST_FIELD_KEYS}

    for group in groups:
        flats = [flat_by_id[item] for item in sorted(group.flat_ids)]
        graphs = [entity_by_key[item] for item in sorted(group.graph_keys)]
        flat_labels = [_flat_label(item) for item in flats]
        graph_labels = [_graph_label(item) for item in graphs]
        if not graphs:
            systems["flat_only"].extend(flat_labels)
        elif not flats:
            systems["graph_only"].extend(graph_labels)
        elif len(flats) == 1 and len(graphs) == 1:
            systems["matched_one_to_one"] += 1
            for name, difference in _field_differences(flats[0], graphs[0]).items():
                host_fields[name].append(difference)
            if not graphs[0].get("classifications") and flats[0].get("classification"):
                observed_classification += 1
        elif len(graphs) == 1:
            systems["merged_in_graph"].append({"graph": graph_labels[0], "flat": flat_labels})
        elif len(flats) == 1:
            systems["split_in_graph"].append({"flat": flat_labels[0], "graph": graph_labels})
        else:
            systems["many_to_many"].append({"flat": flat_labels, "graph": graph_labels})

    neighbors = _compare_edges(
        _flat_edges(flat_hosts, flat_group), _graph_edges(graph, graph_group)
    )

    flat_only_data = {key: 0 for key, _label in FLAT_ONLY_DATA}
    for host in flat_hosts:
        for key, present in _flat_only_values(host).items():
            flat_only_data[key] += int(present)
    flat_only_data["observed_classification"] = observed_classification

    differences = (
        systems["merged_in_graph"]
        or systems["split_in_graph"]
        or systems["many_to_many"]
        or systems["flat_only"]
        or systems["graph_only"]
        or any(host_fields[key] for key in HOST_FIELD_KEYS)
        or neighbors["protocols_differ"]
        or neighbors["flat_duplicates"]
        or neighbors["flat_only"]
        or neighbors["graph_only"]
    )
    discovery = payload.get("discovery") or {}
    return {
        "report_version": REPORT_VERSION,
        "source": source,
        "run_id": discovery.get("run_id"),
        "discovery_schema": payload.get("schema_version"),
        "graph_schema": graph.get("schema_version"),
        "graph_authority": graph.get("authority", {}),
        "systems": systems,
        "host_fields": host_fields,
        "neighbors": neighbors,
        "flat_only_data": flat_only_data,
        "agree": not differences,
    }


def _count(value: Any) -> int:
    return value if isinstance(value, int) else len(value)


def render(report: Mapping[str, Any], *, details: bool = False) -> str:
    """Render one report for a terminal."""

    systems = report["systems"]
    fields = report["host_fields"]
    neighbors = report["neighbors"]
    authority = report["graph_authority"]
    lines = [
        f"Flat hosts vs topology graph: {report['source']}",
        f"  run {report['run_id']}  discovery schema {report['discovery_schema']}  "
        f"graph schema {report['graph_schema']}",
        f"  graph observations {authority.get('observation_completeness', '?')}, "
        f"entity resolution {authority.get('entity_resolution', '?')}",
        "",
        "Systems",
        f"  flat hosts                  {systems['flat_hosts']:>6}",
        f"  graph systems               {systems['graph_systems']:>6}  "
        f"({systems['logical_systems']} logical, {systems['observed_systems']} observed; "
        f"{systems['physical_chassis']} physical chassis not counted)",
        f"  matched one to one          {systems['matched_one_to_one']:>6}",
        f"  merged in the graph         {_count(systems['merged_in_graph']):>6}  "
        "(one graph system, several flat hosts)",
        f"  split in the graph          {_count(systems['split_in_graph']):>6}  "
        "(one flat host, several graph systems)",
        f"  many to many                {_count(systems['many_to_many']):>6}",
        f"  flat only                   {_count(systems['flat_only']):>6}",
        f"  graph only                  {_count(systems['graph_only']):>6}",
        "",
        "Host fields (systems matched one to one)",
        f"  names differ                {len(fields['names']):>6}",
        f"  addresses differ            {len(fields['addresses']):>6}",
        f"  query target differs        {len(fields['query_target']):>6}",
        f"  display name differs        {len(fields['display_name']):>6}",
        f"  classification differs      {len(fields['classification']):>6}",
        f"  state differs               {len(fields['state']):>6}",
        "",
        "Neighbors",
        f"  flat learned rows           {neighbors['flat_rows']:>6}",
        f"  graph relationships         {neighbors['graph_relationships']:>6}",
        f"  matched                     {neighbors['matched']:>6}",
        f"  protocols differ            {len(neighbors['protocols_differ']):>6}",
        f"  duplicate flat rows         {len(neighbors['flat_duplicates']):>6}  "
        "(repeat an edge another flat host already has)",
        f"  flat only                   {len(neighbors['flat_only']):>6}",
        f"  graph only                  {len(neighbors['graph_only']):>6}",
        "",
        "Host data only in the flat view (hosts with a value)",
    ]
    labels = dict(FLAT_ONLY_DATA)
    width = max(len(label) for label in labels.values())
    for key, count in report["flat_only_data"].items():
        lines.append(f"  {labels[key]:<{width}} {count:>6}")
    lines.append("")
    if report["agree"]:
        lines.append(
            "Result: systems, host fields, and neighbors agree. The graph cannot yet "
            "supply the host data counted above."
        )
    else:
        lines.append("Result: the views disagree; see the counts above (--details lists them).")

    if details:
        detail_sections: list[tuple[str, Sequence[Any]]] = [
            ("Merged in the graph", systems["merged_in_graph"]),
            ("Split in the graph", systems["split_in_graph"]),
            ("Many to many", systems["many_to_many"]),
            ("Flat-only hosts", systems["flat_only"]),
            ("Graph-only systems", systems["graph_only"]),
            *((f"Host field: {key}", fields[key]) for key in HOST_FIELD_KEYS),
            ("Neighbor protocols differ", neighbors["protocols_differ"]),
            ("Duplicate flat neighbor rows", neighbors["flat_duplicates"]),
            ("Flat-only neighbor rows", neighbors["flat_only"]),
            ("Graph-only relationships", neighbors["graph_only"]),
        ]
        for title, items in detail_sections:
            if not items:
                continue
            lines.extend(["", f"{title} ({len(items)})"])
            lines.extend(f"  {json.dumps(item, sort_keys=True)}" for item in items)
    return "\n".join(lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="flat_graph_compare.py",
        description=(
            "Derive a flat host list from a discovery.json topology graph and compare it "
            "with the hosts[] view. Reads the files only."
        ),
    )
    parser.add_argument(
        "paths",
        nargs="+",
        type=Path,
        metavar="PATH",
        help="discovery.json file, or an output directory that contains one",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true", help="print machine-readable reports")
    output.add_argument("--details", action="store_true", help="also list every difference")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    reports: list[dict[str, Any]] = []
    failed = False
    for path in args.paths:
        try:
            resolved, payload = load_discovery(path)
        except InputError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            failed = True
            continue
        reports.append(compare(payload, source=str(resolved)))
    if args.json:
        print(json.dumps(reports if len(args.paths) > 1 else (reports or [None])[0], indent=2))
    else:
        print("\n\n".join(render(report, details=args.details) for report in reports))
    if failed:
        return 2
    return 0 if all(report["agree"] for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
