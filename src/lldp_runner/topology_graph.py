"""Claims-driven topology graph materialization.

This module is the deferred resolver boundary. Raw CDP, LLDP, and LLDPv2 rows
are retained before cross-protocol reconciliation. The materializer can
therefore rebuild the current graph from immutable evidence when later
information changes an earlier conclusion.

The graph deliberately does not infer that every link-layer advertisement is a
direct cable relationship.  A local interface with several learned systems is
reported as a multi-neighbor observation until stronger evidence or an operator
policy can classify the relationship.  This is important for Nexus VDCs sharing
one management attachment, transparent devices that pass discovery frames, and
virtual/overlay interfaces.
"""

from __future__ import annotations

import copy
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from lldp_runner.claims import stable_fingerprint
from lldp_runner.collectors import merge_neighbor_observations
from lldp_runner.identity import (
    canonical_mac,
    cisco_ap_mac,
    cisco_sep_mac,
    is_locally_assigned_chassis_subtype,
    normalize_host_address,
    normalize_identity_name,
    normalized_advertised_name,
    typed_port_id_mac,
)
from lldp_runner.models import NeighborObservation

TOPOLOGY_GRAPH_SCHEMA_VERSION = 2

_PROTOCOL_ORDER = {"cdp": 0, "lldp": 1, "lldpv2": 2}
_PLACEHOLDER_NAMES = {
    "",
    "-",
    "(none).(none)",
    "n/a",
    "none",
    "not advertised",
    "null",
    "unknown",
}
_OVERLAY_INTERFACE = re.compile(
    r"(?i)^(?:tu|tunnel|nve|vxlan|vtep|gre|ipip|loopback|lo\d|dialer|virtual-template)"
)
_LOGICAL_INTERFACE = re.compile(
    r"(?i)^(?:po|port-channel|ae\d|bundle-ether|irb|vlan|bdi|bridge|mgmt)"
)


@dataclass(frozen=True, slots=True)
class GraphBuildResult:
    """Materialized graph plus append-only component decisions."""

    document: dict[str, Any]
    decisions: tuple[dict[str, Any], ...]


def _canonical_protocols(values: Iterable[str]) -> list[str]:
    return sorted(
        dict.fromkeys(str(value).casefold() for value in values if value),
        key=lambda value: (_PROTOCOL_ORDER.get(value, 99), value),
    )


def _one_line(value: Any) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ").strip()


def _normalized_name(value: Any) -> str | None:
    text = _one_line(value)
    if not text:
        return None
    parsed = normalized_advertised_name(text)
    base = parsed.base_name if parsed is not None else text
    normalized = normalize_identity_name(base)
    if normalized is None or normalized in _PLACEHOLDER_NAMES:
        return None
    return normalized


def _normalized_address(value: Any) -> str | None:
    try:
        return normalize_host_address(_one_line(value))
    except ValueError:
        return None


def _canonical_mac(value: Any) -> str | None:
    """Compatibility wrapper for the shared strict MAC normalizer."""

    return canonical_mac(value)


def _strict_name_mac(value: Any) -> str | None:
    text = _one_line(value)
    return cisco_sep_mac(text) or cisco_ap_mac(text)


def _loads(value: Any, fallback: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if value in {None, ""}:
        return fallback
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def _observation_payload(observation: NeighborObservation) -> dict[str, Any]:
    payload = observation.to_dict()
    payload["remote_addresses"] = sorted(dict.fromkeys(observation.remote_addresses))
    payload["capabilities"] = sorted(dict.fromkeys(observation.capabilities))
    details = payload.get("details")
    payload["details"] = details if isinstance(details, dict) else {}
    return payload


_GRAPH_INDEX_DETAIL_KEYS = (
    "time_mark",
    "local_port_num",
    "remote_index",
    "destination_mac",
    "ifindex",
    "device_index",
    "address_type",
    "port_id",
    "port_id_subtype",
    "port_id_subtype_id",
    "port_description",
    "local_interface_resolved",
    "local_port_map_failed",
)


def _compact_graph_advertisement(
    observation: NeighborObservation,
) -> dict[str, Any]:
    """Return compact exported evidence while SQLite retains the full raw row.

    Discovery JSON is routinely copied between operators and review systems.  It
    should expose enough information to audit a graph decision without repeating
    the large protocol-detail mapping already retained immutably in the state
    database.  The details fingerprint lets a reviewer detect any change in the
    omitted mapping, while the MIB index fields preserve row provenance.
    """

    details = observation.details if isinstance(observation.details, dict) else {}
    index = {
        key: copy.deepcopy(details[key])
        for key in _GRAPH_INDEX_DETAIL_KEYS
        if key in details and details[key] is not None
    }
    return {
        "local_interface": observation.local_interface,
        "local_interface_raw": observation.local_interface_raw,
        "remote_name": observation.remote_name,
        "remote_interface": observation.remote_interface,
        "remote_interface_raw": observation.remote_interface_raw,
        "remote_addresses": sorted(dict.fromkeys(observation.remote_addresses)),
        "remote_description": observation.remote_description,
        "remote_platform": observation.remote_platform,
        "capabilities": sorted(dict.fromkeys(observation.capabilities)),
        "chassis_id": observation.chassis_id,
        "chassis_id_subtype": observation.chassis_id_subtype,
        "chassis_id_subtype_id": observation.chassis_id_subtype_id,
        "mib_index": index,
        "details_fingerprint": stable_fingerprint(details),
    }


def canonical_raw_advertisements(
    source_host_id: int,
    observations: Sequence[NeighborObservation],
) -> list[dict[str, Any]]:
    """Return order-independent raw-advertisement occurrence records.

    Identical table rows are countable.  A deterministic duplicate ordinal is
    assigned after canonical sorting, so replaying the same unordered row set
    produces the same occurrence fingerprints.
    """

    bases: list[tuple[str, dict[str, Any]]] = []
    for observation in observations:
        raw = _observation_payload(observation)
        basis = {
            "kind": "protocol_advertisement",
            "source_host_id": int(source_host_id),
            "protocol": str(observation.protocol).casefold(),
            "observation": raw,
        }
        bases.append((stable_fingerprint(basis), basis))
    bases.sort(
        key=lambda item: (
            item[0],
            json.dumps(item[1], sort_keys=True, separators=(",", ":"), default=str),
        )
    )
    duplicate_counts: Counter[str] = Counter()
    result: list[dict[str, Any]] = []
    for content_fingerprint, basis in bases:
        ordinal = duplicate_counts[content_fingerprint]
        duplicate_counts[content_fingerprint] += 1
        payload = {
            **basis,
            "content_fingerprint": content_fingerprint,
            "duplicate_ordinal": ordinal,
        }
        payload["occurrence_fingerprint"] = stable_fingerprint(payload)
        result.append(payload)
    return result


def observation_from_payload(payload: Mapping[str, Any]) -> NeighborObservation:
    """Reconstruct one normalized neighbor observation from immutable JSON."""

    return NeighborObservation(
        protocol=str(payload.get("protocol") or "unknown"),
        local_interface=(
            str(payload["local_interface"])
            if payload.get("local_interface") not in {None, ""}
            else None
        ),
        local_interface_raw=(
            str(payload["local_interface_raw"])
            if payload.get("local_interface_raw") not in {None, ""}
            else None
        ),
        remote_name=(
            str(payload["remote_name"])
            if payload.get("remote_name") not in {None, ""}
            else None
        ),
        remote_interface=(
            str(payload["remote_interface"])
            if payload.get("remote_interface") not in {None, ""}
            else None
        ),
        remote_interface_raw=(
            str(payload["remote_interface_raw"])
            if payload.get("remote_interface_raw") not in {None, ""}
            else None
        ),
        remote_addresses=[str(value) for value in payload.get("remote_addresses", [])],
        remote_description=(
            str(payload["remote_description"])
            if payload.get("remote_description") not in {None, ""}
            else None
        ),
        remote_platform=(
            str(payload["remote_platform"])
            if payload.get("remote_platform") not in {None, ""}
            else None
        ),
        capabilities=[str(value) for value in payload.get("capabilities", [])],
        chassis_id=(
            str(payload["chassis_id"])
            if payload.get("chassis_id") not in {None, ""}
            else None
        ),
        chassis_id_subtype=(
            str(payload["chassis_id_subtype"])
            if payload.get("chassis_id_subtype") not in {None, ""}
            else None
        ),
        chassis_id_subtype_id=(
            int(payload["chassis_id_subtype_id"])
            if payload.get("chassis_id_subtype_id") is not None
            else None
        ),
        details=dict(payload.get("details") or {}),
    )


class _UnionFind:
    def __init__(self, values: Iterable[int]) -> None:
        self.parent = {int(value): int(value) for value in values}

    def find(self, value: int) -> int:
        parent = self.parent[value]
        if parent != value:
            self.parent[value] = self.find(parent)
        return self.parent[value]

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root == right_root:
            return
        if left_root < right_root:
            self.parent[right_root] = left_root
        else:
            self.parent[left_root] = right_root


@dataclass(slots=True)
class _HostEvidence:
    host_id: int
    preferred_name: str
    classification: str
    query_target: str | None
    names: set[str]
    addresses: set[str]
    engine_ids: set[str]
    serials: set[str]
    strict_macs: set[str]
    system: dict[str, Any]
    state: str


def _host_evidence(
    row: Mapping[str, Any],
    *,
    names: Iterable[str],
    addresses: Iterable[str],
) -> _HostEvidence:
    system = _loads(row.get("system_json") if hasattr(row, "get") else None, {})
    if not isinstance(system, dict):
        system = {}
    preferred = _one_line(row.get("preferred_name"))
    all_names = {
        normalized
        for value in [preferred, row.get("snmp_sysname"), system.get("sys_name"), *names]
        if (normalized := _normalized_name(value)) is not None
    }
    normalized_addresses = {
        normalized
        for value in [row.get("query_target"), *addresses]
        if (normalized := _normalized_address(value)) is not None
    }
    engine = _one_line(system.get("snmp_engine_id")).casefold()
    serial = _one_line(system.get("serial_number")).casefold()
    strict_macs = {
        mac
        for value in [preferred, row.get("snmp_sysname"), system.get("sys_name"), *names]
        if (mac := _strict_name_mac(value)) is not None
    }
    return _HostEvidence(
        host_id=int(row["id"]),
        preferred_name=preferred or "unknown",
        classification=_one_line(row.get("classification")) or "unknown_device",
        query_target=_normalized_address(row.get("query_target")),
        names=all_names,
        addresses=normalized_addresses,
        engine_ids={engine} if engine else set(),
        serials={serial} if serial else set(),
        strict_macs=strict_macs,
        system=system,
        state=_one_line(row.get("state")).casefold() or "unknown",
    )


def _sets_compatible(left: set[str], right: set[str]) -> bool:
    return not left or not right or bool(left & right)


def _logical_name_anchor(names: Iterable[str]) -> str | None:
    """Return one conservative short-name anchor shared by all direct names.

    A short name and its FQDN are two presentations of the same logical name.
    The anchor is used only with independent physical or management evidence,
    such as an exact chassis serial.  It is never a global name-only merge rule.
    """

    labels = {str(name).split(".", 1)[0].casefold() for name in names if str(name)}
    return next(iter(labels)) if len(labels) == 1 else None


def _cluster_hosts(records: Sequence[_HostEvidence]) -> list[list[_HostEvidence]]:
    """Cluster duplicate projections of one logical SNMP agent conservatively.

    A physical serial never merges logical agents by itself.  This preserves
    separate Nexus VDCs under one chassis.  Queried rows merge when a strong
    agent identity agrees, or when the same query target and logical name agree
    without a conflicting engine/serial/MAC.  Unqueried observations may join a
    unique queried logical name but do not bridge two queried management routes.
    """

    by_id = {record.host_id: record for record in records}
    union = _UnionFind(by_id)

    def compatible(left: _HostEvidence, right: _HostEvidence) -> bool:
        return (
            _sets_compatible(left.engine_ids, right.engine_ids)
            and _sets_compatible(left.serials, right.serials)
            and _sets_compatible(left.strict_macs, right.strict_macs)
        )

    token_indexes: list[defaultdict[str, list[int]]] = [defaultdict(list) for _ in range(4)]
    for record in records:
        for engine in record.engine_ids:
            token_indexes[0][engine].append(record.host_id)
        for mac in record.strict_macs:
            token_indexes[1][mac].append(record.host_id)
        if record.query_target:
            for name in record.names:
                token_indexes[2][f"{record.query_target}\0{name}"].append(record.host_id)
        # Nexus VDCs and similar logical systems may expose more than one
        # management interface.  Exact physical serial plus one shared logical
        # name anchor identifies the same VDC across those routes while sibling
        # VDC names on the same chassis remain separate logical entities.
        name_anchor = _logical_name_anchor(record.names)
        if name_anchor:
            for serial in record.serials:
                token_indexes[3][f"{serial}\0{name_anchor}"].append(record.host_id)
    for index in token_indexes:
        for ids in index.values():
            for left_id in ids:
                for right_id in ids:
                    if left_id < right_id and compatible(by_id[left_id], by_id[right_id]):
                        union.union(left_id, right_id)

    # Name-only observations remain separate unless one and only one queried
    # logical entity has the same normalized name.  Reusing a short hostname is
    # common in large or federated networks, so name equality must not become a
    # global union operation.

    # Attach an unqueried component to one and only one queried component with a
    # matching name. Ambiguous names remain separate instead of becoming a bridge.
    queried_roots_by_name: defaultdict[str, set[int]] = defaultdict(set)
    for record in records:
        if record.query_target:
            for name in record.names:
                queried_roots_by_name[name].add(union.find(record.host_id))
    for record in records:
        if record.query_target is not None:
            continue
        candidates = {
            root
            for name in record.names
            for root in queried_roots_by_name.get(name, set())
        }
        if len(candidates) != 1:
            continue
        candidate_root = next(iter(candidates))
        representative = by_id[candidate_root]
        if compatible(record, representative):
            union.union(record.host_id, candidate_root)

    grouped: defaultdict[int, list[_HostEvidence]] = defaultdict(list)
    for record in records:
        grouped[union.find(record.host_id)].append(record)
    return [sorted(values, key=lambda item: item.host_id) for _, values in sorted(grouped.items())]


def _logical_entity_key(
    *,
    names: set[str],
    addresses: set[str],
    engine_ids: set[str],
    serials: set[str],
    strict_macs: set[str],
    query_targets: set[str],
    host_refs: Sequence[int],
) -> str:
    if len(engine_ids) == 1:
        return f"logical:engine:{next(iter(engine_ids))}"
    if len(strict_macs) == 1:
        return f"endpoint:mac:{next(iter(strict_macs))}"
    name_anchor = _logical_name_anchor(names)
    if len(serials) == 1 and name_anchor:
        return "logical:serial-name:" + stable_fingerprint(
            {"serial": next(iter(serials)), "name_anchor": name_anchor}
        )[:24]
    if name_anchor and len(query_targets) == 1:
        return "logical:agent:" + stable_fingerprint(
            {"name_anchor": name_anchor, "target": next(iter(query_targets))}
        )[:24]
    basis = {
        "names": sorted(names),
        "addresses": sorted(addresses),
        "engine_ids": sorted(engine_ids),
        "serials": sorted(serials),
        "strict_macs": sorted(strict_macs),
        "query_targets": sorted(query_targets),
    }
    if any(basis.values()):
        return "logical:cluster:" + stable_fingerprint(basis)[:24]
    # A completely evidence-free compatibility row has no semantic cross-run
    # identity.  Keep it distinct and mark it run-local in the entity metadata.
    return "logical:run-local:" + stable_fingerprint(
        {"host_refs": sorted(int(value) for value in host_refs)}
    )[:24]


def _display_name(names: set[str], records: Sequence[_HostEvidence]) -> str:
    fqdn = sorted(name for name in names if "." in name)
    if fqdn:
        return fqdn[0]
    if names:
        return sorted(names)[0]
    preferred = sorted(
        (record.preferred_name for record in records if record.preferred_name != "unknown"),
        key=lambda value: ("." not in value, value.casefold()),
    )
    return preferred[0] if preferred else "unknown"


def _physical_entity(serial: str) -> dict[str, Any]:
    key = f"physical:serial:{serial}"
    return {
        "entity_key": key,
        "entity_type": "physical_chassis",
        "display_name": serial.upper(),
        "host_refs": [],
        "identity": {
            "serial_numbers": [serial],
            "names": [],
            "addresses": [],
            "snmp_engine_ids": [],
            "strict_macs": [],
        },
        "cluster_integrity": "consistent",
        "projection_status": "physical_container",
    }


def _interface_kind(name: str) -> str:
    if _OVERLAY_INTERFACE.search(name):
        return "overlay"
    if _LOGICAL_INTERFACE.search(name):
        return "logical_or_aggregate"
    if ":" in name and name.split(":", 1)[0] in {"ifIndex", "lldpLocalPort"}:
        return "unresolved"
    return "physical_or_unknown"


def _local_namespace(observation: NeighborObservation) -> str:
    details = observation.details
    value = details.get("local_interface_namespace") if isinstance(details, dict) else None
    if value:
        return str(value)
    local = observation.local_interface or observation.local_interface_raw or ""
    return "typed" if ":" in local else "resolved"


def _local_chassis_label(observation: NeighborObservation) -> str | None:
    """Return a locally assigned chassis label for display, not identity.

    Vendors often place a useful endpoint label in LLDP chassis subtype 7.
    The value is not guaranteed to be globally unique, so the resolver keeps it
    out of identity matching while still presenting it to Network Operations.
    """

    if not is_locally_assigned_chassis_subtype(
        observation.chassis_id_subtype,
        observation.chassis_id_subtype_id,
    ):
        return None
    value = _one_line(observation.chassis_id)
    return value if value and value.casefold() not in _PLACEHOLDER_NAMES else None


def _canonical_interface_namespace(observation: NeighborObservation) -> str:
    """Return the graph namespace for one local-interface occurrence.

    Once an agent has supplied a usable interface name such as ``Gi0/0/3``,
    CDP ifIndex and LLDP local-port evidence can safely share one graph interface
    occurrence. Unresolved typed identifiers remain in separate namespaces so
    equal integers from unrelated MIB indexes never become equal interfaces.
    """

    local = _one_line(
        observation.local_interface or observation.local_interface_raw
    )
    details = observation.details if isinstance(observation.details, dict) else {}
    explicitly_unresolved = details.get("local_interface_resolved") is False
    typed_unresolved = ":" in local and local.split(":", 1)[0] in {
        "ifIndex",
        "lldpLocalPort",
    }
    if explicitly_unresolved or typed_unresolved or not local:
        return _local_namespace(observation)
    return "resolved"


def _remote_identity_tokens(observation: NeighborObservation) -> dict[str, set[str]]:
    names = {
        normalized
        for value in [observation.remote_name]
        if (normalized := _normalized_name(value)) is not None
    }
    addresses = {
        normalized
        for value in observation.remote_addresses
        if (normalized := _normalized_address(value)) is not None
    }
    strict_macs = {
        mac
        for value in [observation.remote_name]
        if (mac := _strict_name_mac(value)) is not None
    }
    if observation.chassis_id and (
        observation.chassis_id_subtype_id == 4
        or str(observation.chassis_id_subtype or "").casefold() == "mac_address"
    ):
        if mac := _canonical_mac(observation.chassis_id):
            strict_macs.add(mac)
    details = observation.details if isinstance(observation.details, dict) else {}
    port_id = details.get("port_id")
    port_subtype = str(details.get("port_id_subtype") or "").casefold()
    port_subtype_id = details.get("port_id_subtype_id")
    if port_id and (port_subtype == "mac_address" or port_subtype_id == 3):
        if mac := _canonical_mac(port_id):
            strict_macs.add(mac)
    serial_hints: set[str] = set()
    parsed = normalized_advertised_name(observation.remote_name or "")
    if parsed is not None and parsed.serial_hint:
        serial_hints.add(parsed.serial_hint.casefold())
    return {
        "names": names,
        "addresses": addresses,
        "strict_macs": strict_macs,
        "serial_hints": serial_hints,
    }


def _observed_entity_key(tokens: Mapping[str, set[str]], occurrence_basis: Any) -> str:
    strict_macs = tokens.get("strict_macs", set())
    names = tokens.get("names", set())
    if len(strict_macs) == 1:
        return f"endpoint:mac:{next(iter(strict_macs))}"
    # A name without an independently resolved entity is edge-scoped. Reusing
    # the same hostname at unrelated sites must not collapse two endpoints.
    return "observed:edge:" + stable_fingerprint(occurrence_basis)[:24]


def _canonical_merged_observations(
    raw_records: Sequence[dict[str, Any]],
) -> list[NeighborObservation]:
    observations = [
        observation_from_payload(record["observation"])
        for record in raw_records
        if isinstance(record.get("observation"), Mapping)
    ]
    return merge_neighbor_observations(copy.deepcopy(observations))


def _protocol_evidence_keys(
    raw_records: Sequence[dict[str, Any]],
    merged: NeighborObservation,
) -> list[str]:
    """Return raw occurrence keys plausibly supporting one merged observation."""

    merged_name = _normalized_name(merged.remote_name)
    merged_remote = _one_line(merged.remote_interface).casefold()
    merged_local = _one_line(merged.local_interface).casefold()
    protocols = set(
        _canonical_protocols(
            merged.details.get("protocols", [merged.protocol])
            if isinstance(merged.details, dict)
            else [merged.protocol]
        )
    )
    matches: list[str] = []
    for record in raw_records:
        payload = record.get("observation")
        if not isinstance(payload, Mapping):
            continue
        protocol = str(payload.get("protocol") or "").casefold()
        if protocol not in protocols:
            continue
        raw_name = _normalized_name(payload.get("remote_name"))
        raw_remote = _one_line(payload.get("remote_interface")).casefold()
        raw_local = _one_line(payload.get("local_interface")).casefold()
        if merged_name and raw_name and merged_name != raw_name:
            continue
        if merged_remote and raw_remote and merged_remote != raw_remote:
            # Cross-protocol phone representations can differ. Exact name/MAC
            # evidence still lets the merge decision retain both raw rows.
            raw_tokens = _remote_identity_tokens(observation_from_payload(payload))
            merged_tokens = _remote_identity_tokens(merged)
            if not (raw_tokens["strict_macs"] & merged_tokens["strict_macs"]):
                continue
        if merged_local and raw_local and merged_local != raw_local:
            details = merged.details if isinstance(merged.details, dict) else {}
            protocol_local = _one_line(details.get(f"{protocol}.local_interface")).casefold()
            if raw_local != protocol_local:
                continue
        key = str(
            record.get("_graph_advertisement_key")
            or record.get("occurrence_fingerprint")
            or ""
        )
        if key:
            matches.append(key)
    return sorted(dict.fromkeys(matches))


_VOLATILE_ADVERTISEMENT_DETAIL_FIELDS = frozenset(
    {
        "device_index",
        "ifindex",
        "local_ifindex",
        "local_port_num",
        "remote_index",
        "time_mark",
    }
)


def _semantic_detail_value(value: Any) -> Any:
    """Remove collection-local table indexes from graph occurrence identity."""

    if isinstance(value, Mapping):
        return {
            str(key): _semantic_detail_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
            if str(key).rsplit(".", 1)[-1]
            not in _VOLATILE_ADVERTISEMENT_DETAIL_FIELDS
        }
    if isinstance(value, list):
        normalized = [_semantic_detail_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item, sort_keys=True, separators=(",", ":"), default=str
            ),
        )
    return value


def _semantic_advertisement_content(record: Mapping[str, Any]) -> str:
    """Return a cross-run evidence fingerprint without volatile row indexes."""

    payload = record.get("observation")
    if isinstance(payload, Mapping):
        normalized = copy.deepcopy(dict(payload))
        details = normalized.get("details")
        normalized["details"] = _semantic_detail_value(details or {})
        for field in ("remote_addresses", "capabilities"):
            values = normalized.get(field)
            if isinstance(values, list):
                normalized[field] = sorted(dict.fromkeys(str(item) for item in values))
        payload = normalized
    return stable_fingerprint(
        {
            "protocol": str(record.get("protocol") or "").casefold(),
            "observation": payload,
        }
    )


def _source_route_key(record: Mapping[str, Any]) -> str:
    """Return a stable SNMP-agent discriminator, independent of credentials.

    Query target and credential choice are collection-path metadata.  When an
    engine ID exists it identifies the agent directly.  Otherwise the resolved
    graph source entity already separates systems, so one normalized system name
    is sufficient to keep occurrence keys stable when the same VDC is queried
    through another management interface.
    """

    context = record.get("source_context")
    if not isinstance(context, Mapping):
        context = record.get("_source_context")
    if not isinstance(context, Mapping):
        context = {}
    system = context.get("system")
    if not isinstance(system, Mapping):
        system = {}
    engine = _one_line(system.get("snmp_engine_id")).casefold()
    if engine:
        return stable_fingerprint({"snmp_engine_id": engine})
    sys_name = _normalized_name(
        system.get("sys_name") or context.get("snmp_sysname")
    )
    if sys_name:
        return stable_fingerprint({"sys_name": sys_name})
    return stable_fingerprint({"query_target": context.get("query_target")})


def _stable_projection_value(value: Any) -> Any:
    """Remove run-local audit fields from the graph fingerprint basis."""

    if isinstance(value, list):
        return [_stable_projection_value(item) for item in value]
    if isinstance(value, Mapping):
        ignored = {
            "host_refs",
            "source_host_ref",
            "source_host_id",
            "storage_observation_fingerprint",
            "query_targets",
            "source_route",
            "credential_route",
            "details_fingerprint",
            "device_index",
            "ifindex",
            "local_ifindex",
            "local_port_num",
            "remote_index",
            "time_mark",
        }
        return {
            str(key): _stable_projection_value(item)
            for key, item in value.items()
            if str(key) not in ignored
        }
    return value


def _compatibility_projection_diagnostics(
    records: Sequence[dict[str, Any]],
    entities: Mapping[str, Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Report legacy compatibility hosts spanning distinct endpoint MACs.

    The topology graph resolves an anonymous, explicitly typed LLDP Port-ID MAC
    as a distinct observed endpoint.  Older compatibility state can nevertheless
    point several such advertisements at one ``hosts`` row when a repeated
    locally assigned chassis value was previously treated as global identity.
    This diagnostic makes that projection mismatch explicit without changing or
    weakening the authoritative observation graph.
    """

    grouped: defaultdict[int, dict[str, Any]] = defaultdict(
        lambda: {
            "endpoint_macs": set(),
            "graph_entity_keys": set(),
            "source_host_refs": set(),
            "compatibility_edge_count": 0,
        }
    )
    for record in records:
        if not isinstance(record, Mapping):
            continue
        try:
            remote_host_ref = int(record["remote_host_id"])
        except (KeyError, TypeError, ValueError):
            continue
        payload = record.get("observation")
        if not isinstance(payload, Mapping):
            continue
        # A named or addressed multi-interface device can legitimately expose
        # several typed Port-ID MACs while remaining one compatibility host.
        # This warning is specifically for otherwise anonymous observations
        # whose repeated locally assigned chassis value caused the legacy
        # projection to aggregate distinct graph endpoints.
        if _normalized_name(payload.get("remote_name")) is not None:
            continue
        remote_addresses = payload.get("remote_addresses")
        if isinstance(remote_addresses, Sequence) and not isinstance(
            remote_addresses, (str, bytes)
        ):
            if any(_normalized_address(value) is not None for value in remote_addresses):
                continue
        try:
            chassis_subtype_id = (
                int(payload["chassis_id_subtype_id"])
                if payload.get("chassis_id_subtype_id") is not None
                else None
            )
        except (TypeError, ValueError):
            chassis_subtype_id = None
        if not is_locally_assigned_chassis_subtype(
            str(payload.get("chassis_id_subtype") or ""),
            chassis_subtype_id,
        ):
            continue
        details = payload.get("details")
        if not isinstance(details, Mapping):
            continue
        endpoint_mac = typed_port_id_mac(details)
        if endpoint_mac is None:
            continue
        entity_key = f"endpoint:mac:{endpoint_mac}"
        entity = entities.get(entity_key)
        if not isinstance(entity, Mapping) or entity.get("entity_type") != "observed_system":
            continue
        group = grouped[remote_host_ref]
        group["endpoint_macs"].add(endpoint_mac)
        group["graph_entity_keys"].add(entity_key)
        try:
            group["source_host_refs"].add(int(record["source_host_id"]))
        except (KeyError, TypeError, ValueError):
            pass
        group["compatibility_edge_count"] += 1

    diagnostics: list[dict[str, Any]] = []
    for host_ref, group in sorted(grouped.items()):
        endpoint_macs = sorted(group["endpoint_macs"])
        graph_entity_keys = sorted(group["graph_entity_keys"])
        if len(endpoint_macs) <= 1 or len(graph_entity_keys) <= 1:
            continue
        diagnostics.append(
            {
                "diagnostic_type": (
                    "compatibility_host_spans_distinct_endpoint_macs"
                ),
                "severity": "warning",
                "compatibility_host_ref": host_ref,
                "endpoint_mac_count": len(endpoint_macs),
                "graph_entity_count": len(graph_entity_keys),
                "endpoint_macs": endpoint_macs,
                "graph_entity_keys": graph_entity_keys,
                "source_host_refs": sorted(group["source_host_refs"]),
                "compatibility_edge_count": int(group["compatibility_edge_count"]),
                "authoritative_graph_impact": "none",
                "interpretation": (
                    "The compatibility host is an aggregate projection; the "
                    "separate graph endpoint entities remain authoritative."
                ),
            }
        )
    return diagnostics


def build_topology_graph(
    *,
    hosts: Sequence[Mapping[str, Any]],
    names_by_host: Mapping[int, Sequence[str]],
    addresses_by_host: Mapping[int, Sequence[str]],
    raw_advertisements: Sequence[dict[str, Any]],
    compatibility_advertisements: Sequence[dict[str, Any]] = (),
    compatibility_projection_advertisements: Sequence[dict[str, Any]] = (),
    coverage_by_host: Mapping[int, Mapping[str, Any]] | None = None,
) -> GraphBuildResult:
    """Materialize the current graph from immutable evidence.

    ``compatibility_advertisements`` is a migration fallback for state created
    before raw protocol rows were retained. New 0.32 discoveries use raw rows.
    ``compatibility_projection_advertisements`` is diagnostic-only evidence from
    merged host/neighbor rows and never participates in graph materialization.
    """

    coverage_by_host = coverage_by_host or {}
    host_records = [
        _host_evidence(
            row,
            names=names_by_host.get(int(row["id"]), ()),
            addresses=addresses_by_host.get(int(row["id"]), ()),
        )
        for row in hosts
    ]
    host_evidence_by_id = {record.host_id: record for record in host_records}
    # Only a host that reached an SNMP query route is promoted to a logical-agent
    # entity directly.  NO_QUERY and OUT_OF_SCOPE rows are compatibility
    # projections derived from neighbor advertisements; the graph reconstructs
    # those as observed entities from the immutable protocol rows instead of
    # treating an ingestion-time host row as an established device identity.
    agent_records = [record for record in host_records if record.query_target]
    clusters = _cluster_hosts(agent_records)

    entities: dict[str, dict[str, Any]] = {}
    host_to_entity: dict[int, str] = {}
    physical_entities: dict[str, dict[str, Any]] = {}
    memberships: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    for cluster in clusters:
        names = set().union(*(item.names for item in cluster))
        addresses = set().union(*(item.addresses for item in cluster))
        engines = set().union(*(item.engine_ids for item in cluster))
        serials = set().union(*(item.serials for item in cluster))
        strict_macs = set().union(*(item.strict_macs for item in cluster))
        query_targets = {item.query_target for item in cluster if item.query_target}
        key = _logical_entity_key(
            names=names,
            addresses=addresses,
            engine_ids=engines,
            serials=serials,
            strict_macs=strict_macs,
            query_targets=query_targets,
            host_refs=[item.host_id for item in cluster],
        )
        conflicts: list[str] = []
        if len(engines) > 1:
            conflicts.append("conflicting_snmp_engine_ids")
        if len(strict_macs) > 1:
            conflicts.append("conflicting_strict_macs")
        if len(serials) > 1:
            conflicts.append("conflicting_physical_serials")
        host_refs = sorted(item.host_id for item in cluster)
        entity = {
            "entity_key": key,
            "entity_type": "logical_system",
            "display_name": _display_name(names, cluster),
            "host_refs": host_refs,
            "identity": {
                "names": sorted(names),
                "addresses": sorted(addresses),
                "snmp_engine_ids": sorted(engines),
                "serial_numbers": sorted(serials),
                "strict_macs": sorted(strict_macs),
                "query_targets": sorted(query_targets),
            },
            "classifications": sorted(
                dict.fromkeys(item.classification for item in cluster)
            ),
            "states": sorted(dict.fromkeys(item.state for item in cluster)),
            "cluster_integrity": "conflicted" if conflicts else "consistent",
            "conflicts": conflicts,
            "projection_status": (
                "duplicate_projection" if len(host_refs) > 1 else "one_to_one"
            ),
            "identity_key_scope": (
                "run_local" if key.startswith("logical:run-local:") else "semantic"
            ),
        }
        entities[key] = entity
        for host_id in host_refs:
            host_to_entity[host_id] = key
        for serial in sorted(serials):
            physical = physical_entities.setdefault(serial, _physical_entity(serial))
            physical["host_refs"] = sorted(
                dict.fromkeys([*physical["host_refs"], *host_refs])
            )
            memberships.append(
                {
                    "parent_entity_key": physical["entity_key"],
                    "child_entity_key": key,
                    "relationship_type": "logical_member",
                    "confidence": "verified",
                    "evidence": [f"entity_serial:{serial}"],
                }
            )
        decisions.append(
            {
                "component_key": f"entity:{key}",
                "decision_type": (
                    "duplicate_projection_absorbed"
                    if len(host_refs) > 1
                    else "logical_entity_materialized"
                ),
                "outcome": {
                    "entity_key": key,
                    "host_refs": host_refs,
                    "physical_serials": sorted(serials),
                    "cluster_integrity": entity["cluster_integrity"],
                },
                "evidence": sorted(
                    [
                        *[f"name:{value}" for value in names],
                        *[f"address:{value}" for value in addresses],
                        *[f"engine:{value}" for value in engines],
                        *[f"serial:{value}" for value in serials],
                        *[f"strict_mac:{value}" for value in strict_macs],
                    ]
                ),
            }
        )

    entities.update(
        {entity["entity_key"]: entity for entity in physical_entities.values()}
    )

    name_index: defaultdict[str, set[str]] = defaultdict(set)
    address_index: defaultdict[str, set[str]] = defaultdict(set)
    mac_index: defaultdict[str, set[str]] = defaultdict(set)
    serial_to_physical = {
        serial: entity["entity_key"] for serial, entity in physical_entities.items()
    }
    for key, entity in entities.items():
        if entity["entity_type"] != "logical_system":
            continue
        identity = entity["identity"]
        for value in identity.get("names", []):
            name_index[str(value)].add(key)
        for value in identity.get("addresses", []):
            address_index[str(value)].add(key)
        for value in identity.get("strict_macs", []):
            mac_index[str(value)].add(key)

    advertisements = [*raw_advertisements, *compatibility_advertisements]
    advertisement_exclusions: list[dict[str, Any]] = []
    by_source: defaultdict[int, list[dict[str, Any]]] = defaultdict(list)
    for position, record in enumerate(advertisements):
        record_key = (
            str(record.get("occurrence_fingerprint") or "")
            if isinstance(record, Mapping)
            else ""
        ) or stable_fingerprint({"position": position, "record": record})
        if not isinstance(record, Mapping):
            advertisement_exclusions.append(
                {
                    "advertisement_key": record_key,
                    "reason": "record_not_mapping",
                }
            )
            continue
        try:
            source_host_id = int(record["source_host_id"])
        except (KeyError, TypeError, ValueError):
            advertisement_exclusions.append(
                {
                    "advertisement_key": record_key,
                    "reason": "source_host_id_invalid",
                }
            )
            continue
        if not isinstance(record.get("observation"), Mapping):
            advertisement_exclusions.append(
                {
                    "advertisement_key": record_key,
                    "source_host_id": source_host_id,
                    "reason": "observation_payload_invalid",
                }
            )
            continue
        by_source[source_host_id].append(dict(record))

    interfaces: dict[str, dict[str, Any]] = {}
    graph_advertisements: list[dict[str, Any]] = []
    relationship_members: defaultdict[tuple[str, str], list[dict[str, Any]]] = (
        defaultdict(list)
    )

    def resolve_remote(
        observation: NeighborObservation,
        *,
        fallback_remote_host_id: int | None,
        occurrence_basis: Any,
    ) -> tuple[str, list[str]]:
        if fallback_remote_host_id is not None and fallback_remote_host_id in host_to_entity:
            return host_to_entity[fallback_remote_host_id], []
        tokens = _remote_identity_tokens(observation)
        candidates: set[str] = set()
        strong_candidates = {
            item for token in tokens["strict_macs"] for item in mac_index.get(token, set())
        }
        if strong_candidates:
            candidates = strong_candidates
        else:
            name_candidates = {
                item for token in tokens["names"] for item in name_index.get(token, set())
            }
            address_candidates = {
                item
                for token in tokens["addresses"]
                for item in address_index.get(token, set())
            }
            if name_candidates and address_candidates:
                intersection = name_candidates & address_candidates
                candidates = intersection or name_candidates
            else:
                # A shared/default/overlapping address is not sufficient global
                # identity evidence. Name-only candidates may remain ambiguous;
                # address-only observations stay edge scoped.
                candidates = name_candidates
        if len(candidates) == 1:
            return next(iter(candidates)), []

        key = _observed_entity_key(tokens, occurrence_basis)
        fallback_record = (
            host_evidence_by_id.get(fallback_remote_host_id)
            if fallback_remote_host_id is not None
            else None
        )
        fallback_refs = [fallback_remote_host_id] if fallback_record is not None else []
        if key not in entities:
            display = (
                sorted(tokens["names"])[0]
                if tokens["names"]
                else _one_line(observation.remote_name)
                or _local_chassis_label(observation)
                or (
                    sorted(tokens["strict_macs"])[0]
                    if tokens["strict_macs"]
                    else None
                )
                or observation.chassis_id
                or "unknown"
            )
            serials = sorted(tokens["serial_hints"])
            entities[key] = {
                "entity_key": key,
                "entity_type": "observed_system",
                "display_name": display,
                "host_refs": fallback_refs,
                "identity": {
                    "names": sorted(tokens["names"]),
                    "addresses": sorted(tokens["addresses"]),
                    "snmp_engine_ids": [],
                    "serial_numbers": serials,
                    "strict_macs": sorted(tokens["strict_macs"]),
                    "query_targets": [],
                },
                "classifications": (
                    [fallback_record.classification] if fallback_record is not None else []
                ),
                "states": [fallback_record.state] if fallback_record is not None else [],
                "cluster_integrity": "ambiguous" if candidates else "unresolved",
                "conflicts": [],
                "projection_status": "observed_only",
                "candidate_entity_keys": sorted(candidates),
            }
            for serial in serials:
                physical_key = serial_to_physical.get(serial)
                if physical_key:
                    memberships.append(
                        {
                            "parent_entity_key": physical_key,
                            "child_entity_key": key,
                            "relationship_type": "logical_member",
                            "confidence": "high",
                            "evidence": [f"corroborated_advertised_serial:{serial}"],
                        }
                    )
        elif fallback_refs:
            entity = entities[key]
            entity["host_refs"] = sorted(
                dict.fromkeys([*entity.get("host_refs", []), *fallback_refs])
            )
            if fallback_record is not None:
                entity["classifications"] = sorted(
                    dict.fromkeys(
                        [*entity.get("classifications", []), fallback_record.classification]
                    )
                )
                entity["states"] = sorted(
                    dict.fromkeys([*entity.get("states", []), fallback_record.state])
                )
        return key, sorted(candidates)

    # Count equal semantic rows across every provisional source record that has
    # resolved to the same graph entity. This keeps advertisement keys unique
    # when one SNMP result was projected into two compatibility hosts, while the
    # ordinal set remains independent of those run-local host IDs.
    occurrence_counts: Counter[tuple[str, str, str]] = Counter()

    for source_host_id, raw_records in sorted(by_source.items()):
        source_entity = host_to_entity.get(source_host_id)
        if source_entity is None:
            for raw_record in raw_records:
                advertisement_exclusions.append(
                    {
                        "advertisement_key": str(
                            raw_record.get("occurrence_fingerprint")
                            or stable_fingerprint(raw_record)
                        ),
                        "source_host_id": source_host_id,
                        "reason": "source_entity_unresolved",
                    }
                )
            continue

        # Build semantic occurrence keys before any CDP/LLDP reconciliation.
        # The storage fingerprint retains the provisional host ID for immutable
        # SQLite idempotence; the graph key uses the resolved source entity,
        # management route, normalized row content, and duplicate ordinal.
        prepared: list[tuple[str, str, str, dict[str, Any]]] = []
        for raw_record in raw_records:
            content_key = _semantic_advertisement_content(raw_record)
            route_key = _source_route_key(raw_record)
            storage_key = str(
                raw_record.get("occurrence_fingerprint")
                or stable_fingerprint(raw_record)
            )
            prepared.append((content_key, route_key, storage_key, raw_record))
        prepared.sort(key=lambda item: (item[0], item[1], item[2]))
        raw_records = []
        for content_key, route_key, storage_key, raw_record in prepared:
            ordinal_key = (source_entity, content_key, route_key)
            semantic_ordinal = occurrence_counts[ordinal_key]
            occurrence_counts[ordinal_key] += 1
            advertisement_key = "advertisement:" + stable_fingerprint(
                {
                    "source_entity_key": source_entity,
                    "source_route_key": route_key,
                    "content_fingerprint": content_key,
                    "duplicate_ordinal": semantic_ordinal,
                }
            )[:32]
            raw_record["_graph_advertisement_key"] = advertisement_key
            raw_records.append(raw_record)
            raw_observation = observation_from_payload(raw_record["observation"])
            local_name = _one_line(
                raw_observation.local_interface
                or raw_observation.local_interface_raw
                or "unresolved"
            )
            source_context = raw_record.get("source_context")
            if not isinstance(source_context, Mapping):
                source_context = raw_record.get("_source_context")
            if not isinstance(source_context, Mapping):
                source_context = {}
            graph_advertisements.append(
                {
                    "advertisement_key": advertisement_key,
                    "content_fingerprint": content_key,
                    "duplicate_ordinal": semantic_ordinal,
                    "storage_observation_fingerprint": storage_key,
                    "source_host_ref": source_host_id,
                    "source_entity_key": source_entity,
                    "source_route": {
                        "query_target": source_context.get("query_target"),
                        "credential_route": source_context.get("credential_route"),
                    },
                    "protocol": raw_observation.protocol,
                    "local_interface": local_name,
                    "local_interface_namespace": _local_namespace(raw_observation),
                    "observation": _compact_graph_advertisement(raw_observation),
                }
            )

        merged_rows = _canonical_merged_observations(raw_records)
        for merged in merged_rows:
            local_name = _one_line(
                merged.local_interface or merged.local_interface_raw or "unresolved"
            )
            namespace = _canonical_interface_namespace(merged)
            interface_key = "interface:" + stable_fingerprint(
                {
                    "owner_entity_key": source_entity,
                    "name": local_name.casefold(),
                    "namespace": namespace.casefold(),
                }
            )[:24]
            interface = interfaces.setdefault(
                interface_key,
                {
                    "interface_key": interface_key,
                    "owner_entity_key": source_entity,
                    "name": local_name,
                    "namespace": namespace,
                    "kind": _interface_kind(local_name),
                    "raw_identifiers": [],
                    "evidence_namespaces": [],
                },
            )
            # Compute supporting raw rows once per resolved relationship.  Some
            # high-density devices expose hundreds of advertisements; repeating
            # the full evidence scan for every raw row would turn one interface
            # into cubic work and make graph materialization impractically slow.
            evidence_keys = _protocol_evidence_keys(raw_records, merged)
            evidence_key_set = set(evidence_keys)
            for raw_record in raw_records:
                if str(raw_record.get("_graph_advertisement_key") or "") not in evidence_key_set:
                    continue
                payload = raw_record.get("observation")
                if not isinstance(payload, Mapping):
                    continue
                raw_local = _one_line(
                    payload.get("local_interface") or payload.get("local_interface_raw")
                )
                if raw_local and raw_local not in interface["raw_identifiers"]:
                    interface["raw_identifiers"].append(raw_local)
            interface["raw_identifiers"] = sorted(
                interface["raw_identifiers"], key=str.casefold
            )
            evidence_namespaces = {
                _local_namespace(observation_from_payload(record["observation"]))
                for record in raw_records
                if str(record.get("_graph_advertisement_key") or "")
                in evidence_key_set
                and isinstance(record.get("observation"), Mapping)
            }
            interface["evidence_namespaces"] = sorted(
                {
                    *interface.get("evidence_namespaces", []),
                    *evidence_namespaces,
                },
                key=str.casefold,
            )

            fallback_remote: int | None = None
            for raw_record in raw_records:
                if str(raw_record.get("_graph_advertisement_key") or "") in evidence_key_set:
                    raw_remote = raw_record.get("remote_host_id")
                    if raw_remote is not None:
                        try:
                            fallback_remote = int(raw_remote)
                        except (TypeError, ValueError):
                            pass
            remote_entity, candidate_entities = resolve_remote(
                merged,
                fallback_remote_host_id=fallback_remote,
                occurrence_basis={
                    "source_entity": source_entity,
                    "interface": interface_key,
                    "remote_name": merged.remote_name,
                    "remote_interface": merged.remote_interface,
                    "chassis_id": merged.chassis_id,
                },
            )
            protocols = _canonical_protocols(
                merged.details.get("protocols", [merged.protocol])
                if isinstance(merged.details, dict)
                else [merged.protocol]
            )
            member_basis = {
                "source_entity_key": source_entity,
                "interface_key": interface_key,
                "remote_entity_key": remote_entity,
                "remote_interface": _one_line(
                    merged.remote_interface or merged.remote_interface_raw
                ),
                "protocols": protocols,
            }
            member_key = "relationship:" + stable_fingerprint(member_basis)[:24]
            member = {
                "relationship_key": member_key,
                "source_entity_key": source_entity,
                "interface_key": interface_key,
                "remote_entity_key": remote_entity,
                "remote_name": entities[remote_entity]["display_name"],
                "remote_interface": _one_line(
                    merged.remote_interface or merged.remote_interface_raw
                )
                or None,
                "protocols": protocols,
                "relationship_scope": "observed",
                "directness": "unresolved",
                "confidence": "high" if not candidate_entities else "low",
                "candidate_entity_keys": candidate_entities,
                "evidence_advertisement_keys": evidence_keys,
            }
            relationship_members[(source_entity, interface_key)].append(member)


    relationship_groups: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    physical_parent_by_child: defaultdict[str, set[str]] = defaultdict(set)
    for membership in memberships:
        physical_parent_by_child[str(membership["child_entity_key"])].add(
            str(membership["parent_entity_key"])
        )

    for (source_entity, interface_key), members in sorted(relationship_members.items()):
        # Equal rows are represented once with multiplicity; ordering from an
        # agent never affects comparison.
        by_member_key: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
        for member in members:
            by_member_key[str(member["relationship_key"])].append(member)
        canonical_members: list[dict[str, Any]] = []
        for member_key, duplicates in sorted(by_member_key.items()):
            member = copy.deepcopy(duplicates[0])
            member["multiplicity"] = len(duplicates)
            member["evidence_advertisement_keys"] = sorted(
                dict.fromkeys(
                    key
                    for duplicate in duplicates
                    for key in duplicate.get("evidence_advertisement_keys", [])
                )
            )
            canonical_members.append(member)
            relationships.append(member)
        unique_remote = sorted(
            dict.fromkeys(str(member["remote_entity_key"]) for member in canonical_members)
        )
        interface = interfaces[interface_key]
        common_physical: set[str] | None = None
        for remote in unique_remote:
            parents = physical_parent_by_child.get(remote, set())
            common_physical = (
                set(parents) if common_physical is None else common_physical & parents
            )
        common_physical = common_physical or set()
        if interface["kind"] == "overlay":
            classification = "overlay_observations"
        elif len(unique_remote) <= 1:
            classification = "single_observation"
        elif len(common_physical) == 1:
            classification = "shared_chassis_logical_members"
        else:
            classification = "multiple_neighbor_observations"
        discrepancies = []
        if len(unique_remote) > 1 and classification != "shared_chassis_logical_members":
            discrepancies.append("multiple_neighbors_on_interface")
        group_basis = {
            "source_entity_key": source_entity,
            "interface_key": interface_key,
            "member_keys": [
                [member["relationship_key"], member["multiplicity"]]
                for member in canonical_members
            ],
        }
        group_key = "group:" + stable_fingerprint(group_basis)[:24]
        group = {
            "group_key": group_key,
            "source_entity_key": source_entity,
            "interface_key": interface_key,
            "local_interface": interface["name"],
            "interface_kind": interface["kind"],
            "classification": classification,
            "relationship_scope": "observed",
            "directness": "unresolved",
            "member_count": sum(int(member["multiplicity"]) for member in canonical_members),
            "unique_member_count": len(unique_remote),
            "member_entity_keys": unique_remote,
            "relationship_keys": [
                str(member["relationship_key"]) for member in canonical_members
            ],
            "shared_physical_chassis_key": (
                next(iter(common_physical)) if len(common_physical) == 1 else None
            ),
            "discrepancies": discrepancies,
        }
        relationship_groups.append(group)
        decisions.append(
            {
                "component_key": f"relationship_group:{source_entity}:{interface_key}",
                "decision_type": classification,
                "outcome": {
                    "group_key": group_key,
                    "member_entity_keys": unique_remote,
                    "member_count": group["member_count"],
                    "shared_physical_chassis_key": group["shared_physical_chassis_key"],
                    "directness": "unresolved",
                },
                "evidence": sorted(
                    key
                    for member in canonical_members
                    for key in member["evidence_advertisement_keys"]
                ),
            }
        )

    # Membership rows are set-like. A logical entity can be observed through
    # several advertisements without creating duplicate parent/child links.
    membership_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for membership in memberships:
        key = (
            str(membership["parent_entity_key"]),
            str(membership["child_entity_key"]),
            str(membership["relationship_type"]),
        )
        existing = membership_map.get(key)
        if existing is None:
            membership_map[key] = copy.deepcopy(membership)
        else:
            existing["evidence"] = sorted(
                dict.fromkeys([*existing.get("evidence", []), *membership.get("evidence", [])])
            )
            if membership.get("confidence") == "verified":
                existing["confidence"] = "verified"

    coverage_by_entity: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    coverage_seen: defaultdict[str, set[str]] = defaultdict(set)
    for host_id, value in sorted(coverage_by_host.items()):
        entity_key = host_to_entity.get(int(host_id))
        if entity_key is None or not isinstance(value, Mapping):
            continue
        normalized = copy.deepcopy(dict(value))
        fingerprint = stable_fingerprint(normalized)
        if fingerprint in coverage_seen[entity_key]:
            continue
        coverage_seen[entity_key].add(fingerprint)
        coverage_by_entity[entity_key].append(normalized)

    input_advertisement_count = len(advertisements)
    materialized_advertisement_count = len(graph_advertisements)
    excluded_advertisement_count = len(advertisement_exclusions)
    advertisement_key_counts = Counter(
        str(item["advertisement_key"]) for item in graph_advertisements
    )
    duplicate_advertisement_keys = sorted(
        key for key, count in advertisement_key_counts.items() if count > 1
    )
    if duplicate_advertisement_keys:
        # A graph advertisement key identifies one durable occurrence.  Losing
        # uniqueness here would make replay, correspondence, and audit output
        # order-dependent, so fail materialization instead of publishing an
        # internally ambiguous graph.
        preview = ", ".join(duplicate_advertisement_keys[:5])
        raise ValueError(
            "Topology graph advertisement keys are not unique"
            + (f": {preview}" if preview else "")
        )
    unaccounted_advertisement_count = max(
        0,
        input_advertisement_count
        - materialized_advertisement_count
        - excluded_advertisement_count,
    )
    observation_completeness = (
        "complete" if unaccounted_advertisement_count == 0 else "partial"
    )
    compatibility_projection_diagnostics = _compatibility_projection_diagnostics(
        compatibility_projection_advertisements,
        entities,
    )
    for diagnostic in compatibility_projection_diagnostics:
        host_ref = int(diagnostic["compatibility_host_ref"])
        decisions.append(
            {
                "component_key": f"compatibility_host:{host_ref}",
                "decision_type": str(diagnostic["diagnostic_type"]),
                "outcome": {
                    key: copy.deepcopy(value)
                    for key, value in diagnostic.items()
                    if key not in {"interpretation"}
                },
                "evidence": [
                    *[
                        f"endpoint_mac:{value}"
                        for value in diagnostic["endpoint_macs"]
                    ],
                    *[
                        f"graph_entity:{value}"
                        for value in diagnostic["graph_entity_keys"]
                    ],
                ],
            }
        )

    document: dict[str, Any] = {
        "schema_version": TOPOLOGY_GRAPH_SCHEMA_VERSION,
        "authority": {
            "observation_completeness": observation_completeness,
            "observation_projection": (
                "authoritative" if observation_completeness == "complete" else "incomplete"
            ),
            "entity_resolution": "provisional",
            "physical_topology": "not_inferred",
            "directness": "unresolved",
            "compatibility_projection": "diagnostic",
        },
        "directness_policy": "observed_only",
        "entities": sorted(
            entities.values(),
            key=lambda item: (
                str(item["entity_type"]),
                str(item["display_name"]).casefold(),
                str(item["entity_key"]),
            ),
        ),
        "interfaces": sorted(
            interfaces.values(),
            key=lambda item: (
                str(item["owner_entity_key"]),
                str(item["name"]).casefold(),
                str(item["interface_key"]),
            ),
        ),
        "advertisements": sorted(
            graph_advertisements,
            key=lambda item: str(item["advertisement_key"]),
        ),
        "memberships": sorted(
            membership_map.values(),
            key=lambda item: (
                str(item["parent_entity_key"]),
                str(item["child_entity_key"]),
                str(item["relationship_type"]),
            ),
        ),
        "relationships": sorted(
            relationships,
            key=lambda item: (
                str(item["source_entity_key"]),
                str(item["interface_key"]),
                str(item["remote_entity_key"]),
                str(item["relationship_key"]),
            ),
        ),
        "relationship_groups": sorted(
            relationship_groups,
            key=lambda item: (
                str(item["source_entity_key"]),
                str(item["local_interface"]).casefold(),
                str(item["group_key"]),
            ),
        ),
        "advertisement_exclusions": sorted(
            advertisement_exclusions,
            key=lambda item: (
                str(item.get("reason") or ""),
                str(item.get("advertisement_key") or ""),
            ),
        ),
        "collection_coverage": {
            entity_key: values
            for entity_key, values in sorted(coverage_by_entity.items())
        },
    }
    fingerprint_basis = _stable_projection_value(
        {
            key: value
            for key, value in document.items()
            if key != "projection_fingerprint"
        }
    )
    document["projection_fingerprint"] = stable_fingerprint(fingerprint_basis)
    summary = {
        "logical_entities": sum(
            entity["entity_type"] == "logical_system" for entity in document["entities"]
        ),
        "observed_entities": sum(
            entity["entity_type"] == "observed_system" for entity in document["entities"]
        ),
        "physical_chassis": sum(
            entity["entity_type"] == "physical_chassis" for entity in document["entities"]
        ),
        "interfaces": len(document["interfaces"]),
        "input_advertisements": input_advertisement_count,
        "raw_advertisements": len(document["advertisements"]),
        "unique_advertisement_keys": len(advertisement_key_counts),
        "excluded_advertisements": excluded_advertisement_count,
        "unaccounted_advertisements": unaccounted_advertisement_count,
        "relationship_groups": len(document["relationship_groups"]),
        "relationships": len(document["relationships"]),
        "duplicate_projection_entities": sum(
            entity.get("projection_status") == "duplicate_projection"
            for entity in document["entities"]
        ),
        "multi_neighbor_groups": sum(
            group.get("unique_member_count", 0) > 1
            for group in document["relationship_groups"]
        ),
        "shared_chassis_groups": sum(
            group.get("classification") == "shared_chassis_logical_members"
            for group in document["relationship_groups"]
        ),
        "unresolved_directness_groups": len(document["relationship_groups"]),
        "compatibility_projection_diagnostics": len(
            compatibility_projection_diagnostics
        ),
    }
    document["summary"] = summary
    document["compatibility_projection_diagnostics"] = (
        compatibility_projection_diagnostics
    )
    # The summary is derived and intentionally does not affect the projection
    # fingerprint; its values can always be regenerated from the graph arrays.

    return GraphBuildResult(
        document=document,
        decisions=tuple(
            sorted(decisions, key=lambda item: (item["component_key"], item["decision_type"]))
        ),
    )
