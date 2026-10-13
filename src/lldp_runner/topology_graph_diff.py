"""Many-to-many correspondence for claims-driven topology graphs.

The compatibility diff pairs one projected host from run A with one projected
host from run B.  A graph resolver must also describe one-to-many, many-to-one,
and many-to-many changes without inventing physical topology churn.  This module
builds conservative correspondence components and compares local-interface
observation groups through those components.

Relationship directness is intentionally not inferred.  A switch, hypervisor,
shared Nexus management attachment, or transparent device can cause several
protocol advertisements to appear on one local interface.  The diff reports the
observed member set and any discrepancy; operators can classify directness when
site-specific evidence supports it.
"""

from __future__ import annotations

import copy
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from lldp_runner.claims import stable_fingerprint
from lldp_runner.identity import weak_mobility_mac


def _items(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _identity(entity: Mapping[str, Any]) -> Mapping[str, Any]:
    value = entity.get("identity")
    return value if isinstance(value, Mapping) else {}


def _strings(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).casefold() for item in value if str(item).strip()}


def _entity_tokens(entity: Mapping[str, Any]) -> dict[str, set[str]]:
    identity = _identity(entity)
    return {
        "names": _strings(identity.get("names")),
        "addresses": _strings(identity.get("addresses")),
        "engines": _strings(identity.get("snmp_engine_ids")),
        "serials": _strings(identity.get("serial_numbers")),
        "macs": _strings(identity.get("strict_macs")),
        "targets": _strings(identity.get("query_targets")),
    }


def _parent_map(graph: Mapping[str, Any]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = defaultdict(set)
    for membership in _items(graph.get("memberships")):
        if membership.get("relationship_type") != "logical_member":
            continue
        parent = str(membership.get("parent_entity_key") or "")
        child = str(membership.get("child_entity_key") or "")
        if parent and child:
            result[child].add(parent)
    return result


def _match_evidence(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    *,
    left_parents: set[str],
    right_parents: set[str],
) -> tuple[str, ...]:
    """Return conservative evidence connecting two graph entities."""

    left_type = str(left.get("entity_type") or "")
    right_type = str(right.get("entity_type") or "")
    if left_type != right_type:
        return ()
    left_key = str(left.get("entity_key") or "")
    right_key = str(right.get("entity_key") or "")
    if left_key and left_key == right_key:
        return ("exact_entity_key",)

    a = _entity_tokens(left)
    b = _entity_tokens(right)
    evidence: list[str] = []
    if left_type == "physical_chassis":
        for value in sorted(a["serials"] & b["serials"]):
            evidence.append(f"serial:{value}")
        return tuple(evidence)

    for value in sorted(a["engines"] & b["engines"]):
        evidence.append(f"engine:{value}")
    for value in sorted(a["macs"] & b["macs"]):
        evidence.append(f"strict_mac:{value}")
    if evidence:
        return tuple(evidence)

    common_names = a["names"] & b["names"]
    common_targets = a["targets"] & b["targets"]
    common_addresses = a["addresses"] & b["addresses"]
    common_parents = left_parents & right_parents
    if common_names and (common_targets or common_addresses):
        evidence.extend(f"name:{value}" for value in sorted(common_names))
        evidence.extend(f"target:{value}" for value in sorted(common_targets))
        evidence.extend(f"address:{value}" for value in sorted(common_addresses))
        return tuple(evidence)
    if common_names and common_parents:
        evidence.extend(f"name:{value}" for value in sorted(common_names))
        evidence.extend(f"physical_parent:{value}" for value in sorted(common_parents))
        return tuple(evidence)

    # Name-only evidence is retained only when both sides expose exactly one
    # normalized name.  It may form a many-to-many component, but it never forces
    # a one-to-one assignment inside that component.
    if len(a["names"]) == len(b["names"]) == 1 and common_names:
        return tuple(f"name_only:{value}" for value in sorted(common_names))
    return ()


def _entity_view(entity: Mapping[str, Any]) -> dict[str, Any]:
    host_refs = entity.get("host_refs")
    return {
        "entity_key": entity.get("entity_key"),
        "entity_type": entity.get("entity_type"),
        "display_name": entity.get("display_name"),
        "host_refs": list(host_refs) if isinstance(host_refs, list) else [],
        "identity": copy.deepcopy(dict(_identity(entity))),
        "cluster_integrity": entity.get("cluster_integrity"),
        "projection_status": entity.get("projection_status"),
    }


def _semantic_entity(entity: Mapping[str, Any]) -> dict[str, Any]:
    identity = copy.deepcopy(dict(_identity(entity)))
    # The address selected for one SNMP collection is route metadata. It must not
    # turn a stable entity into a topology change when another known address was
    # used in the next run. All observed addresses remain comparable.
    identity.pop("query_targets", None)
    return {
        "entity_type": entity.get("entity_type"),
        "display_name": entity.get("display_name"),
        "identity": identity,
        "cluster_integrity": entity.get("cluster_integrity"),
        "conflicts": sorted(str(value) for value in entity.get("conflicts", [])),
        "classifications": sorted(
            str(value) for value in entity.get("classifications", [])
        ),
    }


def _host_ref_count(entity: Mapping[str, Any]) -> int:
    values = entity.get("host_refs")
    return len(values) if isinstance(values, list) else 0


def _component_status(
    left: Sequence[Mapping[str, Any]], right: Sequence[Mapping[str, Any]]
) -> str:
    if not left:
        return "b_only"
    if not right:
        return "a_only"
    if len(left) == 1 and len(right) == 1:
        if _semantic_entity(left[0]) != _semantic_entity(right[0]):
            return "changed"
        a_count = _host_ref_count(left[0])
        b_count = _host_ref_count(right[0])
        if a_count > b_count:
            return "duplicate_projection_introduced"
        if a_count < b_count:
            return "absorbed_duplicate"
        return "same"
    if len(left) == 1:
        return "cluster_merge"
    if len(right) == 1:
        return "cluster_split"
    left_semantics = sorted(
        stable_fingerprint(_semantic_entity(entity)) for entity in left
    )
    right_semantics = sorted(
        stable_fingerprint(_semantic_entity(entity)) for entity in right
    )
    if left_semantics == right_semantics:
        # The evidence forms a many-to-many component, but its semantic multiset
        # is unchanged. Preserve the ambiguity without reporting topology churn.
        return "same_ambiguous"
    return "cluster_reassociated"


def _correspondence_components(
    a_graph: Mapping[str, Any], b_graph: Mapping[str, Any]
) -> tuple[list[dict[str, Any]], dict[str, str], dict[str, str]]:
    a_entities = _items(a_graph.get("entities"))
    b_entities = _items(b_graph.get("entities"))
    a_by_key = {str(item.get("entity_key")): item for item in a_entities}
    b_by_key = {str(item.get("entity_key")): item for item in b_entities}
    a_parents = _parent_map(a_graph)
    b_parents = _parent_map(b_graph)

    adjacency: dict[tuple[str, str], set[tuple[str, str]]] = defaultdict(set)
    edge_evidence: dict[tuple[str, str], tuple[str, ...]] = {}

    # Production discoveries commonly contain ten thousand or more entities. An
    # all-pairs comparison would be quadratic and needlessly compare unrelated
    # sites. Build candidate pairs from exact typed evidence, then apply the same
    # conservative evidence gate to each candidate.
    b_indexes: dict[str, defaultdict[str, set[str]]] = {
        name: defaultdict(set)
        for name in ("key", "name", "address", "engine", "serial", "mac")
    }
    for b_key, b_entity in b_by_key.items():
        b_indexes["key"][b_key].add(b_key)
        tokens = _entity_tokens(b_entity)
        for value in tokens["names"]:
            b_indexes["name"][value].add(b_key)
        for value in tokens["addresses"]:
            b_indexes["address"][value].add(b_key)
        for value in tokens["engines"]:
            b_indexes["engine"][value].add(b_key)
        for value in tokens["serials"]:
            b_indexes["serial"][value].add(b_key)
        for value in tokens["macs"]:
            b_indexes["mac"][value].add(b_key)

    exact_keys = set(a_by_key) & set(b_by_key)
    for a_key, a_entity in a_by_key.items():
        tokens = _entity_tokens(a_entity)
        candidates = set(b_indexes["key"].get(a_key, set()))
        for value in tokens["engines"]:
            candidates.update(b_indexes["engine"].get(value, set()))
        for value in tokens["macs"]:
            candidates.update(b_indexes["mac"].get(value, set()))
        for value in tokens["serials"]:
            candidates.update(b_indexes["serial"].get(value, set()))
        for value in tokens["names"]:
            candidates.update(b_indexes["name"].get(value, set()))
        # Address-only identity is not sufficient, but addresses can corroborate
        # a shared name. No address-only candidates are added here.
        for b_key in sorted(candidates):
            b_entity = b_by_key[b_key]
            evidence = _match_evidence(
                a_entity,
                b_entity,
                left_parents=a_parents.get(a_key, set()),
                right_parents=b_parents.get(b_key, set()),
            )
            if not evidence:
                continue
            weak_name_only = all(value.startswith("name_only:") for value in evidence)
            if weak_name_only and (
                (a_key in exact_keys and b_key != a_key)
                or (b_key in exact_keys and a_key != b_key)
            ):
                # Exact occurrence identity is allowed to absorb an additional
                # projection only when independent target, address, chassis,
                # engine, or strict-MAC evidence supports the association. A
                # common weak display name cannot glue stable occurrences into a
                # broad many-to-many component.
                continue
            a_node = ("a", a_key)
            b_node = ("b", b_key)
            adjacency[a_node].add(b_node)
            adjacency[b_node].add(a_node)
            edge_evidence[(a_key, b_key)] = evidence

    all_nodes = {
        *(("a", key) for key in a_by_key),
        *(("b", key) for key in b_by_key),
    }
    seen: set[tuple[str, str]] = set()
    components: list[dict[str, Any]] = []
    a_map: dict[str, str] = {}
    b_map: dict[str, str] = {}
    for start in sorted(all_nodes):
        if start in seen:
            continue
        queue: deque[tuple[str, str]] = deque([start])
        nodes: list[tuple[str, str]] = []
        seen.add(start)
        while queue:
            node = queue.popleft()
            nodes.append(node)
            for neighbor in sorted(adjacency.get(node, set())):
                if neighbor not in seen:
                    seen.add(neighbor)
                    queue.append(neighbor)
        a_keys = sorted(key for side, key in nodes if side == "a")
        b_keys = sorted(key for side, key in nodes if side == "b")
        component_key = "correspondence:" + stable_fingerprint(
            {"a": a_keys, "b": b_keys}
        )[:24]
        left = [a_by_key[key] for key in a_keys]
        right = [b_by_key[key] for key in b_keys]
        evidence = sorted(
            {
                token
                for a_key in a_keys
                for b_key in b_keys
                for token in edge_evidence.get((a_key, b_key), ())
            }
        )
        status = _component_status(left, right)
        component = {
            "component_key": component_key,
            "status": status,
            "cardinality": f"{len(left)}:{len(right)}",
            "a_entities": [_entity_view(item) for item in left],
            "b_entities": [_entity_view(item) for item in right],
            "evidence": evidence,
            "physical_topology_effect": (
                "none" if status in {
                    "same",
                    "absorbed_duplicate",
                    "duplicate_projection_introduced",
                } else "not_inferred"
            ),
        }
        components.append(component)
        for key in a_keys:
            a_map[key] = component_key
        for key in b_keys:
            b_map[key] = component_key
    return components, a_map, b_map


def _interface_name(group: Mapping[str, Any]) -> str:
    return str(group.get("local_interface") or "unresolved").strip().casefold()


def _member_signature(
    member: Mapping[str, Any],
    entity_map: Mapping[str, str],
    entities: Mapping[str, Mapping[str, Any]],
) -> tuple[Any, ...]:
    remote_key = str(member.get("remote_entity_key") or "")
    remote_component = entity_map.get(remote_key)
    if remote_component is None:
        entity = entities.get(remote_key, {})
        tokens = _entity_tokens(entity)
        if tokens["macs"]:
            remote_component = "edge-mac:" + ",".join(sorted(tokens["macs"]))
        elif tokens["names"] and tokens["addresses"]:
            remote_component = "edge-name-address:" + stable_fingerprint(
                {
                    "names": sorted(tokens["names"]),
                    "addresses": sorted(tokens["addresses"]),
                }
            )[:24]
        elif tokens["names"]:
            remote_component = "edge-name:" + ",".join(sorted(tokens["names"]))
        elif tokens["addresses"]:
            remote_component = "edge-address:" + ",".join(
                sorted(tokens["addresses"])
            )
        else:
            display = str(entity.get("display_name") or member.get("remote_name") or "")
            remote_component = "edge-display:" + display.casefold()
    protocols = member.get("protocols")
    protocol_values = (
        tuple(sorted(str(value).casefold() for value in protocols))
        if isinstance(protocols, list)
        else ()
    )
    return (
        remote_component,
        str(member.get("remote_interface") or "").strip().casefold(),
        protocol_values,
    )


def _local_port_evidence(
    members: Sequence[Mapping[str, Any]],
    advertisements: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], str]:
    """Return typed LLDP local-port tokens and their resolution state.

    The numeric LLDP local-port identifier is scoped to one observing entity and
    one edge comparison. It is never promoted to a global ifIndex equivalence.
    This evidence exists solely to reconcile the same uniquely corroborated edge
    when one run could render a friendly interface name and the other could not.
    """

    tokens: set[str] = set()
    resolution_values: set[bool] = set()
    for member in members:
        keys = member.get("evidence_advertisement_keys")
        for key in keys if isinstance(keys, list) else []:
            advertisement = advertisements.get(str(key))
            if advertisement is None:
                continue
            protocol = str(advertisement.get("protocol") or "").casefold()
            if protocol not in {"lldp", "lldpv2"}:
                continue
            observation = advertisement.get("observation")
            observation = observation if isinstance(observation, Mapping) else {}
            mib_index = observation.get("mib_index")
            mib_index = mib_index if isinstance(mib_index, Mapping) else {}
            number = mib_index.get("local_port_num")
            if not isinstance(number, int) or isinstance(number, bool):
                continue
            namespace = str(
                advertisement.get("local_interface_namespace") or "lldpLocalPort"
            )
            tokens.add(f"{namespace}:{number}")
            resolved = mib_index.get("local_interface_resolved")
            if isinstance(resolved, bool):
                resolution_values.add(resolved)
    if resolution_values == {True}:
        resolution = "resolved"
    elif resolution_values == {False}:
        resolution = "unresolved"
    elif resolution_values:
        resolution = "mixed"
    else:
        resolution = "unknown"
    return sorted(tokens), resolution


def _group_set(
    graph: Mapping[str, Any], entity_map: Mapping[str, str]
) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    result: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    interface_by_key = {
        str(item.get("interface_key")): item
        for item in _items(graph.get("interfaces"))
    }
    relationship_by_key = {
        str(item.get("relationship_key")): item
        for item in _items(graph.get("relationships"))
        if item.get("relationship_key")
    }
    entity_by_key = {
        str(item.get("entity_key")): item
        for item in _items(graph.get("entities"))
        if item.get("entity_key")
    }
    advertisement_by_key = {
        str(item.get("advertisement_key")): item
        for item in _items(graph.get("advertisements"))
        if item.get("advertisement_key")
    }
    for group in _items(graph.get("relationship_groups")):
        source_key = str(group.get("source_entity_key") or "")
        source_component = entity_map.get(source_key, f"unmatched:{source_key}")
        source_entity = entity_by_key.get(source_key, {})
        interface = interface_by_key.get(str(group.get("interface_key") or ""), {})
        kind = str(group.get("interface_kind") or interface.get("kind") or "unknown")
        key = (source_component, _interface_name(group), kind)
        relationship_keys = group.get("relationship_keys")
        if isinstance(relationship_keys, list):
            members = [
                relationship_by_key[str(value)]
                for value in relationship_keys
                if str(value) in relationship_by_key
            ]
        else:
            members = [
                item
                for item in group.get("members", [])
                if isinstance(item, Mapping)
            ] if isinstance(group.get("members"), list) else []
        signatures = sorted(
            _member_signature(member, entity_map, entity_by_key) for member in members
        )
        member_views: list[dict[str, Any]] = []
        for member in members:
            remote_entity_key = str(member.get("remote_entity_key") or "")
            remote_entity = entity_by_key.get(remote_entity_key, {})
            protocols = member.get("protocols")
            member_views.append(
                {
                    "remote_component_key": entity_map.get(
                        remote_entity_key,
                        _member_signature(member, entity_map, entity_by_key)[0],
                    ),
                    "remote_entity_key": remote_entity_key,
                    "remote_display_name": remote_entity.get("display_name")
                    or member.get("remote_name"),
                    "remote_host_refs": sorted(
                        value
                        for value in remote_entity.get("host_refs", [])
                        if isinstance(value, int) and not isinstance(value, bool)
                    )
                    if isinstance(remote_entity.get("host_refs"), list)
                    else [],
                    "remote_identity": copy.deepcopy(
                        remote_entity.get("identity")
                        if isinstance(remote_entity.get("identity"), Mapping)
                        else {}
                    ),
                    "remote_interface": member.get("remote_interface"),
                    "protocols": sorted(
                        str(value).casefold()
                        for value in protocols
                        if value
                    )
                    if isinstance(protocols, list)
                    else [],
                    "evidence_advertisement_keys": sorted(
                        str(value)
                        for value in member.get("evidence_advertisement_keys", [])
                    )
                    if isinstance(member.get("evidence_advertisement_keys"), list)
                    else [],
                }
            )
        member_views.sort(
            key=lambda item: (
                str(item.get("remote_component_key") or ""),
                str(item.get("remote_interface") or "").casefold(),
                tuple(item.get("protocols") or ()),
            )
        )
        typed_local_ports, port_resolution = _local_port_evidence(
            members, advertisement_by_key
        )
        result[key].append(
            {
                "group_key": group.get("group_key"),
                "source_entity_key": source_key,
                "source_display_name": source_entity.get("display_name"),
                "source_host_refs": sorted(
                    value
                    for value in source_entity.get("host_refs", [])
                    if isinstance(value, int) and not isinstance(value, bool)
                )
                if isinstance(source_entity.get("host_refs"), list)
                else [],
                "local_interface": group.get("local_interface"),
                "interface_kind": kind,
                "classification": group.get("classification"),
                "directness": group.get("directness"),
                "discrepancies": list(group.get("discrepancies") or []),
                "member_signatures": signatures,
                "members": member_views,
                "typed_local_ports": typed_local_ports,
                "local_port_resolution": port_resolution,
                "member_count": group.get("member_count"),
                "unique_member_count": group.get("unique_member_count"),
            }
        )
    return result


def _deduplicated_group_signatures(
    groups: Sequence[Mapping[str, Any]],
) -> tuple[list[tuple[Any, ...]], int]:
    signatures = [
        (
            tuple(group.get("member_signatures") or ()),
            str(group.get("classification") or ""),
            str(group.get("directness") or "unresolved"),
        )
        for group in groups
    ]
    unique = sorted(set(signatures), key=repr)
    return unique, max(0, len(signatures) - len(unique))


def _group_member_identities(
    groups: Sequence[Mapping[str, Any]],
) -> set[tuple[str, str]]:
    """Return remote entity/port identities independent of protocol evidence."""

    result: set[tuple[str, str]] = set()
    for group in groups:
        signatures = group.get("member_signatures")
        for signature in signatures if isinstance(signatures, list) else []:
            if isinstance(signature, (list, tuple)) and len(signature) >= 2:
                result.add((str(signature[0]), str(signature[1])))
    return result


def _group_member_protocols(
    groups: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str], set[str]]:
    """Return protocol evidence per remote entity/port member.

    Relationship groups can contain several neighbors on one local interface.
    Keeping protocol evidence keyed by the remote correspondence component and
    remote port lets the diff describe simultaneous member-presence and
    protocol-evidence changes without allowing evidence from one neighbor to
    qualify a different neighbor.
    """

    result: dict[tuple[str, str], set[str]] = defaultdict(set)
    for group in groups:
        signatures = group.get("member_signatures")
        for signature in signatures if isinstance(signatures, list) else []:
            if not isinstance(signature, (list, tuple)) or len(signature) < 3:
                continue
            member_key = (str(signature[0]), str(signature[1]))
            protocols = signature[2]
            for protocol in protocols if isinstance(protocols, (list, tuple)) else []:
                value = str(protocol).casefold()
                if value:
                    result[member_key].add(value)
    return result


def _member_change_view(
    member_key: tuple[str, str], protocols: set[str]
) -> dict[str, Any]:
    """Return one compact, deterministic member-change record."""

    return {
        "remote_component_key": member_key[0],
        "remote_interface": member_key[1],
        "protocols": sorted(protocols),
    }


def _relationship_change_details(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    *,
    presentation_differences: Sequence[Mapping[str, Any]],
    a_duplicates: int,
    b_duplicates: int,
    weak_candidate_move: bool,
) -> tuple[list[str], dict[str, Any] | None, list[dict[str, Any]]]:
    """Describe orthogonal changes inside one relationship correspondence.

    ``status`` remains the concise primary classification used by existing
    operator output.  A relationship can nevertheless change in more than one
    way at once.  In particular, a neighbor can gain or lose protocol evidence
    while another neighbor appears on the same local interface.  These fields
    preserve both dimensions so reconciliation can validate each compatibility
    observation against the exact graph member that changed.
    """

    a_members = _group_member_protocols(left)
    b_members = _group_member_protocols(right)
    a_only_keys = sorted(set(a_members) - set(b_members))
    b_only_keys = sorted(set(b_members) - set(a_members))
    member_presence_change = None
    dimensions: list[str] = []
    if a_only_keys or b_only_keys:
        dimensions.append("member_presence")
        member_presence_change = {
            "a_only": [
                _member_change_view(key, a_members[key]) for key in a_only_keys
            ],
            "b_only": [
                _member_change_view(key, b_members[key]) for key in b_only_keys
            ],
        }

    member_protocol_changes = [
        {
            "remote_component_key": key[0],
            "remote_interface": key[1],
            "a_protocols": sorted(a_members[key]),
            "b_protocols": sorted(b_members[key]),
        }
        for key in sorted(set(a_members) & set(b_members))
        if a_members[key] != b_members[key]
    ]
    if member_protocol_changes:
        dimensions.append("protocol_evidence")
    if presentation_differences:
        dimensions.append("presentation")
    if a_duplicates != b_duplicates:
        dimensions.append("duplicate_projection")
    if weak_candidate_move:
        dimensions.append("candidate_attachment")
    return dimensions, member_presence_change, member_protocol_changes


def _group_typed_ports(groups: Sequence[Mapping[str, Any]]) -> set[str]:
    result: set[str] = set()
    for group in groups:
        values = group.get("typed_local_ports")
        for value in values if isinstance(values, list) else []:
            result.add(str(value))
    return result


def _group_resolution_states(groups: Sequence[Mapping[str, Any]]) -> set[str]:
    return {
        str(group.get("local_port_resolution") or "unknown")
        for group in groups
    }


def _weak_mobility_component(component: Mapping[str, Any]) -> bool:
    """Return whether one entity component is only a weak MAC correlation hint.

    A low-entropy virtual-appliance token can connect two observations across
    runs, but it cannot establish that one physical endpoint moved between local
    switch ports.  Strong names, addresses, serials, SNMP engines, query targets,
    or a globally administered non-trivial MAC make the component unsuitable for
    this ambiguity-only rule.
    """

    macs: set[str] = set()
    for side in ("a", "b"):
        for entity in _component_entities(component, side):
            tokens = _entity_tokens(entity)
            if any(
                tokens[key]
                for key in ("names", "addresses", "engines", "serials", "targets")
            ):
                return False
            macs.update(tokens["macs"])
    return bool(macs) and all(weak_mobility_mac(value) for value in macs)


def _weak_candidate_move_correspondence(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    weak_components: set[str],
) -> bool:
    """Return whether differently named local groups are one ambiguous move.

    The observations must contain the same remote entity/remote-port members and
    the same protocol evidence.  Every remote entity component must be weak MAC
    evidence, and reciprocal uniqueness is enforced by the caller.  This folds a
    false A-only/B-only pair into one candidate-move record without asserting a
    cable or endpoint move.
    """

    identities = _group_member_identities(left)
    if not identities or identities != _group_member_identities(right):
        return False
    if not all(component in weak_components for component, _port in identities):
        return False
    left_members = sorted(
        {
            tuple(signature)
            for group in left
            for signature in group.get("member_signatures", [])
            if isinstance(signature, (list, tuple))
        },
        key=repr,
    )
    right_members = sorted(
        {
            tuple(signature)
            for group in right
            for signature in group.get("member_signatures", [])
            if isinstance(signature, (list, tuple))
        },
        key=repr,
    )
    return left_members == right_members


def _cross_local_group_correspondence(
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
) -> bool:
    """Return whether two differently named local groups are one unique LLDP edge."""

    a_ports = _group_typed_ports(left)
    b_ports = _group_typed_ports(right)
    if len(a_ports) != 1 or a_ports != b_ports:
        return False
    # The rule is intentionally limited to a resolved/unresolved presentation
    # transition. Two unrelated friendly interfaces must never be joined merely
    # because a device reused a local numeric index.
    resolution = _group_resolution_states(left) | _group_resolution_states(right)
    if not {"resolved", "unresolved"}.issubset(resolution):
        return False
    identities = _group_member_identities(left)
    return bool(identities) and identities == _group_member_identities(right)


def _relationship_record(
    key: tuple[str, str, str],
    left: Sequence[Mapping[str, Any]],
    right: Sequence[Mapping[str, Any]],
    *,
    cross_local: bool = False,
    weak_candidate_move: bool = False,
) -> dict[str, Any]:
    """Build one relationship correspondence record from already matched groups."""

    a_signatures, a_duplicates = _deduplicated_group_signatures(left)
    b_signatures, b_duplicates = _deduplicated_group_signatures(right)
    if not left:
        status = "b_only"
    elif not right:
        status = "a_only"
    elif a_signatures == b_signatures:
        if a_duplicates > b_duplicates:
            status = "duplicate_projection_introduced"
        elif a_duplicates < b_duplicates:
            status = "absorbed_duplicate"
        else:
            status = "same"
    else:
        a_members = {item for signature in a_signatures for item in signature[0]}
        b_members = {item for signature in b_signatures for item in signature[0]}
        if {(item[0], item[1]) for item in a_members} == {
            (item[0], item[1]) for item in b_members
        }:
            status = "protocol_evidence_changed"
        else:
            status = "member_set_changed"

    if weak_candidate_move:
        status = "candidate_move"

    a_local = sorted(
        {str(group.get("local_interface") or "unresolved") for group in left}
    )
    b_local = sorted(
        {str(group.get("local_interface") or "unresolved") for group in right}
    )
    port_resolution = None
    presentation_differences: list[dict[str, Any]] = []
    if cross_local:
        a_resolution = sorted(_group_resolution_states(left))
        b_resolution = sorted(_group_resolution_states(right))
        degraded_side = (
            "a"
            if "unresolved" in a_resolution and "resolved" in b_resolution
            else "b"
            if "unresolved" in b_resolution and "resolved" in a_resolution
            else "unknown"
        )
        port_resolution = {
            "status": "degraded_on_one_side",
            "degraded_side": degraded_side,
            "typed_local_port": sorted(_group_typed_ports(left))[0],
            "a": a_resolution,
            "b": b_resolution,
        }
        presentation_differences = [
            {"path": "local_interface", "a": a_local, "b": b_local},
            {
                "path": "local_port_resolution",
                "a": a_resolution,
                "b": b_resolution,
            },
        ]
    elif weak_candidate_move:
        presentation_differences = [
            {"path": "local_interface", "a": a_local, "b": b_local}
        ]

    (
        change_dimensions,
        member_presence_change,
        member_protocol_changes,
    ) = _relationship_change_details(
        left,
        right,
        presentation_differences=presentation_differences,
        a_duplicates=a_duplicates,
        b_duplicates=b_duplicates,
        weak_candidate_move=weak_candidate_move,
    )

    fingerprint_key: dict[str, Any] = {"key": key}
    if cross_local or weak_candidate_move:
        fingerprint_key["a_local"] = a_local
        fingerprint_key["b_local"] = b_local
        fingerprint_key["correspondence_kind"] = (
            "weak_candidate_move" if weak_candidate_move else "port_resolution"
        )
        if cross_local:
            fingerprint_key["typed_local_port"] = sorted(_group_typed_ports(left))
    return {
        "relationship_component_key": "relationship_correspondence:"
        + stable_fingerprint(fingerprint_key)[:24],
        "status": status,
        "source_correspondence_key": key[0],
        "local_interface": key[1],
        "local_interface_a": a_local,
        "local_interface_b": b_local,
        "interface_kind": key[2],
        "directness": "unresolved",
        "a_groups": copy.deepcopy(list(left)),
        "b_groups": copy.deepcopy(list(right)),
        "a_duplicate_projection_count": a_duplicates,
        "b_duplicate_projection_count": b_duplicates,
        "change_dimensions": change_dimensions,
        "member_presence_change": member_presence_change,
        "member_protocol_changes": member_protocol_changes,
        "presentation_differences": presentation_differences,
        "port_resolution": port_resolution,
        "mobility": (
            {
                "status": "candidate_move",
                "identity_strength": "weak",
                "reason": (
                    "remote identity is insufficient to confirm a physical port move"
                ),
            }
            if weak_candidate_move
            else None
        ),
        "ambiguity_reasons": (
            ["remote identity is insufficient to confirm a physical port move"]
            if weak_candidate_move
            else []
        ),
        "physical_topology_effect": (
            "none"
            if status
            in {
                "same",
                "absorbed_duplicate",
                "duplicate_projection_introduced",
                "protocol_evidence_changed",
            }
            else "not_inferred"
        ),
    }


def _relationship_comparison(
    a_graph: Mapping[str, Any],
    b_graph: Mapping[str, Any],
    a_map: Mapping[str, str],
    b_map: Mapping[str, str],
    components: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    a_groups = _group_set(a_graph, a_map)
    b_groups = _group_set(b_graph, b_map)
    comparisons: list[dict[str, Any]] = []
    exact = sorted(set(a_groups) & set(b_groups))
    for key in exact:
        comparisons.append(_relationship_record(key, a_groups[key], b_groups[key]))

    a_only_keys = sorted(set(a_groups) - set(b_groups))
    b_only_keys = sorted(set(b_groups) - set(a_groups))
    a_candidates: dict[tuple[str, str, str], list[tuple[str, str, str]]] = {}
    b_candidates: dict[tuple[str, str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for a_key in a_only_keys:
        candidates = [
            b_key
            for b_key in b_only_keys
            if a_key[0] == b_key[0]
            and _cross_local_group_correspondence(
                a_groups[a_key], b_groups[b_key]
            )
        ]
        a_candidates[a_key] = candidates
        for b_key in candidates:
            b_candidates[b_key].append(a_key)

    used_a: set[tuple[str, str, str]] = set()
    used_b: set[tuple[str, str, str]] = set()
    for a_key in a_only_keys:
        candidates = a_candidates[a_key]
        if len(candidates) != 1:
            continue
        b_key = candidates[0]
        if len(b_candidates[b_key]) != 1:
            continue
        used_a.add(a_key)
        used_b.add(b_key)
        typed_port = sorted(_group_typed_ports(a_groups[a_key]))[0]
        interface_kind = (
            a_key[2]
            if a_key[2] != "unresolved"
            else b_key[2]
        )
        key = (a_key[0], typed_port.casefold(), interface_kind)
        comparisons.append(
            _relationship_record(
                key,
                a_groups[a_key],
                b_groups[b_key],
                cross_local=True,
            )
        )

    weak_components = {
        str(component.get("component_key") or "")
        for component in components
        if _weak_mobility_component(component)
    }
    remaining_a = [key for key in a_only_keys if key not in used_a]
    remaining_b = [key for key in b_only_keys if key not in used_b]
    weak_a_candidates: dict[
        tuple[str, str, str], list[tuple[str, str, str]]
    ] = {}
    weak_b_candidates: dict[
        tuple[str, str, str], list[tuple[str, str, str]]
    ] = defaultdict(list)
    for a_key in remaining_a:
        candidates = [
            b_key
            for b_key in remaining_b
            if a_key[0] == b_key[0]
            and a_key[2] == b_key[2]
            and _weak_candidate_move_correspondence(
                a_groups[a_key], b_groups[b_key], weak_components
            )
        ]
        weak_a_candidates[a_key] = candidates
        for b_key in candidates:
            weak_b_candidates[b_key].append(a_key)

    for a_key in remaining_a:
        candidates = weak_a_candidates[a_key]
        if len(candidates) != 1:
            continue
        b_key = candidates[0]
        if len(weak_b_candidates[b_key]) != 1:
            continue
        used_a.add(a_key)
        used_b.add(b_key)
        key = (a_key[0], "candidate_move", a_key[2])
        comparisons.append(
            _relationship_record(
                key,
                a_groups[a_key],
                b_groups[b_key],
                weak_candidate_move=True,
            )
        )

    for key in a_only_keys:
        if key not in used_a:
            comparisons.append(_relationship_record(key, a_groups[key], []))
    for key in b_only_keys:
        if key not in used_b:
            comparisons.append(_relationship_record(key, [], b_groups[key]))
    comparisons.sort(key=lambda item: str(item["relationship_component_key"]))
    return comparisons


def _status_counts(records: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = defaultdict(int)
    for record in records:
        result[str(record.get("status") or "unknown")] += 1
    return dict(sorted(result.items()))


def _qualification_counts(records: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    """Count semantic qualifications independently from structural statuses."""

    result: dict[str, int] = defaultdict(int)
    for record in records:
        result[str(record.get("semantic_qualification") or "confirmed")] += 1
    return dict(sorted(result.items()))


def _component_host_refs(component: Mapping[str, Any], side: str) -> set[int]:
    """Return run-local host references represented on one component side."""

    result: set[int] = set()
    entities = component.get(f"{side}_entities")
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, Mapping):
            continue
        refs = entity.get("host_refs")
        for value in refs if isinstance(refs, list) else []:
            if isinstance(value, int) and not isinstance(value, bool):
                result.add(value)
    return result


def _component_entities(
    component: Mapping[str, Any], side: str
) -> list[Mapping[str, Any]]:
    values = component.get(f"{side}_entities")
    return (
        [item for item in values if isinstance(item, Mapping)]
        if isinstance(values, list)
        else []
    )


def _graph_coverage_rows(
    graph: Mapping[str, Any], entity_key: str
) -> list[Mapping[str, Any]]:
    coverage = graph.get("collection_coverage")
    if not isinstance(coverage, Mapping):
        return []
    value = coverage.get(entity_key)
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, Mapping)]
    return []


def _graph_protocol_coverage(
    graph: Mapping[str, Any],
    entities: Sequence[Mapping[str, Any]],
    protocol: str,
) -> tuple[bool, list[dict[str, Any]]]:
    """Return authoritative-negative availability and explicit failed rows.

    Graph schema 2 stores one coverage object per compatibility host projection.
    Any complete projection is sufficient to provide an authoritative negative;
    otherwise every explicit non-complete record is retained for explanation.
    Graph fixtures that predate coverage metadata remain neutral rather than being
    misclassified as failures.
    """

    failures: list[dict[str, Any]] = []
    saw_explicit = False
    for entity in entities:
        entity_key = str(entity.get("entity_key") or "")
        for row in _graph_coverage_rows(graph, entity_key):
            aggregate = row.get(protocol)
            if not isinstance(aggregate, Mapping):
                continue
            table_name = protocol
            table: Mapping[str, Any] = aggregate
            if protocol in {"lldp", "lldpv2"}:
                subtables = aggregate.get("subtables")
                subtables = subtables if isinstance(subtables, Mapping) else {}
                remote_neighbor = subtables.get("remote_neighbor")
                if isinstance(remote_neighbor, Mapping):
                    table_name = f"{protocol}.remote_neighbor"
                    table = remote_neighbor
            saw_explicit = True
            status = str(table.get("status") or "unknown").casefold()
            if status == "complete":
                return True, []
            failures.append(
                {
                    "entity": entity,
                    "table": table_name,
                    "status": status,
                    "message": table.get("message"),
                }
            )
    if not saw_explicit:
        return True, []
    return False, failures


def _graph_incident_key(
    *,
    missing_side: str,
    missing_entity: Mapping[str, Any],
    protocol: str,
    table: str,
    status: str,
) -> str:
    """Use the compatibility incident identity when a host reference is known."""

    refs = missing_entity.get("host_refs")
    values = refs if isinstance(refs, list) else []
    host_refs = [
        value
        for value in values
        if isinstance(value, int) and not isinstance(value, bool)
    ]
    if host_refs:
        payload = {
            "missing_side": missing_side,
            "missing_observer_id": min(host_refs),
            "protocol": protocol,
            "table": table,
            "status": status,
        }
    else:
        payload = {
            "missing_side": missing_side,
            "missing_entity_key": missing_entity.get("entity_key"),
            "protocol": protocol,
            "table": table,
            "status": status,
        }
    return "coverage:" + stable_fingerprint(payload)[:24]


def _graph_coverage_sources(
    *,
    source_component: Mapping[str, Any],
    present_side: str,
    missing_side: str,
    missing_graph: Mapping[str, Any],
    protocols: Iterable[str],
) -> tuple[list[dict[str, Any]], bool]:
    """Return table incidents and whether an independent complete path exists."""

    present_entities = _component_entities(source_component, present_side)
    missing_entities = _component_entities(source_component, missing_side)
    if not missing_entities:
        return [], False
    present_entity = present_entities[0] if present_entities else {}
    sources: list[dict[str, Any]] = []
    complete_path = False
    for protocol in sorted({str(value).casefold() for value in protocols if value}):
        complete, failures = _graph_protocol_coverage(
            missing_graph, missing_entities, protocol
        )
        if complete:
            complete_path = True
            continue
        for failure in failures:
            missing_entity = failure["entity"]
            status = str(failure["status"])
            table_name = str(failure.get("table") or protocol)
            sources.append(
                {
                    "incident_key": _graph_incident_key(
                        missing_side=missing_side,
                        missing_entity=missing_entity,
                        protocol=protocol,
                        table=table_name,
                        status=status,
                    ),
                    "missing_side": missing_side,
                    "observer": {
                        present_side: {
                            "entity_key": present_entity.get("entity_key"),
                            "display_name": present_entity.get("display_name"),
                            "host_refs": list(present_entity.get("host_refs") or []),
                        },
                        missing_side: {
                            "entity_key": missing_entity.get("entity_key"),
                            "display_name": missing_entity.get("display_name"),
                            "host_refs": list(missing_entity.get("host_refs") or []),
                        },
                    },
                    "protocol": protocol,
                    "table": table_name,
                    "status": status,
                    "message": failure.get("message"),
                    "origin": "direct",
                    "recursive_path": [],
                }
            )
    unique = {stable_fingerprint(source): source for source in sources}
    return [unique[key] for key in sorted(unique)], complete_path


def _group_protocols(groups: Sequence[Mapping[str, Any]]) -> set[str]:
    """Return protocol evidence represented by graph relationship groups."""

    result: set[str] = set()
    for group in groups:
        signatures = group.get("member_signatures")
        for signature in signatures if isinstance(signatures, list) else []:
            if not isinstance(signature, (list, tuple)) or len(signature) < 3:
                continue
            protocols = signature[2]
            for protocol in protocols if isinstance(protocols, (list, tuple)) else []:
                value = str(protocol).casefold()
                if value:
                    result.add(value)
    return result


def _remote_components(
    relationship: Mapping[str, Any], side: str
) -> set[str]:
    """Return remote correspondence component keys represented on one side."""

    result: set[str] = set()
    groups = relationship.get(f"{side}_groups")
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, Mapping):
            continue
        signatures = group.get("member_signatures")
        for signature in signatures if isinstance(signatures, list) else []:
            if isinstance(signature, (list, tuple)) and signature:
                result.add(str(signature[0]))
    return result


def _relationship_coverage_sources(
    relationship: Mapping[str, Any],
    *,
    source_component: Mapping[str, Any],
    a_graph: Mapping[str, Any],
    b_graph: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return failed corresponding table evidence for one relationship result."""

    status = str(relationship.get("status") or "unknown")
    raw_a = relationship.get("a_groups")
    raw_b = relationship.get("b_groups")
    a_groups = raw_a if isinstance(raw_a, list) else []
    b_groups = raw_b if isinstance(raw_b, list) else []
    a_members = _group_member_protocols(a_groups)
    b_members = _group_member_protocols(b_groups)
    checks: list[tuple[str, str, Mapping[str, Any], set[str]]] = []
    if status == "a_only":
        checks.extend(("a", "b", b_graph, protocols) for protocols in a_members.values())
    elif status == "b_only":
        checks.extend(("b", "a", a_graph, protocols) for protocols in b_members.values())
    elif status == "protocol_evidence_changed":
        for member_key in sorted(set(a_members) | set(b_members)):
            checks.extend(
                (
                    (
                        "a",
                        "b",
                        b_graph,
                        a_members.get(member_key, set())
                        - b_members.get(member_key, set()),
                    ),
                    (
                        "b",
                        "a",
                        a_graph,
                        b_members.get(member_key, set())
                        - a_members.get(member_key, set()),
                    ),
                )
            )
    elif status == "member_set_changed":
        for member_key in sorted(set(a_members) - set(b_members)):
            checks.append(("a", "b", b_graph, a_members[member_key]))
        for member_key in sorted(set(b_members) - set(a_members)):
            checks.append(("b", "a", a_graph, b_members[member_key]))

    sources: list[dict[str, Any]] = []
    for present_side, missing_side, missing_graph, protocols in checks:
        if not protocols:
            continue
        found, complete_path = _graph_coverage_sources(
            source_component=source_component,
            present_side=present_side,
            missing_side=missing_side,
            missing_graph=missing_graph,
            protocols=protocols,
        )
        # One complete protocol that observed this exact member is an
        # authoritative negative. A failure in another redundant protocol does
        # not turn the same physical observation into an uncertain absence.
        if not complete_path:
            sources.extend(found)
    unique = {
        stable_fingerprint(source): source
        for source in sources
    }
    return [unique[key] for key in sorted(unique)]


def _qualify_entity_components(
    components: Sequence[dict[str, Any]],
    *,
    a_uncertain_host_refs: set[int],
    b_uncertain_host_refs: set[int],
    a_attribute_uncertainty: Mapping[int, Sequence[Mapping[str, Any]]],
    b_attribute_uncertainty: Mapping[int, Sequence[Mapping[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    """Add initial coverage/presentation semantics to entity components.

    Host-reference evidence catches projected entities that compatibility diff has
    already traced to a collection incident. Graph-native relationship propagation
    adds endpoint entities that do not retain compatibility host references.
    """

    uncertain_components: dict[str, list[dict[str, Any]]] = {}
    presentation_statuses = {
        "absorbed_duplicate",
        "duplicate_projection_introduced",
        "cluster_split",
        "cluster_merge",
    }
    ambiguous_statuses = {"same_ambiguous", "cluster_reassociated"}
    for component in components:
        status = str(component.get("status") or "unknown")
        qualification = "confirmed"
        coverage_sources: list[dict[str, Any]] = []
        for host_ref in sorted(_component_host_refs(component, "a")):
            coverage_sources.extend(
                copy.deepcopy(dict(source))
                for source in a_attribute_uncertainty.get(host_ref, ())
            )
        for host_ref in sorted(_component_host_refs(component, "b")):
            coverage_sources.extend(
                copy.deepcopy(dict(source))
                for source in b_attribute_uncertainty.get(host_ref, ())
            )
        if coverage_sources:
            unique = {
                stable_fingerprint(source): source for source in coverage_sources
            }
            coverage_sources = [unique[key] for key in sorted(unique)]
        if status == "a_only" and (
            _component_host_refs(component, "a") & a_uncertain_host_refs
        ):
            qualification = "coverage_uncertain"
        elif status == "b_only" and (
            _component_host_refs(component, "b") & b_uncertain_host_refs
        ):
            qualification = "coverage_uncertain"
        elif status in presentation_statuses:
            qualification = "presentation_only"
        elif status in ambiguous_statuses:
            qualification = "ambiguous"
        elif status in {"changed", "a_only", "b_only"} and coverage_sources:
            # The component remains semantically different, but its missing
            # LLDP-derived attribute is not an authoritative removal because
            # the source observer lacked coverage in that run.  This can alter
            # an existing component or make an identity-derived component
            # appear one-sided.
            qualification = "coverage_uncertain"
        component["semantic_qualification"] = qualification
        component["presence_status"] = status
        component["presence_confidence"] = (
            "coverage_uncertain"
            if qualification == "coverage_uncertain"
            else "ambiguous"
            if qualification == "ambiguous"
            else "confirmed"
        )
        component["coverage_source"] = (
            coverage_sources[0] if len(coverage_sources) == 1 else None
        )
        component["coverage_sources"] = coverage_sources
        if qualification == "coverage_uncertain":
            uncertain_components[str(component.get("component_key") or "")] = (
                copy.deepcopy(coverage_sources)
            )
    return uncertain_components


def _inherited_graph_sources(
    sources: Sequence[Mapping[str, Any]], source_component_key: str
) -> list[dict[str, Any]]:
    """Mark an originating table incident as recursively propagated."""

    result: list[dict[str, Any]] = []
    for source in sources:
        item = copy.deepcopy(dict(source))
        item["origin"] = "recursive"
        path = item.get("recursive_path")
        recursive_path = list(path) if isinstance(path, list) else []
        if not recursive_path or recursive_path[-1] != source_component_key:
            recursive_path.append(source_component_key)
        item["recursive_path"] = recursive_path
        result.append(item)
    return result


def _qualify_relationships(
    relationships: Sequence[dict[str, Any]],
    components: Sequence[dict[str, Any]],
    uncertain_components: dict[str, list[dict[str, Any]]],
    *,
    a_graph: Mapping[str, Any],
    b_graph: Mapping[str, Any],
) -> None:
    """Apply collection confidence and recursively propagate originating incidents.

    A failed protocol table first qualifies one-sided relationships observed by
    that source. Any one-sided managed entity reached through those relationships
    can itself be an observer in recursive discovery, so its downstream one-sided
    relationships inherit the same incident. The fixed-point pass preserves that
    provenance without inferring physical directness.
    """

    presentation_statuses = {
        "absorbed_duplicate",
        "duplicate_projection_introduced",
    }
    ambiguous_statuses = {"same_ambiguous", "candidate_move"}
    component_by_key = {
        str(component.get("component_key") or ""): component
        for component in components
    }

    # The relationship graph is finite. Each successful pass adds at least one
    # one-sided component, so this bound guarantees convergence.
    for _pass in range(max(1, len(components) + 1)):
        propagated = False
        for relationship in relationships:
            status = str(relationship.get("status") or "unknown")
            source_key = str(relationship.get("source_correspondence_key") or "")
            source_component = component_by_key.get(source_key, {})
            explicit_sources = _relationship_coverage_sources(
                relationship,
                source_component=source_component,
                a_graph=a_graph,
                b_graph=b_graph,
            )
            inherited_sources = _inherited_graph_sources(
                uncertain_components.get(source_key, []), source_key
            )
            unique_sources = {
                stable_fingerprint(source): source
                for source in [*explicit_sources, *inherited_sources]
            }
            coverage_sources = [
                unique_sources[key] for key in sorted(unique_sources)
            ]

            qualification = "confirmed"
            if status == "same" and relationship.get("presentation_differences"):
                qualification = "presentation_only"
            elif status in {
                "a_only",
                "b_only",
                "member_set_changed",
                "protocol_evidence_changed",
            } and (coverage_sources or source_key in uncertain_components):
                qualification = "coverage_uncertain"
            elif status in presentation_statuses:
                qualification = "presentation_only"
            elif status in ambiguous_statuses:
                qualification = "ambiguous"

            relationship["semantic_qualification"] = qualification
            relationship["presence_status"] = status
            relationship["presence_confidence"] = (
                "coverage_uncertain"
                if qualification == "coverage_uncertain"
                else "ambiguous"
                if qualification == "ambiguous"
                else "confirmed"
            )
            relationship["coverage_source"] = (
                coverage_sources[0] if len(coverage_sources) == 1 else None
            )
            relationship["coverage_sources"] = coverage_sources
            if qualification != "coverage_uncertain":
                continue

            a_remote = _remote_components(relationship, "a")
            b_remote = _remote_components(relationship, "b")
            if status == "a_only":
                candidates = a_remote
                expected_status = "a_only"
            elif status == "b_only":
                candidates = b_remote
                expected_status = "b_only"
            else:
                candidates = (a_remote - b_remote) | (b_remote - a_remote)
                expected_status = ""

            for component_key in sorted(candidates):
                component = component_by_key.get(component_key)
                if component is None:
                    continue
                component_status = str(component.get("status") or "")
                if expected_status and component_status != expected_status:
                    continue
                if component_status not in {"a_only", "b_only"}:
                    continue
                current_sources = uncertain_components.get(component_key)
                if current_sources is None:
                    uncertain_components[component_key] = copy.deepcopy(
                        coverage_sources
                    )
                    component["semantic_qualification"] = "coverage_uncertain"
                    component["presence_status"] = component_status
                    component["presence_confidence"] = "coverage_uncertain"
                    component["coverage_source"] = (
                        coverage_sources[0] if len(coverage_sources) == 1 else None
                    )
                    component["coverage_sources"] = copy.deepcopy(coverage_sources)
                    propagated = True
                elif not current_sources and coverage_sources:
                    uncertain_components[component_key] = copy.deepcopy(
                        coverage_sources
                    )
                    component["coverage_source"] = (
                        coverage_sources[0] if len(coverage_sources) == 1 else None
                    )
                    component["coverage_sources"] = copy.deepcopy(coverage_sources)
                    propagated = True
        if not propagated:
            break


def compare_topology_graphs(
    a_graph: Any,
    b_graph: Any,
    *,
    changes_only: bool = False,
    a_uncertain_host_refs: set[int] | None = None,
    b_uncertain_host_refs: set[int] | None = None,
    a_attribute_uncertainty: Mapping[
        int, Sequence[Mapping[str, Any]]
    ] | None = None,
    b_attribute_uncertainty: Mapping[
        int, Sequence[Mapping[str, Any]]
    ] | None = None,
) -> dict[str, Any]:
    """Compare two schema-2 topology graphs without forcing one-to-one pairs."""

    if not isinstance(a_graph, Mapping) or not isinstance(b_graph, Mapping):
        return {
            "available": False,
            "authority": {
                "observation_completeness": "unavailable",
                "entity_resolution": "unavailable",
                "physical_topology": "unavailable",
                "directness": "unavailable",
            },
            "message": "one or both discovery documents do not contain a topology graph",
            "has_differences": False,
            "has_resolution_differences": False,
            "has_observed_relationship_differences": False,
            "physical_topology_assessment": "unavailable",
            "summary": {},
            "entity_correspondence": [],
            "relationship_groups": [],
        }
    if a_graph.get("schema_version") != 2 or b_graph.get("schema_version") != 2:
        return {
            "available": False,
            "authority": {
                "observation_completeness": "unavailable",
                "entity_resolution": "unavailable",
                "physical_topology": "unavailable",
                "directness": "unavailable",
            },
            "message": "unsupported topology graph schema",
            "has_differences": False,
            "has_resolution_differences": False,
            "has_observed_relationship_differences": False,
            "physical_topology_assessment": "unavailable",
            "summary": {},
            "entity_correspondence": [],
            "relationship_groups": [],
        }

    components, a_map, b_map = _correspondence_components(a_graph, b_graph)
    relationships = _relationship_comparison(
        a_graph, b_graph, a_map, b_map, components
    )
    uncertain_components = _qualify_entity_components(
        components,
        a_uncertain_host_refs=set(a_uncertain_host_refs or ()),
        b_uncertain_host_refs=set(b_uncertain_host_refs or ()),
        a_attribute_uncertainty=a_attribute_uncertainty or {},
        b_attribute_uncertainty=b_attribute_uncertainty or {},
    )
    _qualify_relationships(
        relationships,
        components,
        uncertain_components,
        a_graph=a_graph,
        b_graph=b_graph,
    )
    unchanged_statuses = {"same", "same_ambiguous"}
    projection_only_statuses = {
        "absorbed_duplicate",
        "duplicate_projection_introduced",
        "cluster_split",
        "cluster_merge",
        "cluster_reassociated",
    }
    relationship_no_topology_statuses = {
        "same",
        "same_ambiguous",
        "absorbed_duplicate",
        "duplicate_projection_introduced",
        "protocol_evidence_changed",
    }
    has_differences = any(
        item["status"] not in unchanged_statuses
        or item.get("semantic_qualification") == "presentation_only"
        for item in components
    ) or any(
        item["status"] not in unchanged_statuses
        or item.get("semantic_qualification") == "presentation_only"
        for item in relationships
    )
    has_resolution_differences = any(
        item["status"] in projection_only_statuses for item in components
    )
    has_observed_relationship_differences = any(
        item["status"] not in relationship_no_topology_statuses
        for item in relationships
    )
    has_confirmed_observed_relationship_differences = any(
        item["status"] not in relationship_no_topology_statuses
        and item.get("semantic_qualification") == "confirmed"
        for item in relationships
    )
    entity_counts = _status_counts(components)
    relationship_counts = _status_counts(relationships)
    entity_qualification_counts = _qualification_counts(components)
    relationship_qualification_counts = _qualification_counts(relationships)
    if changes_only:
        components = [
            item
            for item in components
            if item["status"] not in unchanged_statuses
            or item.get("semantic_qualification") == "presentation_only"
        ]
        relationships = [
            item
            for item in relationships
            if item["status"] not in unchanged_statuses
            or item.get("semantic_qualification") == "presentation_only"
        ]
    a_authority = a_graph.get("authority")
    b_authority = b_graph.get("authority")
    a_authority = dict(a_authority) if isinstance(a_authority, Mapping) else {}
    b_authority = dict(b_authority) if isinstance(b_authority, Mapping) else {}
    observation_completeness = (
        "complete"
        if a_authority.get("observation_completeness") == "complete"
        and b_authority.get("observation_completeness") == "complete"
        else "partial"
    )
    return {
        "available": True,
        "authority": {
            "observation_completeness": observation_completeness,
            "a_observation_completeness": a_authority.get(
                "observation_completeness", "unknown"
            ),
            "b_observation_completeness": b_authority.get(
                "observation_completeness", "unknown"
            ),
            "entity_resolution": "provisional",
            "physical_topology": "not_inferred",
            "directness": "unresolved",
        },
        "message": (
            "Graph differences found" if has_differences else "No graph differences"
        ),
        "has_differences": has_differences,
        "has_resolution_differences": has_resolution_differences,
        "has_observed_relationship_differences": has_observed_relationship_differences,
        "has_confirmed_observed_relationship_differences": (
            has_confirmed_observed_relationship_differences
        ),
        # Directness remains unresolved by policy.  The graph can report changed
        # observations without asserting that a cable or physical adjacency
        # changed.  This field is intentionally categorical rather than boolean.
        "physical_topology_assessment": (
            "not_inferred"
            if has_observed_relationship_differences
            else "no_change_indicated"
        ),
        "summary": {
            "entity_correspondence": entity_counts,
            "relationship_groups": relationship_counts,
            "entity_qualifications": entity_qualification_counts,
            "relationship_qualifications": relationship_qualification_counts,
            "a_projection_fingerprint": a_graph.get("projection_fingerprint"),
            "b_projection_fingerprint": b_graph.get("projection_fingerprint"),
        },
        "entity_correspondence": components,
        "relationship_groups": relationships,
    }
