"""Reconcile compatibility neighbor rows with topology-graph relationships.

The flat learned-neighbor projection and the graph intentionally expose different
units: compatibility rows are observer-directional, while graph records group all
observations on one local interface.  This module joins those views after each has
performed its own conservative comparison.  The join is diagnostic; it never
creates topology evidence that was absent from either source.
"""

from __future__ import annotations

import copy
from collections import defaultdict
from collections.abc import Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any

from lldp_runner.claims import stable_fingerprint
from lldp_runner.identity import normalize_identity_name

_STABLE_GRAPH_STATUSES = {
    "same",
    "same_ambiguous",
    "absorbed_duplicate",
    "duplicate_projection_introduced",
}


@dataclass(frozen=True, slots=True)
class _CompatibilityObservation:
    """One directional compatibility comparison row and its observer context."""

    key: str
    status: str
    row: MutableMapping[str, Any]
    observer_a: Mapping[str, Any]
    observer_b: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _GraphSideMatch:
    """One relationship record member matching one compatibility side."""

    relationship: MutableMapping[str, Any]
    member: Mapping[str, Any]
    score: int


@dataclass(frozen=True, slots=True)
class _GraphPairMatch:
    """One exact A/B graph-member pair backing a compatibility observation."""

    relationship: MutableMapping[str, Any]
    member_key: tuple[str, str]
    score: int


def _text(value: object) -> str:
    """Return normalized comparison text without treating placeholders as identity."""

    return str(value or "").strip().casefold()


def _name(value: object) -> str:
    """Return the repository's conservative normalized identity name."""

    return normalize_identity_name(str(value or "")) or ""


def _int_values(value: object) -> set[int]:
    """Return non-Boolean integer values from a JSON list."""

    if not isinstance(value, list):
        return set()
    return {
        item
        for item in value
        if isinstance(item, int) and not isinstance(item, bool)
    }


def _protocols(value: object) -> set[str]:
    """Return normalized protocol labels from a JSON list."""

    if not isinstance(value, list):
        return set()
    return {_text(item) for item in value if _text(item)}


def _compact_neighbor(value: object) -> dict[str, Any] | None:
    """Return stable relationship identity fields for one compatibility side."""

    if not isinstance(value, Mapping):
        return None
    return {
        "host_ref": value.get("host_ref"),
        "name": value.get("name") or value.get("observed_name"),
        "local_interface": value.get("local_interface"),
        "remote_interface": value.get("remote_interface"),
        "protocols": sorted(_protocols(value.get("protocols"))),
    }


def _observation_key(
    row: Mapping[str, Any],
    observer_a: Mapping[str, Any],
    observer_b: Mapping[str, Any],
) -> str:
    """Build a deterministic key for one compatibility comparison row."""

    payload = {
        "observer_a": observer_a.get("id"),
        "observer_b": observer_b.get("id"),
        "status": row.get("status"),
        "a": _compact_neighbor(row.get("a")),
        "b": _compact_neighbor(row.get("b")),
    }
    return "compatibility_observation:" + stable_fingerprint(payload)[:24]


def _compatibility_observations(
    comparisons: Sequence[MutableMapping[str, Any]],
) -> list[_CompatibilityObservation]:
    """Collect non-stable learned-neighbor rows from paired host comparisons."""

    result: list[_CompatibilityObservation] = []
    for comparison in comparisons:
        observer_a = comparison.get("a")
        observer_b = comparison.get("b")
        observer_a = observer_a if isinstance(observer_a, Mapping) else {}
        observer_b = observer_b if isinstance(observer_b, Mapping) else {}
        neighbors = comparison.get("learned_neighbors")
        for row in neighbors if isinstance(neighbors, list) else []:
            if not isinstance(row, MutableMapping):
                continue
            status = str(row.get("status") or "unknown")
            qualification = str(row.get("semantic_qualification") or "confirmed")
            if status == "same" and qualification == "confirmed":
                continue
            key = _observation_key(row, observer_a, observer_b)
            row["compatibility_observation_key"] = key
            result.append(
                _CompatibilityObservation(
                    key=key,
                    status=status,
                    row=row,
                    observer_a=observer_a,
                    observer_b=observer_b,
                )
            )
    return result


def _projection_refs(
    host_id: object,
    members_by_id: Mapping[int, Sequence[int]],
) -> set[int]:
    """Expand a canonical compatibility host ID to raw graph host references."""

    if not isinstance(host_id, int) or isinstance(host_id, bool):
        return set()
    return {host_id, *members_by_id.get(host_id, ())}


def _identity_macs(identity: object) -> set[str]:
    """Return strict MAC tokens from one graph entity identity object."""

    if not isinstance(identity, Mapping):
        return set()
    values = identity.get("strict_macs")
    if not isinstance(values, list):
        return set()
    return {_text(value) for value in values if _text(value)}


def _row_macs(row: Mapping[str, Any]) -> set[str]:
    """Return MAC-shaped strong edge tokens preserved by a compatibility row."""

    result: set[str] = set()
    for value in (
        row.get("remote_interface"),
        row.get("remote_interface_raw"),
        row.get("name"),
        row.get("observed_name"),
    ):
        text = _text(value)
        compact = text.replace(":", "").replace("-", "").replace(".", "")
        if len(compact) == 12 and all(char in "0123456789abcdef" for char in compact):
            result.add(":".join(compact[index : index + 2] for index in range(0, 12, 2)))
    details = row.get("details")
    if isinstance(details, Mapping):
        for key in (
            "chassis_id",
            "port_id",
            "lldp.chassis_id",
            "lldp.port_id",
            "lldpv2.chassis_id",
            "lldpv2.port_id",
        ):
            text = _text(details.get(key))
            compact = text.replace(":", "").replace("-", "").replace(".", "")
            if len(compact) == 12 and all(
                char in "0123456789abcdef" for char in compact
            ):
                result.add(
                    ":".join(
                        compact[index : index + 2] for index in range(0, 12, 2)
                    )
                )
    return result


def _remote_identity_matches(
    row: Mapping[str, Any],
    member: Mapping[str, Any],
    remote_refs: set[int],
) -> tuple[bool, int]:
    """Return whether remote identity is corroborated and its matching score."""

    row_ref = row.get("host_ref")
    member_refs = _int_values(member.get("remote_host_refs"))
    if isinstance(row_ref, int) and not isinstance(row_ref, bool):
        if remote_refs & member_refs:
            return True, 12

    row_port = _text(row.get("remote_interface") or row.get("remote_interface_raw"))
    member_port = _text(member.get("remote_interface"))
    if row_port and member_port and row_port == member_port:
        return True, 8

    row_macs = _row_macs(row)
    member_macs = _identity_macs(member.get("remote_identity"))
    if row_macs & member_macs:
        return True, 10

    row_names = {
        _name(row.get("name")),
        _name(row.get("observed_name")),
    }
    row_names.discard("")
    identity = member.get("remote_identity")
    member_names = {
        _name(member.get("remote_display_name")),
    }
    if isinstance(identity, Mapping) and isinstance(identity.get("names"), list):
        member_names.update(_name(value) for value in identity["names"])
    member_names.discard("")
    if row_names & member_names:
        return True, 6
    return False, 0


def _graph_side_matches(
    observation: _CompatibilityObservation,
    side: str,
    relationships: Sequence[MutableMapping[str, Any]],
    members_by_id: Mapping[int, Sequence[int]],
) -> list[_GraphSideMatch]:
    """Find graph members compatible with one side of a flat neighbor row."""

    row = observation.row.get(side)
    if not isinstance(row, Mapping):
        return []
    observer = observation.observer_a if side == "a" else observation.observer_b
    observer_refs = _projection_refs(observer.get("id"), members_by_id)
    remote_refs = _projection_refs(row.get("host_ref"), members_by_id)
    local = _text(row.get("local_interface") or row.get("local_interface_raw"))
    row_protocols = _protocols(row.get("protocols"))
    result: list[_GraphSideMatch] = []
    for relationship in relationships:
        groups = relationship.get(f"{side}_groups")
        for group in groups if isinstance(groups, list) else []:
            if not isinstance(group, Mapping):
                continue
            source_refs = _int_values(group.get("source_host_refs"))
            if observer_refs and not observer_refs.intersection(source_refs):
                continue
            group_local = _text(group.get("local_interface"))
            if local and group_local and local != group_local:
                continue
            members = group.get("members")
            for member in members if isinstance(members, list) else []:
                if not isinstance(member, Mapping):
                    continue
                remote_match, score = _remote_identity_matches(
                    row, member, remote_refs
                )
                if not remote_match:
                    continue
                member_protocols = _protocols(member.get("protocols"))
                if row_protocols and member_protocols:
                    if row_protocols == member_protocols:
                        score += 4
                    elif row_protocols.intersection(member_protocols):
                        score += 2
                    else:
                        continue
                if observer_refs.intersection(source_refs):
                    score += 16
                if local and local == group_local:
                    score += 8
                result.append(
                    _GraphSideMatch(
                        relationship=relationship,
                        member=member,
                        score=score,
                    )
                )
    result.sort(
        key=lambda item: (
            -item.score,
            str(item.relationship.get("relationship_component_key") or ""),
            str(item.member.get("remote_component_key") or ""),
        )
    )
    return result


def _expected_graph_statuses(status: str) -> set[str]:
    """Return graph statuses compatible with one compatibility status."""

    return {
        "moved": {"a_only", "b_only", "member_set_changed"},
        "protocol_changed": {
            "protocol_evidence_changed",
            "member_set_changed",
        },
        "management_address_changed": {
            "same",
            "same_ambiguous",
            "member_set_changed",
        },
        "relationship_evidence_changed": {
            "same",
            "same_ambiguous",
            "member_set_changed",
        },
        "changed": {"member_set_changed", "same", "same_ambiguous"},
        "a_only": {"a_only", "member_set_changed"},
        "b_only": {"b_only", "member_set_changed"},
        "uncertain": {
            "a_only",
            "b_only",
            "member_set_changed",
            "protocol_evidence_changed",
            "same",
            "same_ambiguous",
        },
    }.get(status, set())


def _member_key(member: Mapping[str, Any]) -> tuple[str, str]:
    """Return the graph's strong remote component/port identity key."""

    return (
        str(member.get("remote_component_key") or ""),
        _text(member.get("remote_interface")),
    )


def _member_protocol_change_is_recorded(
    relationship: Mapping[str, Any],
    member_key: tuple[str, str],
    a_protocols: set[str],
    b_protocols: set[str],
) -> bool:
    """Return whether a compound graph record explicitly contains this transition.

    A primary ``member_set_changed`` status can mask a simultaneous protocol-set
    change for a different, still-present member.  Schema-12 graph comparisons
    expose those per-member transitions.  Reconciliation requires the exact
    component, remote port, and A/B protocol sets rather than treating every
    member-set change as generic support for a protocol change.
    """

    changes = relationship.get("member_protocol_changes")
    if not isinstance(changes, list):
        return False
    for change in changes:
        if not isinstance(change, Mapping):
            continue
        candidate_key = (
            str(change.get("remote_component_key") or ""),
            _text(change.get("remote_interface")),
        )
        if candidate_key != member_key:
            continue
        if _protocols(change.get("a_protocols")) != a_protocols:
            continue
        if _protocols(change.get("b_protocols")) != b_protocols:
            continue
        return True
    return False


def _paired_member_supported(
    observation: _CompatibilityObservation,
    relationship: Mapping[str, Any],
    a_member: Mapping[str, Any],
    b_member: Mapping[str, Any],
) -> tuple[str, str] | None:
    """Return the exact common member key when a paired observation is supported.

    This guard is intentionally stricter than the general side matcher.  It is
    used for evidence-only observations whose enclosing interface group may also
    contain unrelated membership churn.  Both sides must resolve to the same
    graph correspondence component and remote port, and protocol evidence must
    agree exactly with the compatibility row.
    """

    a_key = _member_key(a_member)
    b_key = _member_key(b_member)
    if not a_key[0] or not a_key[1] or a_key != b_key:
        return None
    a_row = observation.row.get("a")
    b_row = observation.row.get("b")
    if not isinstance(a_row, Mapping) or not isinstance(b_row, Mapping):
        return None
    a_row_protocols = _protocols(a_row.get("protocols"))
    b_row_protocols = _protocols(b_row.get("protocols"))
    a_member_protocols = _protocols(a_member.get("protocols"))
    b_member_protocols = _protocols(b_member.get("protocols"))
    if not a_row_protocols or not b_row_protocols:
        return None
    if a_row_protocols != a_member_protocols:
        return None
    if b_row_protocols != b_member_protocols:
        return None

    relationship_status = str(relationship.get("status") or "unknown")
    if observation.status == "protocol_changed":
        if a_row_protocols == b_row_protocols:
            return None
        if relationship_status == "member_set_changed" and not (
            _member_protocol_change_is_recorded(
                relationship,
                a_key,
                a_row_protocols,
                b_row_protocols,
            )
        ):
            return None
    elif observation.status in {
        "management_address_changed",
        "relationship_evidence_changed",
    }:
        if a_row_protocols != b_row_protocols:
            return None
    else:
        return None
    return a_key


def _select_exact_paired_member_relationship(
    observation: _CompatibilityObservation,
    a_matches: Sequence[_GraphSideMatch],
    b_matches: Sequence[_GraphSideMatch],
    expected: set[str],
) -> tuple[list[MutableMapping[str, Any]], str, list[tuple[str, str]]]:
    """Select one relationship through an exact common-member transition.

    Several graph members can share a local interface.  Candidate pairs are
    therefore deduplicated by relationship plus strong member key and ranked by
    the combined side score.  A tie between different members or relationships
    remains ambiguous rather than being collapsed merely because it occurred on
    one interface.
    """

    candidates: dict[tuple[str, tuple[str, str]], _GraphPairMatch] = {}
    for a_match in a_matches:
        relationship = a_match.relationship
        if str(relationship.get("status") or "unknown") not in expected:
            continue
        ref = str(relationship.get("relationship_component_key") or "")
        for b_match in b_matches:
            b_ref = str(
                b_match.relationship.get("relationship_component_key") or ""
            )
            if not ref or b_ref != ref:
                continue
            member_key = _paired_member_supported(
                observation,
                relationship,
                a_match.member,
                b_match.member,
            )
            if member_key is None:
                continue
            key = (ref, member_key)
            candidate = _GraphPairMatch(
                relationship=relationship,
                member_key=member_key,
                score=a_match.score + b_match.score,
            )
            current = candidates.get(key)
            if current is None or candidate.score > current.score:
                candidates[key] = candidate

    if not candidates:
        return (
            [],
            "conflicting" if a_matches and b_matches else "unmatched",
            [],
        )
    ordered = sorted(
        candidates.values(),
        key=lambda item: (
            -item.score,
            str(item.relationship.get("relationship_component_key") or ""),
            item.member_key,
        ),
    )
    best_score = ordered[0].score
    best = [item for item in ordered if item.score == best_score]
    if len(best) != 1:
        return [], "ambiguous", []
    return [best[0].relationship], "matched", [best[0].member_key]


def _best_relationships(
    matches: Sequence[_GraphSideMatch], expected: set[str]
) -> tuple[list[MutableMapping[str, Any]], str, list[tuple[str, str]]]:
    """Return unique best-scoring graph records and match confidence."""

    filtered = [
        item
        for item in matches
        if not expected or str(item.relationship.get("status")) in expected
    ]
    if not filtered:
        return [], "unmatched", []
    best_score = filtered[0].score
    best = [item for item in filtered if item.score == best_score]
    relationships = {
        str(item.relationship.get("relationship_component_key") or ""): item.relationship
        for item in best
    }
    values = [relationships[key] for key in sorted(relationships)]
    member_key_set: set[tuple[str, str]] = set()
    for item in best:
        member_key = _member_key(item.member)
        if any(member_key):
            member_key_set.add(member_key)
    member_keys = sorted(member_key_set)
    return (
        values,
        "matched" if len(values) == 1 else "ambiguous",
        member_keys,
    )


def _select_relationships(
    observation: _CompatibilityObservation,
    relationships: Sequence[MutableMapping[str, Any]],
    a_members_by_id: Mapping[int, Sequence[int]],
    b_members_by_id: Mapping[int, Sequence[int]],
) -> tuple[list[MutableMapping[str, Any]], str, list[tuple[str, str]]]:
    """Select graph records backing one compatibility observation."""

    expected = _expected_graph_statuses(observation.status)
    a_matches = _graph_side_matches(
        observation, "a", relationships, a_members_by_id
    )
    b_matches = _graph_side_matches(
        observation, "b", relationships, b_members_by_id
    )

    if observation.status in {
        "protocol_changed",
        "management_address_changed",
        "relationship_evidence_changed",
    }:
        return _select_exact_paired_member_relationship(
            observation,
            a_matches,
            b_matches,
            expected,
        )

    a_records, a_state, a_member_keys = _best_relationships(a_matches, expected)
    b_records, b_state, b_member_keys = _best_relationships(b_matches, expected)

    if observation.status == "moved":
        if a_state == "matched" and b_state == "matched":
            remote_a = {
                str(item.member.get("remote_component_key") or "")
                for item in a_matches
                if item.relationship is a_records[0]
                and item.score == a_matches[0].score
            }
            remote_b = {
                str(item.member.get("remote_component_key") or "")
                for item in b_matches
                if item.relationship is b_records[0]
                and item.score == b_matches[0].score
            }
            if remote_a and remote_b and remote_a.isdisjoint(remote_b):
                return [], "conflicting", []
            unique = {
                str(item.get("relationship_component_key") or ""): item
                for item in [*a_records, *b_records]
            }
            return (
                [unique[key] for key in sorted(unique)],
                "matched",
                sorted(set(a_member_keys) | set(b_member_keys)),
            )
        if "ambiguous" in {a_state, b_state}:
            return [], "ambiguous", []
        return [], "unmatched", []

    if a_records and b_records:
        a_keys = {
            str(item.get("relationship_component_key") or "") for item in a_records
        }
        b_keys = {
            str(item.get("relationship_component_key") or "") for item in b_records
        }
        common = a_keys & b_keys
        if len(common) == 1:
            key = next(iter(common))
            by_key = {
                str(item.get("relationship_component_key") or ""): item
                for item in [*a_records, *b_records]
            }
            return (
                [by_key[key]],
                "matched",
                sorted(set(a_member_keys) | set(b_member_keys)),
            )
        if common or "ambiguous" in {a_state, b_state}:
            return [], "ambiguous", []
        return [], "conflicting", []

    records = a_records or b_records
    state = a_state if a_records else b_state
    member_keys = a_member_keys if a_records else b_member_keys
    if len(records) == 1 and state == "matched":
        return records, "matched", member_keys
    if state == "ambiguous":
        return [], "ambiguous", []
    return [], "unmatched", []


def _event_type(status: str) -> str:
    """Translate compatibility status into graph-backed event vocabulary."""

    return {
        "moved": "observed_attachment_changed",
        "protocol_changed": "protocol_evidence_changed",
        "management_address_changed": "management_address_changed",
        "relationship_evidence_changed": "relationship_evidence_changed",
        "a_only": "observed_in_a_only",
        "b_only": "observed_in_b_only",
        "uncertain": "coverage_uncertain",
        "changed": "relationship_changed",
    }.get(status, status)


def _change_scope(status: str) -> str:
    """Return the semantic scope without inferring physical directness."""

    return {
        "moved": "observed_attachment",
        "protocol_changed": "protocol_evidence",
        "management_address_changed": "management_address_evidence",
        "relationship_evidence_changed": "relationship_evidence",
        "a_only": "observed_relationship_presence",
        "b_only": "observed_relationship_presence",
        "uncertain": "collection_coverage",
    }.get(status, "observed_relationship")


def _attachment_change(row: Mapping[str, Any]) -> dict[str, Any] | None:
    """Describe a moved row as an observed attachment-port change."""

    if str(row.get("status")) != "moved":
        return None
    a = row.get("a") if isinstance(row.get("a"), Mapping) else {}
    b = row.get("b") if isinstance(row.get("b"), Mapping) else {}
    return {
        "kind": "local_interface_changed",
        "a_local_interface": a.get("local_interface"),
        "b_local_interface": b.get("local_interface"),
        "remote_interface": a.get("remote_interface") or b.get("remote_interface"),
        "identity_continuity": "confirmed",
        "movement_confidence": "confirmed",
        "relationship_scope": "observed",
        "directness": "unresolved",
        "physical_topology": "not_inferred",
    }


def _event_key(
    event_type: str,
    graph_refs: Sequence[str],
    graph_member_keys: Sequence[tuple[str, str]],
    observation: _CompatibilityObservation,
) -> str:
    """Build a stable event key without folding distinct graph members together."""

    payload: dict[str, Any] = {
        "event_type": event_type,
        "graph_relationship_refs": sorted(graph_refs),
        "graph_member_keys": sorted(graph_member_keys),
    }
    if not graph_refs:
        payload["compatibility_observation"] = observation.key
    return "change_event:" + stable_fingerprint(payload)[:24]


def _graph_qualification(records: Sequence[Mapping[str, Any]]) -> str:
    """Return the most conservative qualification represented by graph records."""

    values = {
        str(item.get("semantic_qualification") or "confirmed") for item in records
    }
    if "coverage_uncertain" in values:
        return "coverage_uncertain"
    if "ambiguous" in values:
        return "ambiguous"
    if "presentation_only" in values:
        return "presentation_only"
    return "confirmed"


def _graph_change_dimensions(record: Mapping[str, Any]) -> set[str]:
    """Return orthogonal graph-change dimensions with legacy-status fallback."""

    raw = record.get("change_dimensions")
    if isinstance(raw, list):
        values = {_text(value) for value in raw if _text(value)}
        if values:
            return values
    status = str(record.get("status") or "unknown")
    return {
        "a_only": {"member_presence"},
        "b_only": {"member_presence"},
        "member_set_changed": {"member_presence"},
        "protocol_evidence_changed": {"protocol_evidence"},
        "candidate_move": {"candidate_attachment"},
    }.get(status, set())


def _claimed_graph_dimensions(
    observation_status: str, record: Mapping[str, Any]
) -> set[str]:
    """Return graph dimensions represented by one compatibility observation."""

    available = _graph_change_dimensions(record)
    if observation_status == "protocol_changed":
        claimed = {"protocol_evidence"}
    elif observation_status in {"moved", "a_only", "b_only"}:
        claimed = {"member_presence", "candidate_attachment"}
    elif observation_status in {"changed", "uncertain"}:
        claimed = available
    else:
        # Management-address and raw relationship-evidence transitions can be
        # linked to a stable member inside a compound relationship, but they do
        # not explain an independent graph member-presence dimension.
        claimed = set()
    return available & claimed


def _event_graph_dimensions(
    records: Sequence[Mapping[str, Any]], observation_status: str
) -> list[str]:
    """Return graph dimensions specifically represented by one event."""

    return sorted(
        {
            dimension
            for record in records
            for dimension in _claimed_graph_dimensions(observation_status, record)
        }
    )


def _graph_only_event_type(record: Mapping[str, Any], dimension: str | None) -> str:
    """Return a stable event type for one unrepresented graph dimension."""

    status = str(record.get("status") or "relationship_changed")
    if dimension == "protocol_evidence":
        return "graph_protocol_evidence_changed"
    if dimension == "candidate_attachment":
        return "graph_candidate_move"
    return "graph_" + status


def _filter_graph_for_changes(graph: MutableMapping[str, Any]) -> None:
    """Apply the existing changes-only projection after cross-view reconciliation."""

    components = graph.get("entity_correspondence")
    if isinstance(components, list):
        graph["entity_correspondence"] = [
            item
            for item in components
            if isinstance(item, Mapping)
            and (
                str(item.get("status")) not in {"same", "same_ambiguous"}
                or str(item.get("semantic_qualification") or "confirmed")
                != "confirmed"
            )
        ]
    relationships = graph.get("relationship_groups")
    if isinstance(relationships, list):
        graph["relationship_groups"] = [
            item
            for item in relationships
            if isinstance(item, Mapping)
            and (
                str(item.get("status")) not in {"same", "same_ambiguous"}
                or str(item.get("semantic_qualification") or "confirmed")
                != "confirmed"
            )
        ]


def reconcile_compatibility_and_graph(
    comparisons: Sequence[MutableMapping[str, Any]],
    graph: MutableMapping[str, Any],
    *,
    a_members_by_id: Mapping[int, Sequence[int]],
    b_members_by_id: Mapping[int, Sequence[int]],
    changes_only: bool,
    unrepresented_one_sided_observation_count: int = 0,
) -> dict[str, Any]:
    """Cross-reference flat changes with graph records and create unique events.

    Every compatibility row remains available for familiar operator output.  A
    graph-backed event is the deduplicated audit unit.  Unmatched or contradictory
    views are reported explicitly rather than silently forcing correspondence.
    """

    raw_relationships = graph.get("relationship_groups")
    relationships = [
        item for item in raw_relationships if isinstance(item, MutableMapping)
    ] if isinstance(raw_relationships, list) else []
    observations = _compatibility_observations(comparisons)
    if graph.get("available") is not True:
        for observation in observations:
            observation.row["cross_view_consistency"] = "unavailable"
            observation.row["graph_relationship_refs"] = []
            observation.row["graph_event_ref"] = None
            observation.row["change_scope"] = _change_scope(observation.status)
            attachment = _attachment_change(observation.row)
            if attachment is not None:
                observation.row["attachment_change"] = attachment
        consistency = {
            "status": "unavailable",
            "compatibility_observation_count": (
                len(observations) + unrepresented_one_sided_observation_count
            ),
            "reconciled_compatibility_observation_count": len(observations),
            "unrepresented_one_sided_observation_count": (
                unrepresented_one_sided_observation_count
            ),
            "matched_observation_count": 0,
            "unmatched_observation_count": 0,
            "ambiguous_observation_count": 0,
            "conflicting_observation_count": 0,
            "graph_only_event_count": 0,
            "change_event_count": 0,
            "all_reported_changes_graph_backed": False,
        }
        return {
            "change_events": [],
            "change_event_summary": {"total": 0, "by_type": {}},
            "cross_view_consistency": consistency,
        }
    events: dict[str, dict[str, Any]] = {}
    claimed_graph_refs: set[str] = set()
    claimed_graph_dimensions: defaultdict[str, set[str]] = defaultdict(set)
    counts: defaultdict[str, int] = defaultdict(int)

    for observation in observations:
        records, match_state, graph_member_keys = _select_relationships(
            observation,
            relationships,
            a_members_by_id,
            b_members_by_id,
        )
        graph_refs = sorted(
            str(item.get("relationship_component_key") or "") for item in records
        )
        graph_qualification = _graph_qualification(records)
        compatibility_qualification = str(
            observation.row.get("semantic_qualification") or "confirmed"
        )
        if (
            match_state == "matched"
            and compatibility_qualification == "confirmed"
            and graph_qualification in {"coverage_uncertain", "ambiguous"}
        ):
            match_state = "conflicting"
        counts[match_state] += 1
        observation.row["cross_view_consistency"] = match_state
        observation.row["graph_relationship_refs"] = graph_refs
        observation.row["change_scope"] = _change_scope(observation.status)
        attachment = _attachment_change(observation.row)
        if attachment is not None:
            observation.row["attachment_change"] = attachment

        event_type = _event_type(observation.status)
        key = _event_key(
            event_type, graph_refs, graph_member_keys, observation
        )
        observation.row["graph_event_ref"] = key
        graph_dimensions = _event_graph_dimensions(records, observation.status)
        event = events.setdefault(
            key,
            {
                "event_key": key,
                "event_type": event_type,
                "change_scope": _change_scope(observation.status),
                "semantic_qualification": compatibility_qualification,
                "cross_view_consistency": match_state,
                "graph_backing": match_state,
                "graph_relationship_refs": graph_refs,
                "graph_member_keys": [
                    {
                        "remote_component_key": member_key[0],
                        "remote_interface": member_key[1],
                    }
                    for member_key in graph_member_keys
                ],
                "graph_change_dimensions": graph_dimensions,
                "compatibility_observation_refs": [],
                "directional_observation_count": 0,
                "reported_difference_depends_on_collection_gap": bool(
                    compatibility_qualification == "coverage_uncertain"
                    or graph_qualification == "coverage_uncertain"
                ),
                "physical_topology_effect": observation.row.get(
                    "physical_topology_effect", "not_inferred"
                ),
                "relationship_scope": "observed",
                "directness": "unresolved",
                "observer": {
                    "a": copy.deepcopy(dict(observation.observer_a)),
                    "b": copy.deepcopy(dict(observation.observer_b)),
                },
                "a": copy.deepcopy(_compact_neighbor(observation.row.get("a"))),
                "b": copy.deepcopy(_compact_neighbor(observation.row.get("b"))),
                "attachment_change": copy.deepcopy(attachment),
            },
        )
        event["compatibility_observation_refs"].append(observation.key)
        event["compatibility_observation_refs"] = sorted(
            set(event["compatibility_observation_refs"])
        )
        event["directional_observation_count"] = len(
            event["compatibility_observation_refs"]
        )
        if event["cross_view_consistency"] == "matched" and match_state != "matched":
            event["cross_view_consistency"] = match_state
            event["graph_backing"] = match_state
        for record in records:
            ref = str(record.get("relationship_component_key") or "")
            claimed_graph_refs.add(ref)
            claimed_graph_dimensions[ref].update(
                _claimed_graph_dimensions(observation.status, record)
            )
            refs = record.setdefault("compatibility_observation_refs", [])
            if isinstance(refs, list) and observation.key not in refs:
                refs.append(observation.key)
                refs.sort()
            event_refs = record.setdefault("change_event_refs", [])
            if isinstance(event_refs, list) and key not in event_refs:
                event_refs.append(key)
                event_refs.sort()

    graph_only_dimensions: list[
        tuple[MutableMapping[str, Any], str | None]
    ] = []
    reportable_dimensions = {
        "member_presence",
        "protocol_evidence",
        "candidate_attachment",
    }
    for record in relationships:
        if str(record.get("status") or "unknown") in _STABLE_GRAPH_STATUSES:
            continue
        ref = str(record.get("relationship_component_key") or "")
        dimensions = _graph_change_dimensions(record) & reportable_dimensions
        if dimensions:
            for dimension in sorted(dimensions - claimed_graph_dimensions[ref]):
                graph_only_dimensions.append((record, dimension))
        elif ref not in claimed_graph_refs:
            graph_only_dimensions.append((record, None))

    for record, dimension in graph_only_dimensions:
        ref = str(record.get("relationship_component_key") or "")
        event_type = _graph_only_event_type(record, dimension)
        key = "change_event:" + stable_fingerprint(
            {
                "event_type": event_type,
                "graph_relationship_refs": [ref],
                "graph_change_dimension": dimension,
            }
        )[:24]
        qualification = str(record.get("semantic_qualification") or "confirmed")
        events[key] = {
            "event_key": key,
            "event_type": event_type,
            "change_scope": "observed_relationship",
            "semantic_qualification": qualification,
            "cross_view_consistency": "graph_only",
            "graph_backing": "graph_only",
            "graph_relationship_refs": [ref],
            "graph_member_keys": [],
            "graph_change_dimensions": [dimension] if dimension else [],
            "compatibility_observation_refs": [],
            "directional_observation_count": 0,
            "reported_difference_depends_on_collection_gap": (
                qualification == "coverage_uncertain"
            ),
            "physical_topology_effect": record.get(
                "physical_topology_effect", "not_inferred"
            ),
            "relationship_scope": "observed",
            "directness": "unresolved",
            "observer": None,
            "a": None,
            "b": None,
            "attachment_change": None,
        }
        record.setdefault("change_event_refs", []).append(key)
    counts["graph_only"] = len(graph_only_dimensions)

    event_values = [events[key] for key in sorted(events)]
    by_type: defaultdict[str, int] = defaultdict(int)
    for event in event_values:
        by_type[str(event["event_type"])] += 1
    consistency_status = (
        "consistent"
        if not any(
            counts.get(name, 0)
            for name in ("unmatched", "ambiguous", "conflicting", "graph_only")
        )
        and not unrepresented_one_sided_observation_count
        else "attention_required"
    )
    consistency = {
        "status": consistency_status,
        "compatibility_observation_count": (
            len(observations) + unrepresented_one_sided_observation_count
        ),
        "reconciled_compatibility_observation_count": len(observations),
        "unrepresented_one_sided_observation_count": (
            unrepresented_one_sided_observation_count
        ),
        "matched_observation_count": counts.get("matched", 0),
        "unmatched_observation_count": counts.get("unmatched", 0),
        "ambiguous_observation_count": counts.get("ambiguous", 0),
        "conflicting_observation_count": counts.get("conflicting", 0),
        "graph_only_event_count": counts.get("graph_only", 0),
        "change_event_count": len(event_values),
        "all_reported_changes_graph_backed": not any(
            counts.get(name, 0)
            for name in ("unmatched", "ambiguous", "conflicting")
        )
        and not unrepresented_one_sided_observation_count,
    }
    if changes_only:
        _filter_graph_for_changes(graph)
    return {
        "change_events": event_values,
        "change_event_summary": {
            "total": len(event_values),
            "by_type": dict(sorted(by_type.items())),
        },
        "cross_view_consistency": consistency,
    }
