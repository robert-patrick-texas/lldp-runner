"""Terminal and JSON rendering for ``lldp-runner diff`` results."""

from __future__ import annotations

import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from typing import Any

from lldp_runner.config import AppConfig
from lldp_runner.discovery_diff import DiffOutcome, outcome_json
from lldp_runner.terminal_style import build_terminal_styles, paint, use_color


def _text(value: Any) -> str:
    """Return compact deterministic single-line text for a diff table cell."""

    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return str(value).replace("\n", "\\n").replace("\r", "\\r")


def _truncate(value: Any, width: int) -> str:
    text = _text(value)
    if len(text) <= width:
        return text
    if width <= 3:
        return text[:width]
    return text[: width - 3] + "..."


def _style_status(status: str, config: AppConfig, color: bool) -> str:
    styles = build_terminal_styles(config.terminal)
    normalized = status.casefold()
    if normalized in {"same", "same_ambiguous", "no_differences"}:
        style = styles.success
    elif normalized in {
        "changed",
        "moved",
        "attachment",
        "observed_attachment_changed",
        "observed_in_a_only",
        "observed_in_b_only",
        "candidate_move",
        "protocol_changed",
        "management_address_changed",
        "relationship_evidence_changed",
        "mgmt-address",
        "differences_found",
        "uncertain",
        "collection_only",
        "presentation_only",
        "evidence_only",
        "presentation_and_collection_only",
        "absorbed_duplicate",
        "duplicate_projection_introduced",
        "cluster_split",
        "cluster_merge",
        "cluster_reassociated",
        "protocol_evidence_changed",
        "member_set_changed",
    }:
        style = styles.warning
    else:
        style = styles.error
    return paint(status, style, color)


def _source_lines(outcome: DiffOutcome) -> list[str]:
    lines: list[str] = []
    if outcome.source_a is not None:
        lines.append(f"A: {outcome.source_a.label}")
        lines.append(f"   {outcome.source_a.path}")
    if outcome.source_b is not None:
        lines.append(f"B: {outcome.source_b.label}")
        lines.append(f"   {outcome.source_b.path}")
    return lines


def _result_header(outcome: DiffOutcome, config: AppConfig, *, color: bool) -> list[str]:
    """Render source/result/warning lines in the stable operator-facing order."""

    styles = build_terminal_styles(config.terminal)
    result_style = (
        styles.success
        if outcome.exit_code == 0
        else styles.warning
        if outcome.exit_code == 1
        else styles.error
    )
    lines = _source_lines(outcome)
    lines.append(f"Result: {paint(outcome.message, result_style, color)}")
    for warning in outcome.warnings:
        lines.append(f"Warning: {paint(warning, styles.warning, color)}")
    return lines


def _id_name_rows(matches: Sequence[Mapping[str, Any]]) -> list[str]:
    width = max([len(str(item.get("id", "-"))) for item in matches] + [2])
    lines = [f"{'ID':>{width}}  Preferred name", f"{'-' * width}  {'-' * 40}"]
    for item in matches:
        lines.append(f"{item.get('id', '-')!s:>{width}}  {item.get('preferred_name') or 'unknown'}")
    return lines


def _summary_table(summary: Mapping[str, Any]) -> list[str]:
    headers = (
        "Category",
        "Same",
        "Changed",
        "Attachment",
        "Protocol",
        "Mgmt Addr",
        "Evidence",
        "A only",
        "B only",
        "Uncertain",
    )
    rows: list[tuple[str, int, int, int, int, int, int, int, int, int | str]] = []
    hosts = summary.get("hosts", {})
    learned = summary.get("learned_neighbors", {})
    if isinstance(hosts, Mapping):
        rows.append(
            (
                "Hosts",
                int(hosts.get("same", 0)),
                int(hosts.get("changed", 0)),
                0,
                0,
                0,
                0,
                int(hosts.get("a_only", 0)),
                int(hosts.get("b_only", 0)),
                int(hosts.get("uncertain", 0)),
            )
        )
    if isinstance(learned, Mapping):
        rows.append(
            (
                "Learned neighbors",
                int(learned.get("same", 0)),
                int(learned.get("changed", 0)),
                int(learned.get("moved", 0)),
                int(learned.get("protocol_changed", 0)),
                int(learned.get("management_address_changed", 0)),
                int(learned.get("relationship_evidence_changed", 0)),
                int(learned.get("a_only", 0)),
                int(learned.get("b_only", 0)),
                int(learned.get("uncertain", 0)),
            )
        )
    widths = [len(item) for item in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    lines = [
        "  ".join(
            str(header).ljust(widths[index]) if index == 0 else str(header).rjust(widths[index])
            for index, header in enumerate(headers)
        ),
        "  ".join("-" * width for width in widths),
    ]
    for row in rows:
        lines.append(
            "  ".join(
                str(value).ljust(widths[index]) if index == 0 else str(value).rjust(widths[index])
                for index, value in enumerate(row)
            )
        )
    return lines


def _graph_summary_table(summary: Mapping[str, Any]) -> list[str]:
    """Render compact counts for graph correspondence and relationship groups."""

    rows: list[tuple[str, str, int]] = []
    for category, label in (
        ("entity_correspondence", "Entity components"),
        ("relationship_groups", "Relationship groups"),
        ("entity_qualifications", "Entity qualification"),
        ("relationship_qualifications", "Relationship qualification"),
    ):
        values = summary.get(category)
        if not isinstance(values, Mapping):
            continue
        for status, count in sorted(values.items()):
            rows.append((label, str(status), int(count)))
    if not rows:
        return ["No graph summary is available."]
    category_width = max(len("Category"), *(len(row[0]) for row in rows))
    status_width = max(len("Status"), *(len(row[1]) for row in rows))
    lines = [
        f"{'Category':<{category_width}}  {'Status':<{status_width}}  {'Count':>5}",
        f"{'-' * category_width}  {'-' * status_width}  {'-' * 5}",
    ]
    lines.extend(
        f"{category:<{category_width}}  {status:<{status_width}}  {count:>5}"
        for category, status, count in rows
    )
    return lines


def _change_event_summary_table(summary: Mapping[str, Any]) -> list[str]:
    """Render unique graph-backed events and cross-view reconciliation health."""

    events = summary.get("change_events")
    consistency = summary.get("cross_view_consistency")
    if not isinstance(events, Mapping) and not isinstance(consistency, Mapping):
        return []
    rows: list[tuple[str, str, int | str]] = []
    if isinstance(events, Mapping):
        by_type = events.get("by_type")
        if isinstance(by_type, Mapping):
            labels = {
                "observed_attachment_changed": "Observed attachment change",
                "observed_in_a_only": "Observed in A only",
                "observed_in_b_only": "Observed in B only",
                "protocol_evidence_changed": "Protocol evidence change",
                "management_address_changed": "Management-address change",
                "relationship_evidence_changed": "Relationship evidence change",
            }
            for status, count in sorted(by_type.items()):
                rows.append(
                    ("Unique change events", labels.get(str(status), str(status)), int(count))
                )
    if isinstance(consistency, Mapping):
        rows.extend(
            [
                (
                    "Cross-view consistency",
                    "status",
                    str(consistency.get("status") or "unknown"),
                ),
                (
                    "Compatibility observations",
                    "matched",
                    int(consistency.get("matched_observation_count", 0)),
                ),
                (
                    "Compatibility observations",
                    "unmatched/ambiguous/conflicting",
                    "/".join(
                        str(int(consistency.get(key, 0)))
                        for key in (
                            "unmatched_observation_count",
                            "ambiguous_observation_count",
                            "conflicting_observation_count",
                        )
                    ),
                ),
                (
                    "Topology graph",
                    "graph-only events",
                    int(consistency.get("graph_only_event_count", 0)),
                ),
            ]
        )
    headers = ("Category", "Status", "Count / result")
    widths = [len(value) for value in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    lines = [
        "  ".join(
            str(value).ljust(widths[index]) if index < 2 else str(value).rjust(widths[index])
            for index, value in enumerate(headers)
        ),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(
            str(value).ljust(widths[index]) if index < 2 else str(value).rjust(widths[index])
            for index, value in enumerate(row)
        )
        for row in rows
    )
    return lines


def _management_health_table(summary: Mapping[str, Any]) -> list[str]:
    """Render compact persistence/new/recovery management-table health counts."""

    values = summary.get("management_address_health")
    if not isinstance(values, Mapping):
        return []
    headers = (
        "A incomplete",
        "B incomplete",
        "Persistent",
        "New in A",
        "Recovered in A",
        "Changed",
    )
    row = (
        int(values.get("a_incomplete_count", 0)),
        int(values.get("b_incomplete_count", 0)),
        int(values.get("persistent_count", 0)),
        int(values.get("new_in_a_count", 0)),
        int(values.get("recovered_in_a_count", 0)),
        int(values.get("changed_count", 0)),
    )
    widths = [max(len(headers[index]), len(str(row[index]))) for index in range(len(row))]
    lines = [
        "  ".join(headers[index].rjust(widths[index]) for index in range(len(headers))),
        "  ".join("-" * width for width in widths),
        "  ".join(str(row[index]).rjust(widths[index]) for index in range(len(row))),
    ]
    for key, label in (
        ("persistent_by_cause", "Persistent causes"),
        ("new_in_a_by_cause", "New in A causes"),
        ("recovered_in_a_by_cause", "Recovered in A causes"),
        ("changed_by_cause", "Changed causes"),
    ):
        causes = values.get(key)
        if isinstance(causes, Mapping) and causes:
            rendered = ", ".join(f"{cause}={int(count)}" for cause, count in sorted(causes.items()))
            lines.append(f"{label}: {rendered}")
    return lines


def _coverage_summary_table(summary: Mapping[str, Any]) -> list[str]:
    """Render aggregate health separately from topology-sensitive coverage."""

    coverage = summary.get("collection_coverage")
    if not isinstance(coverage, Mapping):
        return []
    headers = (
        "Side",
        "Queried",
        "Topo OK",
        "Topo affected",
        "Health partial/failed",
        "Mgmt-only",
        "Other-only",
        "NO_QUERY",
        "OUT_OF_SCOPE",
        "Obscured",
    )
    rows: list[tuple[str, int, int, int, int, int, int, int, int, int]] = []
    for side in ("a", "b"):
        values = coverage.get(side)
        if not isinstance(values, Mapping):
            continue
        rows.append(
            (
                side.upper(),
                int(values.get("actively_queried_count", 0)),
                int(values.get("topology_complete_queried_count", 0)),
                int(values.get("topology_affected_queried_count", 0)),
                int(values.get("aggregate_partial_or_failed_queried_count", 0)),
                int(values.get("management_address_only_incomplete_count", 0)),
                int(values.get("other_health_only_incomplete_count", 0)),
                int(values.get("no_query_count", 0)),
                int(values.get("out_of_scope_count", 0)),
                int(values.get("obscured_downstream_count", 0)),
            )
        )
    if not rows:
        return []
    widths = [len(value) for value in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    lines = [
        "  ".join(
            str(value).ljust(widths[index]) if index == 0 else str(value).rjust(widths[index])
            for index, value in enumerate(headers)
        ),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(
            str(value).ljust(widths[index]) if index == 0 else str(value).rjust(widths[index])
            for index, value in enumerate(row)
        )
        for row in rows
    )
    return lines


def _host_dimension_table(summary: Mapping[str, Any]) -> list[str]:
    """Render entity, presentation, and collection host dimensions separately."""

    dimensions = summary.get("host_dimensions")
    if not isinstance(dimensions, Mapping):
        return []
    labels = {
        "entity_attributes": "Entity/attributes",
        "presentation": "Presentation/evidence",
        "collection": "Collection/provenance",
    }
    rows: list[tuple[str, int, int, int]] = []
    for key in ("entity_attributes", "presentation", "collection"):
        values = dimensions.get(key)
        if not isinstance(values, Mapping):
            continue
        rows.append(
            (
                labels[key],
                int(values.get("same", 0)),
                int(values.get("changed", 0)),
                int(values.get("uncertain", 0)),
            )
        )
    if not rows:
        return []
    headers = ("Dimension", "Same", "Changed", "Uncertain")
    widths = [len(value) for value in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(str(value)))
    lines = [
        "  ".join(
            str(value).ljust(widths[index]) if index == 0 else str(value).rjust(widths[index])
            for index, value in enumerate(headers)
        ),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(
            str(value).ljust(widths[index]) if index == 0 else str(value).rjust(widths[index])
            for index, value in enumerate(row)
        )
        for row in rows
    )
    return lines


def _collection_incident_lines(data: Mapping[str, Any]) -> list[str]:
    """Render the highest-impact originating collection incidents."""

    raw = data.get("collection_incidents")
    if not isinstance(raw, list):
        return []
    incidents = [item for item in raw if isinstance(item, Mapping)]
    if not incidents:
        return []
    maximum = 12
    lines = [
        "Collection incidents",
        "Side  Observer                              Protocol/table                  "
        "Status                Affects diff  Relationships  Entities  Attributes",
        "-" * 150,
    ]
    for item in incidents[:maximum]:
        observers = item.get("observer")
        missing_side = str(item.get("missing_side") or "-").casefold()
        observer = "unknown"
        if isinstance(observers, Mapping):
            selected = observers.get(missing_side)
            if not isinstance(selected, Mapping):
                selected = observers.get("a") or observers.get("b")
            if isinstance(selected, Mapping):
                observer = str(
                    selected.get("preferred_name") or selected.get("display_name") or "unknown"
                )
        protocol = str(item.get("protocol") or "-")
        table = str(item.get("table") or "-")
        protocol_table = (
            table
            if table == protocol or table.startswith(f"{protocol}.")
            else f"{protocol}/{table}"
        )
        relationships = int(item.get("total_affected_relationship_count", 0))
        entities = int(item.get("total_affected_entity_count", 0))
        attributes = int(item.get("affected_attribute_count", 0))
        affects = "yes" if item.get("reported_difference_depends_on_gap") else "no"
        lines.append(
            f"{missing_side.upper():<4}  {_truncate(observer, 36):<36}  "
            f"{_truncate(protocol_table, 32):<32}  "
            f"{_truncate(item.get('status') or '-', 20):<20}  "
            f"{affects:>12}  {relationships:>13}  {entities:>8}  {attributes:>10}"
        )
    if len(incidents) > maximum:
        lines.append(
            f"... {len(incidents) - maximum} additional incident(s) are retained in JSON output."
        )
    return lines


def _graph_change_lines(
    graph: Mapping[str, Any],
    config: AppConfig,
    *,
    color: bool,
    expand_collection_incidents: bool,
) -> list[str]:
    """Render non-one-to-one graph changes without implying direct cabling."""

    lines: list[str] = []
    components = graph.get("entity_correspondence")
    changed_components = (
        [
            item
            for item in components
            if isinstance(item, Mapping)
            and (
                item.get("status") not in {"same", "same_ambiguous"}
                or item.get("semantic_qualification") != "confirmed"
            )
            and (
                expand_collection_incidents
                or item.get("semantic_qualification") != "coverage_uncertain"
                or not item.get("coverage_sources")
            )
        ]
        if isinstance(components, list)
        else []
    )
    if changed_components:
        lines.extend(
            [
                "Graph entity correspondence",
                "Status / qualification                  A entities -> B entities",
            ]
        )
        lines.append("-" * 122)
        for item in changed_components:
            status_text = str(item.get("status") or "changed")
            qualification = str(item.get("semantic_qualification") or "confirmed")
            if qualification != "confirmed":
                status_text = f"{status_text}/{qualification}"
            status = _style_status(status_text[:36].ljust(36), config, color)
            a_values = item.get("a_entities") if isinstance(item.get("a_entities"), list) else []
            b_values = item.get("b_entities") if isinstance(item.get("b_entities"), list) else []
            a_names = (
                ", ".join(
                    str(value.get("display_name") or value.get("entity_key") or "unknown")
                    for value in a_values
                    if isinstance(value, Mapping)
                )
                or "-"
            )
            b_names = (
                ", ".join(
                    str(value.get("display_name") or value.get("entity_key") or "unknown")
                    for value in b_values
                    if isinstance(value, Mapping)
                )
                or "-"
            )
            lines.append(f"{status}  {_truncate(a_names, 38)} -> {_truncate(b_names, 38)}")

    groups = graph.get("relationship_groups")
    changed_groups = (
        [
            item
            for item in groups
            if isinstance(item, Mapping)
            and (
                item.get("status") not in {"same", "same_ambiguous"}
                or item.get("semantic_qualification") != "confirmed"
            )
            and (
                expand_collection_incidents
                or item.get("semantic_qualification") != "coverage_uncertain"
                or not item.get("coverage_sources")
            )
        ]
        if isinstance(groups, list)
        else []
    )
    if changed_groups:
        if lines:
            lines.append("")
        lines.extend(
            [
                "Graph relationship-group changes",
                "Status / qualification                  Interface               Interpretation",
            ]
        )
        lines.append("-" * 112)
        for item in changed_groups:
            status_text = str(item.get("status") or "changed")
            qualification = str(item.get("semantic_qualification") or "confirmed")
            if qualification != "confirmed":
                status_text = f"{status_text}/{qualification}"
            status = _style_status(status_text[:36].ljust(36), config, color)
            interface = _truncate(item.get("local_interface") or "unresolved", 22)
            effect = str(item.get("physical_topology_effect") or "not_inferred")
            lines.append(f"{status}  {interface:<22}  physical_topology_effect={effect}")
    return lines


def _host_table(data: Mapping[str, Any], config: AppConfig, *, color: bool) -> list[str]:
    """Render the macro one-row-per-host comparison table."""

    records: list[dict[str, Any]] = []
    hosts = data.get("hosts", [])
    if isinstance(hosts, list):
        for item in hosts:
            if not isinstance(item, Mapping):
                continue
            a = item.get("a") if isinstance(item.get("a"), Mapping) else {}
            b = item.get("b") if isinstance(item.get("b"), Mapping) else {}
            match = item.get("match") if isinstance(item.get("match"), Mapping) else {}
            records.append(
                {
                    "status": str(item.get("status", "same")),
                    "confidence": str(match.get("confidence", "-")),
                    "a_id": a.get("id", "-"),
                    "a_name": a.get("preferred_name") or "unknown",
                    "b_id": b.get("id", "-"),
                    "b_name": b.get("preferred_name") or "unknown",
                    "host_delta": int(item.get("host_difference_count", 0)),
                    "presentation_delta": int(item.get("presentation_difference_count", 0)),
                    "collection_delta": int(item.get("collection_difference_count", 0)),
                    "neighbor_delta": int(item.get("learned_neighbor_difference_count", 0)),
                }
            )
    for item in data.get("a_only", []) if isinstance(data.get("a_only"), list) else []:
        if isinstance(item, Mapping):
            records.append(
                {
                    "status": "A only",
                    "confidence": "-",
                    "a_id": item.get("id", "-"),
                    "a_name": item.get("preferred_name") or "unknown",
                    "b_id": "-",
                    "b_name": "-",
                    "host_delta": "-",
                    "presentation_delta": "-",
                    "collection_delta": "-",
                    "neighbor_delta": item.get("learned_neighbor_count", 0),
                }
            )
    for item in data.get("b_only", []) if isinstance(data.get("b_only"), list) else []:
        if isinstance(item, Mapping):
            records.append(
                {
                    "status": "B only",
                    "confidence": "-",
                    "a_id": "-",
                    "a_name": "-",
                    "b_id": item.get("id", "-"),
                    "b_name": item.get("preferred_name") or "unknown",
                    "host_delta": "-",
                    "presentation_delta": "-",
                    "collection_delta": "-",
                    "neighbor_delta": item.get("learned_neighbor_count", 0),
                }
            )
    for item in data.get("uncertain", []) if isinstance(data.get("uncertain"), list) else []:
        if not isinstance(item, Mapping):
            continue
        a = item.get("a") if isinstance(item.get("a"), Mapping) else {}
        candidates = item.get("candidates") if isinstance(item.get("candidates"), list) else []
        b_names = ", ".join(
            f"{candidate.get('id')}:{candidate.get('preferred_name') or 'unknown'}"
            for candidate in candidates
            if isinstance(candidate, Mapping)
        )
        records.append(
            {
                "status": "uncertain",
                "confidence": "ambiguous",
                "a_id": a.get("id", "-"),
                "a_name": a.get("preferred_name") or "unknown",
                "b_id": "?",
                "b_name": b_names or "?",
                "host_delta": "?",
                "presentation_delta": "?",
                "collection_delta": "?",
                "neighbor_delta": "?",
            }
        )

    if not records:
        return ["No host rows to display."]
    width = max(90, min(shutil.get_terminal_size((140, 24)).columns, 180))
    name_width = max(16, min(38, (width - 77) // 2))
    header = (
        f"{'Status':<10} {'Confidence':<9} {'A ID':>6}  "
        f"{'A Preferred name':<{name_width}}  "
        f"{'B ID':>6}  {'B Preferred name':<{name_width}}  "
        f"{'Entity':>6}  {'Pres':>4}  {'Coll':>4}  {'Nbr':>4}"
    )
    lines = [header, "-" * len(header)]
    for item in records:
        raw_status = str(item["status"])
        display_status = _style_status(raw_status, config, color)
        visible_status = raw_status[:10].ljust(10)
        if color:
            display_status = _style_status(visible_status, config, color)
        else:
            display_status = visible_status
        confidence = str(item["confidence"])[:9].ljust(9)
        lines.append(
            f"{display_status} {confidence} {item['a_id']!s:>6}  "
            f"{_truncate(item['a_name'], name_width):<{name_width}}  "
            f"{item['b_id']!s:>6}  "
            f"{_truncate(item['b_name'], name_width):<{name_width}}  "
            f"{item['host_delta']!s:>6}  "
            f"{item['presentation_delta']!s:>4}  "
            f"{item['collection_delta']!s:>4}  "
            f"{item['neighbor_delta']!s:>4}"
        )
    return lines


def _neighbor_name(item: Mapping[str, Any] | None) -> str:
    if item is None:
        return "-"
    return str(item.get("name") or item.get("observed_name") or "unknown")


def _neighbor_port(item: Mapping[str, Any] | None, key: str) -> str:
    if item is None:
        return "-"
    raw = f"{key}_raw"
    return str(item.get(key) or item.get(raw) or "-")


def _neighbor_change_table(
    title: str,
    neighbors: Sequence[Mapping[str, Any]],
    config: AppConfig,
    *,
    color: bool,
    expand_collection_incidents: bool = True,
) -> list[str]:
    changed = [
        item
        for item in neighbors
        if str(item.get("status")) != "same"
        or str(item.get("semantic_qualification") or "confirmed") != "confirmed"
        or bool(item.get("presentation_differences"))
        if expand_collection_incidents
        or not (
            str(item.get("semantic_qualification") or "") == "coverage_uncertain"
            and bool(item.get("coverage_sources"))
        )
    ]
    if not changed:
        return []
    lines = [title]
    header = (
        f"{'Status':<12}  {'A Local':<18}  {'A Neighbor':<28}  {'A Remote':<18}  "
        f"{'B Local':<18}  {'B Neighbor':<28}  {'B Remote':<18}"
    )
    lines.extend([header, "-" * len(header)])
    for item in changed:
        a = item.get("a") if isinstance(item.get("a"), Mapping) else None
        b = item.get("b") if isinstance(item.get("b"), Mapping) else None
        raw_status = str(item.get("status", "changed"))
        qualification = str(item.get("semantic_qualification") or "confirmed")
        if raw_status == "same" and qualification != "confirmed":
            raw_status = qualification
        if raw_status == "protocol_changed":
            display_status = "protocol"
        elif raw_status == "moved":
            display_status = "attachment"
        elif raw_status == "management_address_changed":
            display_status = "mgmt-address"
        elif raw_status == "relationship_evidence_changed":
            display_status = "evidence"
        else:
            display_status = raw_status
        status = _style_status(display_status[:12].ljust(12), config, color)
        lines.append(
            f"{status}  {_truncate(_neighbor_port(a, 'local_interface'), 18):<18}  "
            f"{_truncate(_neighbor_name(a), 28):<28}  "
            f"{_truncate(_neighbor_port(a, 'remote_interface'), 18):<18}  "
            f"{_truncate(_neighbor_port(b, 'local_interface'), 18):<18}  "
            f"{_truncate(_neighbor_name(b), 28):<28}  "
            f"{_truncate(_neighbor_port(b, 'remote_interface'), 18):<18}"
        )
        protocol_change = item.get("protocol_change")
        if isinstance(protocol_change, Mapping):
            left_protocols = protocol_change.get("a")
            right_protocols = protocol_change.get("b")
            if isinstance(left_protocols, list) and isinstance(right_protocols, list):
                lines.append(
                    "           protocols: "
                    f"{','.join(str(value) for value in left_protocols)} -> "
                    f"{','.join(str(value) for value in right_protocols)}"
                )
        management_change = item.get("management_address_change")
        if isinstance(management_change, Mapping):
            added = management_change.get("added")
            removed = management_change.get("removed")
            added_text = ",".join(str(value) for value in added) if isinstance(added, list) else "-"
            removed_text = (
                ",".join(str(value) for value in removed) if isinstance(removed, list) else "-"
            )
            lines.append(
                "           management addresses: "
                f"added={added_text or '-'} removed={removed_text or '-'}"
            )
            lines.append(
                "           management-address confidence: "
                f"{management_change.get('confidence') or '-'}; "
                f"{management_change.get('rationale') or '-'}"
            )
        differences = item.get("differences")
        if isinstance(differences, list):
            for difference in differences:
                if isinstance(difference, Mapping):
                    if difference.get("path") == "protocols" and isinstance(
                        protocol_change, Mapping
                    ):
                        continue
                    if isinstance(management_change, Mapping) and (
                        difference.get("path") == "observed_addresses"
                        or str(difference.get("path") or "").endswith(".remote_addresses")
                    ):
                        continue
                    lines.append(
                        f"           {difference.get('path')}: "
                        f"{_text(difference.get('a'))} -> {_text(difference.get('b'))}"
                    )
        presentation = item.get("presentation_differences")
        if isinstance(presentation, list):
            for difference in presentation:
                if isinstance(difference, Mapping):
                    lines.append(
                        f"           presentation {difference.get('path')}: "
                        f"{_text(difference.get('a'))} -> "
                        f"{_text(difference.get('b'))}"
                    )
        effect = item.get("physical_topology_effect")
        if effect is not None:
            lines.append(f"           physical topology effect: {_text(effect)}")
        attachment = item.get("attachment_change")
        if isinstance(attachment, Mapping):
            lines.append(
                "           observed attachment: "
                f"{attachment.get('b_local_interface') or '-'} -> "
                f"{attachment.get('a_local_interface') or '-'}; "
                "physical directness not inferred"
            )
        event_ref = item.get("graph_event_ref")
        if event_ref:
            lines.append(
                "           graph event: "
                f"{event_ref}; consistency="
                f"{item.get('cross_view_consistency') or 'unknown'}"
            )
        coverage_sources = item.get("coverage_sources")
        if isinstance(coverage_sources, list):
            for source in coverage_sources:
                if not isinstance(source, Mapping):
                    continue
                observer = source.get("missing_observer")
                observer_name = (
                    observer.get("preferred_name") if isinstance(observer, Mapping) else "unknown"
                )
                lines.append(
                    "           coverage: "
                    f"{observer_name or 'unknown'} "
                    f"{source.get('protocol') or '-'}/"
                    f"{source.get('table') or '-'} "
                    f"{source.get('status') or '-'}"
                )
        uncertainty = item.get("uncertainty_reasons")
        if isinstance(uncertainty, list):
            for reason in uncertainty:
                lines.append(f"           uncertainty: {_text(reason)}")
    return lines


def _field_table(differences: Sequence[Mapping[str, Any]]) -> list[str]:
    """Render host fields while distinguishing change from missing coverage."""

    if not differences:
        return []
    path_width = min(
        52,
        max(8, max(len(str(item.get("path", ""))) for item in differences)),
    )
    kind_width = min(
        16,
        max(4, max(len(str(item.get("kind", "changed"))) for item in differences)),
    )
    lines = [
        f"{'Field':<{path_width}}  {'Result':<{kind_width}}  {'A':<32}  {'B':<32}",
        f"{'-' * path_width}  {'-' * kind_width}  {'-' * 32}  {'-' * 32}",
    ]
    for item in differences:
        kind = str(item.get("kind") or "changed")
        lines.append(
            f"{_truncate(item.get('path'), path_width):<{path_width}}  "
            f"{_truncate(kind, kind_width):<{kind_width}}  "
            f"{_truncate(item.get('a'), 32):<32}  {_truncate(item.get('b'), 32):<32}"
        )
        sources = item.get("coverage_sources")
        if not isinstance(sources, list):
            continue
        for source in sources:
            if not isinstance(source, Mapping):
                continue
            observer = source.get("observer")
            missing_side = str(source.get("missing_side") or "-").casefold()
            observer_name = "unknown"
            if isinstance(observer, Mapping):
                selected = observer.get(missing_side)
                if not isinstance(selected, Mapping):
                    selected = observer.get("a") or observer.get("b")
                if isinstance(selected, Mapping):
                    observer_name = str(
                        selected.get("preferred_name") or selected.get("display_name") or "unknown"
                    )
            lines.append(
                "  coverage: "
                f"{missing_side.upper()} {_truncate(observer_name, 36)} "
                f"{source.get('protocol') or '-'}/{source.get('table') or '-'} "
                f"status={source.get('status') or '-'} "
                f"origin={source.get('origin') or 'direct'}"
            )
    return lines


def _render_macro(
    outcome: DiffOutcome,
    config: AppConfig,
    *,
    color: bool,
    summary_only: bool = False,
    expand_collection_incidents: bool = False,
) -> list[str]:
    data = outcome.data if isinstance(outcome.data, Mapping) else {}
    lines = _result_header(outcome, config, color=color)
    if outcome.status in {"error", "comparison_unavailable"}:
        return lines
    summary = data.get("summary")
    if isinstance(summary, Mapping):
        lines.extend(["", "Summary"])
        lines.extend(_summary_table(summary))
        dimension_lines = _host_dimension_table(summary)
        if dimension_lines:
            lines.extend(["", "Host comparison dimensions"])
            lines.extend(dimension_lines)
        coverage_lines = _coverage_summary_table(summary)
        if coverage_lines:
            lines.extend(["", "Collection coverage"])
            lines.extend(coverage_lines)
        graph_summary = summary.get("topology_graph")
        if isinstance(graph_summary, Mapping):
            lines.extend(["", "Topology graph summary"])
            lines.extend(_graph_summary_table(graph_summary))
        event_lines = _change_event_summary_table(summary)
        if event_lines:
            lines.extend(["", "Graph-backed observed change events"])
            lines.extend(event_lines)
        management_lines = _management_health_table(summary)
        if management_lines:
            lines.extend(["", "Management-address collection health"])
            lines.extend(management_lines)
    incident_lines = _collection_incident_lines(data)
    if incident_lines:
        lines.extend(["", *incident_lines])
    if summary_only:
        return lines
    graph = data.get("topology_graph")
    if isinstance(graph, Mapping):
        graph_lines = _graph_change_lines(
            graph,
            config,
            color=color,
            expand_collection_incidents=expand_collection_incidents,
        )
        if graph_lines:
            lines.extend(["", *graph_lines])
    lines.extend(["", "Compatibility host comparison"])
    lines.extend(_host_table(data, config, color=color))

    hosts = data.get("hosts")
    if isinstance(hosts, list):
        for host in hosts:
            if not isinstance(host, Mapping):
                continue
            dimension_sections = (
                ("Host entity/attribute changes", host.get("host_differences")),
                ("Host presentation/evidence changes", host.get("presentation_differences")),
                ("Host collection/provenance changes", host.get("collection_differences")),
            )
            a = host.get("a") if isinstance(host.get("a"), Mapping) else {}
            b = host.get("b") if isinstance(host.get("b"), Mapping) else {}
            emitted_label = False
            for title, raw_differences in dimension_sections:
                if not isinstance(raw_differences, list) or not raw_differences:
                    continue
                if not emitted_label:
                    lines.extend(
                        [
                            "",
                            "Host detail dimensions: "
                            f"{a.get('preferred_name')} / {b.get('preferred_name')}",
                        ]
                    )
                    emitted_label = True
                lines.append(title)
                lines.extend(
                    _field_table([item for item in raw_differences if isinstance(item, Mapping)])
                )
            neighbors = host.get("learned_neighbors")
            if not isinstance(neighbors, list) or not any(
                isinstance(item, Mapping)
                and (
                    item.get("status") != "same"
                    or item.get("semantic_qualification") != "confirmed"
                    or bool(item.get("presentation_differences"))
                )
                for item in neighbors
            ):
                continue
            label = (
                f"Learned neighbor changes: {a.get('preferred_name')} / {b.get('preferred_name')}"
            )
            lines.append("")
            rendered_neighbors = _neighbor_change_table(
                label,
                neighbors,
                config,
                color=color,
                expand_collection_incidents=expand_collection_incidents,
            )
            if rendered_neighbors:
                lines.extend(rendered_neighbors)
    if not expand_collection_incidents:
        collapsed_neighbors = sum(
            1
            for host in data.get("hosts", [])
            if isinstance(host, Mapping)
            for item in host.get("learned_neighbors", [])
            if isinstance(item, Mapping)
            and item.get("semantic_qualification") == "coverage_uncertain"
            and bool(item.get("coverage_sources"))
        )
        graph = data.get("topology_graph")
        collapsed_graph_entities = 0
        collapsed_graph_relationships = 0
        if isinstance(graph, Mapping):
            components = graph.get("entity_correspondence")
            if isinstance(components, list):
                collapsed_graph_entities = sum(
                    1
                    for item in components
                    if isinstance(item, Mapping)
                    and item.get("semantic_qualification") == "coverage_uncertain"
                    and bool(item.get("coverage_sources"))
                )
            groups = graph.get("relationship_groups")
            if isinstance(groups, list):
                collapsed_graph_relationships = sum(
                    1
                    for item in groups
                    if isinstance(item, Mapping)
                    and item.get("semantic_qualification") == "coverage_uncertain"
                    and bool(item.get("coverage_sources"))
                )
        if collapsed_neighbors or collapsed_graph_entities or collapsed_graph_relationships:
            lines.extend(
                [
                    "",
                    "Collapsed derivative coverage-uncertain rows under the "
                    "collection incidents above: "
                    f"compatibility_neighbors={collapsed_neighbors}, "
                    f"graph_entities={collapsed_graph_entities}, "
                    f"graph_relationships={collapsed_graph_relationships}. "
                    "Use --expand-collection-incidents to show them.",
                ]
            )
    return lines


def _render_host(
    outcome: DiffOutcome,
    config: AppConfig,
    *,
    color: bool,
    summary_only: bool = False,
    expand_collection_incidents: bool = False,
) -> list[str]:
    data = outcome.data if isinstance(outcome.data, Mapping) else {}
    lines = _result_header(outcome, config, color=color)
    if outcome.status == "multiple_matches_first_data_set":
        lines.extend(["", "Multiple records matched:"])
        matches = data.get("matches")
        if isinstance(matches, list):
            lines.extend(_id_name_rows([item for item in matches if isinstance(item, Mapping)]))
        return lines
    if outcome.status == "multiple_matches_second_data_set":
        label = outcome.source_b.label if outcome.source_b is not None else "second data set"
        lines.extend(["", f"Multiple records matched in {label}:"])
        matches = data.get("matches")
        if isinstance(matches, list):
            lines.extend(_id_name_rows([item for item in matches if isinstance(item, Mapping)]))
        return lines
    if outcome.status == "identity_uncertain_second_data_set":
        label = outcome.source_b.label if outcome.source_b is not None else "second data set"
        lines.extend(["", f"Identity uncertain in {label}:"])
        matches = data.get("matches")
        if isinstance(matches, list):
            lines.extend(_id_name_rows([item for item in matches if isinstance(item, Mapping)]))
        return lines
    if outcome.status == "no_match_first_data_set":
        label = outcome.source_a.label if outcome.source_a is not None else "first data set"
        lines.append(f"No match in the first data set ({label}) was found to compare.")
        return lines
    if outcome.status == "no_match_second_data_set":
        label = outcome.source_b.label if outcome.source_b is not None else "second data set"
        lines.append(f"No match in the second data set ({label}) was found to compare.")
        return lines

    host = data.get("host")
    if not isinstance(host, Mapping):
        return lines
    a = host.get("a") if isinstance(host.get("a"), Mapping) else {}
    b = host.get("b") if isinstance(host.get("b"), Mapping) else {}
    lines.extend(
        [
            "",
            f"Host: A {a.get('id')} {a.get('preferred_name')}  <->  "
            f"B {b.get('id')} {b.get('preferred_name')}",
        ]
    )
    if summary_only:
        lines.append(
            "Status dimensions: "
            f"entity={host.get('host_status') or '-'} "
            f"presentation={host.get('presentation_status') or '-'} "
            f"collection={host.get('collection_status') or '-'}"
        )
        return lines
    differences = host.get("host_differences")
    if isinstance(differences, list) and differences:
        lines.append("")
        lines.append("Host entity/attribute changes")
        lines.extend(_field_table([item for item in differences if isinstance(item, Mapping)]))
    presentation = host.get("presentation_differences")
    if isinstance(presentation, list) and presentation:
        lines.extend(["", "Host presentation/evidence changes"])
        lines.extend(_field_table([item for item in presentation if isinstance(item, Mapping)]))
    collection = host.get("collection_differences")
    if isinstance(collection, list) and collection:
        lines.extend(["", "Host collection/provenance changes"])
        lines.extend(_field_table([item for item in collection if isinstance(item, Mapping)]))
    if (
        outcome.status == "no_differences"
        and not differences
        and not presentation
        and not collection
    ):
        lines.append(
            "No host detail, collection, presentation, or neighbor differences were found."
        )

    learned = host.get("learned_neighbors")
    if isinstance(learned, list):
        rendered = _neighbor_change_table(
            "Learned neighbor changes",
            learned,
            config,
            color=color,
            expand_collection_incidents=expand_collection_incidents,
        )
        if rendered:
            lines.extend(["", *rendered])
    observed = host.get("observed_by_neighbors")
    if isinstance(observed, list):
        rendered = _neighbor_change_table(
            "Observed_by neighbor changes",
            observed,
            config,
            color=color,
            expand_collection_incidents=expand_collection_incidents,
        )
        if rendered:
            lines.extend(["", *rendered])
    return lines


def render_diff(
    config: AppConfig,
    outcome: DiffOutcome,
    *,
    json_output: bool,
    json_indent: int,
    summary_only: bool = False,
    expand_collection_incidents: bool = False,
    stream: Any = sys.stdout,
) -> str:
    """Render one diff outcome as terminal text or valid machine-readable JSON."""

    if json_output:
        return json.dumps(outcome_json(outcome), indent=json_indent, ensure_ascii=False)
    color = use_color(stream, config.terminal)
    if outcome.mode == "macro":
        return "\n".join(
            _render_macro(
                outcome,
                config,
                color=color,
                summary_only=summary_only,
                expand_collection_incidents=expand_collection_incidents,
            )
        )
    return "\n".join(
        _render_host(
            outcome,
            config,
            color=color,
            summary_only=summary_only,
            expand_collection_incidents=expand_collection_incidents,
        )
    )
