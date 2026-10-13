"""Render selected records from finalized LLDP-Runner discovery JSON.

Human renderers are terminal-width aware, use whitespace-padded columns, and
apply ANSI color only for an interactive TTY unless ``NO_COLOR`` is set.
Machine-readable CSV/JSON output never contains ANSI escape sequences.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import shutil
import sys
from collections.abc import Mapping, Sequence
from typing import Any, cast

from lldp_runner.config import AppConfig
from lldp_runner.discovery_query import DiscoveryDocument
from lldp_runner.neighbor_table import (
    NeighborTableWidths,
    format_neighbor_header,
    format_neighbor_row,
    plan_neighbor_widths,
)
from lldp_runner.terminal_style import (
    TerminalStyles,
    build_terminal_styles,
    format_title_line,
    paint,
    use_color,
)
from lldp_runner.textutil import safe_output_text
from lldp_runner.timeutil import format_iso_wall_clock

NeighborDirection = str


def _one_line(value: Any) -> str:
    """Convert an arbitrary stored value to safe compact terminal text."""

    if value is None or value == "":
        return "-"
    if isinstance(value, list):
        text = ";".join(_one_line(item) for item in value if item not in (None, ""))
        return text or "-"
    if isinstance(value, Mapping):
        text = ";".join(f"{key}={_one_line(item)}" for key, item in value.items())
        return text or "-"
    return " ".join(safe_output_text(value).split()) or "-"


def _truncate(value: Any, width: int) -> str:
    """Return safe one-line text truncated to a visible terminal width."""

    text = _one_line(value)
    if width <= 1:
        return text[:width]
    return text if len(text) <= width else text[: width - 1] + "…"


def _system(host: Mapping[str, Any]) -> Mapping[str, Any]:
    """Return the host's system mapping or an empty mapping when absent."""

    value = host.get("system")
    return value if isinstance(value, Mapping) else {}


def _addresses(host: Mapping[str, Any], family: str) -> list[str]:
    """Return normalized textual addresses for one host/address family."""

    addresses = host.get("addresses")
    if not isinstance(addresses, Mapping):
        return []
    values = addresses.get(family, [])
    return [str(value) for value in values] if isinstance(values, list) else []


def _uptime_seconds(system: Mapping[str, Any]) -> str:
    """Render SYSTEM-MIB uptime ticks as seconds when the field is available."""

    ticks = system.get("sys_uptime_ticks")
    try:
        return f"{int(ticks) / 100.0:.2f}" if ticks is not None else "-"
    except (TypeError, ValueError):
        return "-"


def _document_timestamp(document: DiscoveryDocument) -> str | None:
    """Return the source discovery generation time in the configured timezone.

    The viewer deliberately uses persisted ``discovery.generated`` provenance.
    Missing, malformed, or timezone-naive values are treated as unavailable
    rather than falling back to file metadata or the current clock.
    """

    discovery = document.payload.get("discovery")
    if not isinstance(discovery, Mapping):
        return None
    return format_iso_wall_clock(discovery.get("generated"))


def _neighbor_lists(host: Mapping[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return validated learned and observed_by neighbor dictionaries."""

    def records(name: str) -> list[dict[str, Any]]:
        """Return mapping elements from one named neighbor-array field."""

        value = host.get(name, [])
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    return records("learned_neighbors"), records("observed_by_neighbors")


def selected_neighbor_sections(
    host: Mapping[str, Any],
    neighbor_mode: str | None,
) -> list[tuple[NeighborDirection, list[dict[str, Any]]]]:
    """Choose neighbor directions using default fallback or explicit selection.

    Args:
        host: Selected discovery host record.
        neighbor_mode: ``None`` for default learned-then-observed_by fallback, or
            explicit ``learned``, ``observed_by``, or ``both``.

    Returns:
        Ordered ``(direction, records)`` sections. Explicit ``learned`` never
        falls back when empty. ``both`` always returns learned first.
    """

    learned, observed_by = _neighbor_lists(host)
    if neighbor_mode == "learned":
        return [("learned", learned)]
    if neighbor_mode == "observed_by":
        return [("observed_by", observed_by)]
    if neighbor_mode == "both":
        return [("learned", learned), ("observed_by", observed_by)]
    if learned:
        return [("learned", learned)]
    return [("observed_by", observed_by)] if observed_by else []


_GRAPH_SECTION_ORDER = (
    "single_observation",
    "shared_chassis_logical_members",
    "overlay_observations",
    "multiple_neighbor_observations",
)
_GRAPH_SECTION_META = {
    "single_observation": ("A", "Single observed relationship"),
    "shared_chassis_logical_members": (
        "V",
        "Shared chassis logical members",
    ),
    "overlay_observations": ("O", "Overlay observations"),
    "multiple_neighbor_observations": (
        "M",
        "Multiple neighbor observations (directness unresolved)",
    ),
}


def _topology_graph(document: DiscoveryDocument) -> Mapping[str, Any]:
    """Return the observation-complete topology graph or an empty mapping.

    ``show-neighbors`` reads finalized JSON rather than SQLite.  Keeping this
    helper defensive lets an operator inspect a partially written or hand-edited
    document without an opaque traceback.
    """

    value = document.payload.get("topology_graph")
    if not isinstance(value, Mapping):
        return {}
    authority = value.get("authority")
    if not isinstance(authority, Mapping):
        return {}
    if authority.get("observation_projection") != "authoritative":
        return {}
    return value


def _graph_entities(document: DiscoveryDocument) -> dict[str, Mapping[str, Any]]:
    """Index graph entities by stable entity key for terminal rendering."""

    graph = _topology_graph(document)
    values = graph.get("entities", [])
    if not isinstance(values, list):
        return {}
    return {
        str(item["entity_key"]): item
        for item in values
        if isinstance(item, Mapping) and item.get("entity_key")
    }


def _graph_source_entity_key(document: DiscoveryDocument, host: Mapping[str, Any]) -> str | None:
    """Return the logical graph entity containing the selected host projection."""

    host_id = host.get("id")
    if not isinstance(host_id, int) or isinstance(host_id, bool):
        return None
    for key, entity in _graph_entities(document).items():
        refs = entity.get("host_refs", [])
        if (
            entity.get("entity_type") in {"logical_system", "observed_system"}
            and isinstance(refs, list)
            and host_id in refs
        ):
            return key
    return None


def _graph_relationship_groups(
    document: DiscoveryDocument, host: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    """Return stable learned-relationship groups for one selected host."""

    source_key = _graph_source_entity_key(document, host)
    if source_key is None:
        return []
    graph = _topology_graph(document)
    values = graph.get("relationship_groups", [])
    groups = (
        [
            item
            for item in values
            if isinstance(item, Mapping) and item.get("source_entity_key") == source_key
        ]
        if isinstance(values, list)
        else []
    )
    return sorted(
        groups,
        key=lambda item: (
            _GRAPH_SECTION_ORDER.index(str(item.get("classification")))
            if str(item.get("classification")) in _GRAPH_SECTION_ORDER
            else len(_GRAPH_SECTION_ORDER),
            str(item.get("local_interface") or "").casefold(),
            str(item.get("group_key") or ""),
        ),
    )


def _graph_management(member: Mapping[str, Any], entities: Mapping[str, Mapping[str, Any]]) -> str:
    """Select one management address from the remote graph entity."""

    entity = entities.get(str(member.get("remote_entity_key") or ""), {})
    identity = entity.get("identity", {})
    if not isinstance(identity, Mapping):
        return "-"
    values = identity.get("addresses", [])
    return str(values[0]) if isinstance(values, list) and values else "-"


def _graph_protocol_text(member: Mapping[str, Any], *, code: str | None) -> str:
    """Return deterministic protocol text, optionally prefixed by a view label."""

    values = member.get("protocols", [])
    protocol = (
        ",".join(str(value) for value in values) if isinstance(values, list) else str(values or "-")
    )
    multiplicity = member.get("multiplicity")
    if isinstance(multiplicity, int) and multiplicity > 1:
        protocol = f"{protocol} x{multiplicity}"
    return f"{code}:{protocol}" if code else protocol


def _graph_rows(
    document: DiscoveryDocument,
    groups: Sequence[Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    """Flatten graph groups while preserving canonical relationship order."""

    graph = _topology_graph(document)
    values = graph.get("relationships", [])
    relationship_by_key = (
        {
            str(item["relationship_key"]): item
            for item in values
            if isinstance(item, Mapping) and item.get("relationship_key")
        }
        if isinstance(values, list)
        else {}
    )
    rows: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for group in groups:
        keys = group.get("relationship_keys")
        if isinstance(keys, list):
            for key in keys:
                member = relationship_by_key.get(str(key))
                if member is not None:
                    rows.append((group, member))
            continue
        # Defensive fallback for a hand-edited document while schema validation
        # remains responsible for rejecting incompatible formal input.
        members = group.get("members", [])
        if isinstance(members, list):
            rows.extend((group, member) for member in members if isinstance(member, Mapping))
    return rows


def _append_graph_relationship_tables(
    lines: list[str],
    config: AppConfig,
    document: DiscoveryDocument,
    host: Mapping[str, Any],
    *,
    relationship_view: str,
    color: bool,
    width: int,
    styles: TerminalStyles,
) -> bool:
    """Render graph-projected learned relationships and return whether any existed.

    The graph deliberately reports observations rather than guessing that every
    CDP or LLDP advertisement is a direct cable.  Multiple advertisements on one
    interface are therefore visible as a discrepancy that Network Operations can
    investigate without LLDP-Runner inventing a downstream path.
    """

    groups = _graph_relationship_groups(document, host)
    rows = _graph_rows(document, groups)
    if not rows:
        return False
    entities = _graph_entities(document)
    widths = plan_neighbor_widths(
        width,
        configured_local=config.output.neighbor_local_width,
        configured_remote_port=config.output.neighbor_remote_port_width,
        local_values=(_one_line(group.get("local_interface")) for group, _member in rows),
        remote_port_values=(_one_line(member.get("remote_interface")) for _group, member in rows),
        management_values=(_graph_management(member, entities) for _group, member in rows),
    )

    def append_rows(
        selected: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
        *,
        code: str | None,
        indent: bool,
    ) -> None:
        for group, member in selected:
            local = _one_line(group.get("local_interface"))
            if indent:
                local = f"  {local}"
            lines.append(
                format_neighbor_row(
                    widths,
                    local=local,
                    protocol=_graph_protocol_text(member, code=code),
                    neighbor=_one_line(member.get("remote_name") or "unknown"),
                    remote_port=_one_line(member.get("remote_interface")),
                    management=_graph_management(member, entities),
                    protocol_style=lambda cell: paint(cell, styles.learned, color),
                )
            )

    lines.append("-" * min(width, 120))
    if relationship_view == "combined":
        lines.append(
            "Relationship labels: A=observed relationship, V=shared-chassis logical "
            "member, O=overlay, M=multiple-neighbor discrepancy"
        )
        lines.append(
            _neighbor_header(widths, label="Graph", label_style=styles.learned, color=color)
        )
        lines.append("-" * widths.table)
        for classification in _GRAPH_SECTION_ORDER:
            selected = [row for row in rows if row[0].get("classification") == classification]
            if not selected:
                continue
            code = _GRAPH_SECTION_META[classification][0]
            append_rows(selected, code=code, indent=False)
        return True

    for section_index, classification in enumerate(_GRAPH_SECTION_ORDER):
        selected = [row for row in rows if row[0].get("classification") == classification]
        if not selected:
            continue
        if section_index or lines[-1] != "-" * min(width, 120):
            lines.append("-" * min(width, 120))
        _code, title = _GRAPH_SECTION_META[classification]
        lines.append(paint(title, styles.heading, color))
        if classification == "multiple_neighbor_observations":
            lines.append(
                "  Review required: more than one learned system is associated with "
                "this local interface; directness is not inferred."
            )
        lines.append(_neighbor_header(widths, label=None, label_style=styles.learned, color=color))
        lines.append("-" * widths.table)
        append_rows(
            selected,
            code=None,
            indent=classification != "single_observation",
        )
    return True


def _neighbor_management(
    neighbor: Mapping[str, Any],
    *,
    direction: NeighborDirection,
    document: DiscoveryDocument,
) -> str:
    """Resolve the most useful management address for one neighbor row.

    Learned records carry management addresses advertised by the remote peer in
    ``observed_addresses``. An observed_by record instead describes the host that
    observed the selected device; its observer management address is therefore
    taken from the referenced host record when available.
    """

    if direction == "learned":
        addresses = neighbor.get("observed_addresses")
        if isinstance(addresses, list) and addresses:
            return str(addresses[0])
    host_ref = neighbor.get("host_ref")
    if isinstance(host_ref, int):
        remote = document.hosts_by_id.get(host_ref)
        if remote is not None:
            values = _addresses(remote, "ipv4") or _addresses(remote, "ipv6")
            if values:
                return values[0]
    return "-"


def _protocol_text(neighbor: Mapping[str, Any]) -> str:
    """Return a comma-separated stable protocol label for one neighbor record."""

    values = neighbor.get("protocols", [])
    if isinstance(values, list):
        return ",".join(str(value) for value in values) or "-"
    return str(values) if values else "-"


def _neighbor_header(
    widths: NeighborTableWidths,
    *,
    label: str | None,
    label_style: str,
    color: bool,
) -> str:
    """Build the shared neighbor header with an optional right-aligned section label."""

    columns = format_neighbor_header(widths)
    if label is None:
        return columns
    # Place the direction marker at the far right of the planned visible table
    # width. The label is applied after width planning so ANSI bytes never affect
    # alignment calculations.
    visible_width = max(widths.table, len(columns))
    padded = columns.ljust(visible_width)
    start = visible_width - len(label)
    if start > padded.rfind("Mgmt") + len("Mgmt"):
        return f"{padded[:start]}{paint(label, label_style, color)}"
    return f"{columns}  {paint(label, label_style, color)}"


def _neighbor_row(
    neighbor: Mapping[str, Any],
    *,
    direction: NeighborDirection,
    document: DiscoveryDocument,
    widths: NeighborTableWidths,
    color: bool,
    styles: TerminalStyles,
) -> str:
    """Render one learned/observed_by row through the shared table formatter."""

    style = styles.learned if direction == "learned" else styles.observed_by
    return format_neighbor_row(
        widths,
        local=_one_line(neighbor.get("local_interface") or neighbor.get("local_interface_raw")),
        protocol=_protocol_text(neighbor),
        neighbor=_one_line(neighbor.get("name") or "unknown"),
        remote_port=_one_line(
            neighbor.get("remote_interface") or neighbor.get("remote_interface_raw")
        ),
        management=_one_line(
            _neighbor_management(neighbor, direction=direction, document=document)
        ),
        protocol_style=lambda cell: paint(cell, style, color),
    )


def _summary_lines(
    document: DiscoveryDocument,
    host: Mapping[str, Any],
    *,
    color: bool,
    width: int,
    styles: TerminalStyles,
) -> list[str]:
    """Build compact system summary lines for one stored host record."""

    system = _system(host)
    platform = " ".join(
        str(value)
        for value in (system.get("manufacturer"), system.get("model"), system.get("version"))
        if value
    )
    state = str(host.get("state") or "-")
    state_style = styles.success if state.casefold() == "complete" else styles.warning
    stack_members = system.get("stack_members", [])
    member_count = len(stack_members) if isinstance(stack_members, list) else 0
    timestamp = _document_timestamp(document)
    line_width = min(width, 120)
    return [
        format_title_line(
            "LLDP-Runner discovery record",
            f"(json {timestamp if timestamp is not None else 'unknown-time'})",
            width=line_width,
            title_style=styles.heading,
            color=color,
        ),
        "=" * line_width,
        f"ID:              {host.get('id', '-')}",
        f"Preferred name:  {_truncate(host.get('preferred_name'), max(20, width - 17))}",
        f"Query target:    {_truncate(host.get('queried_as'), max(20, width - 17))}",
        f"Classification:  {_truncate(host.get('classification'), max(20, width - 17))}",
        f"State:           {paint(state, state_style, color)}",
        f"IPv4:            {_truncate(_addresses(host, 'ipv4'), max(20, width - 17))}",
        f"IPv6:            {_truncate(_addresses(host, 'ipv6'), max(20, width - 17))}",
        f"System name:     {_truncate(system.get('sys_name'), max(20, width - 17))}",
        f"Platform:        {_truncate(platform or '-', max(20, width - 17))}",
        f"Serial:          {_truncate(system.get('serial_number'), max(20, width - 17))}",
        f"Uptime seconds:  {_uptime_seconds(system)}",
        f"Stack members:   {member_count}",
    ]


def _append_compatibility_neighbor_table(
    lines: list[str],
    config: AppConfig,
    host: Mapping[str, Any],
    document: DiscoveryDocument,
    *,
    neighbor_mode: str | None,
    color: bool,
    width: int,
    styles: TerminalStyles,
) -> None:
    """Append selected learned/observed_by sections using shared width planning."""

    sections = selected_neighbor_sections(host, neighbor_mode)
    selected_rows = [(direction, neighbor) for direction, values in sections for neighbor in values]
    selected_neighbors = [neighbor for _direction, neighbor in selected_rows]
    widths = plan_neighbor_widths(
        width,
        configured_local=config.output.neighbor_local_width,
        configured_remote_port=config.output.neighbor_remote_port_width,
        local_values=(
            _one_line(neighbor.get("local_interface") or neighbor.get("local_interface_raw"))
            for neighbor in selected_neighbors
        ),
        remote_port_values=(
            _one_line(neighbor.get("remote_interface") or neighbor.get("remote_interface_raw"))
            for neighbor in selected_neighbors
        ),
        management_values=(
            _neighbor_management(
                neighbor,
                direction=direction,
                document=document,
            )
            for direction, neighbor in selected_rows
        ),
    )
    labeled = neighbor_mode in {"both", "observed_by"} or (
        neighbor_mode is None and sections and sections[0][0] == "observed_by"
    )
    if not sections:
        lines.append("-" * min(width, 120))
        lines.append("No learned or observed_by neighbors are available")
        return

    for index, (direction, neighbors) in enumerate(sections):
        if index == 0:
            lines.append("-" * min(width, 120))
        else:
            lines.append("-" * min(width, 120))
        label: str | None = None
        if labeled or neighbor_mode == "both":
            label = "Learned" if direction == "learned" else "Observed_by"
        style = styles.learned if direction == "learned" else styles.observed_by
        lines.append(_neighbor_header(widths, label=label, label_style=style, color=color))
        lines.append("-" * widths.table)
        for neighbor in neighbors:
            lines.append(
                _neighbor_row(
                    neighbor,
                    direction=direction,
                    document=document,
                    widths=widths,
                    color=color,
                    styles=styles,
                )
            )
        if not neighbors:
            label_text = "learned" if direction == "learned" else "observed_by"
            lines.append(f"No {label_text} neighbors are available")


def _append_neighbor_table(
    lines: list[str],
    config: AppConfig,
    host: Mapping[str, Any],
    document: DiscoveryDocument,
    *,
    neighbor_mode: str | None,
    relationship_view: str,
    color: bool,
    width: int,
    styles: TerminalStyles,
) -> None:
    """Append graph relationships or fall back to the flat compatibility view.

    Learned relationships use the observation-complete graph projection.  ``observed_by`` remains
    available from the compatibility host projection until inverse graph views
    are introduced in a later release.
    """

    graph_rendered = False
    if neighbor_mode != "observed_by":
        graph_rendered = _append_graph_relationship_tables(
            lines,
            config,
            document,
            host,
            relationship_view=relationship_view,
            color=color,
            width=width,
            styles=styles,
        )
    if graph_rendered:
        if neighbor_mode == "both":
            _append_compatibility_neighbor_table(
                lines,
                config,
                host,
                document,
                neighbor_mode="observed_by",
                color=color,
                width=width,
                styles=styles,
            )
        return
    _append_compatibility_neighbor_table(
        lines,
        config,
        host,
        document,
        neighbor_mode=neighbor_mode,
        color=color,
        width=width,
        styles=styles,
    )


def render_table(
    config: AppConfig,
    document: DiscoveryDocument,
    host: Mapping[str, Any],
    *,
    neighbor_mode: str | None,
    relationship_view: str | None = None,
    system_only: bool,
    stream: Any = sys.stdout,
) -> str:
    """Render the default compact stored-discovery table view.

    Args:
        document: Complete discovery document for neighbor host-reference lookup.
        host: Exactly one selected host record.
        neighbor_mode: Default fallback or explicit neighbor direction selection.
        system_only: Suppress all neighbor sections when true.
        stream: Output stream used only to determine ANSI/TTY capabilities.

    Returns:
        Human-readable terminal text with aligned neighbor columns.
    """

    color = use_color(stream, config.terminal)
    styles = build_terminal_styles(config.terminal)
    width = max(72, min(shutil.get_terminal_size((120, 24)).columns, 160))
    lines = _summary_lines(document, host, color=color, width=width, styles=styles)
    if not system_only:
        _append_neighbor_table(
            lines,
            config,
            host,
            document,
            neighbor_mode=neighbor_mode,
            relationship_view=(relationship_view or config.output.relationship_view),
            color=color,
            width=width,
            styles=styles,
        )
    return "\n".join(lines)


def _detail_field(lines: list[str], label: str, value: Any, *, indent: str = "") -> None:
    """Append one label/value detail line while keeping output grep-friendly."""

    lines.append(f"{indent}{label:<20}{_one_line(value)}")


def _append_mapping_details(
    lines: list[str],
    title: str,
    value: Mapping[str, Any],
    *,
    color: bool,
    width: int,
    styles: TerminalStyles,
) -> None:
    """Append sorted non-neighbor mapping fields for a detail-view section."""

    lines.append("=" * min(width, 120))
    lines.append(paint(title, styles.heading, color))
    for key in sorted(value):
        item = value[key]
        if key == "stack_members" and isinstance(item, list):
            _detail_field(lines, "stack_members:", f"{len(item)} member(s)")
            for index, member in enumerate(item, start=1):
                if not isinstance(member, Mapping):
                    continue
                lines.append(paint(f"  Stack member {index}", styles.bold, color))
                fields = cast(Mapping[str, Any], member)
                for member_key in sorted(fields):
                    _detail_field(lines, f"{member_key}:", fields[member_key], indent="    ")
            continue
        _detail_field(lines, f"{key}:", item)


def render_detail(
    config: AppConfig,
    document: DiscoveryDocument,
    host: Mapping[str, Any],
    *,
    neighbor_mode: str | None,
    relationship_view: str | None = None,
    system_only: bool,
    stream: Any = sys.stdout,
) -> str:
    """Render a scrolling detailed view of one persisted host record."""

    color = use_color(stream, config.terminal)
    styles = build_terminal_styles(config.terminal)
    width = max(72, min(shutil.get_terminal_size((120, 24)).columns, 160))
    lines = _summary_lines(document, host, color=color, width=width, styles=styles)
    base = {
        key: value
        for key, value in host.items()
        if key not in {"system", "snmp", "icmp", "learned_neighbors", "observed_by_neighbors"}
    }
    _append_mapping_details(lines, "Host details", base, color=color, width=width, styles=styles)
    system = _system(host)
    if system:
        _append_mapping_details(
            lines, "System details", system, color=color, width=width, styles=styles
        )
    snmp = host.get("snmp")
    if isinstance(snmp, Mapping):
        _append_mapping_details(
            lines, "SNMP details", snmp, color=color, width=width, styles=styles
        )
    icmp = host.get("icmp")
    if icmp not in (None, [], {}):
        lines.append("=" * min(width, 120))
        lines.append(paint("ICMP details", styles.heading, color))
        _detail_field(lines, "icmp:", icmp)

    if not system_only:
        sections = selected_neighbor_sections(host, neighbor_mode)
        _append_neighbor_table(
            lines,
            config,
            host,
            document,
            neighbor_mode=neighbor_mode,
            relationship_view=(relationship_view or config.output.relationship_view),
            color=color,
            width=width,
            styles=styles,
        )
        for direction, neighbors in sections:
            if not neighbors:
                continue
            title = (
                "Learned neighbor detail"
                if direction == "learned"
                else "Observed_by neighbor detail"
            )
            lines.append("=" * min(width, 120))
            style = styles.learned if direction == "learned" else styles.observed_by
            lines.append(paint(title, style, color))
            for index, neighbor in enumerate(neighbors, start=1):
                lines.append(paint(f"Neighbor {index}", styles.bold, color))
                for key in sorted(neighbor):
                    _detail_field(lines, f"{key}:", neighbor[key], indent="  ")
    return "\n".join(lines)


def _csv_comment_value(value: Any) -> str:
    """Return compact comma-safe metadata text for a CSV comment line."""

    return _one_line(value).replace(",", ";")


def render_csv(
    document: DiscoveryDocument,
    host: Mapping[str, Any],
    *,
    neighbor_mode: str | None,
    system_only: bool,
) -> str:
    """Render two metadata comments followed by selected neighbor CSV rows.

    ``system_only`` intentionally returns only the two ``#`` comment lines: no
    CSV header or neighbor rows are emitted when the operator explicitly asks for
    host/system information without topology detail.
    """

    system = _system(host)
    timestamp = _document_timestamp(document) or "unknown"
    lines = [
        (
            f"# id={_csv_comment_value(host.get('id'))},"
            f"preferred_name={_csv_comment_value(host.get('preferred_name'))},"
            f"query_target={_csv_comment_value(host.get('queried_as'))},"
            f"state={_csv_comment_value(host.get('state'))},"
            f"timestamp={_csv_comment_value(timestamp)}"
        ),
        (
            f"# classification={_csv_comment_value(host.get('classification'))},"
            f"ipv4={_csv_comment_value(_addresses(host, 'ipv4'))},"
            f"ipv6={_csv_comment_value(_addresses(host, 'ipv6'))},"
            f"model={_csv_comment_value(system.get('model'))},"
            f"serial_number={_csv_comment_value(system.get('serial_number'))}"
        ),
    ]
    if system_only:
        return "\n".join(lines)

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "direction",
            "local_interface",
            "protocol",
            "neighbor",
            "remote_port",
            "mgmt",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for direction, neighbors in selected_neighbor_sections(host, neighbor_mode):
        for neighbor in neighbors:
            writer.writerow(
                {
                    "direction": direction,
                    "local_interface": neighbor.get("local_interface")
                    or neighbor.get("local_interface_raw")
                    or "",
                    "protocol": _protocol_text(neighbor),
                    "neighbor": neighbor.get("name") or "unknown",
                    "remote_port": neighbor.get("remote_interface")
                    or neighbor.get("remote_interface_raw")
                    or "",
                    "mgmt": _neighbor_management(
                        neighbor,
                        direction=direction,
                        document=document,
                    ),
                }
            )
    return "\n".join(lines) + "\n" + buffer.getvalue().rstrip("\n")


def render_json(
    host: Mapping[str, Any],
    *,
    neighbor_mode: str | None,
    system_only: bool,
    indent: int,
) -> str:
    """Render one standalone host JSON record with selected neighbor content.

    Args:
        host: Exactly one selected discovery host object.
        neighbor_mode: Default fallback or explicit direction selection.
        system_only: Remove both neighbor arrays entirely when true.
        indent: Pretty-print indentation from effective output configuration.

    Returns:
        JSON text containing the original host ``id`` and no outer discovery
        document wrapper. When neighbors are requested, unselected directions are
        represented by empty arrays so the host-record schema remains recognizable.
    """

    payload = copy.deepcopy(dict(host))
    if system_only:
        payload.pop("learned_neighbors", None)
        payload.pop("observed_by_neighbors", None)
    else:
        sections = dict(selected_neighbor_sections(host, neighbor_mode))
        payload["learned_neighbors"] = sections.get("learned", [])
        payload["observed_by_neighbors"] = sections.get("observed_by", [])
    return json.dumps(payload, indent=indent, sort_keys=False, ensure_ascii=False)


def render_ambiguous_matches(hosts: Sequence[Mapping[str, Any]]) -> str:
    """Render ID/preferred-name choices for an ambiguous search result."""

    id_width = max(2, *(len(str(host.get("id", ""))) for host in hosts))
    lines = ["Multiple records matched:", "", f"{'ID':>{id_width}}  Preferred name"]
    lines.append(f"{'-' * id_width}  {'-' * 40}")
    for host in hosts:
        lines.append(
            f"{host.get('id', '-')!s:>{id_width}}  {_one_line(host.get('preferred_name'))}"
        )
    return "\n".join(lines)


def render_selected_host(
    config: AppConfig,
    document: DiscoveryDocument,
    host: Mapping[str, Any],
    *,
    output_format: str,
    neighbor_mode: str | None,
    relationship_view: str | None = None,
    system_only: bool,
    json_indent: int,
    stream: Any = sys.stdout,
) -> str:
    """Dispatch one selected host to the requested discovery-view renderer."""

    if output_format == "detail":
        return render_detail(
            config,
            document,
            host,
            neighbor_mode=neighbor_mode,
            relationship_view=relationship_view,
            system_only=system_only,
            stream=stream,
        )
    if output_format == "csv":
        return render_csv(
            document,
            host,
            neighbor_mode=neighbor_mode,
            system_only=system_only,
        )
    if output_format == "json":
        return render_json(
            host,
            neighbor_mode=neighbor_mode,
            system_only=system_only,
            indent=json_indent,
        )
    return render_table(
        config,
        document,
        host,
        neighbor_mode=neighbor_mode,
        relationship_view=relationship_view,
        system_only=system_only,
        stream=stream,
    )
