"""stdout renderers for single-device LLDP/CDP inspection.

Machine-readable renderers are deliberately independent of terminal width and
never emit ANSI escapes. Human renderers use ANSI color only for an interactive
TTY and honor the conventional ``NO_COLOR`` environment variable. All renderers
avoid blank spacer lines so captured output remains compact and grep-friendly.
"""

from __future__ import annotations

import csv
import io
import json
import re
import shutil
import sys
from typing import Any

from lldp_runner.config import AppConfig
from lldp_runner.inspection import InspectionResult, inspection_json, neighbor_record
from lldp_runner.models import NeighborObservation
from lldp_runner.neighbor_table import (
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
from lldp_runner.timeutil import format_iso_wall_clock, iso_now


def _clean(value: Any) -> str:
    """Convert arbitrary renderer input into safe, compact display text.

    Args:
        value: Scalar, collection, mapping, or ``None`` supplied by inspection data.

    Returns:
        Sanitized text, using ``-`` for empty values and semicolons for nested
        collection/map separators.
    """

    if value is None:
        return "-"
    if isinstance(value, (list, tuple, set)):
        text = ";".join(_clean(item) for item in value if item not in (None, ""))
        return text or "-"
    if isinstance(value, dict):
        text = ";".join(f"{key}={_clean(item)}" for key, item in value.items())
        return text or "-"
    return safe_output_text(value) or "-"


def _one_line(value: Any) -> str:
    """Collapse sanitized output text onto one whitespace-normalized line.

    Args:
        value: Renderer value accepted by :func:`_clean`.

    Returns:
        Single-line safe text suitable for tables, comments, or CSV cells.
    """

    return " ".join(_clean(value).split())


def _truncate(value: Any, width: int) -> str:
    """Fit one display value within a visible terminal-column budget.

    Args:
        value: Value converted through :func:`_one_line`.
        width: Maximum visible character count.

    Returns:
        Original text when it fits, otherwise an ellipsis-terminated truncation.
    """

    text = _one_line(value)
    if width <= 1:
        return text[:width]
    if len(text) <= width:
        return text
    return text[: width - 1] + "…"


def _protocols(obs: NeighborObservation) -> list[str]:
    """Return de-duplicated neighbor discovery protocols in display priority order.

    Args:
        obs: Neighbor observation whose merged details may list multiple protocols.

    Returns:
        Protocol names ordered CDP, LLDP, LLDPv2, then unknown names alphabetically.
    """

    values = obs.details.get("protocols", [obs.protocol])
    if not isinstance(values, list):
        values = [str(values)]
    order = {"cdp": 0, "lldp": 1, "lldpv2": 2}
    return sorted(
        dict.fromkeys(str(item) for item in values),
        key=lambda item: (order.get(item, 99), item),
    )


def _neighbor_name(obs: NeighborObservation) -> str:
    """Choose the best human identifier available for one remote neighbor.

    Args:
        obs: Neighbor observation containing names, chassis ID, and addresses.

    Returns:
        Remote name, chassis ID, first management address, or ``unknown`` in that
        preference order.
    """

    if obs.remote_name:
        return obs.remote_name
    if obs.chassis_id:
        return obs.chassis_id
    if obs.remote_addresses:
        return obs.remote_addresses[0]
    return "unknown"


def _ping_summary(result: InspectionResult) -> str:
    """Return compact ping results with the unit supplied once by the field label.

    Human output labels the field ``Ping RTT ms``. Keeping ``ms`` out of every
    individual probe value reduces visual noise and makes the line easier to scan
    when a target has several candidate management addresses. JSON retains its
    explicit ``rtt_ms`` keys and is intentionally unaffected by this renderer.
    """

    if not result.device or not result.device.ping_probes:
        return "not sent" if result.dry_run else "no probes recorded"
    values: list[str] = []
    for probe in result.device.ping_probes:
        address = probe.address or result.device.query_target or "?"
        if probe.status == "reply" and probe.rtt_ms is not None:
            values.append(f"{address}={probe.rtt_ms:.3f}")
        else:
            values.append(f"{address}={probe.status}")
    return "; ".join(values)


def _timing_summary(result: InspectionResult) -> str:
    """Return human timing assignments with milliseconds declared by the label."""

    pieces = [f"dns={result.dns_duration_ms:.3f}"]
    if not result.dry_run:
        pieces.append(f"query={result.query_duration_ms:.3f}")
        if "basic_phase" in result.probe_timings:
            pieces.append(f"basic={result.probe_timings['basic_phase']:.3f}")
        if "detail_phase" in result.probe_timings:
            pieces.append(f"detail={result.probe_timings['detail_phase']:.3f}")
    pieces.append(f"total={result.total_duration_ms:.3f}")
    return "; ".join(pieces)


def _adaptive_snmp_summary(result: InspectionResult) -> str | None:
    """Return a compact target profile when adaptive slowdown was activated."""

    if not result.device or not result.device.snmp_sessions:
        return None
    values: list[str] = []
    for session in result.device.snmp_sessions:
        if not session.degraded:
            continue
        values.append(
            f"{session.target}: timeout={session.initial_timeout_seconds:g}->"
            f"{session.effective_timeout_seconds:g}s, max-repetitions="
            f"{session.initial_max_repetitions}->{session.effective_max_repetitions}, "
            f"pacing={session.effective_inter_pdu_delay_ms:g}ms"
        )
    return "; ".join(values) or None


def _collection_metrics_summary(result: InspectionResult) -> str | None:
    """Return one compact ``objects/duration_ms`` assignment per queried section.

    The section order mirrors the worker collector chain.  Absence means the
    section was not queried; a value such as ``lldpv2=0/201.3`` deliberately
    distinguishes an attempted collector that returned zero objects.
    """

    if not result.device or not result.device.collection_metrics:
        return None
    order = ("sys", "entity", "interfaces", "lldp", "lldpv2", "cdp")
    pieces: list[str] = []
    for section in order:
        metric = result.device.collection_metrics.get(section)
        if metric is None:
            continue
        pieces.append(f"{section}={metric.objects}/{metric.duration_ms:.1f}")
    return "; ".join(pieces) or None


def _highlight_metric_values(
    text: str,
    *,
    color: bool,
    styles: TerminalStyles,
) -> str:
    """Highlight both object counts and milliseconds in ``section=obj/ms`` text."""

    if not color:
        return text
    return re.sub(
        r"(?<=[=/])([0-9]+(?:\.[0-9]+)?)",
        lambda match: paint(match.group(1), styles.metric, True),
        text,
    )


def _highlight_numeric_assignments(
    text: str,
    *,
    color: bool,
    styles: TerminalStyles,
) -> str:
    """Highlight numeric values on human ``name=value`` timing fields.

    Apply this only after terminal-width truncation. ANSI escape sequences add
    bytes but no visible columns, so coloring before ``_truncate`` would make the
    width calculation inaccurate. Matching only numbers immediately following
    ``=`` also leaves addresses, labels, separators, and non-numeric probe states
    such as ``timeout`` visually unchanged.
    """

    if not color:
        return text
    return re.sub(
        r"(?<==)([0-9]+(?:\.[0-9]+)?)",
        lambda match: paint(match.group(1), styles.metric, True),
        text,
    )


def _query_target(result: InspectionResult) -> str:
    """Return the address actually queried or the first policy-permitted candidate.

    Args:
        result: Inspection result with optional device and policy candidate data.

    Returns:
        Query target text, falling back to ``-`` when no candidate exists.
    """

    if result.device and result.device.query_target:
        return result.device.query_target
    permitted = next((row.address for row in result.policies if row.query_allowed), None)
    return permitted or "-"


def _status_color(result: InspectionResult, styles: TerminalStyles) -> str:
    """Map one inspection status to the ANSI palette used by human renderers.

    Args:
        result: Inspection result whose status determines severity emphasis.

    Returns:
        Green for success/dry-run, yellow for partial, otherwise red.
    """

    if result.status in {"success", "dry_run"}:
        return styles.success
    if result.status == "partial":
        return styles.warning
    return styles.error


def _summary_lines(
    result: InspectionResult,
    *,
    color: bool,
    width: int,
    styles: TerminalStyles,
) -> list[str]:
    """Build the common system/policy/timing lines for terminal inspection views.

    Args:
        result: Completed inspection containing DNS, policy, probe, and system data.
        color: Whether ANSI highlighting may be included.
        width: Terminal width used to truncate long values before coloring.

    Returns:
        Ordered human-readable lines shared by table and detail renderers.
    """

    boundary_outside = [row.address for row in result.policies if not row.boundary_allowed]
    denied = [row.address for row in result.policies if not row.query_allowed]
    allowed = [row.address for row in result.policies if row.query_allowed]
    device = result.device
    system = device.system if device else None
    timestamp = format_iso_wall_clock(result.collected_at)
    if timestamp is None:
        timestamp = format_iso_wall_clock(iso_now()) or "unknown-time"
    line_width = min(width, 120)
    lines = [
        format_title_line(
            "LLDP-Runner single-device inspection",
            f"(collected {timestamp})",
            width=line_width,
            title_style=styles.heading,
            color=color,
        ),
        "=" * line_width,
        f"Target:          {_truncate(result.input_target, max(20, width - 17))}",
        f"Preferred name:  {_truncate(result.preferred_name, max(20, width - 17))}",
        f"Query target:    {_query_target(result)}",
        f"State:           {paint(result.status, _status_color(result, styles), color)}",
        f"Forward DNS:     {_truncate(result.forward_dns or ['none'], max(20, width - 17))}",
        f"Reverse DNS:     {_truncate([f'{item.address}->{item.name or "none"}' for item in result.reverse_dns] or ['none'], max(20, width - 17))}",
        f"Boundary:        {'outside for ' + ';'.join(boundary_outside) + ' (inspect override)' if boundary_outside else 'inside configured discovery boundary'}",
        f"Query policy:    {('allowed; denied candidates=' + ';'.join(denied)) if allowed and denied else ('allowed' if allowed else ('denied for ' + ';'.join(denied) if denied else 'no resolved candidates'))}",
        f"Ping RTT ms:     {_highlight_numeric_assignments(_truncate(_ping_summary(result), max(20, width - 17)), color=color, styles=styles)}",
        f"Timing ms:       {_highlight_numeric_assignments(_truncate(_timing_summary(result), max(20, width - 17)), color=color, styles=styles)}",
    ]
    metrics = _collection_metrics_summary(result)
    if metrics:
        # Keep the generated record on one physical line. Very narrow terminals
        # may visually wrap it, but LLDP-Runner does not truncate or split the
        # diagnostic because every section is useful for performance comparison.
        lines.append(
            f"SNMP obj/ms:     {_highlight_metric_values(metrics, color=color, styles=styles)}"
        )
    adaptive = _adaptive_snmp_summary(result)
    if adaptive:
        lines.append(f"SNMP adaptive:   {adaptive}")
    if device:
        lines.extend(
            [
                f"SNMP profile:    {device.credential_profile or '-'} / {device.credential_result or '-'}",
                f"System name:     {_truncate(system.sys_name if system else None, max(20, width - 17))}",
                f"Platform:        {_truncate(' '.join(x for x in [system.manufacturer if system else None, system.model if system else None, system.version if system else None] if x), max(20, width - 17))}",
            ]
        )
    return lines


def render_table(config: AppConfig, result: InspectionResult, *, stream: Any = sys.stdout) -> str:
    """Render the default abbreviated terminal view with terminal-aware widths."""

    color = use_color(stream, config.terminal)
    styles = build_terminal_styles(config.terminal)
    width = max(72, min(shutil.get_terminal_size((120, 24)).columns, 160))
    lines = _summary_lines(result, color=color, width=width, styles=styles)
    lines.append("-" * min(width, 120))
    if result.dry_run:
        lines.append("Address                                   Boundary  Query  Credential")
        lines.append("-" * min(width, 120))
        for row in result.policies:
            boundary = "inside" if row.boundary_allowed else "outside"
            query = "allow" if row.query_allowed else "deny"
            lines.append(
                f"{_truncate(row.address, 39):<39} {boundary:<8} {query:<6} {_truncate(row.credential_profile or '-', 24)}"
            )
        if not result.policies:
            lines.append("No resolved address candidates")
        return "\n".join(lines)

    if result.system_only:
        # The operator explicitly requested only the baseline SYSTEM-MIB probe.
        # Do not print an empty neighbor table that could be mistaken for a real
        # LLDP/CDP query which happened to return no neighbors.
        return "\n".join(lines)

    neighbors = result.device.neighbors if result.device else []
    widths = plan_neighbor_widths(
        width,
        configured_local=config.output.neighbor_local_width,
        configured_remote_port=config.output.neighbor_remote_port_width,
        local_values=(
            _one_line(obs.local_interface or obs.local_interface_raw) for obs in neighbors
        ),
        remote_port_values=(
            _one_line(obs.remote_interface or obs.remote_interface_raw) for obs in neighbors
        ),
        management_values=(
            _one_line(obs.remote_addresses[0] if obs.remote_addresses else "-") for obs in neighbors
        ),
    )
    lines.append(format_neighbor_header(widths))
    lines.append("-" * widths.table)
    for obs in neighbors:
        lines.append(
            format_neighbor_row(
                widths,
                local=_one_line(obs.local_interface or obs.local_interface_raw),
                protocol=",".join(_protocols(obs)),
                neighbor=_one_line(_neighbor_name(obs)),
                remote_port=_one_line(obs.remote_interface or obs.remote_interface_raw),
                management=_one_line(obs.remote_addresses[0] if obs.remote_addresses else "-"),
                protocol_style=lambda cell: paint(cell, styles.inspection_neighbor, color),
            )
        )
    if not neighbors:
        lines.append("No CDP/LLDP neighbors were returned")
    if result.device and result.device.errors:
        lines.append("-" * min(width, 120))
        lines.append(
            paint(
                f"Collector diagnostics: {len(result.device.errors)} (use --detail or --json for details)",
                styles.warning,
                color,
            )
        )
    return "\n".join(lines)


def _detail_field(lines: list[str], label: str, value: Any, *, indent: str = "") -> None:
    """Append one possibly-multiline detail field while suppressing blank lines."""

    text = _clean(value)
    parts = [part.strip() for part in text.splitlines() if part.strip()]
    if not parts:
        parts = ["-"]
    prefix = f"{indent}{label:<18}" if len(label) <= 18 else f"{indent}{label} "
    lines.append(f"{prefix}{parts[0]}")
    continuation = " " * max(len(prefix), len(indent) + 18)
    lines.extend(f"{continuation}{part}" for part in parts[1:])


def render_detail(config: AppConfig, result: InspectionResult, *, stream: Any = sys.stdout) -> str:
    """Render a scrolling switch/lldpcli-inspired detail view."""

    color = use_color(stream, config.terminal)
    styles = build_terminal_styles(config.terminal)
    width = max(72, min(shutil.get_terminal_size((120, 24)).columns, 160))
    lines = _summary_lines(result, color=color, width=width, styles=styles)
    device = result.device
    system = device.system if device else None
    lines.append("=" * min(width, 120))
    lines.append(paint("Seed details", styles.heading, color))
    _detail_field(lines, "Addresses:", result.addresses)
    _detail_field(lines, "DNS errors:", result.dns_errors or "none")
    if system:
        _detail_field(lines, "sysObjectID:", system.sys_object_id)
        _detail_field(lines, "sysDescr:", system.sys_descr)
        _detail_field(lines, "sysLocation:", system.sys_location)
        _detail_field(lines, "sysContact:", system.sys_contact)
        if not result.system_only:
            # These values are normally supplied by ENTITY-MIB enrichment.  A
            # system-only inspection intentionally never queried that MIB, so
            # omit the fields instead of rendering misleading empty placeholders.
            _detail_field(lines, "Serial:", system.serial_number)
            _detail_field(lines, "Hardware rev:", system.hardware_revision)
            _detail_field(lines, "Firmware rev:", system.firmware_revision)
        _detail_field(lines, "SNMP engine ID:", system.snmp_engine_id)
    if result.dry_run:
        lines.append("=" * min(width, 120))
        lines.append(paint("Dry-run policy candidates", styles.heading, color))
        for index, row in enumerate(result.policies, start=1):
            lines.append("-" * min(width, 120))
            _detail_field(lines, f"Address {index}:", row.address)
            _detail_field(lines, "Boundary:", row.boundary_reason)
            _detail_field(lines, "Inspect query:", row.query_reason)
            _detail_field(lines, "Credential:", row.credential_profile or "none")
            _detail_field(lines, "Credential rule:", row.credential_reason or "none")
        if not result.policies:
            lines.append("No resolved address candidates")
        return "\n".join(lines)

    if result.system_only:
        return "\n".join(lines)

    neighbors = device.neighbors if device else []
    lines.append("=" * min(width, 120))
    lines.append(paint(f"Neighbors ({len(neighbors)})", styles.heading, color))
    for index, obs in enumerate(neighbors, start=1):
        record = neighbor_record(config, obs)
        lines.append("-" * min(width, 120))
        lines.append(paint(f"Neighbor {index}", styles.bold, color))
        _detail_field(lines, "Local interface:", obs.local_interface)
        _detail_field(lines, "Local raw:", obs.local_interface_raw)
        _detail_field(lines, "Protocols:", ",".join(_protocols(obs)))
        _detail_field(lines, "Neighbor name:", _neighbor_name(obs))
        _detail_field(lines, "Classification:", record["classification"])
        _detail_field(lines, "Mgmt address:", obs.remote_addresses or "none")
        _detail_field(lines, "Chassis ID:", obs.chassis_id)
        _detail_field(lines, "Chassis subtype:", obs.chassis_id_subtype)
        _detail_field(lines, "Port ID:", obs.details.get("port_id"))
        _detail_field(lines, "Port subtype:", obs.details.get("port_id_subtype"))
        _detail_field(lines, "Port subtype ID:", obs.details.get("port_id_subtype_id"))
        _detail_field(lines, "Remote port:", obs.remote_interface)
        _detail_field(lines, "Remote port raw:", obs.remote_interface_raw)
        _detail_field(lines, "Platform:", obs.remote_platform)
        _detail_field(lines, "Capabilities:", obs.capabilities or "none")
        _detail_field(lines, "Description:", obs.remote_description)
        extra = {
            key: value
            for key, value in obs.details.items()
            if key
            not in {
                "protocols",
                "port_id",
                "port_id_subtype",
                "port_id_subtype_id",
            }
            and value not in (None, "", [], {})
        }
        for key in sorted(extra):
            _detail_field(lines, f"Evidence {key}:", extra[key])
    if not neighbors:
        lines.append("No CDP/LLDP neighbors were returned")
    if device and device.errors:
        lines.append("=" * min(width, 120))
        lines.append(
            paint(
                f"Diagnostics ({len(device.errors)})",
                styles.bold + styles.warning,
                color,
            )
        )
        for error in device.errors:
            _detail_field(lines, f"{error.operation}:", f"{error.category}: {error.message}")
    return "\n".join(lines)


def _csv_comment_value(value: Any) -> str:
    """Prepare one value for comma-separated metadata in a ``#`` comment line.

    Args:
        value: Value accepted by the normal single-line sanitation helper.

    Returns:
        Single-line text with embedded commas replaced by semicolons.
    """

    return _one_line(value).replace(",", ";")


def render_csv(config: AppConfig, result: InspectionResult) -> str:
    """Render inspection metadata and optional neighbor rows as CSV text.

    Args:
        config: Effective application configuration used by shared output helpers.
        result: Completed single-device inspection result. When ``system_only`` is
            true, only the two system metadata comment lines are returned.

    Returns:
        Two ``#`` metadata lines followed by a fixed neighbor CSV header/rows for
        normal inspections, or just those metadata lines for system-only output.
    """

    device = result.device
    system = device.system if device else None
    lines = [
        (
            f"# target={_csv_comment_value(result.input_target)},"
            f"preferred_name={_csv_comment_value(result.preferred_name)},"
            f"query_target={_csv_comment_value(_query_target(result))},"
            f"state={_csv_comment_value(result.status)},"
            f"timestamp={_csv_comment_value(format_iso_wall_clock(result.collected_at) or 'unknown')}"
        ),
        (
            f"# ping={_csv_comment_value(_ping_summary(result))},"
            f"dns_ms={result.dns_duration_ms:.3f},query_ms={result.query_duration_ms:.3f},"
            f"total_ms={result.total_duration_ms:.3f},"
            f"system={_csv_comment_value(system.sys_name if system else '-')}"
        ),
    ]
    # ``--system-only`` explicitly suppresses neighbor output. Returning before
    # dry-run annotations and DictWriter construction also prevents a misleading
    # neighbor header when the operator requested only basic system metadata.
    if result.system_only:
        return "\n".join(lines)

    if result.dry_run:
        for row in result.policies:
            lines.append(
                f"# candidate={_csv_comment_value(row.address)},"
                f"boundary={'inside' if row.boundary_allowed else 'outside'},"
                f"query={'allow' if row.query_allowed else 'deny'},"
                f"credential={_csv_comment_value(row.credential_profile or '-')}"
            )

    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(
        buffer,
        fieldnames=[
            "local_interface",
            "protocol",
            "neighbor",
            "remote_interface",
            "address",
            "platform",
        ],
        lineterminator="\n",
    )
    writer.writeheader()
    for obs in device.neighbors if device else []:
        writer.writerow(
            {
                "local_interface": _one_line(obs.local_interface or obs.local_interface_raw),
                "protocol": ",".join(_protocols(obs)),
                "neighbor": _one_line(_neighbor_name(obs)),
                "remote_interface": _one_line(obs.remote_interface or obs.remote_interface_raw),
                "address": _one_line(obs.remote_addresses[0] if obs.remote_addresses else ""),
                "platform": _one_line(obs.remote_platform or ""),
            }
        )
    return "\n".join(lines) + "\n" + buffer.getvalue().rstrip("\n")


def _safe_json(value: Any) -> Any:
    """Recursively sanitize strings while preserving JSON-compatible structure.

    Args:
        value: Nested dict/list/tuple/scalar inspection data.

    Returns:
        Equivalent JSON-serializable structure with textual values passed through
        :func:`safe_output_text`.
    """

    if isinstance(value, dict):
        return {safe_output_text(key): _safe_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_json(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_json(item) for item in value]
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return safe_output_text(value)
    return value


def render_json(config: AppConfig, result: InspectionResult) -> str:
    """Render rich inspection JSON aligned with discovery.json host/edge concepts."""

    return json.dumps(
        _safe_json(inspection_json(config, result)),
        indent=config.output.pretty_json_indent,
        ensure_ascii=False,
    )


def render_inspection(
    config: AppConfig,
    result: InspectionResult,
    output_format: str,
    *,
    stream: Any = sys.stdout,
) -> str:
    """Dispatch one of the four stable inspect presentation modes."""

    if output_format == "table":
        return render_table(config, result, stream=stream)
    if output_format == "detail":
        return render_detail(config, result, stream=stream)
    if output_format == "csv":
        return render_csv(config, result)
    if output_format == "json":
        return render_json(config, result)
    raise ValueError(f"unknown inspect output format {output_format!r}")
