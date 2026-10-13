"""Draft snapshots and final JSON/CSV output generation."""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from lldp_runner.config import AppConfig, CustomCsvConfig
from lldp_runner.csv_fields import (
    ERRORS_CSV_FIELDS,
    HOSTS_CSV_FIELDS,
    STACK_MEMBERS_CSV_FIELDS,
    UNKNOWN_DEVICES_CSV_FIELDS,
    default_header,
    resolve_json_path,
    transform_value,
)
from lldp_runner.identity import (
    canonical_mac,
    is_locally_assigned_chassis_subtype,
    normalized_advertised_name,
)
from lldp_runner.runtime import publish_latest_symlink
from lldp_runner.seeds import SEED_CSV_COLUMNS
from lldp_runner.state import StateStore
from lldp_runner.textutil import safe_output_text
from lldp_runner.timeutil import iso_now

LOG = logging.getLogger(__name__)

OUTPUT_NAMES = (
    "discovery.json",
    "hosts.csv",
    "stack-members.csv",
    "seeds.csv",
    "unknown-devices.csv",
    "errors.csv",
)


class OutputWriteResult(list[Path]):
    """List-compatible output paths plus measured finalization subphases.

    Keeping this object list-compatible avoids changing callers that only need
    filenames.  The coordinator additionally reads ``phase_metrics`` for final
    ``run.json`` telemetry.  Durations are wall-clock seconds rounded to
    milliseconds, matching the existing run-manifest precision.
    """

    def __init__(self, paths: list[Path], *, phase_metrics: dict[str, float]) -> None:
        super().__init__(paths)
        self.phase_metrics = dict(phase_metrics)


# discovery.json is the durable structured interchange contract.  Increment this
# only when consumers need to distinguish incompatible document structures.
DISCOVERY_JSON_SCHEMA_VERSION = 8


def _json(value: str | None, fallback: Any) -> Any:
    """Decode stored JSON text, returning ``fallback`` for absent/invalid data.

    Args:
        value: JSON text read from SQLite, or ``None``/empty text.
        fallback: Value returned when decoding cannot produce a JSON value.

    Returns:
        The decoded JSON value or ``fallback``.
    """

    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _split_addresses(addresses: list[str]) -> tuple[list[str], list[str]]:
    """Normalize address strings into separate IPv4 and IPv6 output lists.

    Args:
        addresses: Candidate textual IP addresses associated with one host.

    Returns:
        ``(ipv4, ipv6)`` lists; malformed values are omitted.
    """

    ipv4: list[str] = []
    ipv6: list[str] = []
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        (ipv4 if ip.version == 4 else ipv6).append(str(ip))
    return ipv4, ipv6


_MAC_PATTERNS = (
    re.compile(r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$"),
    re.compile(r"(?i)^[0-9a-f]{2}(?:-[0-9a-f]{2}){5}$"),
    re.compile(r"(?i)^[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}$"),
)
_NAME_LIKE_CHASSIS = re.compile(r"(?i)^(?=.{1,253}$)(?=.*[a-z])[a-z0-9][a-z0-9._-]*$")


def _is_ip(value: str) -> bool:
    """Return whether ``value`` is a syntactically valid IPv4/IPv6 address."""

    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


def _usable_chassis_name(chassis_id: str | None, mode: str | bool) -> str | None:
    """Return a chassis ID when policy permits it as an output display name.

    Args:
        chassis_id: Neighbor-provided chassis identifier.
        mode: ``disabled``, ``name_like``, ``any``, or boolean equivalent.

    Returns:
        A permitted fallback name, otherwise ``None``.
    """

    if not chassis_id:
        return None
    value = str(chassis_id).strip()
    if not value or mode == "disabled" or mode is False:
        return None
    if mode == "any":
        return value
    if _is_ip(value) or any(pattern.fullmatch(value) for pattern in _MAC_PATTERNS):
        return None
    return value if _NAME_LIKE_CHASSIS.fullmatch(value) else None


def _display_name(
    stored_name: str | None,
    chassis_id: str | None,
    mode: str | bool,
    *,
    has_observed_name: bool = False,
) -> str:
    """Choose the stable operator-facing name for one output host.

    Args:
        stored_name: Preferred name currently stored for the host.
        chassis_id: Neighbor chassis identifier available as a fallback.
        mode: Chassis-ID fallback policy.
        has_observed_name: Whether a genuine observed/resolved name exists.

    Returns:
        Best display name, falling back to ``unknown`` when necessary.
    """

    stored = str(stored_name or "").strip()
    # A real observed/discovered name always outranks a chassis-id fallback.
    if has_observed_name and stored and stored != "unknown":
        return stored
    fallback = _usable_chassis_name(chassis_id, mode)
    if fallback and (not stored or stored == "unknown" or _is_ip(stored)):
        return fallback
    return stored or "unknown"


_NULL_ADVERTISED_NAME_VALUES = frozenset(
    {"null", "not advertised", "not-advertised", "not_advertised"}
)


def _normalized_subtype_id(value: object | None) -> int | None:
    """Return an integer chassis subtype ID when one was serialized."""

    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _is_mac_chassis_subtype(subtype_name: object | None, subtype_id: object | None) -> bool:
    """Return whether an observed chassis value is explicitly a MAC address."""

    normalized = str(subtype_name or "").strip().casefold().replace("-", "_").replace(" ", "_")
    return _normalized_subtype_id(subtype_id) == 4 or normalized in {
        "mac",
        "mac_address",
    }


def _observed_name_evidence(
    neighbors: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Return nonblank advertised names and descriptions from inbound edges."""

    names: list[str] = []
    descriptions: list[str] = []
    for neighbor in neighbors:
        observed_name = str(neighbor.get("observed_name") or "").strip()
        if observed_name:
            names.append(observed_name)
        details = neighbor.get("details", {})
        if not isinstance(details, dict):
            continue
        description = str(details.get("remote_description") or "").strip()
        if description:
            descriptions.append(description)
    return names, descriptions


def _observed_chassis_candidates(
    neighbors: list[dict[str, Any]],
    *,
    subtype: str,
) -> list[str]:
    """Return stable unique chassis values matching one explicit subtype class.

    Locally assigned IDs are retained as their advertised text. MAC candidates
    are canonicalized so conventional colon, hyphen, dotted, and compact forms
    produce the same operator-facing value.
    """

    values: list[str] = []
    for neighbor in neighbors:
        details = neighbor.get("details", {})
        if not isinstance(details, dict):
            continue
        value = str(details.get("chassis_id") or "").strip()
        if not value:
            continue
        subtype_name = details.get("chassis_id_subtype")
        subtype_id = _normalized_subtype_id(details.get("chassis_id_subtype_id"))
        if subtype == "local":
            if not is_locally_assigned_chassis_subtype(
                str(subtype_name) if subtype_name is not None else None,
                subtype_id,
            ):
                return []
            candidate = value
        elif subtype == "mac":
            if not _is_mac_chassis_subtype(subtype_name, subtype_id):
                return []
            candidate = canonical_mac(value)
            if candidate is None:
                return []
        else:  # pragma: no cover - internal caller contract
            raise ValueError(f"unsupported chassis subtype selector: {subtype}")
        if candidate not in values:
            values.append(candidate)
    return values


def _output_preferred_name(
    display_name: str,
    observed_by_neighbors: list[dict[str, Any]],
) -> str:
    """Normalize one host name at the canonical output presentation boundary.

    This does not alter persisted aliases or identity correlation. It strips a
    recognized trailing hardware serial from a usable advertised name, then uses
    one unambiguous typed chassis value for the two placeholder-only cases where
    the run has no better human-readable evidence.
    """

    name = str(display_name or "").strip() or "unknown"
    parsed = normalized_advertised_name(name)
    if parsed is not None and parsed.serial_hint is not None:
        name = parsed.base_name

    observed_names, descriptions = _observed_name_evidence(observed_by_neighbors)
    normalized_name = name.casefold()
    if normalized_name == "unknown" and not observed_names and not descriptions:
        # This is deliberately below alias promotion, configured chassis-name
        # fallback, and serial-decoration cleanup.  A typed chassis value is only
        # presentation evidence here; it never becomes a global identity alias.
        for subtype in ("local", "mac"):
            candidates = _observed_chassis_candidates(
                observed_by_neighbors,
                subtype=subtype,
            )
            if len(candidates) == 1:
                return candidates[0]

    if normalized_name in _NULL_ADVERTISED_NAME_VALUES:
        names_are_placeholders = bool(observed_names) and all(
            value.casefold() in _NULL_ADVERTISED_NAME_VALUES for value in observed_names
        )
        descriptions_are_placeholders = bool(descriptions) and all(
            value.casefold() in _NULL_ADVERTISED_NAME_VALUES for value in descriptions
        )
        if names_are_placeholders and descriptions_are_placeholders:
            candidates = _observed_chassis_candidates(
                observed_by_neighbors,
                subtype="mac",
            )
            if len(candidates) == 1:
                return candidates[0]
    return name


_PROTOCOL_ORDER = {"cdp": 0, "lldp": 1, "lldpv2": 2}


def _edge_protocols(edge: Any) -> list[str]:
    """Return a stable, de-duplicated protocol list for one topology edge.

    Neighbor collectors may merge CDP and LLDP evidence in discovery order. Output
    should not depend on which protocol happened to answer first, so formal files use
    a deterministic order (`cdp`, `lldp`, `lldpv2`, then any future protocol names).
    This also makes CSV strings easy for operators and downstream scripts to compare.
    """

    protocols = list(dict.fromkeys(x for x in str(edge["protocols"]).split(",") if x))
    return sorted(protocols, key=lambda value: (_PROTOCOL_ORDER.get(value, 99), value))


def _protocol_tag(edge: Any) -> str:
    """Format a topology edge's protocol provenance for flattened CSV output."""

    return ",".join(_edge_protocols(edge))


def _learned_neighbor_record(edge: Any, config: AppConfig) -> dict[str, Any]:
    """Render a neighbor learned directly from the current host's CDP/LLDP tables.

    `learned_neighbors` is authoritative evidence supplied by the host represented by
    the surrounding record. Interface direction therefore follows the SNMP-polled
    host: `local_interface` belongs to that host and `remote_interface` belongs to the
    discovered neighbor.
    """

    details = _json(edge["details_json"], {})
    remote_chassis_id = (
        str(details.get("chassis_id"))
        if isinstance(details, dict) and details.get("chassis_id")
        else None
    )
    return {
        "host_ref": int(edge["remote_host_id"]),
        "name": _display_name(
            edge["remote_preferred_name"],
            remote_chassis_id,
            config.output.chassis_id_name_fallback,
            has_observed_name=bool(edge["observed_name"]),
        ),
        "classification": edge["remote_classification"],
        "local_interface": edge["local_interface"] or None,
        "local_interface_raw": edge["local_interface_raw"],
        "remote_interface": edge["remote_interface"] or None,
        "remote_interface_raw": edge["remote_interface_raw"],
        "protocols": _edge_protocols(edge),
        "protocol_tag": f"[{_protocol_tag(edge)}]",
        "observed_name": edge["observed_name"],
        "observed_addresses": _json(edge["observed_addresses_json"], []),
        "details": details,
        "last_seen": edge["last_seen"],
    }


def _observed_by_neighbor_record(edge: Any, config: AppConfig) -> dict[str, Any]:
    """Render reciprocal evidence reported by another managed device.

    The stored edge is oriented from the observing device toward the current host.
    For the current host's JSON record we reverse the interface perspective so
    `local_interface` still means "this host's interface" and `remote_interface`
    means "the observing neighbor's interface". `observed_name` intentionally
    remains the name that the observing device advertised for the current host; it is
    raw topology evidence and should not be rewritten to describe the observer.
    """

    details = _json(edge["details_json"], {})
    return {
        "host_ref": int(edge["source_host_id"]),
        "name": _display_name(
            edge["source_preferred_name"],
            None,
            config.output.chassis_id_name_fallback,
            has_observed_name=bool(edge["source_preferred_name"]),
        ),
        "classification": edge["source_classification"],
        "local_interface": edge["remote_interface"] or None,
        "local_interface_raw": edge["remote_interface_raw"],
        "remote_interface": edge["local_interface"] or None,
        "remote_interface_raw": edge["local_interface_raw"],
        "protocols": _edge_protocols(edge),
        "protocol_tag": f"[{_protocol_tag(edge)}]",
        "observed_name": edge["observed_name"],
        "observed_addresses": _json(edge["observed_addresses_json"], []),
        "details": details,
        "last_seen": edge["last_seen"],
    }


def _host_record(state: StateStore, row: Any, config: AppConfig) -> dict[str, Any]:
    """Build one canonical structured host record from persisted discovery state.

    Args:
        state: Store used to retrieve aliases, tags, and topology edges.
        row: Host database row returned by ``StateStore.all_hosts``.
        config: Effective configuration controlling output naming and metrics.

    Returns:
        Dictionary for one element of the ``discovery.json`` hosts array.
    """

    host_id = int(row["id"])
    names, addresses, chassis_id = state.aliases_for_host(host_id)
    stored_display_name = str(row["preferred_name"])
    if names and (stored_display_name in {"", "unknown"} or _is_ip(stored_display_name)):
        stored_display_name = next((name for name in names if "." in name), names[0])
    ipv4, ipv6 = _split_addresses(addresses)
    system = _json(row["system_json"], {})
    ping = _json(row["ping_json"], [])
    # Keep the two evidence directions separate. A failed or intentionally unpolled
    # host can have no learned neighbors of its own while still having reliable
    # inbound topology evidence from the managed device that discovered it.
    learned_neighbors = [
        _learned_neighbor_record(edge, config) for edge in state.neighbors_from(host_id)
    ]
    observed_by_neighbors = [
        _observed_by_neighbor_record(edge, config) for edge in state.neighbors_to(host_id)
    ]
    display_name = _output_preferred_name(
        _display_name(
            stored_display_name,
            chassis_id,
            config.output.chassis_id_name_fallback,
            has_observed_name=bool(names),
        ),
        observed_by_neighbors,
    )
    snmp = {
        "credential_source": row["credential_source"],
        "credential_profile": row["credential_profile"],
        "credential_label": row["credential_label"],
        "credential_result": row["credential_result"],
    }
    if config.snmp.report_metrics:
        metrics = _json(row["metrics_json"], {})
        if metrics:
            # Metrics are optional discovery telemetry rather than topology data.
            # Keep them nested under SNMP so schema consumers can ignore the
            # additive field when report_metrics is disabled or unavailable.
            snmp["collection_metrics"] = metrics
    adaptive_sessions = _json(row["snmp_sessions_json"], [])
    if adaptive_sessions:
        snmp["adaptive_sessions"] = adaptive_sessions
    collection_coverage = _json(row["collection_coverage_json"], {})
    if collection_coverage:
        snmp["collection_coverage"] = collection_coverage
    interface_groups = _json(row["interface_groups_json"], [])
    if interface_groups:
        # Keep the compatibility observation groups available while operators
        # compare the established host view with the provisional graph view.
        # These groups are diagnostic projections, not a second evidence source.
        snmp["interface_observation_groups"] = interface_groups
    return {
        "id": host_id,
        "preferred_name": display_name,
        "queried_as": row["query_target"],
        "snmp_sysname": row["snmp_sysname"],
        "classification": row["classification"],
        "classification_reason": _json(row["classification_reason_json"], []),
        "tags": state.tags_for_host(host_id),
        "state": str(row["state"]).lower(),
        "is_seed": bool(row["is_seed"]),
        "first_seen": row["first_seen"],
        "last_seen": row["last_seen"],
        "last_seen_source": row["last_seen_source"],
        "names": names,
        "addresses": {"ipv4": ipv4, "ipv6": ipv6},
        "chassis_id": chassis_id,
        "icmp": ping,
        "system": system,
        "snmp": snmp,
        "learned_neighbors": learned_neighbors,
        "observed_by_neighbors": observed_by_neighbors,
    }


def _neighbor_protocol_tag(neighbor: dict[str, Any]) -> str:
    """Return the compact protocol tag used by flattened neighbor CSV fields.

    Args:
        neighbor: Canonical learned/observed-by neighbor object from discovery JSON.

    Returns:
        Comma-separated protocol names wrapped in square brackets.
    """

    protocols = neighbor.get("protocols", [])
    if not isinstance(protocols, list):
        protocols = []
    values = [str(value) for value in protocols if value]
    return f"[{','.join(values)}]"


def _learned_neighbor_summary(record: dict[str, Any]) -> str:
    """Flatten canonical learned-neighbor records into the hosts CSV summary.

    Args:
        record: One canonical host object from ``discovery.json``.

    Returns:
        Semicolon-separated ``local=neighbor:remote[protocols]`` relationships.
    """

    parts: list[str] = []
    neighbors = record.get("learned_neighbors", [])
    if not isinstance(neighbors, list):
        return ""
    for neighbor in neighbors:
        if not isinstance(neighbor, dict):
            continue
        local = neighbor.get("local_interface") or "?"
        remote = neighbor.get("name") or "unknown"
        remote_if = neighbor.get("remote_interface") or "?"
        parts.append(f"{local}={remote}:{remote_if}{_neighbor_protocol_tag(neighbor)}")
    return ";".join(parts)


def _observed_by_neighbor_summary(record: dict[str, Any]) -> str:
    """Flatten canonical inbound neighbor evidence for one selected host.

    Args:
        record: One canonical host object from ``discovery.json``.

    Returns:
        Semicolon-separated ``observer:port=this-port[protocols]`` relationships.
    """

    parts: list[str] = []
    neighbors = record.get("observed_by_neighbors", [])
    if not isinstance(neighbors, list):
        return ""
    for neighbor in neighbors:
        if not isinstance(neighbor, dict):
            continue
        source = neighbor.get("name") or "unknown"
        # Canonical observed_by records are oriented from the selected host's
        # perspective: local_interface belongs to this host and remote_interface
        # belongs to the device that observed it.  The flattened historical form
        # intentionally prints the observer first.
        source_if = neighbor.get("remote_interface") or "?"
        this_if = neighbor.get("local_interface") or "?"
        parts.append(f"{source}:{source_if}={this_if}{_neighbor_protocol_tag(neighbor)}")
    return ";".join(parts)


def _canonical_protocol_values(values: list[str]) -> list[str]:
    """Return de-duplicated protocol names in LLDP-Runner's stable output order."""

    unique = dict.fromkeys(value for value in values if value)
    return sorted(unique, key=lambda value: (_PROTOCOL_ORDER.get(value, 99), value))


def _inbound_evidence(record: dict[str, Any]) -> dict[str, str]:
    """Aggregate unknown-device evidence from canonical observed-by neighbors.

    Args:
        record: Canonical unknown-device host object.

    Returns:
        Flattened review fields for ``unknown-devices.csv``. Protocols are derived
        exclusively from ``observed_by_neighbors[].protocols[]`` so the CSV can be
        reproduced from ``discovery.json`` without reopening SQLite state.
    """

    protocols: list[str] = []
    observed_names: list[str] = []
    platforms: list[str] = []
    descriptions: list[str] = []
    capabilities: list[str] = []
    observed_chassis_ids: list[str] = []
    observed_chassis_id_subtypes: list[str] = []
    observed_chassis_id_subtype_ids: list[str] = []

    neighbors = record.get("observed_by_neighbors", [])
    if not isinstance(neighbors, list):
        neighbors = []
    for neighbor in neighbors:
        if not isinstance(neighbor, dict):
            continue
        neighbor_protocols = neighbor.get("protocols", [])
        if isinstance(neighbor_protocols, list):
            protocols.extend(str(value) for value in neighbor_protocols if value)
        if neighbor.get("observed_name"):
            observed_names.append(str(neighbor["observed_name"]))
        details = neighbor.get("details", {})
        if not isinstance(details, dict):
            continue
        if details.get("remote_platform"):
            platforms.append(str(details["remote_platform"]))
        if details.get("remote_description"):
            descriptions.append(str(details["remote_description"]))
        values = details.get("capabilities", [])
        if isinstance(values, list):
            capabilities.extend(str(value) for value in values)
        if details.get("chassis_id"):
            observed_chassis_ids.append(str(details["chassis_id"]))
        if details.get("chassis_id_subtype"):
            observed_chassis_id_subtypes.append(str(details["chassis_id_subtype"]))
        if details.get("chassis_id_subtype_id") is not None:
            observed_chassis_id_subtype_ids.append(str(details["chassis_id_subtype_id"]))

    return {
        "protocols": ";".join(_canonical_protocol_values(protocols)),
        "observed_names": ";".join(dict.fromkeys(observed_names)),
        "remote_platforms": ";".join(dict.fromkeys(platforms)),
        "remote_descriptions": ";".join(dict.fromkeys(descriptions)),
        "capabilities": ";".join(dict.fromkeys(capabilities)),
        "observed_chassis_ids": ";".join(dict.fromkeys(observed_chassis_ids)),
        "observed_chassis_id_subtypes": ";".join(dict.fromkeys(observed_chassis_id_subtypes)),
        "observed_chassis_id_subtype_ids": ";".join(dict.fromkeys(observed_chassis_id_subtype_ids)),
    }


def _uptime_seconds(system: dict[str, Any]) -> float | None:
    """Convert SYSTEM-MIB centisecond uptime ticks to seconds when available.

    Args:
        system: Structured system-details dictionary for the logical device.

    Returns:
        Uptime in seconds, or ``None`` when no valid tick count was collected.
    """

    ticks = system.get("sys_uptime_ticks")
    try:
        return round(int(ticks) / 100.0, 2) if ticks is not None else None
    except (TypeError, ValueError):
        return None


def _host_csv_row(record: dict[str, Any]) -> dict[str, Any]:
    """Build one fixed ``hosts.csv`` row from a canonical host object.

    Args:
        record: Structured host representation from the canonical discovery document.

    Returns:
        Mapping matching :data:`HOSTS_CSV_FIELDS`. No SQLite/state access is
        required; derived presentation fields are calculated solely from JSON data.
    """

    system = record.get("system", {})
    if not isinstance(system, dict):
        system = {}
    snmp = record.get("snmp", {})
    if not isinstance(snmp, dict):
        snmp = {}
    addresses = record.get("addresses", {})
    if not isinstance(addresses, dict):
        addresses = {}
    tags = record.get("tags", [])
    if not isinstance(tags, list):
        tags = []

    return {
        "preferred_name": record.get("preferred_name") or "",
        "queried_as": record.get("queried_as") or "",
        "snmp_sysname": record.get("snmp_sysname") or "",
        "origin": "seed" if record.get("is_seed") else "learned",
        "classification": record.get("classification") or "",
        "tags": ";".join(str(value) for value in tags),
        "state": record.get("state") or "",
        "last_seen": record.get("last_seen") or "",
        "last_seen_source": record.get("last_seen_source") or "",
        "ipv4": ";".join(str(value) for value in addresses.get("ipv4", [])),
        "ipv6": ";".join(str(value) for value in addresses.get("ipv6", [])),
        "manufacturer": system.get("manufacturer") or "",
        "model": system.get("model") or "",
        "version": system.get("version") or "",
        "serial_number": system.get("serial_number") or "",
        "uptime_seconds": _uptime_seconds(system) or "",
        "credential_profile": snmp.get("credential_profile") or "",
        "credential_result": snmp.get("credential_result") or "",
        "learned_neighbors": _learned_neighbor_summary(record),
        "observed_by_neighbors": _observed_by_neighbor_summary(record),
    }


def _stack_member_csv_row(
    record: dict[str, Any],
    member: dict[str, Any],
) -> dict[str, Any]:
    """Build one fixed stack-member row from host/member JSON objects.

    Args:
        record: Canonical logical-host object.
        member: One ``system.stack_members[]`` object beneath that host.

    Returns:
        Mapping matching :data:`STACK_MEMBERS_CSV_FIELDS`. Host context is
        intentionally repeated while physical identity values come from the
        member. ``version`` falls back to the logical system version when the
        member does not expose an ENTITY-MIB software revision.
    """

    system = record.get("system", {})
    if not isinstance(system, dict):
        system = {}
    item = dict(_host_csv_row(record))
    item.update(
        {
            "member_number": member.get("member_number")
            if member.get("member_number") is not None
            else "",
            "entity_index": member.get("entity_index") or "",
            "name": member.get("name") or "",
            "description": member.get("description") or "",
            "manufacturer": member.get("manufacturer") or "",
            "model": member.get("model") or "",
            "version": member.get("software_revision") or system.get("version") or "",
            "serial_number": member.get("serial_number") or "",
            "hardware_revision": member.get("hardware_revision") or "",
            "firmware_revision": member.get("firmware_revision") or "",
            "uptime_seconds": member.get("uptime_seconds")
            if member.get("uptime_seconds") is not None
            else "",
        }
    )
    return item


def _stack_member_csv_rows(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Expand canonical stack hosts into one CSV row per physical member.

    Args:
        records: Canonical discovery host objects.

    Returns:
        Rows matching :data:`STACK_MEMBERS_CSV_FIELDS`. Logical host context is
        repeated intentionally while physical identity/revision values come from
        ``system.stack_members[]``.
    """

    rows: list[dict[str, Any]] = []
    for record in records:
        system = record.get("system", {})
        if not isinstance(system, dict):
            continue
        members = system.get("stack_members", [])
        if not isinstance(members, list):
            continue
        for member in members:
            if isinstance(member, dict):
                rows.append(_stack_member_csv_row(record, member))
    return rows


def _safe_output_value(value: Any) -> Any:
    """Recursively remove unsafe control characters before serializing output.

    SNMP collectors sanitize values before they enter discovery state, but output
    is a trust boundary of its own: error messages, imported/resumed state, or a
    future collector could still contain embedded controls.  Applying a final
    recursive pass keeps JSON human-readable and prevents raw control bytes from
    escaping through nested dictionaries/lists.
    """

    if isinstance(value, dict):
        return {safe_output_text(key): _safe_output_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_safe_output_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_safe_output_value(item) for item in value)
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return safe_output_text(value)
    return value


def _safe_csv_cell(value: Any) -> Any:
    """Return a CSV value that cannot contain embedded terminal controls.

    Numeric/boolean values stay numeric so the csv module can format them
    normally.  Everything else is normalized to a safe one-line string.
    """

    if value is None:
        return ""
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        return safe_output_text(value)
    if isinstance(value, (int, float, bool)):
        return value
    return safe_output_text(value)


def _safe_csv_row(row: dict[str, Any], fieldnames: list[str]) -> dict[str, Any]:
    """Sanitize all configured CSV fields while ignoring unrelated row keys."""

    return {name: _safe_csv_cell(row.get(name, "")) for name in fieldnames}


def _missing_query_target_message(state_name: str) -> tuple[str, bool]:
    """Explain why a managed-device seed row has no recorded query target.

    COMPLETE without a target is an integrity violation because successful SNMP
    collection necessarily used an address.  Other states may legitimately lack
    a target, but the reusable inventory still records that fact as an operator-
    visible diagnostic rather than leaving a blank cell unexplained.
    """

    if state_name == "COMPLETE":
        return (
            "managed device status COMPLETE has no recorded query_target; "
            "successful SNMP polling state is internally inconsistent",
            False,
        )
    if state_name == "FAILED":
        return (
            "managed device status FAILED has no recorded query_target; "
            "the attempted target was not retained",
            True,
        )
    if state_name == "NO_QUERY":
        return (
            "managed device status NO_QUERY has no query_target because SNMP "
            "polling was not performed",
            True,
        )
    if state_name == "OUT_OF_SCOPE":
        return (
            "managed device status OUT_OF_SCOPE has no query_target because no "
            "in-scope SNMP target was selected",
            True,
        )
    return (
        f"managed device status {state_name} has no query_target at snapshot time",
        True,
    )


_SEED_TARGET_TERMINAL_STATES = {"COMPLETE", "FAILED", "NO_QUERY", "OUT_OF_SCOPE"}


def _ensure_seed_integrity_errors(state: StateStore, hosts: list[Any]) -> None:
    """Validate terminal seed inventory state without flagging active work as broken.

    A managed device normally has no ``query_target`` while it is DISCOVERED, READY,
    or CLAIMED.  The target is recorded only after a worker gets far enough in the
    SNMP workflow to establish which address actually succeeded.  Periodic draft
    snapshots therefore must not persist a missing-target error for transient states.

    Older releases did exactly that, so this validator also removes any stale
    ``missing_query_target`` error when the host now has a target or is currently in
    a nonterminal state.  Terminal rows continue to receive the operator-visible
    diagnostics established for seeds.csv, with COMPLETE/no-target remaining a hard
    state-integrity error.
    """

    operation = "seed_inventory_validation"
    category = "missing_query_target"
    stale_error_host_ids: list[int] = []
    missing_terminal_rows: list[Any] = []

    for row in hosts:
        if row["classification"] != "managed_device":
            continue

        state_name = str(row["state"])
        query_target = str(row["query_target"] or "").strip()
        if query_target or state_name not in _SEED_TARGET_TERMINAL_STATES:
            # Self-heal snapshot-time warnings written by v0.7.0 and earlier.
            # Collect IDs first so StateStore can delete any stale rows using one
            # batched commit instead of one transaction per managed device.
            stale_error_host_ids.append(int(row["id"]))
        else:
            missing_terminal_rows.append(row)

    state.clear_errors(stale_error_host_ids, operation, category)

    for row in missing_terminal_rows:
        state_name = str(row["state"])
        message, recoverable = _missing_query_target_message(state_name)
        state.ensure_error(
            int(row["id"]),
            operation,
            category,
            message,
            recoverable=recoverable,
            final_device_status=state_name,
        )


def _seed_notes(errors: list[dict[str, Any]], host_ref: int) -> str:
    """Build concise seed notes from canonical JSON error records.

    Args:
        errors: Canonical ``discovery.json`` error objects in discovery order.
        host_ref: Host ID whose associated errors should be summarized.

    Returns:
        Distinct ``operation/category: message`` entries joined by `` | ``.
    """

    notes: list[str] = []
    for error in errors:
        if not isinstance(error, dict) or error.get("host_ref") != host_ref:
            continue
        operation = str(error.get("operation") or "error")
        category = str(error.get("category") or "error")
        message = str(error.get("message") or "").strip()
        item = f"{operation}/{category}: {message}" if message else f"{operation}/{category}"
        if item not in notes:
            notes.append(item)
    return " | ".join(notes)


def _seed_output_row(
    record: dict[str, Any],
    errors: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return one reusable ``seeds.csv`` row from the discovery document.

    Args:
        record: Canonical host object already normalized for JSON output.
        errors: Canonical error objects used for the derived ``notes`` field.

    Returns:
        Mapping matching :data:`SEED_CSV_COLUMNS`. Direct identity/state fields
        retain the same names and values as JSON; ``origin`` and ``notes`` are
        deliberate presentation transforms.
    """

    addresses = record.get("addresses", {})
    if not isinstance(addresses, dict):
        addresses = {}
    snmp = record.get("snmp", {})
    if not isinstance(snmp, dict):
        snmp = {}
    host_ref = int(record["id"])
    return {
        "preferred_name": record.get("preferred_name") or "",
        "queried_as": record.get("queried_as") or "",
        "ipv4": ";".join(str(value) for value in addresses.get("ipv4", [])),
        "ipv6": ";".join(str(value) for value in addresses.get("ipv6", [])),
        "credential_profile": snmp.get("credential_profile") or "",
        "credential_result": snmp.get("credential_result") or "",
        "origin": "seed" if record.get("is_seed") else "learned",
        "state": record.get("state") or "",
        "last_seen": record.get("last_seen") or "",
        "notes": _seed_notes(errors, host_ref),
    }


def _unknown_device_csv_row(record: dict[str, Any]) -> dict[str, Any]:
    """Project one canonical unknown host into ``unknown-devices.csv``.

    Args:
        record: Canonical host object whose classification is ``unknown_device``.

    Returns:
        Review projection built from host and ``observed_by_neighbors`` data.
        Custom fixed-field reports share this exact public field set; callers
        that need system values must select explicit ``json.host.system.*``
        paths instead.
    """

    addresses = record.get("addresses", {})
    if not isinstance(addresses, dict):
        addresses = {}
    reasons = record.get("classification_reason", [])
    if not isinstance(reasons, list):
        reasons = []
    return {
        "preferred_name": record.get("preferred_name") or "",
        "ipv4": ";".join(str(value) for value in addresses.get("ipv4", [])),
        "ipv6": ";".join(str(value) for value in addresses.get("ipv6", [])),
        "last_seen": record.get("last_seen") or "",
        **_inbound_evidence(record),
        "observed_by_neighbors": _observed_by_neighbor_summary(record),
        "classification_reason": ";".join(str(value) for value in reasons),
    }


def _error_csv_row(error: dict[str, Any]) -> dict[str, Any]:
    """Project canonical scalar error fields directly into ``errors.csv``."""

    return {
        "timestamp": error.get("timestamp") or "",
        "device": error.get("device") or "",
        "query_target": error.get("query_target") or "",
        "attempted_target": error.get("attempted_target") or "",
        "address_family": error.get("address_family") or "",
        "phase": error.get("phase") or "",
        "operation": error.get("operation") or "",
        "collector": error.get("collector") or "",
        "category": error.get("category") or "",
        "exception_type": error.get("exception_type") or "",
        "exception_errno": (
            error.get("exception_errno") if error.get("exception_errno") is not None else ""
        ),
        "exception_strerror": error.get("exception_strerror") or "",
        "credential_profile": error.get("credential_profile") or "",
        "credential_stage": error.get("credential_stage") or "",
        "credential_source": error.get("credential_source") or "",
        "credential_label": error.get("credential_label") or "",
        "attempt": (error.get("attempt") if error.get("attempt") is not None else ""),
        "message": error.get("message") or "",
        "recoverable": bool(error.get("recoverable")),
        "final_state": error.get("final_state") or "",
        "recovered": bool(error.get("recovered")),
        "recovered_by_target": error.get("recovered_by_target") or "",
    }


def _error_record(row: Any) -> dict[str, Any]:
    """Return one canonical error with per-route and final-host provenance.

    ``query_target`` is host-level context and may identify a later successful
    route.  ``attempted_target`` belongs to this historical error.  Final state
    and recovery fields are derived at snapshot time so late success never
    rewrites or hides the failed observation.
    """

    current_state = row["current_host_state"]
    stored_state = row["final_device_status"]
    final_state = (
        str(current_state or stored_state).lower()
        if current_state is not None or stored_state is not None
        else None
    )
    attempted_target = row["attempted_target"] or None
    query_target = row["query_target"] or None
    recovered = bool(
        final_state == "complete"
        and attempted_target
        and query_target
        and str(row["operation"]) == "snmp_basic"
    )
    exception_args = _json(row["exception_args_json"], [])
    if not isinstance(exception_args, list):
        exception_args = []
    return {
        "host_ref": int(row["host_id"]) if row["host_id"] is not None else None,
        "device": row["preferred_name"] or None,
        "query_target": query_target,
        "attempted_target": attempted_target,
        "address_family": row["address_family"] or None,
        "phase": row["phase"] or None,
        "timestamp": row["timestamp"],
        "operation": row["operation"],
        "collector": row["collector"] or None,
        "category": row["category"],
        "exception_type": row["exception_type"] or None,
        "exception_errno": row["exception_errno"],
        "exception_strerror": row["exception_strerror"] or None,
        "exception_args": exception_args,
        "credential_profile": row["credential_profile"],
        "credential_stage": row["credential_stage"],
        "credential_source": row["credential_source"],
        "credential_label": row["credential_label"],
        "attempt": row["attempt"],
        "message": row["message"],
        "recoverable": bool(row["recoverable"]),
        "final_state": final_state,
        "recovered": recovered,
        "recovered_by_target": query_target if recovered else None,
    }


def _remove_disabled_output(path: Path) -> None:
    """Remove a stale fixed/custom CSV when configuration disables it.

    A paused run can be resumed with a changed output configuration.  Removing an
    older draft/final file prevents a disabled report from surviving merely because
    it was written by a previous invocation of the same run.
    """

    path.unlink(missing_ok=True)


def _build_discovery_document(
    state: StateStore,
    config: AppConfig,
    *,
    run_id: str,
    status: str,
    phase_metrics: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Build the canonical in-memory document used by JSON and every fixed CSV.

    Args:
        state: Authoritative SQLite discovery state to snapshot.
        config: Effective runtime configuration.
        run_id: Logical run identifier recorded in discovery metadata.
        status: Current or terminal run status recorded in the snapshot.

    Returns:
        Sanitized schema-versioned discovery document. After this boundary fixed
        CSV rendering must not query ``StateStore`` again; this invariant keeps
        ``discovery.json`` sufficient for post-processing and future exporters.
    """

    hosts = state.all_hosts()
    _ensure_seed_integrity_errors(state, hosts)
    graph_started = time.monotonic()
    graph_result = state.materialize_topology_graph()
    if phase_metrics is not None:
        phase_metrics["graph_resolution_duration"] = round(
            max(0.0, time.monotonic() - graph_started), 3
        )
    records = [_host_record(state, row, config) for row in hosts]
    metadata = {
        "run_id": run_id,
        "status": status,
        "started": state.get_meta("started"),
        "completed": state.get_meta("completed"),
        "generated": iso_now(),
        "boundaries": config.discovery.boundaries,
        "discovery_mode": state.get_meta("discovery_mode"),
        "effective_max_devices": state.get_meta("effective_max_devices"),
        "configured_max_devices": config.discovery.max_devices,
        "configured_max_hosts": config.discovery.max_hosts,
        "seed_order": state.get_meta("seed_order", config.discovery.seed_order),
        "shuffle_key": state.get_meta("seed_shuffle_key"),
        "limit_behavior": config.discovery.limit_behavior,
        "limit_reason": state.get_meta("limit_reason"),
        "completion_reason": state.get_meta("completion_reason"),
        "snmp_report_metrics": config.snmp.report_metrics,
        "counts": state.counts(),
        "topology_graph_fingerprint": graph_result.document.get("projection_fingerprint"),
        "topology_graph_summary": graph_result.document.get("summary", {}),
    }
    errors = [_error_record(row) for row in state.all_errors()]
    return _safe_output_value(
        {
            "schema_version": DISCOVERY_JSON_SCHEMA_VERSION,
            "discovery": metadata,
            "topology_graph": graph_result.document,
            "hosts": records,
            "errors": errors,
        }
    )


def _custom_csv_contexts(
    document: dict[str, Any],
    custom: CustomCsvConfig,
) -> Any:
    """Yield row contexts for one configured custom CSV source.

    Args:
        document: Canonical schema-versioned discovery document.
        custom: Validated custom CSV definition whose ``source`` determines row
            cardinality and which JSON contexts are available.

    Yields:
        Dictionaries carrying a fixed presentation row plus the relevant
        ``host``, ``member``, ``error``, and ``discovery`` JSON roots.
    """

    hosts = document.get("hosts", [])
    errors = document.get("errors", [])
    discovery = document.get("discovery", {})
    if not isinstance(hosts, list):
        hosts = []
    if not isinstance(errors, list):
        errors = []
    if not isinstance(discovery, dict):
        discovery = {}
    error_records = [item for item in errors if isinstance(item, dict)]

    if custom.source == "errors":
        for error in error_records:
            yield {
                "fixed": _error_csv_row(error),
                "error": error,
                "discovery": discovery,
            }
        return

    for host in hosts:
        if not isinstance(host, dict):
            continue
        if custom.source == "hosts":
            yield {
                "fixed": _host_csv_row(host),
                "host": host,
                "discovery": discovery,
            }
            continue
        if custom.source == "seeds":
            if host.get("classification") != "managed_device":
                continue
            # Seed rows retain their normal fixed seed projection and also expose
            # the same host presentation row used by hosts.csv. This is safe
            # because the seed source remains exactly one row per managed host.
            yield {
                "fixed": _seed_output_row(host, error_records),
                "host_fixed": _host_csv_row(host),
                "host": host,
                "discovery": discovery,
            }
            continue
        if custom.source == "unknown-devices":
            if host.get("classification") != "unknown_device":
                continue
            yield {
                "fixed": _unknown_device_csv_row(host),
                "host": host,
                "discovery": discovery,
            }
            continue
        if custom.source != "stack-members":
            continue
        system = host.get("system", {})
        if not isinstance(system, dict):
            continue
        members = system.get("stack_members", [])
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, dict):
                continue
            yield {
                "fixed": _stack_member_csv_row(host, member),
                "host": host,
                "member": member,
                "discovery": discovery,
            }


def _custom_csv_row(
    custom: CustomCsvConfig,
    context: dict[str, Any],
) -> dict[str, Any]:
    """Resolve one configured custom CSV row from a validated row context.

    Args:
        custom: Custom report definition with ordered field/header selections.
        context: Context yielded by :func:`_custom_csv_contexts`.

    Returns:
        Header-keyed row ready for final CSV sanitation/serialization.
    """

    row: dict[str, Any] = {}
    for column in custom.columns:
        field_name = str(column.field).strip()
        header = column.header.strip() if column.header is not None else default_header(field_name)
        fixed_prefix = f"{custom.source}."
        if field_name.startswith(fixed_prefix):
            leaf = field_name[len(fixed_prefix) :]
            row[header] = context.get("fixed", {}).get(leaf, "")
            continue
        if custom.source == "seeds" and field_name.startswith("hosts."):
            leaf = field_name[len("hosts.") :]
            row[header] = context.get("host_fixed", {}).get(leaf, "")
            continue

        _, root, path = field_name.split(".", 2)
        value = resolve_json_path(context.get(root), path)
        row[header] = transform_value(value, column.transform)
    return row


def _custom_csv_fieldnames(custom: CustomCsvConfig) -> list[str]:
    """Return configured/custom-default header labels in output column order."""

    return [
        column.header.strip()
        if column.header is not None
        else default_header(str(column.field).strip())
        for column in custom.columns
    ]


def write_custom_csv_outputs(
    document: dict[str, Any],
    config: AppConfig,
    directory: Path,
    *,
    draft: bool = False,
    _empty_csvs_not_written: list[str] | None = None,
    _emit_empty_alert: bool = True,
) -> list[Path]:
    """Write enabled operator-defined CSV reports from the canonical document.

    Args:
        document: Canonical discovery document; SQLite/state access is never used.
        config: Effective configuration containing validated custom definitions.
        directory: Destination run/scratch output directory.
        draft: Append ``.draft`` to custom filenames for periodic snapshots.
        _empty_csvs_not_written: Internal accumulator used by :func:`write_outputs`
            to aggregate fixed/custom empty-file logging into one INFO record.
        _emit_empty_alert: Emit an empty-file INFO record directly when true.

    Returns:
        Paths of custom CSV files actually written.

    Raises:
        ValueError: If the discovery document schema is unsupported.
    """

    schema_version = document.get("schema_version")
    if schema_version != DISCOVERY_JSON_SCHEMA_VERSION:
        raise ValueError(
            "unsupported discovery document schema version "
            f"{schema_version!r}; expected {DISCOVERY_JSON_SCHEMA_VERSION}"
        )

    directory.mkdir(parents=True, exist_ok=True)
    suffix = ".draft" if draft else ""
    written: list[Path] = []
    suppressed = _empty_csvs_not_written if _empty_csvs_not_written is not None else []

    for name in sorted(config.output.custom_csv):
        custom = config.output.custom_csv[name]
        path = directory / f"{custom.filename}{suffix}"
        if not custom.enabled:
            _remove_disabled_output(path)
            continue
        if _atomic_csv(
            path,
            _custom_csv_fieldnames(custom),
            (
                _custom_csv_row(custom, context)
                for context in _custom_csv_contexts(document, custom)
            ),
            write_empty=config.output.write_empty_csv,
        ):
            written.append(path)
        else:
            suppressed.append(custom.filename)

    discovery = document.get("discovery", {})
    status = discovery.get("status") if isinstance(discovery, dict) else None
    if (
        _emit_empty_alert
        and suppressed
        and config.output.log_alert_on_empty_csv
        and status != "RUNNING"
    ):
        LOG.info("empty csv not written for %s", ", ".join(suppressed))

    return written


def write_fixed_csv_outputs(
    document: dict[str, Any],
    config: AppConfig,
    directory: Path,
    *,
    draft: bool = False,
    _empty_csvs_not_written: list[str] | None = None,
    _emit_empty_alert: bool = True,
) -> list[Path]:
    """Write all enabled fixed CSV views from a canonical discovery document.

    Args:
        document: Parsed canonical discovery document, normally the same object
            serialized as ``discovery.json``. The function intentionally has no
            ``StateStore`` parameter so callers can reproduce CSVs post-run from
            JSON alone.
        config: Effective output configuration controlling which fixed views and
            empty files are written.
        directory: Destination directory.
        draft: Append ``.draft`` to generated filenames when true.
        _empty_csvs_not_written: Internal accumulator used to combine fixed and
            custom empty-file messages during a normal discovery snapshot.
        _emit_empty_alert: Emit the optional empty-file INFO record directly.

    Returns:
        Paths of fixed CSV files actually written.

    Raises:
        ValueError: If ``hosts`` or ``errors`` are not JSON arrays.
    """

    schema_version = document.get("schema_version")
    if schema_version != DISCOVERY_JSON_SCHEMA_VERSION:
        raise ValueError(
            "unsupported discovery document schema version "
            f"{schema_version!r}; expected {DISCOVERY_JSON_SCHEMA_VERSION}"
        )

    directory.mkdir(parents=True, exist_ok=True)
    suffix = ".draft" if draft else ""
    hosts = document.get("hosts", [])
    errors = document.get("errors", [])
    if not isinstance(hosts, list):
        raise ValueError("discovery document hosts must be an array")
    if not isinstance(errors, list):
        raise ValueError("discovery document errors must be an array")
    host_records = [record for record in hosts if isinstance(record, dict)]
    error_records = [record for record in errors if isinstance(record, dict)]

    written_paths: list[Path] = []
    empty_csvs_not_written = _empty_csvs_not_written if _empty_csvs_not_written is not None else []

    hosts_path = directory / f"hosts.csv{suffix}"
    if config.output.write_hosts_csv:
        if _atomic_csv(
            hosts_path,
            HOSTS_CSV_FIELDS,
            (_host_csv_row(record) for record in host_records),
            write_empty=config.output.write_empty_csv,
        ):
            written_paths.append(hosts_path)
        else:
            empty_csvs_not_written.append("hosts.csv")
    else:
        _remove_disabled_output(hosts_path)

    stack_members_path = directory / f"stack-members.csv{suffix}"
    if config.output.write_stack_members_csv:
        if _atomic_csv(
            stack_members_path,
            STACK_MEMBERS_CSV_FIELDS,
            _stack_member_csv_rows(host_records),
            write_empty=config.output.write_empty_csv,
        ):
            written_paths.append(stack_members_path)
        else:
            empty_csvs_not_written.append("stack-members.csv")
    else:
        _remove_disabled_output(stack_members_path)

    seeds_path = directory / f"seeds.csv{suffix}"
    if config.output.write_seeds_csv:
        if _atomic_csv(
            seeds_path,
            SEED_CSV_COLUMNS,
            (
                _seed_output_row(record, error_records)
                for record in host_records
                if record.get("classification") == "managed_device"
            ),
            write_empty=config.output.write_empty_csv,
        ):
            written_paths.append(seeds_path)
        else:
            empty_csvs_not_written.append("seeds.csv")
    else:
        _remove_disabled_output(seeds_path)

    unknown_path = directory / f"unknown-devices.csv{suffix}"
    if config.output.write_unknown_devices_csv:
        if _atomic_csv(
            unknown_path,
            UNKNOWN_DEVICES_CSV_FIELDS,
            (
                _unknown_device_csv_row(record)
                for record in host_records
                if record.get("classification") == "unknown_device"
            ),
            write_empty=config.output.write_empty_csv,
        ):
            written_paths.append(unknown_path)
        else:
            empty_csvs_not_written.append("unknown-devices.csv")
    else:
        _remove_disabled_output(unknown_path)

    errors_path = directory / f"errors.csv{suffix}"
    if config.output.write_errors_csv:
        if _atomic_csv(
            errors_path,
            ERRORS_CSV_FIELDS,
            (_error_csv_row(error) for error in error_records),
            write_empty=config.output.write_empty_csv,
        ):
            written_paths.append(errors_path)
        else:
            empty_csvs_not_written.append("errors.csv")
    else:
        _remove_disabled_output(errors_path)

    discovery = document.get("discovery", {})
    status = discovery.get("status") if isinstance(discovery, dict) else None
    if (
        _emit_empty_alert
        and empty_csvs_not_written
        and config.output.log_alert_on_empty_csv
        and status != "RUNNING"
    ):
        LOG.info(
            "empty csv not written for %s",
            ", ".join(empty_csvs_not_written),
        )

    return written_paths


def write_outputs(
    state: StateStore,
    config: AppConfig,
    directory: Path,
    *,
    run_id: str,
    status: str,
    draft: bool,
) -> OutputWriteResult:
    """Write canonical JSON plus fixed/custom CSV projections for one snapshot.

    Args:
        state: Authoritative SQLite discovery state used only to assemble the
            canonical discovery document.
        config: Effective output/SNMP configuration for this invocation.
        directory: Destination directory for draft or final files.
        run_id: Logical run identifier recorded in discovery metadata.
        status: Current or terminal run status recorded in the snapshot.
        draft: Append ``.draft`` to generated filenames when true.

    Returns:
        Paths actually written, beginning with ``discovery.json``. Once the
        canonical document is built, every CSV is rendered exclusively from it.
    """

    directory.mkdir(parents=True, exist_ok=True)
    suffix = ".draft" if draft else ""
    phase_metrics: dict[str, float] = {}
    document = _build_discovery_document(
        state,
        config,
        run_id=run_id,
        status=status,
        phase_metrics=phase_metrics,
    )
    discovery_path = directory / f"discovery.json{suffix}"
    serialization_started = time.monotonic()
    _atomic_json(discovery_path, document, config.output.pretty_json_indent)
    phase_metrics["graph_serialization_duration"] = round(
        max(0.0, time.monotonic() - serialization_started), 3
    )
    empty_csvs_not_written: list[str] = []
    fixed_csv_paths = write_fixed_csv_outputs(
        document,
        config,
        directory,
        draft=draft,
        _empty_csvs_not_written=empty_csvs_not_written,
        _emit_empty_alert=False,
    )
    custom_csv_paths = write_custom_csv_outputs(
        document,
        config,
        directory,
        draft=draft,
        _empty_csvs_not_written=empty_csvs_not_written,
        _emit_empty_alert=False,
    )
    if empty_csvs_not_written and config.output.log_alert_on_empty_csv and status != "RUNNING":
        LOG.info(
            "empty csv not written for %s",
            ", ".join(empty_csvs_not_written),
        )
    return OutputWriteResult(
        [discovery_path, *fixed_csv_paths, *custom_csv_paths],
        phase_metrics=phase_metrics,
    )


def _atomic_json(path: Path, payload: Any, indent: int) -> None:
    """Serialize JSON through an fsynced temporary file, then atomically replace.

    Args:
        path: Final JSON pathname.
        payload: JSON-serializable discovery structure.
        indent: Pretty-print indentation width.
    """

    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8") as fh:
        json.dump(_safe_output_value(payload), fh, indent=indent, sort_keys=False, default=str)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp, path)


def _atomic_csv(
    path: Path,
    fieldnames: list[str],
    rows: Any,
    *,
    write_empty: bool = True,
) -> bool:
    """Write one fixed-schema CSV atomically after final cell sanitization.

    Args:
        path: Final CSV pathname.
        fieldnames: Ordered project-owned schema written as the header.
        rows: Iterable of row mappings; extra keys are ignored by design.
        write_empty: Write a header-only file when ``rows`` is empty. When false,
            remove any stale file at ``path`` and report that no file was written.

    Returns:
        ``True`` when a CSV was written, otherwise ``False`` for an empty iterable
        suppressed by ``write_empty=False``. The iterator is consumed only once,
        so generator-backed reports do not need to be materialized in memory.
    """

    iterator = iter(rows)
    sentinel = object()
    first = next(iterator, sentinel)
    if first is sentinel and not write_empty:
        path.unlink(missing_ok=True)
        return False

    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        # Sanitize each row at the final serialization boundary.  This protects
        # grep/awk and other line-oriented tools even if malformed data was loaded
        # from an older checkpoint created before collector-level sanitation.
        if first is not sentinel:
            writer.writerow(_safe_csv_row(dict(first), fieldnames))
            writer.writerows(_safe_csv_row(dict(row), fieldnames) for row in iterator)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp, path)
    return True


def finalize_to_persistent(
    scratch_dir: Path,
    output_run_dir: Path,
    latest_link: Path,
    *,
    output_names: tuple[str, ...] | list[str] | None = None,
    known_output_names: tuple[str, ...] | list[str] | None = None,
) -> None:
    """Atomically publish enabled outputs and update the ``latest`` symlink.

    Args:
        scratch_dir: Directory containing completed non-draft output files.
        output_run_dir: Timestamped persistent destination for the run.
        latest_link: Symlink updated to reference ``output_run_dir`` after success.
        output_names: Exact filenames written by ``write_outputs``. When omitted,
            existing names from ``OUTPUT_NAMES`` are discovered in ``scratch_dir``.
        known_output_names: Complete fixed/custom filename set that may belong to
            this run. Names absent from ``output_names`` are removed from a reused
            persistent output directory so disabled/empty custom reports cannot
            survive a resumed invocation.

    Raises:
        ValueError: If ``discovery.json`` is not part of the finalized set.
        FileNotFoundError: If an explicitly selected source file is missing.

    The optional name list prevents disabled or conditionally empty reports from
    being mistaken for missing artifacts.
    """

    output_run_dir.mkdir(parents=True, exist_ok=True)
    names = (
        tuple(output_names)
        if output_names is not None
        else tuple(name for name in OUTPUT_NAMES if (scratch_dir / name).exists())
    )
    if "discovery.json" not in names:
        raise ValueError("discovery.json must always be finalized")

    # A finalization retry can reuse a partially populated output directory. Remove
    # any fixed report that is disabled now so old files cannot contradict the
    # configuration associated with the completed run.
    cleanup_names = tuple(known_output_names or OUTPUT_NAMES)
    for known_name in cleanup_names:
        if known_name not in names:
            (output_run_dir / known_name).unlink(missing_ok=True)

    for name in names:
        source = scratch_dir / name
        if not source.exists():
            raise FileNotFoundError(source)
        temp = output_run_dir / f".{name}.tmp"
        with source.open("rb") as src, temp.open("wb") as dst:
            shutil.copyfileobj(src, dst, length=1024 * 1024)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(temp, output_run_dir / name)

    publish_latest_symlink(latest_link, output_run_dir)
