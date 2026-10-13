"""Canonical fixed/custom CSV field namespace and JSON-value transforms.

The custom CSV interface intentionally exposes a bounded registry rather than
arbitrary Python expressions.  Future developers can add a field here when its
row meaning and JSON source are understood, which keeps operator configuration
stable and prevents ad-hoc exporter semantics from diverging from
``discovery.json``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Literal

from lldp_runner.seeds import SEED_CSV_COLUMNS

HOSTS_CSV_FIELDS = [
    "preferred_name",
    "queried_as",
    "snmp_sysname",
    "origin",
    "classification",
    "tags",
    "state",
    "last_seen",
    "last_seen_source",
    "ipv4",
    "ipv6",
    "manufacturer",
    "model",
    "version",
    "serial_number",
    "uptime_seconds",
    "credential_profile",
    "credential_result",
    "learned_neighbors",
    "observed_by_neighbors",
]

STACK_MEMBERS_CSV_FIELDS = [
    "preferred_name",
    "queried_as",
    "snmp_sysname",
    "origin",
    "classification",
    "tags",
    "state",
    "last_seen",
    "last_seen_source",
    "ipv4",
    "ipv6",
    "member_number",
    "entity_index",
    "name",
    "description",
    "manufacturer",
    "model",
    "version",
    "serial_number",
    "hardware_revision",
    "firmware_revision",
    "uptime_seconds",
    "credential_profile",
    "credential_result",
    "learned_neighbors",
    "observed_by_neighbors",
]

UNKNOWN_DEVICES_CSV_FIELDS = [
    "preferred_name",
    "ipv4",
    "ipv6",
    "last_seen",
    "protocols",
    "observed_names",
    "remote_platforms",
    "remote_descriptions",
    "capabilities",
    "observed_chassis_ids",
    "observed_chassis_id_subtypes",
    "observed_chassis_id_subtype_ids",
    "observed_by_neighbors",
    "classification_reason",
]

ERRORS_CSV_FIELDS = [
    "timestamp",
    "device",
    "query_target",
    "attempted_target",
    "address_family",
    "phase",
    "operation",
    "collector",
    "category",
    "exception_type",
    "exception_errno",
    "exception_strerror",
    "credential_profile",
    "credential_stage",
    "credential_source",
    "credential_label",
    "attempt",
    "message",
    "recoverable",
    "final_state",
    "recovered",
    "recovered_by_target",
]

FIXED_FIELDS_BY_SOURCE: dict[str, tuple[str, ...]] = {
    "hosts": tuple(HOSTS_CSV_FIELDS),
    "stack-members": tuple(STACK_MEMBERS_CSV_FIELDS),
    "seeds": tuple(SEED_CSV_COLUMNS),
    "unknown-devices": tuple(UNKNOWN_DEVICES_CSV_FIELDS),
    "errors": tuple(ERRORS_CSV_FIELDS),
}


@dataclass(frozen=True, slots=True)
class JsonFieldSpec:
    """Describe one JSON path that is safe to expose to custom CSV output.

    Args:
        kind: JSON value shape expected at the path.
        transforms: Explicit transforms permitted for the field.  An empty set
            means the scalar can be emitted directly without a transform.
        description: Operator/developer explanation of the value's meaning.
    """

    kind: Literal["scalar", "list", "object"]
    transforms: frozenset[str] = frozenset()
    description: str = ""


_SCALAR = JsonFieldSpec("scalar")
_BOOL_ORIGIN = JsonFieldSpec("scalar", frozenset({"origin"}))
_LIST_JOIN = JsonFieldSpec(
    "list", frozenset({"join:semicolon", "join:comma", "json"})
)
_LIST_JSON = JsonFieldSpec("list", frozenset({"json"}))
_OBJECT_JSON = JsonFieldSpec("object", frozenset({"json"}))

# These are intentionally explicit.  A key merely existing somewhere in a JSON
# document does not automatically make it a stable custom-CSV field.  Additions
# should have clear row semantics and tests before becoming operator-facing API.
JSON_FIELDS: dict[str, dict[str, JsonFieldSpec]] = {
    "host": {
        "id": _SCALAR,
        "preferred_name": _SCALAR,
        "queried_as": _SCALAR,
        "snmp_sysname": _SCALAR,
        "classification": _SCALAR,
        "state": _SCALAR,
        "is_seed": _BOOL_ORIGIN,
        "first_seen": _SCALAR,
        "last_seen": _SCALAR,
        "last_seen_source": _SCALAR,
        "chassis_id": _SCALAR,
        "classification_reason": _LIST_JOIN,
        "tags": _LIST_JOIN,
        "names": _LIST_JOIN,
        "addresses.ipv4": _LIST_JOIN,
        "addresses.ipv6": _LIST_JOIN,
        "icmp": _LIST_JSON,
        "learned_neighbors": _LIST_JSON,
        "observed_by_neighbors": _LIST_JSON,
        "system.sys_name": _SCALAR,
        "system.sys_descr": _SCALAR,
        "system.sys_object_id": _SCALAR,
        "system.sys_uptime_ticks": _SCALAR,
        "system.sys_contact": _SCALAR,
        "system.sys_location": _SCALAR,
        "system.manufacturer": _SCALAR,
        "system.model": _SCALAR,
        "system.version": _SCALAR,
        "system.serial_number": _SCALAR,
        "system.hardware_revision": _SCALAR,
        "system.firmware_revision": _SCALAR,
        "system.entity_software_revision": _SCALAR,
        "system.snmp_engine_id": _SCALAR,
        "system.stack_members": _LIST_JSON,
        "snmp.credential_profile": _SCALAR,
        "snmp.credential_result": _SCALAR,
        "snmp.collection_metrics": _OBJECT_JSON,
    },
    "member": {
        "entity_index": _SCALAR,
        "member_number": _SCALAR,
        "name": _SCALAR,
        "description": _SCALAR,
        "manufacturer": _SCALAR,
        "model": _SCALAR,
        "serial_number": _SCALAR,
        "hardware_revision": _SCALAR,
        "firmware_revision": _SCALAR,
        "software_revision": _SCALAR,
        "uptime_seconds": _SCALAR,
    },
    "error": {
        "host_ref": _SCALAR,
        "device": _SCALAR,
        "query_target": _SCALAR,
        "attempted_target": _SCALAR,
        "address_family": _SCALAR,
        "phase": _SCALAR,
        "timestamp": _SCALAR,
        "operation": _SCALAR,
        "collector": _SCALAR,
        "category": _SCALAR,
        "exception_type": _SCALAR,
        "exception_errno": _SCALAR,
        "exception_strerror": _SCALAR,
        "exception_args": _LIST_JSON,
        "credential_profile": _SCALAR,
        "credential_stage": _SCALAR,
        "credential_source": _SCALAR,
        "credential_label": _SCALAR,
        "attempt": _SCALAR,
        "message": _SCALAR,
        "recoverable": _SCALAR,
        "final_state": _SCALAR,
        "recovered": _SCALAR,
        "recovered_by_target": _SCALAR,
    },
    "discovery": {
        "run_id": _SCALAR,
        "status": _SCALAR,
        "started": _SCALAR,
        "completed": _SCALAR,
        "generated": _SCALAR,
        "boundaries": _LIST_JOIN,
        "discovery_mode": _SCALAR,
        "effective_max_devices": _SCALAR,
        "configured_max_devices": _SCALAR,
        "configured_max_hosts": _SCALAR,
        "seed_order": _SCALAR,
        "shuffle_key": _SCALAR,
        "limit_behavior": _SCALAR,
        "limit_reason": _SCALAR,
        "completion_reason": _SCALAR,
        "snmp_report_metrics": _SCALAR,
        "counts": _OBJECT_JSON,
    },
}

_SOURCE_JSON_ROOTS: dict[str, frozenset[str]] = {
    "hosts": frozenset({"host", "discovery"}),
    "stack-members": frozenset({"host", "member", "discovery"}),
    "seeds": frozenset({"host", "discovery"}),
    "unknown-devices": frozenset({"host", "discovery"}),
    "errors": frozenset({"error", "discovery"}),
}


def default_header(field_name: str) -> str:
    """Return the default CSV header for one public field reference.

    Args:
        field_name: Fixed-field or ``json.<root>.<path>`` reference.

    Returns:
        Final leaf component, which matches LLDP-Runner's canonical key/header
        naming rule unless the operator supplies an explicit custom label.
    """

    return field_name.rsplit(".", 1)[-1]


def validate_field_reference(
    source: str,
    field_name: str,
    transform: str | None,
) -> None:
    """Validate one custom column against its declared row source.

    Args:
        source: Custom CSV row source.
        field_name: Operator-facing fixed or JSON field reference.
        transform: Optional controlled transform name.

    Raises:
        ValueError: If the namespace, path, or transform is unsupported.
    """

    if source not in FIXED_FIELDS_BY_SOURCE:
        raise ValueError(f"unknown custom CSV source {source!r}")

    # The seeds source is a managed-host subset with one host per row. Reusing
    # hosts.* fixed presentation fields therefore preserves row cardinality while
    # allowing seed-grain inventory reports to share hosts.csv formatting.
    fixed_namespaces = (source, "hosts") if source == "seeds" else (source,)
    for namespace in fixed_namespaces:
        prefix = f"{namespace}."
        if not field_name.startswith(prefix):
            continue
        leaf = field_name[len(prefix) :]
        if "." in leaf or leaf not in FIXED_FIELDS_BY_SOURCE[namespace]:
            raise ValueError(
                f"unknown field {field_name!r} for custom CSV source {source!r}"
            )
        if transform:
            raise ValueError(
                f"field {field_name!r} is already a fixed presentation field; "
                "select a json.* source when an additional transform is needed"
            )
        return

    if not field_name.startswith("json."):
        allowed = f"{source}.<field> or json.<context>.<field>"
        raise ValueError(f"invalid custom CSV field {field_name!r}; expected {allowed}")

    parts = field_name.split(".", 2)
    if len(parts) != 3 or not parts[2]:
        raise ValueError(f"invalid custom CSV JSON field {field_name!r}")
    root, path = parts[1], parts[2]
    if root not in _SOURCE_JSON_ROOTS[source]:
        allowed_roots = ", ".join(sorted(_SOURCE_JSON_ROOTS[source]))
        raise ValueError(
            f"JSON context {root!r} is not valid for source {source!r}; "
            f"use one of: {allowed_roots}"
        )
    spec = JSON_FIELDS.get(root, {}).get(path)
    if spec is None:
        raise ValueError(f"unsupported custom CSV JSON field {field_name!r}")

    if spec.kind == "scalar":
        allowed = spec.transforms | frozenset({"lower", "upper"})
        if transform is not None and transform not in allowed:
            names = ", ".join(sorted(allowed)) or "none"
            raise ValueError(
                f"transform {transform!r} is not valid for {field_name!r}; "
                f"allowed: {names}"
            )
        return

    if transform is None:
        raise ValueError(
            f"field {field_name!r} contains a JSON {spec.kind}; "
            f"set transform to one of: {', '.join(sorted(spec.transforms))}"
        )
    if transform not in spec.transforms:
        raise ValueError(
            f"transform {transform!r} is not valid for {field_name!r}; "
            f"allowed: {', '.join(sorted(spec.transforms))}"
        )


def resolve_json_path(value: Any, path: str) -> Any:
    """Resolve a validated dotted JSON path from one row context object.

    Args:
        value: Root JSON mapping selected by the custom row context.
        path: Dotted path previously validated against :data:`JSON_FIELDS`.

    Returns:
        Stored value, or ``None`` when an optional/missing key is absent.
    """

    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def transform_value(value: Any, transform: str | None) -> Any:
    """Convert one validated JSON value into a deterministic CSV cell.

    Args:
        value: JSON scalar/list/object resolved from the canonical document.
        transform: Optional controlled transform selected in configuration.

    Returns:
        CSV-safe scalar/string value. Missing JSON values become an empty cell.
    """

    if value is None:
        return ""
    if transform == "origin":
        return "seed" if bool(value) else "learned"
    if transform == "lower":
        return str(value).lower()
    if transform == "upper":
        return str(value).upper()
    if transform == "join:semicolon":
        return ";".join(str(item) for item in value)
    if transform == "join:comma":
        return ",".join(str(item) for item in value)
    if transform == "json":
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, bool):
        return "true" if value else "false"
    return value
