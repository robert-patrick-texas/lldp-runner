"""Deterministic shadow analysis for local-interface observation groups.

The current compatibility projection still stores one learned-neighbor row per
resolved edge.  This module builds a second, audit-only view that treats a local
interface as a container for one or more protocol advertisements.  It prepares
LLDP-Runner for the 0.32 graph resolver without changing live scheduling or host
materialization in the 0.31 maintenance line.
"""

from __future__ import annotations

from typing import Any

from lldp_runner.claims import stable_fingerprint
from lldp_runner.identity import normalized_advertised_name
from lldp_runner.models import NeighborObservation

_PROTOCOL_ORDER = {"cdp": 0, "lldp": 1, "lldpv2": 2}


def _protocols(observation: NeighborObservation) -> list[str]:
    raw = observation.details.get("protocols", [observation.protocol])
    values = (
        [str(value).casefold() for value in raw]
        if isinstance(raw, list)
        else [observation.protocol]
    )
    return sorted(
        dict.fromkeys(values),
        key=lambda value: (_PROTOCOL_ORDER.get(value, 99), value),
    )


def _member_payload(observation: NeighborObservation) -> dict[str, Any]:
    raw_name = observation.remote_name
    parsed = normalized_advertised_name(raw_name)
    payload = {
        "protocols": _protocols(observation),
        "remote_name": raw_name,
        "remote_base_name": parsed.base_name if parsed is not None else raw_name,
        "serial_hint": parsed.serial_hint if parsed is not None else None,
        "remote_interface": observation.remote_interface,
        "remote_interface_raw": observation.remote_interface_raw,
        "remote_addresses": sorted(dict.fromkeys(observation.remote_addresses)),
        "chassis_id": observation.chassis_id,
        "chassis_id_subtype": observation.chassis_id_subtype,
        "chassis_id_subtype_id": observation.chassis_id_subtype_id,
        "relationship_scope": "unclassified",
    }
    payload["member_fingerprint"] = stable_fingerprint(payload)
    return payload


def _member_sort_key(member: dict[str, Any]) -> tuple[Any, ...]:
    protocols = tuple(member.get("protocols") or [])
    return (
        str(member.get("relationship_scope") or ""),
        str(member.get("remote_base_name") or "").casefold(),
        str(member.get("chassis_id") or "").casefold(),
        str(member.get("remote_interface") or "").casefold(),
        protocols,
        str(member.get("member_fingerprint") or ""),
    )


def build_interface_observation_groups(
    source_host_id: int,
    observations: list[NeighborObservation],
) -> list[dict[str, Any]]:
    """Return complex local-interface groups in canonical order.

    Only interfaces with more than one projected member are emitted.  Single
    neighbors already have a clear representation in ``learned_neighbors``;
    retaining only complex groups keeps discovery output and SQLite state useful
    to operators while limiting audit volume.
    """

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for observation in observations:
        local = observation.local_interface or ""
        namespace = str(
            observation.details.get("local_interface_namespace")
            or ("resolved" if local and ":" not in local else "typed")
        )
        key = (namespace.casefold(), local.casefold())
        grouped.setdefault(key, []).append(_member_payload(observation))

    result: list[dict[str, Any]] = []
    for (namespace, local_key), members in grouped.items():
        if len(members) <= 1:
            continue
        members.sort(key=_member_sort_key)
        local_interface = next(
            (
                observation.local_interface
                for observation in observations
                if (observation.local_interface or "").casefold() == local_key
                and str(
                    observation.details.get("local_interface_namespace")
                    or (
                        "resolved"
                        if observation.local_interface
                        and ":" not in observation.local_interface
                        else "typed"
                    )
                ).casefold()
                == namespace
            ),
            local_key,
        )
        # The group is nested under its source host, so a run-local database ID
        # is not part of the fingerprint. This keeps the audit identity stable
        # when the same device receives a different host ID in another run.
        group_basis = {
            "local_interface_namespace": namespace,
            "local_interface": local_key,
            "member_fingerprints": [member["member_fingerprint"] for member in members],
        }
        result.append(
            {
                "group_fingerprint": stable_fingerprint(group_basis),
                "analysis_status": "shadow",
                "source_host_id": source_host_id,
                "local_interface": local_interface,
                "local_interface_namespace": namespace,
                "cardinality": "many",
                "member_count": len(members),
                "members": members,
            }
        )
    return sorted(
        result,
        key=lambda group: (
            str(group["local_interface_namespace"]),
            str(group["local_interface"]).casefold(),
            str(group["group_fingerprint"]),
        ),
    )
