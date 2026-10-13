"""Neighbor collector utilities."""

from __future__ import annotations

import json

from lldp_runner.identity import (
    cisco_sep_mac,
    normalize_host_address,
    normalize_identity_name,
    normalize_name,
    normalized_advertised_name,
    usable_host_addresses,
)
from lldp_runner.models import NeighborObservation


def _identity_key(obs: NeighborObservation) -> tuple[str, str, str]:
    """Return the historical exact-match key for one normalized observation."""

    remote = ""
    if obs.remote_addresses:
        remote = sorted(obs.remote_addresses)[0]
    elif obs.remote_name:
        remote = obs.remote_name.casefold()
    elif obs.chassis_id:
        remote = obs.chassis_id.casefold()
    return (obs.local_interface or "", remote, obs.remote_interface or "")


def _protocol_evidence(obs: NeighborObservation) -> dict[str, object]:
    """Preserve protocol-specific evidence for classification and troubleshooting."""

    prefix = obs.protocol
    evidence: dict[str, object] = {f"{prefix}.{key}": value for key, value in obs.details.items()}
    normalized = {
        "remote_name": obs.remote_name,
        "remote_description": obs.remote_description,
        "remote_platform": obs.remote_platform,
        "chassis_id": obs.chassis_id,
        "chassis_id_subtype": obs.chassis_id_subtype,
        "chassis_id_subtype_id": obs.chassis_id_subtype_id,
        "local_interface": obs.local_interface,
        "local_interface_raw": obs.local_interface_raw,
        "remote_interface": obs.remote_interface,
        "remote_interface_raw": obs.remote_interface_raw,
        "remote_addresses": obs.remote_addresses,
        "capabilities": obs.capabilities,
    }
    for key, value in normalized.items():
        if value not in (None, "", []):
            evidence[f"{prefix}.{key}"] = value
    return evidence


def _same_link(left: NeighborObservation, right: NeighborObservation) -> bool:
    """Return whether two observations describe the same local/remote port pair.

    The collectors already normalize common interface abbreviations before this
    stage.  Requiring both ends of the edge prevents name heuristics from merging
    separate parallel links or unrelated neighbors that merely advertise similar
    identifiers.
    """

    if not left.local_interface or not right.local_interface:
        return False
    if not left.remote_interface or not right.remote_interface:
        return False
    return (
        left.local_interface.casefold() == right.local_interface.casefold()
        and left.remote_interface.casefold() == right.remote_interface.casefold()
    )


def _same_local_interface(left: NeighborObservation, right: NeighborObservation) -> bool:
    """Return whether two observations were learned on the same local port."""

    if not left.local_interface or not right.local_interface:
        return False
    return left.local_interface.casefold() == right.local_interface.casefold()


def _observation_usable_addresses(obs: NeighborObservation) -> set[str]:
    """Return usable address evidence carried by one protocol observation.

    LLDP's management-address table is the preferred source, but a chassis ID
    explicitly typed as ``network_address`` is also address-like corroboration.
    Keeping the sources distinct in ``details`` preserves protocol semantics while
    allowing a transient management-address subtable gap to avoid needlessly
    splitting an otherwise well-identified edge.
    """

    addresses = set(usable_host_addresses(obs.remote_addresses))
    subtype = (obs.chassis_id_subtype or "").casefold()
    if obs.chassis_id and (obs.chassis_id_subtype_id == 5 or subtype == "network_address"):
        try:
            addresses.add(normalize_host_address(obs.chassis_id))
        except ValueError:
            pass
    return addresses


def _shared_usable_address(left: NeighborObservation, right: NeighborObservation) -> bool:
    """Return whether both protocols carry at least one same usable host IP."""

    return bool(_observation_usable_addresses(left) & _observation_usable_addresses(right))


def _sep_name_match(left_name: str | None, right_name: str | None) -> tuple[bool, str | None]:
    """Match strict Cisco ``SEP<MAC>`` endpoint names across suffix changes.

    Cisco phones and video endpoints encode the endpoint MAC in the left-most
    ``SEP`` host component.  That exact embedded hardware identity is strong enough
    to reconcile short and FQDN forms, including different domain suffixes, without
    applying generic suffix stripping to arbitrary host names.
    """

    left_mac = cisco_sep_mac(left_name)
    right_mac = cisco_sep_mac(right_name)
    if left_mac is None or left_mac != right_mac:
        return False, None
    candidates = sorted(
        (str(name) for name in (left_name, right_name) if name),
        key=lambda name: ("." not in name, name.casefold(), name),
    )
    return True, candidates[0]


def _short_fqdn_match(left_name: str | None, right_name: str | None) -> tuple[bool, str | None]:
    """Match one short host name to the host component of one FQDN.

    This is intentionally narrower than generic suffix stripping.  Exactly one
    side must be a single-label short name and the other side must begin with
    that same normalized label followed by a domain suffix.  Two different
    FQDNs that merely share their left-most label do not match here.

    The rule is used only as same-edge corroboration together with a shared
    usable management address and identical local switch interface.  It is not
    a global host-name aliasing rule.
    """

    if not left_name or not right_name:
        return False, None
    left_parsed = normalized_advertised_name(left_name)
    right_parsed = normalized_advertised_name(right_name)
    left = normalize_identity_name(left_parsed.base_name if left_parsed is not None else left_name)
    right = normalize_identity_name(
        right_parsed.base_name if right_parsed is not None else right_name
    )
    if left is None or right is None:
        return False, None
    if left == right:
        return True, left_name

    left_is_short = "." not in left
    right_is_short = "." not in right
    if left_is_short == right_is_short:
        return False, None
    if left_is_short and right.startswith(left + "."):
        return True, right_name
    if right_is_short and left.startswith(right + "."):
        return True, left_name
    return False, None


def _is_cross_protocol(left: NeighborObservation, right: NeighborObservation) -> bool:
    """Return whether CDP is being compared with LLDP or LLDPv2."""

    protocols = {left.protocol, right.protocol}
    return "cdp" in protocols and bool(protocols & {"lldp", "lldpv2"})


def _local_interface_is_resolved(obs: NeighborObservation) -> bool:
    """Return whether a collector supplied a human interface identifier."""

    resolved = obs.details.get("local_interface_resolved")
    if isinstance(resolved, bool):
        return resolved
    value = (obs.local_interface or "").casefold()
    return bool(value) and not value.startswith(("ifindex:", "lldplocalport:"))


def _local_numeric_index(obs: NeighborObservation) -> int | None:
    """Return one protocol's local numeric index without erasing its namespace.

    The integer is used only as corroborating evidence inside a guarded
    same-device, same-endpoint CDP/LLDP reconciliation.  It is never promoted to
    a general equivalence between ``lldpLocalPort`` and IF-MIB ``ifIndex``.
    """

    key = {
        "cdp": "ifindex",
        "lldp": "local_port_num",
        "lldpv2": "local_ifindex",
    }.get(obs.protocol)
    if key is None:
        return None
    value = obs.details.get(key)
    if isinstance(value, bool):
        return None
    try:
        return int(value)  # ty: ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return None


def _exact_remote_port_match(left: NeighborObservation, right: NeighborObservation) -> bool:
    """Return whether both protocols name the same remote physical port."""

    if not left.remote_interface or not right.remote_interface:
        return False
    return left.remote_interface.casefold() == right.remote_interface.casefold()


def _inferred_local_cross_protocol_match(
    left: NeighborObservation, right: NeighborObservation
) -> bool:
    """Guardedly reconcile one unresolved LLDP local index with resolved CDP.

    Some Cisco IOS agents expose a usable CDP ``ifIndex`` mapping but omit a
    usable ``lldpLocPortId``/``lldpLocPortDesc`` value.  In that situation the
    raw LLDP row remains correctly typed as ``lldpLocalPort:<n>``.  It can still
    be attached to the resolved physical edge when all of the following agree:

    * exactly one protocol has a resolved local interface;
    * the protocol-local numeric indexes are equal;
    * the exact remote port agrees; and
    * the remote endpoint has either an exact name, strict SEP hardware identity,
      or compatible name plus a shared usable address.

    Numeric equality is therefore only one corroborating fact.  It never creates
    a device-wide ``lldpLocalPort == ifIndex`` rule.
    """

    if not _is_cross_protocol(left, right):
        return False
    if _local_interface_is_resolved(left) == _local_interface_is_resolved(right):
        return False
    left_index = _local_numeric_index(left)
    right_index = _local_numeric_index(right)
    if left_index is None or left_index != right_index:
        return False
    if not _exact_remote_port_match(left, right):
        return False

    left_name = normalize_identity_name(left.remote_name or "")
    right_name = normalize_identity_name(right.remote_name or "")
    if left_name is not None and left_name == right_name:
        return True
    sep_match, _preferred_name = _sep_name_match(left.remote_name, right.remote_name)
    if sep_match:
        return True
    if not _shared_usable_address(left, right):
        return False
    names_match, _preferred_name = _cross_protocol_edge_name_match(left, right)
    return names_match


def _cross_protocol_name_match(
    left: NeighborObservation, right: NeighborObservation
) -> tuple[bool, str | None]:
    """Compare logical names after separating trailing serial metadata.

    ``name(serial)`` and ``name`` are two advertisements of the same logical
    name.  The raw decorated value remains in protocol evidence, while the serial
    token becomes an independent physical-container hint in the claims ledger.
    """

    if not left.remote_name or not right.remote_name:
        return False, None
    left_parsed = normalized_advertised_name(left.remote_name)
    right_parsed = normalized_advertised_name(right.remote_name)
    left_base = left_parsed.base_name if left_parsed is not None else left.remote_name
    right_base = right_parsed.base_name if right_parsed is not None else right.remote_name
    left_name = normalize_name(left_base)
    right_name = normalize_name(right_base)
    if left_name != right_name:
        return False, None
    candidates = sorted(
        {left_base, right_base},
        key=lambda name: ("." not in name, name.casefold(), name),
    )
    return True, candidates[0]


def _cross_protocol_edge_name_match(
    left: NeighborObservation, right: NeighborObservation
) -> tuple[bool, str | None]:
    """Return the guarded logical-name match used for edge reconciliation.

    Existing exact/Nexus rules remain authoritative.  A second edge-scoped rule
    accepts one short protocol name and one FQDN when their host component is
    identical; callers must additionally require same local port and shared
    usable management address before using that weaker representation match.
    """

    names_match, preferred_name = _cross_protocol_name_match(left, right)
    if names_match:
        return True, preferred_name
    sep_match, sep_preferred = _sep_name_match(left.remote_name, right.remote_name)
    if sep_match:
        return True, sep_preferred
    return _short_fqdn_match(left.remote_name, right.remote_name)


def _observations_match(left: NeighborObservation, right: NeighborObservation) -> bool:
    """Return whether two collector rows should become one topology edge."""

    if _identity_key(left) == _identity_key(right):
        return True
    if not _is_cross_protocol(left, right):
        return False
    if _same_link(left, right):
        names_match, _preferred_name = _cross_protocol_edge_name_match(left, right)
        if names_match:
            return True
    if not _same_local_interface(left, right):
        return False
    sep_match, _preferred_name = _sep_name_match(left.remote_name, right.remote_name)
    if sep_match:
        return True
    if not _shared_usable_address(left, right):
        return False
    names_match, _preferred_name = _cross_protocol_edge_name_match(left, right)
    return names_match


def _ordered_remote_addresses(left: NeighborObservation, right: NeighborObservation) -> list[str]:
    """Combine addresses while preferring LLDP management-address evidence.

    CISCO-CDP-MIB ``cdpCacheAddress`` is an entry address and can differ from the
    explicit management address printed by Cisco CLI.  LLDP remote-management
    addresses are therefore kept first when the protocols are reconciled.  All
    unique addresses remain available as host evidence and in structured output.
    """

    observations = [left, right]
    observations.sort(key=lambda item: 1 if item.protocol == "cdp" else 0)
    values: list[str] = []
    for obs in observations:
        values.extend(sorted(dict.fromkeys(obs.remote_addresses)))
    return list(dict.fromkeys(values))


def _merge_into(
    current: NeighborObservation,
    obs: NeighborObservation,
    *,
    inferred_local_resolution: bool = False,
) -> None:
    """Merge ``obs`` into ``current`` while retaining raw protocol evidence.

    Args:
        current: Existing normalized edge projection.
        obs: Newly collected protocol observation.
        inferred_local_resolution: The caller matched one unresolved LLDP local
            index to one resolved cross-protocol edge using the guarded
            same-endpoint rule. Recording this explicitly keeps the projection
            explainable regardless of collector insertion order.
    """

    current_local_resolved = _local_interface_is_resolved(current)
    protocol_evidence = _protocol_evidence(obs)
    protocols = list(current.details.get("protocols", [current.protocol]))
    if obs.protocol not in protocols:
        protocols.append(obs.protocol)
    protocol_rank = {"cdp": 0, "lldp": 1, "lldpv2": 2}
    current.details["protocols"] = sorted(
        dict.fromkeys(protocols),
        key=lambda value: (protocol_rank.get(value, 99), value),
    )
    for detail_key, detail_value in obs.details.items():
        current.details.setdefault(detail_key, detail_value)
    current.details.update(protocol_evidence)

    if _is_cross_protocol(current, obs):
        names_match, preferred_name = _cross_protocol_edge_name_match(current, obs)
        if names_match and preferred_name:
            current.remote_name = preferred_name
        current.remote_addresses = _ordered_remote_addresses(current, obs)
    else:
        current.remote_addresses = list(
            dict.fromkeys([*current.remote_addresses, *obs.remote_addresses])
        )

    current.capabilities = sorted(dict.fromkeys([*current.capabilities, *obs.capabilities]))
    # LLDP generally carries the richer system description and actual management
    # address semantics.  Prefer its description when reconciling with CDP while
    # retaining both raw protocol values under ``details``.
    if obs.protocol in {"lldp", "lldpv2"} and obs.remote_description:
        current.remote_description = obs.remote_description
    else:
        current.remote_description = current.remote_description or obs.remote_description
    current.remote_platform = current.remote_platform or obs.remote_platform

    if obs.protocol in {"lldp", "lldpv2"} and obs.chassis_id:
        current.chassis_id = obs.chassis_id
        current.chassis_id_subtype = obs.chassis_id_subtype
        current.chassis_id_subtype_id = obs.chassis_id_subtype_id
    else:
        current.chassis_id = current.chassis_id or obs.chassis_id
        current.chassis_id_subtype = current.chassis_id_subtype or obs.chassis_id_subtype
        if current.chassis_id_subtype_id is None:
            current.chassis_id_subtype_id = obs.chassis_id_subtype_id

    if inferred_local_resolution:
        resolved = current if current_local_resolved else obs
        # Present the resolved physical port while retaining the original typed
        # LLDP value under ``lldp.*`` protocol evidence. This is a projection of
        # the guarded cross-protocol edge decision, not a rewrite of the factual
        # protocol evidence or a general numeric namespace equivalence.
        current.local_interface = resolved.local_interface
        current.local_interface_raw = resolved.local_interface_raw
        current.details["local_interface_resolved"] = True
        current.details["local_interface_namespace"] = resolved.details.get(
            "local_interface_namespace", "cross_protocol"
        )
        current.details["local_interface_resolution_method"] = "cross_protocol_same_endpoint"
        current.details["local_interface_resolution_source"] = resolved.protocol
    else:
        current.local_interface = current.local_interface or obs.local_interface
        current.local_interface_raw = current.local_interface_raw or obs.local_interface_raw
    # When protocols use different remote-port representations for the same
    # edge (for example Cisco phone CDP ``Port 1`` versus LLDP ``<MAC>:P1``),
    # prefer LLDP's typed Port ID while retaining both raw protocol views under
    # ``details``.
    if obs.protocol in {"lldp", "lldpv2"} and obs.remote_interface:
        current.remote_interface = obs.remote_interface
        current.remote_interface_raw = obs.remote_interface_raw
    else:
        current.remote_interface = current.remote_interface or obs.remote_interface
        current.remote_interface_raw = current.remote_interface_raw or obs.remote_interface_raw


def _observation_sort_key(obs: NeighborObservation) -> tuple[object, ...]:
    """Return a canonical key independent of SNMP table row order."""

    protocol_rank = {"lldp": 0, "lldpv2": 1, "cdp": 2}
    parsed = normalized_advertised_name(obs.remote_name)
    base_name = parsed.base_name if parsed is not None else (obs.remote_name or "")
    canonical_record = obs.to_dict()
    canonical_record["remote_addresses"] = sorted(dict.fromkeys(obs.remote_addresses))
    canonical_record["capabilities"] = sorted(dict.fromkeys(obs.capabilities))
    return (
        (obs.local_interface or "").casefold(),
        base_name.casefold(),
        (obs.remote_interface or "").casefold(),
        (obs.chassis_id or "").casefold(),
        tuple(sorted(obs.remote_addresses)),
        protocol_rank.get(obs.protocol, 99),
        obs.protocol,
        # Distinct duplicate advertisements can otherwise tie on the fields
        # above and reintroduce device-returned row order through ``setdefault``
        # during merge. A canonical full-record tiebreak keeps replay stable.
        json.dumps(
            canonical_record,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ),
    )


def merge_neighbor_observations(
    observations: list[NeighborObservation],
) -> list[NeighborObservation]:
    """Reconcile collector rows that describe the same physical topology edge.

    Exact historical identity keys remain supported.  Guarded cross-protocol
    paths reconcile CDP and LLDP when either their local/remote ports and logical
    names agree, when strict Cisco ``SEP<MAC>`` identity agrees on the same local
    port, or when the same local port plus shared usable address evidence
    corroborates an exact/short-name-to-FQDN logical-name match. A separately
    guarded path can attach one unresolved LLDP local-port index to one resolved
    CDP edge when numeric index, remote port, and endpoint identity all agree.
    A plausible trailing ``name(serial)`` decoration contributes its logical
    base only to guarded same-link comparison; the raw value and serial hint
    remain separate evidence. Generic domain-suffix handling remains
    edge-scoped, and strict SEP identity is also registered by the canonical
    host-identity layer.
    """

    merged: list[NeighborObservation] = []
    for obs in sorted(observations, key=_observation_sort_key):
        # Address and capability order is not identity evidence. Normalize these
        # set-like protocol fields before any merge so output does not inherit
        # SNMP table or decoder insertion order.
        obs.remote_addresses = sorted(dict.fromkeys(obs.remote_addresses))
        obs.capabilities = sorted(dict.fromkeys(obs.capabilities))
        matched = next((item for item in merged if _observations_match(item, obs)), None)
        inferred_local_resolution = False
        if matched is None:
            inferred_matches = [
                item for item in merged if _inferred_local_cross_protocol_match(item, obs)
            ]
            # Do not let a numeric coincidence choose among parallel or duplicate
            # candidates. Ambiguous rows remain distinct observations for the
            # later claims/resolution layer.
            if len(inferred_matches) == 1:
                matched = inferred_matches[0]
                inferred_local_resolution = True
        if matched is None:
            obs.details = {
                **obs.details,
                **_protocol_evidence(obs),
                "protocols": [obs.protocol],
            }
            merged.append(obs)
            continue
        _merge_into(
            matched,
            obs,
            inferred_local_resolution=inferred_local_resolution,
        )
    for item in merged:
        protocols = item.details.get("protocols", [item.protocol])
        if isinstance(protocols, list):
            protocol_rank = {"cdp": 0, "lldp": 1, "lldpv2": 2}
            item.details["protocols"] = sorted(
                dict.fromkeys(str(value) for value in protocols),
                key=lambda value: (protocol_rank.get(value, 99), value),
            )
        item.remote_addresses = list(dict.fromkeys(item.remote_addresses))
        item.capabilities = sorted(dict.fromkeys(item.capabilities))
    return sorted(merged, key=_observation_sort_key)
