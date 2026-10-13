"""Immutable observation claims used by the incremental identity resolver.

The historical LLDP-Runner state model projects a candidate directly into one
``hosts`` row while the candidate is being ingested.  That projection remains
for compatibility, but it is no longer the only durable record of what the
network actually reported.  This module converts observations into typed claims
whose provenance, scope, and strength are explicit.

Claims are deliberately factual.  A claim records that one source reported one
value; it does not assert that two claims identify the same physical device.
Resolution decisions are stored separately by :mod:`lldp_runner.state`, which
allows a later decision to supersede an earlier conclusion without rewriting the
underlying evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from lldp_runner.identity import (
    anonymous_endpoint_port_mac,
    canonical_mac,
    chassis_identity_value,
    cisco_ap_mac,
    cisco_sep_mac,
    is_locally_assigned_chassis_subtype,
    normalize_host_address,
    normalize_identity_name,
    normalized_advertised_name,
)
from lldp_runner.models import Candidate, DeviceResult, NeighborObservation

ClaimScope = Literal[
    "global",
    "physical_container",
    "snmp_agent",
    "observer",
    "edge",
    "diagnostic",
]
ClaimStrength = Literal["strong", "moderate", "weak", "diagnostic"]
ClaimProvenance = Literal[
    "seed",
    "direct_protocol",
    "dns_enrichment",
    "snmp_self",
    "derived_strict",
    "collection_context",
]


@dataclass(frozen=True, slots=True)
class IdentityClaim:
    """One immutable assertion extracted from a network observation.

    ``identity_eligible`` means the claim may participate in a resolver decision
    when its scope permits.  It does not mean that the value is globally unique.
    For example, a directly advertised management address is weak identity
    evidence, while an LLDP ``network_address`` chassis value is edge-scoped and
    never sufficient by itself to merge observations from unrelated links.
    """

    claim_type: str
    claim_subtype: str | None
    raw_value: Any
    normalized_value: str
    provenance: ClaimProvenance
    scope: ClaimScope
    strength: ClaimStrength
    identity_eligible: bool
    context: dict[str, Any] = field(default_factory=dict)

    def canonical_payload(self) -> dict[str, Any]:
        """Return a deterministic JSON-compatible representation."""

        return asdict(self)

    def fingerprint(self, observation_fingerprint: str) -> str:
        """Return a stable fingerprint unique within one observation."""

        payload = {
            "observation": observation_fingerprint,
            **self.canonical_payload(),
        }
        return stable_fingerprint(payload)


def stable_json(value: Any) -> str:
    """Serialize ``value`` canonically for fingerprints and durable payloads."""

    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        default=str,
    )


def stable_fingerprint(value: Any) -> str:
    """Return a SHA-256 fingerprint for a canonical JSON value."""

    return hashlib.sha256(stable_json(value).encode("utf-8")).hexdigest()


def candidate_observation_payload(
    candidate: Candidate,
    *,
    preferred_name: str | None,
    synthetic_alias: str | None,
    is_seed: bool,
) -> dict[str, Any]:
    """Return the immutable factual payload for one candidate ingestion.

    Runtime timestamps are intentionally excluded.  Replaying the exact same
    normalized network observation in one run therefore yields the same
    fingerprint and does not append duplicate evidence.
    """

    return {
        "kind": "seed_candidate" if is_seed else "neighbor_candidate",
        "preferred_name": preferred_name,
        "synthetic_alias": synthetic_alias,
        "candidate": asdict(candidate),
    }


def candidate_claims(candidate: Candidate, *, is_seed: bool = False) -> list[IdentityClaim]:
    """Derive typed identity and diagnostic claims from ``candidate``.

    Direct protocol values and DNS enrichment intentionally receive different
    provenance.  Strict Cisco SEP and AP names additionally produce strong
    hardware-MAC claims.  LLDP chassis values are classified by subtype and
    scope rather than all being treated as globally unique aliases.
    """

    claims: list[IdentityClaim] = []
    direct_names = list(
        dict.fromkeys(
            candidate.identity_names
            if candidate.identity_names is not None
            else candidate.names
        )
    )
    all_names = list(dict.fromkeys(candidate.names))
    direct_name_keys: set[str] = set()
    for value in direct_names:
        normalized = normalize_identity_name(value)
        if normalized is not None:
            direct_name_keys.add(normalized)
        parsed = normalized_advertised_name(value)
        if parsed is not None and parsed.serial_hint is not None:
            base = normalize_identity_name(parsed.base_name)
            if base is not None:
                direct_name_keys.add(base)

    for raw_name in all_names:
        normalized = normalize_identity_name(raw_name)
        if normalized is None:
            continue
        direct = normalized in direct_name_keys
        provenance: ClaimProvenance
        if is_seed:
            provenance = "seed"
        elif direct:
            provenance = "direct_protocol"
        else:
            provenance = "dns_enrichment"
        claims.append(
            IdentityClaim(
                claim_type="name",
                claim_subtype="dns_name",
                raw_value=raw_name,
                normalized_value=normalized,
                provenance=provenance,
                scope="global" if direct or is_seed else "diagnostic",
                strength="moderate" if direct or is_seed else "weak",
                identity_eligible=direct or is_seed,
            )
        )

        parsed_name = normalized_advertised_name(raw_name)
        if parsed_name is not None and parsed_name.serial_hint is not None:
            base_normalized = normalize_identity_name(parsed_name.base_name)
            if base_normalized is not None:
                claims.append(
                    IdentityClaim(
                        claim_type="name",
                        claim_subtype="decorated_base_name",
                        raw_value=parsed_name.base_name,
                        normalized_value=base_normalized,
                        provenance=provenance,
                        scope="global" if direct or is_seed else "diagnostic",
                        strength="moderate" if direct or is_seed else "weak",
                        identity_eligible=direct or is_seed,
                        context={"decorated_raw_name": parsed_name.raw_name},
                    )
                )
            claims.append(
                IdentityClaim(
                    claim_type="hardware_identity",
                    claim_subtype="advertised_serial_hint",
                    raw_value=parsed_name.serial_hint,
                    normalized_value=parsed_name.serial_hint.casefold(),
                    provenance="direct_protocol" if direct else provenance,
                    scope="physical_container",
                    strength="moderate",
                    # A suffix is a high-quality hint, but remains ineligible for
                    # a physical merge until ENTITY-MIB or another direct serial
                    # claim corroborates it.
                    identity_eligible=False,
                    context={
                        "source_claim": "name",
                        "base_name": parsed_name.base_name,
                        "decorated_raw_name": parsed_name.raw_name,
                    },
                )
            )

        sep_mac = cisco_sep_mac(raw_name)
        if sep_mac is not None:
            claims.append(
                IdentityClaim(
                    claim_type="hardware_identity",
                    claim_subtype="cisco_sep_mac",
                    raw_value=raw_name,
                    normalized_value=sep_mac,
                    provenance="derived_strict",
                    scope="global",
                    strength="strong",
                    identity_eligible=True,
                    context={"source_claim": "name"},
                )
            )
        ap_mac = cisco_ap_mac(raw_name)
        if ap_mac is not None:
            claims.append(
                IdentityClaim(
                    claim_type="hardware_identity",
                    claim_subtype="cisco_ap_mac",
                    raw_value=raw_name,
                    normalized_value=ap_mac,
                    provenance="derived_strict",
                    scope="global",
                    strength="strong",
                    identity_eligible=True,
                    context={"source_claim": "name"},
                )
            )

    direct_addresses = list(
        dict.fromkeys(
            candidate.identity_addresses
            if candidate.identity_addresses is not None
            else candidate.addresses
        )
    )
    direct_address_keys: set[str] = set()
    for value in direct_addresses:
        try:
            direct_address_keys.add(normalize_host_address(value))
        except ValueError:
            continue
    for raw_address in dict.fromkeys(candidate.addresses):
        try:
            normalized = normalize_host_address(raw_address)
        except ValueError:
            continue
        direct = normalized in direct_address_keys
        claims.append(
            IdentityClaim(
                claim_type="address",
                claim_subtype="ipv6" if ":" in normalized else "ipv4",
                raw_value=raw_address,
                normalized_value=normalized,
                provenance=(
                    "seed"
                    if is_seed
                    else "direct_protocol"
                    if direct
                    else "dns_enrichment"
                ),
                scope="global" if direct or is_seed else "diagnostic",
                strength="weak",
                identity_eligible=direct or is_seed,
            )
        )

    subtype_name = (candidate.chassis_id_subtype or "").strip().casefold()
    subtype_id = candidate.chassis_id_subtype_id
    if candidate.chassis_id:
        chassis_context = {
            "subtype_name": candidate.chassis_id_subtype,
            "subtype_id": subtype_id,
        }
        if subtype_id == 4 or subtype_name == "mac_address":
            normalized_mac = canonical_mac(candidate.chassis_id)
            if normalized_mac is not None:
                claims.append(
                    IdentityClaim(
                        claim_type="hardware_identity",
                        claim_subtype="lldp_chassis_mac",
                        raw_value=candidate.chassis_id,
                        normalized_value=normalized_mac,
                        provenance="direct_protocol",
                        scope="global",
                        strength="strong",
                        identity_eligible=True,
                        context=chassis_context,
                    )
                )
        elif subtype_id == 5 or subtype_name == "network_address":
            try:
                normalized_address = normalize_host_address(candidate.chassis_id)
            except ValueError:
                normalized_address = candidate.chassis_id.strip().casefold()
            claims.append(
                IdentityClaim(
                    claim_type="chassis",
                    claim_subtype="network_address",
                    raw_value=candidate.chassis_id,
                    normalized_value=normalized_address,
                    provenance="direct_protocol",
                    scope="edge",
                    strength="weak",
                    identity_eligible=False,
                    context=chassis_context,
                )
            )
        elif (
            subtype_id in {1, 2, 3, 6}
            or subtype_name
            in {
                "chassis_component",
                "interface_alias",
                "port_component",
                "interface_name",
            }
            or is_locally_assigned_chassis_subtype(subtype_name, subtype_id)
        ):
            claims.append(
                IdentityClaim(
                    claim_type="chassis",
                    claim_subtype=subtype_name or str(subtype_id or "unknown"),
                    raw_value=candidate.chassis_id,
                    normalized_value=candidate.chassis_id.strip().casefold(),
                    provenance="direct_protocol",
                    scope="edge",
                    strength="weak",
                    identity_eligible=False,
                    context=chassis_context,
                )
            )
        else:
            normalized_chassis = chassis_identity_value(
                candidate.chassis_id,
                candidate.chassis_id_subtype,
                candidate.chassis_id_subtype_id,
            )
            if normalized_chassis is not None:
                claims.append(
                    IdentityClaim(
                        claim_type="chassis",
                        claim_subtype=subtype_name or str(subtype_id or "unknown"),
                        raw_value=candidate.chassis_id,
                        normalized_value=normalized_chassis,
                        provenance="direct_protocol",
                        scope="global",
                        strength="moderate",
                        identity_eligible=True,
                        context=chassis_context,
                    )
                )

    port_id = candidate.details.get("port_id")
    port_subtype = candidate.details.get("port_id_subtype")
    port_subtype_id = candidate.details.get("port_id_subtype_id")
    if port_id not in {None, ""}:
        raw_port = str(port_id)
        normalized_port = raw_port.strip().casefold()
        strong_port_mac = None
        if port_subtype_id == 3 or str(port_subtype or "").casefold() == "mac_address":
            strong_port_mac = canonical_mac(raw_port)
            if strong_port_mac is not None:
                normalized_port = strong_port_mac
        claims.append(
            IdentityClaim(
                claim_type="remote_port",
                claim_subtype=str(port_subtype or port_subtype_id or "unknown"),
                raw_value=port_id,
                normalized_value=normalized_port,
                provenance="direct_protocol",
                scope="edge",
                strength="strong" if strong_port_mac is not None else "weak",
                identity_eligible=strong_port_mac is not None,
                context={"subtype_id": port_subtype_id},
            )
        )

    endpoint_port_mac = anonymous_endpoint_port_mac(
        names=direct_names,
        addresses=direct_addresses,
        chassis_id=candidate.chassis_id,
        chassis_id_subtype=candidate.chassis_id_subtype,
        chassis_id_subtype_id=candidate.chassis_id_subtype_id,
        details=candidate.details,
    )
    if endpoint_port_mac is not None:
        claims.append(
            IdentityClaim(
                claim_type="hardware_identity",
                claim_subtype="anonymous_lldp_port_mac",
                raw_value=port_id,
                normalized_value=endpoint_port_mac,
                provenance="derived_strict",
                scope="global",
                strength="strong",
                identity_eligible=True,
                context={
                    "boundary": "otherwise_anonymous_endpoint",
                    "source_claim": "typed_mac_address_port_id",
                    "port_id_subtype": port_subtype,
                    "port_id_subtype_id": port_subtype_id,
                },
            )
        )

    if candidate.source_host_id is not None:
        claims.append(
            IdentityClaim(
                claim_type="edge_context",
                claim_subtype=candidate.protocol,
                raw_value={
                    "source_host_id": candidate.source_host_id,
                    "local_interface": candidate.local_interface,
                    "local_interface_raw": candidate.local_interface_raw,
                    "remote_interface": candidate.remote_interface,
                    "remote_interface_raw": candidate.remote_interface_raw,
                },
                normalized_value=stable_fingerprint(
                    {
                        "source_host_id": candidate.source_host_id,
                        "protocol": candidate.protocol,
                        "local_interface": candidate.local_interface,
                        "local_interface_raw": candidate.local_interface_raw,
                        "remote_interface": candidate.remote_interface,
                        "remote_interface_raw": candidate.remote_interface_raw,
                    }
                ),
                provenance="collection_context",
                scope="edge",
                strength="moderate",
                identity_eligible=True,
            )
        )

    # De-duplicate semantically equal claims while retaining their first raw form.
    unique: list[IdentityClaim] = []
    seen: set[str] = set()
    for claim in claims:
        key = stable_fingerprint(claim.canonical_payload())
        if key in seen:
            continue
        seen.add(key)
        unique.append(claim)
    return unique


def neighbor_observation_candidate(
    source_host_id: int, observation: NeighborObservation
) -> Candidate:
    """Convert one raw protocol row into a claim-only candidate.

    The compatibility coordinator performs DNS enrichment and projection after
    collection.  Immutable raw-advertisement claims must instead retain only
    values supplied by the device, so this helper deliberately excludes DNS and
    classification policy results.
    """

    protocols = [observation.protocol]
    details_protocols = observation.details.get("protocols", [])
    if isinstance(details_protocols, list):
        protocols.extend(str(value) for value in details_protocols if value)
    return Candidate(
        names=[observation.remote_name] if observation.remote_name else [],
        identity_names=[observation.remote_name] if observation.remote_name else [],
        addresses=list(observation.remote_addresses),
        identity_addresses=list(observation.remote_addresses),
        source_host_id=source_host_id,
        protocol=observation.protocol,
        local_interface=observation.local_interface,
        local_interface_raw=observation.local_interface_raw,
        remote_interface=observation.remote_interface,
        remote_interface_raw=observation.remote_interface_raw,
        remote_description=observation.remote_description,
        remote_platform=observation.remote_platform,
        capabilities=list(observation.capabilities),
        chassis_id=observation.chassis_id,
        chassis_id_subtype=observation.chassis_id_subtype,
        chassis_id_subtype_id=observation.chassis_id_subtype_id,
        protocols=list(dict.fromkeys(protocols)),
        details=dict(observation.details),
    )


def neighbor_observation_claims(
    source_host_id: int, observation: NeighborObservation
) -> list[IdentityClaim]:
    """Return typed claims for one pre-merge CDP/LLDP advertisement."""

    return candidate_claims(
        neighbor_observation_candidate(source_host_id, observation),
        is_seed=False,
    )


def device_result_observation_payload(result: DeviceResult) -> dict[str, Any]:
    """Return a timestamp-independent payload for one SNMP device result."""

    system = asdict(result.system) if result.system is not None else None
    return {
        "kind": "snmp_device_result",
        "host_id": result.host_id,
        "status": result.status,
        "query_target": result.query_target,
        "credential_profile": result.credential_profile,
        "credential_source": result.credential_source,
        "credential_label": result.credential_label,
        "credential_result": result.credential_result,
        "system": system,
        "snmp_sessions": [asdict(item) for item in result.snmp_sessions],
        "interface_observation_groups": result.interface_observation_groups,
        "collection_coverage": {
            key: asdict(value) for key, value in sorted(result.collection_coverage.items())
        },
        "raw_neighbor_count": len(result.raw_neighbors),
    }


def device_result_claims(result: DeviceResult) -> list[IdentityClaim]:
    """Extract direct SNMP self-claims without forcing an immediate re-merge."""

    claims: list[IdentityClaim] = []
    if result.query_target:
        try:
            normalized = normalize_host_address(result.query_target)
        except ValueError:
            pass
        else:
            claims.append(
                IdentityClaim(
                    claim_type="address",
                    claim_subtype="queried_as",
                    raw_value=result.query_target,
                    normalized_value=normalized,
                    provenance="snmp_self",
                    scope="snmp_agent",
                    strength="weak",
                    identity_eligible=True,
                )
            )
    system = result.system
    if system is None:
        return claims
    if system.sys_name:
        normalized_name = normalize_identity_name(system.sys_name)
        if normalized_name is not None:
            claims.append(
                IdentityClaim(
                    claim_type="name",
                    claim_subtype="snmp_sysname",
                    raw_value=system.sys_name,
                    normalized_value=normalized_name,
                    provenance="snmp_self",
                    scope="snmp_agent",
                    strength="moderate",
                    identity_eligible=True,
                )
            )
    if system.snmp_engine_id:
        claims.append(
            IdentityClaim(
                claim_type="hardware_identity",
                claim_subtype="snmp_engine_id",
                raw_value=system.snmp_engine_id,
                normalized_value=system.snmp_engine_id.strip().casefold(),
                provenance="snmp_self",
                scope="snmp_agent",
                strength="strong",
                identity_eligible=True,
            )
        )
    if system.serial_number:
        claims.append(
            IdentityClaim(
                claim_type="hardware_identity",
                claim_subtype="entity_serial",
                raw_value=system.serial_number,
                normalized_value=system.serial_number.strip().casefold(),
                provenance="snmp_self",
                scope="physical_container",
                strength="strong",
                identity_eligible=True,
            )
        )
    for member in system.stack_members:
        if not member.serial_number:
            continue
        claims.append(
            IdentityClaim(
                claim_type="hardware_identity",
                claim_subtype="stack_member_serial",
                raw_value=member.serial_number,
                normalized_value=member.serial_number.strip().casefold(),
                provenance="snmp_self",
                scope="physical_container",
                strength="strong",
                identity_eligible=True,
                context={
                    "entity_index": member.entity_index,
                    "member_number": member.member_number,
                },
            )
        )
    return claims
