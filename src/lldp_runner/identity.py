"""Seed parsing, DNS resolution, and identity normalization."""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from lldp_runner.models import SeedInput


_IPV4_THIS_NETWORK = ipaddress.ip_network("0.0.0.0/8")
_IPV4_RESERVED_FUTURE = ipaddress.ip_network("240.0.0.0/4")
_CISCO_SEP_HOST = re.compile(r"^sep(?P<mac>[0-9a-f]{12})$")
_CISCO_AP_HOST = re.compile(
    r"^ap(?P<mac>(?:[0-9a-f]{12}|[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}))$"
)
_ADVERTISED_SERIAL_SUFFIX = re.compile(
    r"^(?P<base>.+?)\((?P<serial>[A-Za-z0-9]{6,32})\)$"
)
_IDENTITY_NAME_SENTINELS = frozenset(
    {
        "-",
        "(none)",
        "(none).(none)",
        "n/a",
        "na",
        "none",
        "not advertised",
        "not-advertised",
        "not_advertised",
        "null",
        "unknown",
    }
)

if TYPE_CHECKING:
    from lldp_runner.snmp.trace import SnmpTrace


@dataclass(slots=True)
class ResolvedIdentity:
    original: str
    preferred_name: str
    names: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class AdvertisedName:
    """Parsed protocol name with an optional trailing hardware serial hint."""

    raw_name: str
    base_name: str
    serial_hint: str | None = None


def normalized_advertised_name(value: str | None) -> AdvertisedName | None:
    """Parse ``name(serial)`` without destroying the advertised raw value.

    Cisco Nexus and some other network systems append a physical serial to a
    logical system name.  The base name is used for protocol and DNS comparison,
    while the serial remains a separate claim that requires corroboration before
    it can merge physical chassis.  Parenthesized descriptive text is not treated
    as a serial unless it is an alphanumeric token of plausible length containing
    at least one digit.
    """

    if value is None:
        return None
    raw = value.strip().rstrip(".")
    if not raw:
        return None
    match = _ADVERTISED_SERIAL_SUFFIX.fullmatch(raw)
    if match is None:
        return AdvertisedName(raw_name=raw, base_name=raw)
    base = match.group("base").strip().rstrip(".")
    serial = match.group("serial").strip()
    if not base or not any(character.isdigit() for character in serial):
        return AdvertisedName(raw_name=raw, base_name=raw)
    if normalize_identity_name(base) is None:
        return AdvertisedName(raw_name=raw, base_name=raw)
    return AdvertisedName(raw_name=raw, base_name=base, serial_hint=serial)


def normalize_name(value: str) -> str:
    return value.strip().rstrip(".").lower()


def weak_mobility_mac(value: str | None) -> bool:
    """Return whether a MAC value is too weak to prove endpoint movement.

    Discovery can legitimately retain low-entropy or locally administered MAC-like
    values as observation evidence.  Virtual appliances, hypervisors, and vendor
    defaults may expose the same value through several physical uplinks, however,
    so those values are correlation hints rather than proof that one endpoint moved
    between switch ports.

    A value is considered weak when it is malformed, multicast, locally
    administered, all zero, or has at most two non-zero octets.  This boundary is
    intentionally conservative and is shared by the compatibility and graph diff
    layers so they cannot disagree about the same observation.
    """

    if value is None:
        return True
    compact = value.strip().lower().replace(":", "").replace("-", "").replace(".", "")
    if len(compact) != 12 or any(
        character not in "0123456789abcdef" for character in compact
    ):
        return True
    first_octet = int(compact[:2], 16)
    nonzero_octets = sum(
        compact[index : index + 2] != "00" for index in range(0, 12, 2)
    )
    return (
        compact == "000000000000"
        or nonzero_octets <= 2
        or bool(first_octet & 0x01)
        or bool(first_octet & 0x02)
    )


def canonical_mac(value: object | None) -> str | None:
    """Return a canonical MAC only for an unambiguous complete representation.

    LLDP collectors normally decode a typed MAC-address Port ID to colon-separated
    text before it reaches the identity layer.  This helper also accepts the two
    other conventional complete forms (twelve hexadecimal characters and Cisco
    dotted quartets), but deliberately rejects arbitrary punctuation or embedded
    text.  Identity promotion must not turn a malformed diagnostic value into a
    global endpoint key merely because twelve hexadecimal characters can be
    extracted from it.
    """

    if value is None:
        return None
    text = str(value).strip().casefold()
    if not text:
        return None
    if re.fullmatch(r"[0-9a-f]{12}", text):
        compact = text
    elif re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", text):
        compact = text.replace(":", "")
    elif re.fullmatch(r"[0-9a-f]{2}(?:-[0-9a-f]{2}){5}", text):
        compact = text.replace("-", "")
    elif re.fullmatch(r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}", text):
        compact = text.replace(".", "")
    else:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def is_locally_assigned_chassis_subtype(
    subtype_name: str | None,
    subtype_id: int | None,
) -> bool:
    """Return whether an LLDP chassis subtype is locally assigned (subtype 7).

    A locally assigned value is useful raw/display evidence, but IEEE subtype 7
    does not promise network-wide uniqueness.  Vendors commonly repeat opaque
    values across many unrelated endpoints, so this classification is shared by
    the compatibility resolver, immutable claim ledger, and topology graph.
    """

    normalized = str(subtype_name or "").strip().casefold().replace("-", "_")
    return subtype_id == 7 or normalized in {
        "local",
        "local_assigned",
        "locally_assigned",
    }


def typed_port_id_mac(details: Mapping[str, object] | None) -> str | None:
    """Return one exact LLDP/LLDPv2 MAC-address Port ID from observation details.

    Cross-protocol reconciliation can retain the selected Port ID in unprefixed
    fields and protocol-specific alternatives under ``lldp.`` or ``lldpv2.``.
    The value is usable only when the corresponding subtype explicitly says MAC
    address and all usable representations agree.  Ambiguous mixed values are
    left as edge evidence instead of being promoted to endpoint identity.
    """

    if not isinstance(details, Mapping):
        return None
    candidates: set[str] = set()
    for prefix in ("", "lldp.", "lldpv2."):
        value = details.get(f"{prefix}port_id")
        subtype_name = str(details.get(f"{prefix}port_id_subtype") or "")
        subtype_id = details.get(f"{prefix}port_id_subtype_id")
        try:
            numeric_subtype = int(subtype_id) if subtype_id is not None else None
        except (TypeError, ValueError):
            numeric_subtype = None
        normalized_subtype = subtype_name.strip().casefold().replace("-", "_")
        if numeric_subtype != 3 and normalized_subtype not in {
            "mac",
            "mac_address",
        }:
            continue
        if mac := canonical_mac(value):
            candidates.add(mac)
    return next(iter(candidates)) if len(candidates) == 1 else None


def cisco_sep_mac(value: str | None) -> str | None:
    """Return the canonical MAC encoded by a strict Cisco ``SEP<MAC>`` name.

    Cisco IP phones and video endpoints commonly advertise a CDP short name such
    as ``SEP001234560004`` while LLDP advertises the same host component with a
    DNS suffix.  The twelve hexadecimal characters are the endpoint MAC address,
    making that host component stronger identity evidence than a generic
    short-name/FQDN heuristic.

    Only the left-most host component is inspected and it must match ``SEP`` plus
    exactly twelve hexadecimal characters.  No arbitrary suffix stripping or
    hexadecimal-ending hostname inference is performed.
    """

    if value is None:
        return None
    normalized = normalize_name(value)
    if not normalized:
        return None
    host_component = normalized.split(".", 1)[0]
    match = _CISCO_SEP_HOST.fullmatch(host_component)
    if match is None:
        return None
    raw = match.group("mac")
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2))


def cisco_ap_mac(value: str | None) -> str | None:
    """Return the canonical MAC encoded by a strict Cisco AP device name.

    Cisco access points commonly advertise CDP device IDs such as
    ``AP0012.3456.A001`` while LLDP supplies the same hardware value as a
    chassis MAC.  Only a complete left-most component in dotted or compact
    twelve-hexadecimal form is accepted; generic ``AP`` prefixes and arbitrary
    hexadecimal hostname suffixes are intentionally ignored.
    """

    if value is None:
        return None
    normalized = normalize_name(value)
    if not normalized:
        return None
    host_component = normalized.split(".", 1)[0]
    # A dotted AP name contains dots inside the strict hardware component, so
    # inspect the first three labels before treating any remainder as DNS.
    labels = normalized.split(".")
    if len(labels) >= 3 and labels[0].startswith("ap"):
        dotted_component = ".".join(labels[:3])
        if _CISCO_AP_HOST.fullmatch(dotted_component) is not None:
            host_component = dotted_component
    match = _CISCO_AP_HOST.fullmatch(host_component)
    if match is None:
        return None
    raw = match.group("mac").replace(".", "")
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2))


def normalize_identity_name(value: str) -> str | None:
    """Return a normalized name only when it is useful host identity evidence.

    Discovery protocols sometimes expose explicit missing-value strings instead
    of omitting a system name.  Values such as ``null`` or ``not advertised``
    are useful raw diagnostics but are dangerous global aliases: thousands of
    unrelated endpoints can advertise the same placeholder.  IP literals also
    belong in the address namespace rather than the weaker name namespace.

    The presentation layer may still display these raw strings.  This helper is
    deliberately limited to canonical identity/correlation decisions.
    """

    normalized = normalize_name(value)
    if not normalized or normalized in _IDENTITY_NAME_SENTINELS:
        return None
    if is_ip(normalized):
        return None
    return normalized


def normalize_address(value: str) -> str:
    """Return canonical IPv4/IPv6 text after syntax validation only."""

    return str(ipaddress.ip_address(value.strip().strip("[]")))


def host_address_rejection_reason(value: str) -> str | None:
    """Return why an IP literal is unsafe as a remote-host identity address.

    ``ipaddress`` is intentionally used instead of a regular expression.  A
    regex can validate dotted/hexadecimal shape, but values such as
    ``255.255.255.255`` and ``ff02::1`` are syntactically valid IP addresses
    while still being unsuitable as an address for one discovered host.

    Private, CGNAT, benchmark/documentation, and link-local unicast addresses
    remain eligible.  LLDP-Runner sees legitimate management and control-plane
    addresses from those ranges, so using ``is_global`` would be too strict.
    """

    text = value.strip().strip("[]")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return "invalid IP address syntax"

    if address.is_unspecified:
        return "unspecified address"
    if address.is_loopback:
        return "loopback address"
    if address.is_multicast:
        return "multicast address"
    if isinstance(address, ipaddress.IPv4Address):
        if address in _IPV4_THIS_NETWORK:
            return "IPv4 this-network address"
        if address == ipaddress.IPv4Address("255.255.255.255"):
            return "IPv4 limited-broadcast address"
        if address in _IPV4_RESERVED_FUTURE:
            return "reserved IPv4 address"
    elif address.ipv4_mapped is not None:
        mapped = address.ipv4_mapped
        if mapped in _IPV4_THIS_NETWORK:
            return "IPv4-mapped this-network address"
        if mapped == ipaddress.IPv4Address("255.255.255.255"):
            return "IPv4-mapped limited-broadcast address"
        if mapped in _IPV4_RESERVED_FUTURE:
            return "IPv4-mapped reserved address"
    return None


def normalize_host_address(value: str) -> str:
    """Return canonical text for an address usable as one remote host identity.

    Raises:
        ValueError: If the value is malformed or has non-host semantics.
    """

    reason = host_address_rejection_reason(value)
    if reason is not None:
        raise ValueError(f"{value!r} is not a usable host address: {reason}")
    return normalize_address(value)


def is_usable_host_address(value: str) -> bool:
    """Return whether ``value`` is valid unicast-like host identity evidence."""

    return host_address_rejection_reason(value) is None


def usable_host_addresses(values: list[str]) -> list[str]:
    """Normalize and de-duplicate only host-eligible addresses from ``values``."""

    result: list[str] = []
    for value in values:
        try:
            normalized = normalize_host_address(value)
        except ValueError:
            continue
        if normalized not in result:
            result.append(normalized)
    return result


def is_ip(value: str) -> bool:
    """Return whether ``value`` has valid IPv4/IPv6 syntax.

    This remains a syntax predicate.  Call :func:`is_usable_host_address` when
    the address will identify or query a remote host.
    """

    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


def unique_preserve(values: list[str]) -> list[str]:
    return list(dict.fromkeys(x for x in values if x))


def _trace_gethostbyaddr(
    address: str,
    *,
    trace: SnmpTrace | None,
    source: str,
) -> tuple[str, list[str], list[str]]:
    """Run one reverse resolver call and optionally expose all returned values."""

    number = None
    if trace is not None:
        number = trace.resolver_query(
            operation="gethostbyaddr",
            query_type="Reverse resolution",
            value_label="Address",
            value=address,
            source=source,
        )
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(address)
    except OSError as exc:
        if trace is not None and number is not None:
            trace.resolver_no_response(number, f"{exc.__class__.__name__}: {exc}")
        raise
    if trace is not None and number is not None:
        rows: list[tuple[str, object]] = [("PTR name", hostname.rstrip("."))]
        rows.extend(("Alias", alias.rstrip(".")) for alias in aliases)
        rows.extend(("Address", item) for item in addresses)
        trace.resolver_response(number, rows)
    return hostname, aliases, addresses


def _trace_getaddrinfo(
    name: str,
    *,
    trace: SnmpTrace | None,
    source: str,
) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    """Run one forward resolver call while preserving the OS resolver result."""

    number = None
    if trace is not None:
        number = trace.resolver_query(
            operation="getaddrinfo",
            query_type="Forward resolution",
            value_label="Name",
            value=name,
            source=source,
            address_family="IPv4 / IPv6",
        )
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        if trace is not None and number is not None:
            trace.resolver_no_response(number, f"{exc.__class__.__name__}: {exc}")
        raise
    if trace is not None and number is not None:
        rows: list[tuple[str, object]] = []
        seen: set[tuple[str, str]] = set()
        for family, _socktype, _proto, canonname, sockaddr in infos:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            family_name = "IPv4" if family == socket.AF_INET else "IPv6"
            address = str(ipaddress.ip_address(str(sockaddr[0])))
            pair = (family_name, address)
            if pair not in seen:
                rows.append((family_name, address))
                seen.add(pair)
            if canonname:
                canonical = canonname.rstrip(".")
                key = ("Canonical", canonical)
                if key not in seen:
                    rows.append(("Canonical", canonical))
                    seen.add(key)
        trace.resolver_response(number, rows)
    return infos


def _trace_getfqdn(name: str, *, trace: SnmpTrace | None, source: str) -> str:
    """Run ``getfqdn`` and describe the operating-system resolver result."""

    number = None
    if trace is not None:
        number = trace.resolver_query(
            operation="getfqdn",
            query_type="Canonical-name resolution",
            value_label="Name",
            value=name,
            source=source,
        )
    try:
        canonical = socket.getfqdn(name).rstrip(".")
    except OSError as exc:
        if trace is not None and number is not None:
            trace.resolver_no_response(
                number, f"{exc.__class__.__name__}: {exc}"
            )
        raise
    if trace is not None and number is not None:
        if canonical:
            trace.resolver_response(number, [("Canonical", canonical)])
        else:
            trace.resolver_no_response(
                number, "resolver returned an empty canonical name"
            )
    return canonical


def resolve_seed(
    seed: str,
    dns_suffixes: list[str],
    *,
    trace: SnmpTrace | None = None,
) -> ResolvedIdentity:
    """Resolve a seed and optionally trace every OS resolver operation performed."""

    # Future consideration: a run-scoped DNS cache could avoid repeated forward,
    # reverse, and canonical-name resolver calls during very large discoveries.
    # Keep resolver semantics centralized here so such caching can later be added
    # without teaching individual collectors or schedulers their own DNS policy.

    original = seed.strip()
    if not original:
        raise ValueError("empty seed")
    if is_ip(original):
        # A syntactically valid IP is not automatically a usable remote target.
        # Reject placeholders/broadcast/multicast/loopback values before DNS,
        # state, or worker scheduling can treat them as host identity evidence.
        address = normalize_host_address(original)
        names: list[str] = []
        try:
            reverse = _trace_gethostbyaddr(
                address, trace=trace, source="input IP reverse lookup"
            )[0]
            if reverse:
                names.append(reverse.rstrip("."))
        except OSError:
            pass
        preferred = names[0] if names else address
        return ResolvedIdentity(original, preferred, unique_preserve(names), [address])

    candidates = [original.rstrip(".")]
    if "." not in original:
        candidates.extend(f"{original}.{suffix.lstrip('.')}" for suffix in dns_suffixes)
    candidates = unique_preserve(candidates)

    names: list[str] = []
    addresses: list[str] = []
    errors: list[str] = []
    for index, name in enumerate(candidates):
        source = "input hostname" if index == 0 else "configured DNS suffix candidate"
        try:
            infos = _trace_getaddrinfo(name, trace=trace, source=source)
        except socket.gaierror as exc:
            errors.append(f"{name}: {exc}")
            continue
        canonical = _trace_getfqdn(name, trace=trace, source=source)
        if canonical:
            names.append(canonical)
        names.append(name)
        for family, _socktype, _proto, canonname, sockaddr in infos:
            if canonname:
                names.append(canonname.rstrip("."))
            if family in {socket.AF_INET, socket.AF_INET6}:
                try:
                    addresses.append(normalize_host_address(str(sockaddr[0])))
                except ValueError:
                    # Resolver output can contain local/sentinel values.  Keep
                    # names, but never promote a non-host address into identity.
                    pass

    names = unique_preserve(names)
    addresses = unique_preserve(addresses)
    if names:
        fqdn = next((x for x in names if "." in x), names[0])
    else:
        fqdn = original.rstrip(".")
    return ResolvedIdentity(
        original,
        fqdn,
        names or [original.rstrip(".")],
        addresses,
        errors,
    )


def seed_dns_skip_eligible(seed: SeedInput, mode: str) -> bool:
    """Return whether one seed may conservatively bypass resolver work.

    The fast path requires a logical (non-IP) name plus a valid prior query
    target. Historical state, when available, must indicate success. This keeps
    failed or mixed reusable inventory rows from turning an attempted address
    into authoritative seed identity merely because DNS skipping was requested.
    """

    if mode != "skip-addressed":
        return False
    if (
        seed.query_target is None
        or not is_usable_host_address(seed.query_target)
        or is_ip(seed.seed)
    ):
        return False
    prior_state = (seed.prior_state or "").strip().casefold()
    if prior_state and prior_state not in {"complete", "success"}:
        return False
    return True


def resolve_seed_input(
    seed: SeedInput,
    dns_suffixes: list[str],
    *,
    mode: str,
    trace: SnmpTrace | None = None,
) -> tuple[ResolvedIdentity, str]:
    """Resolve one :class:`SeedInput` using the configured startup DNS policy.

    Returns the resolved identity plus ``"resolved"`` or ``"skipped"`` for
    run-phase accounting. Address hints from reusable seed inventory are merged
    in both modes so dry-run and normal coordinator initialization evaluate the
    same candidate addresses.
    """

    if seed_dns_skip_eligible(seed, mode):
        name = seed.seed.strip().rstrip(".")
        return (
            ResolvedIdentity(
                original=seed.seed,
                preferred_name=name,
                names=[name],
                addresses=usable_host_addresses(seed.addresses()),
            ),
            "skipped",
        )

    if trace is None:
        resolved = resolve_seed(seed.seed, dns_suffixes)
    else:
        resolved = resolve_seed(seed.seed, dns_suffixes, trace=trace)
    return (
        ResolvedIdentity(
            original=resolved.original,
            preferred_name=resolved.preferred_name,
            names=resolved.names,
            addresses=usable_host_addresses([*seed.addresses(), *resolved.addresses]),
            errors=resolved.errors,
        ),
        "resolved",
    )


def resolve_discovered_name(name: str, dns_suffixes: list[str]) -> ResolvedIdentity:
    """Resolve the logical base of a decorated protocol name through DNS."""

    parsed = normalized_advertised_name(name)
    return resolve_seed(parsed.base_name if parsed is not None else name, dns_suffixes)


def chassis_identity_value(
    chassis_id: str | None,
    chassis_id_subtype: str | None = None,
    chassis_id_subtype_id: int | None = None,
) -> str | None:
    """Return a typed chassis identity value when it is safe for correlation.

    Chassis IDs remain visible in neighbor observation details even when a device
    returns malformed binary data.  Identity correlation must be more selective:
    a value advertised as ``mac_address`` or ``network_address`` is only trusted
    when it can actually be decoded as that advertised type.  This prevents a
    repeated diagnostic value such as ``hex:15:00:00:00:00:00`` from collapsing
    otherwise unrelated LLDP neighbors into one canonical host.

    The subtype is included in the stored identity value so equal text emitted
    under different LLDP chassis subtypes cannot collide in the alias registry.
    """

    if not chassis_id or not chassis_id.strip():
        return None
    value = chassis_id.strip()
    subtype_name = (chassis_id_subtype or "").strip().lower()
    subtype_key = (
        str(chassis_id_subtype_id)
        if chassis_id_subtype_id is not None
        else subtype_name or "unknown"
    )

    if chassis_id_subtype_id == 4 or subtype_name == "mac_address":
        parts = value.lower().replace("-", ":").split(":")
        if len(parts) != 6 or any(
            len(part) != 2 or any(ch not in "0123456789abcdef" for ch in part)
            for part in parts
        ):
            return None
        value = ":".join(parts)
    elif chassis_id_subtype_id == 5 or subtype_name == "network_address":
        try:
            value = normalize_host_address(value)
        except ValueError:
            return None
    else:
        value = value.lower()

    return f"{subtype_key}:{value}"


def alias_tuples(
    names: list[str],
    addresses: list[str],
    chassis_id: str | None = None,
    chassis_id_subtype: str | None = None,
    chassis_id_subtype_id: int | None = None,
) -> list[tuple[str, str]]:
    """Return normalized aliases used to correlate candidate host identities.

    LLDP Chassis ID is a typed field, not a promise that every subtype is
    network-wide unique.  Device-local values such as ``interface_name`` and
    ``interface_alias`` remain useful observation details but must not become
    global host aliases.  A ``network_address`` chassis value is retained as an
    edge-scoped claim, but it does not enter the global IPv4/IPv6 or chassis
    alias namespaces.  MAC-address chassis identities retain their existing
    typed aliases.  Locally assigned subtype-7 values remain raw/display
    evidence because that subtype does not promise network-wide uniqueness.
    """

    aliases: list[tuple[str, str]] = []
    for name in names:
        value = normalize_identity_name(name)
        if value is not None:
            aliases.append(("name", value))
        parsed_name = normalized_advertised_name(name)
        if parsed_name is not None and parsed_name.serial_hint is not None:
            base_value = normalize_identity_name(parsed_name.base_name)
            if base_value is not None:
                aliases.append(("name", base_value))
        sep_mac = cisco_sep_mac(name)
        if sep_mac is not None:
            aliases.append(("mac", sep_mac))
        ap_mac = cisco_ap_mac(name)
        if ap_mac is not None:
            aliases.append(("mac", ap_mac))
            # Strict Cisco AP names encode the same hardware value that
            # LLDP commonly advertises as a MAC-address chassis ID.  Add
            # that exact typed equivalent without making every chassis MAC
            # a generic global MAC alias.
            aliases.append(("chassis_id", f"4:{ap_mac}"))
    for address in addresses:
        try:
            normalized = normalize_host_address(address)
        except ValueError:
            continue
        aliases.append(("ipv6" if ":" in normalized else "ipv4", normalized))
    subtype_name = (chassis_id_subtype or "").strip().lower()
    subtype_id = chassis_id_subtype_id
    # ``network_address`` is an observed chassis representation, not a global
    # endpoint address.  It is retained in the immutable claim ledger and raw
    # protocol details but cannot select or merge a host across unrelated edges.
    if chassis_id and (subtype_id == 4 or subtype_name == "mac_address"):
        chassis_value = chassis_identity_value(
            chassis_id, chassis_id_subtype, chassis_id_subtype_id
        )
        if chassis_value:
            aliases.append(("chassis_id", chassis_value))
    elif subtype_id == 5 or subtype_name == "network_address":
        pass
    elif is_locally_assigned_chassis_subtype(subtype_name, subtype_id):
        pass
    elif subtype_id not in {1, 2, 3, 6} and subtype_name not in {
        "chassis_component",
        "interface_alias",
        "port_component",
        "interface_name",
    }:
        chassis_value = chassis_identity_value(
            chassis_id, chassis_id_subtype, chassis_id_subtype_id
        )
        if chassis_value:
            aliases.append(("chassis_id", chassis_value))
    return list(dict.fromkeys(aliases))


def anonymous_endpoint_port_mac(
    *,
    names: list[str],
    addresses: list[str],
    chassis_id: str | None,
    chassis_id_subtype: str | None,
    chassis_id_subtype_id: int | None,
    details: Mapping[str, object] | None,
) -> str | None:
    """Return a typed Port-ID MAC only for an otherwise anonymous endpoint.

    A MAC-address Port ID is strong evidence for a single anonymous endpoint,
    but network devices can advertise different interface MACs on different
    links.  It therefore supplements compatibility identity only when no usable
    name, management address, or trusted chassis alias already identifies the
    candidate.  Named/addressed multi-interface devices continue to correlate
    through their stronger device-level evidence.
    """

    if alias_tuples(
        names,
        addresses,
        chassis_id,
        chassis_id_subtype,
        chassis_id_subtype_id,
    ):
        return None
    return typed_port_id_mac(details)
