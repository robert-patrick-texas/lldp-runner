"""Original LLDP-MIB and LLDP-V2-MIB neighbor collectors."""

from __future__ import annotations

import ipaddress
import time
from collections import defaultdict
from typing import Protocol

from lldp_runner.collectors.interfaces import display_interface_name
from lldp_runner.identity import is_usable_host_address
from lldp_runner.models import CollectionCoverage, NeighborObservation
from lldp_runner.snmp.resilience import (
    SnmpAccessRestrictedError,
    is_snmp_timeout,
)
from lldp_runner.textutil import lldp_chassis_id, lldp_port_id, snmp_text

LLDP_REM_ENTRY = "1.0.8802.1.1.2.1.4.1.1"
LLDP_REM_MAN_ADDR_ENTRY = "1.0.8802.1.1.2.1.4.2.1"
LLDP_LOC_PORT_ENTRY = "1.0.8802.1.1.2.1.3.7.1"

LLDPV2_REM_ENTRY = "1.3.111.2.802.1.1.13.1.4.1.1"
LLDPV2_REM_MAN_ADDR_ENTRY = "1.3.111.2.802.1.1.13.1.4.2.1"


class Walker(Protocol):
    async def walk(self, oid: str) -> list[tuple[str, object]]: ...


class LldpSnapshotIncompleteError(RuntimeError):
    """Raised when one LLDP table walk is internally incomplete.

    The LLDP remote-entry table is walked column-by-column by SNMP.  If an
    endpoint is inserted, removed, or rebuilt while that walk is in progress,
    later columns can exist for a row whose mandatory chassis/port identifier
    columns were not present in the same snapshot.  Returning such a partial row
    as ordinary topology makes a transient collection race look like host churn.

    The worker treats this exception like a transient table timeout and retries
    the complete protocol collector once, including its management-address walk.
    """

    def __init__(self, message: str, *, partial_row_count: int = 1) -> None:
        super().__init__(message)
        self.partial_row_count = max(1, int(partial_row_count))


def _text(value: object | None) -> str | None:
    """Normalize an LLDP field whose MIB semantics are textual."""

    return snmp_text(value)


CHASSIS_ID_SUBTYPES: dict[int, str] = {
    1: "chassis_component",
    2: "interface_alias",
    3: "port_component",
    4: "mac_address",
    5: "network_address",
    6: "interface_name",
    7: "local",
}

# IEEE 802.1AB Port ID subtypes use a different numeric assignment from Chassis
# ID subtypes. Keep a separate map so subtype 3 is correctly interpreted as a
# MAC address rather than as a chassis-style port component.
PORT_ID_SUBTYPES: dict[int, str] = {
    1: "interface_alias",
    2: "port_component",
    3: "mac_address",
    4: "network_address",
    5: "interface_name",
    6: "agent_circuit_id",
    7: "local",
}


def _integer(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, bytes):
            if not value:
                return None
            try:
                return int(value.decode("ascii").strip())
            except (UnicodeDecodeError, ValueError):
                return int.from_bytes(value, byteorder="big", signed=False)
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None


def _identifier_subtype(
    value: object | None, mapping: dict[int, str]
) -> tuple[int | None, str | None]:
    """Return the numeric and stable snake-case name for an LLDP subtype."""

    subtype_id = _integer(value)
    if subtype_id is None:
        return None, None
    return subtype_id, mapping.get(subtype_id, f"unknown_{subtype_id}")


def _chassis_id_subtype(value: object | None) -> tuple[int | None, str | None]:
    """Decode an LLDP chassis-ID subtype value."""

    return _identifier_subtype(value, CHASSIS_ID_SUBTYPES)


def _port_id_subtype(value: object | None) -> tuple[int | None, str | None]:
    """Decode an LLDP Port-ID subtype value using the Port ID enumeration."""

    return _identifier_subtype(value, PORT_ID_SUBTYPES)


def _capabilities(value: object | None) -> list[str]:
    if isinstance(value, bytes):
        raw = value
    else:
        try:
            number = int(value)  # type: ignore[arg-type]
            raw = bytes([number & 0xFF])
        except (TypeError, ValueError):
            return []
    if not raw:
        return []
    byte = raw[0]
    mapping = [
        (0x80, "other"),
        (0x40, "repeater"),
        (0x20, "bridge"),
        (0x10, "wlanAccessPoint"),
        (0x08, "router"),
        (0x04, "telephone"),
        (0x02, "docsisCableDevice"),
        (0x01, "stationOnly"),
    ]
    return [name for bit, name in mapping if byte & bit]


def _extract_indexed_ip(parts: list[int]) -> tuple[str | None, list[int]]:
    # LLDP management-address indexes end in: addressSubtype, length, address-octets.
    for pos in range(max(0, len(parts) - 20), len(parts) - 1):
        subtype = parts[pos]
        length = parts[pos + 1]
        if subtype == 1 and length == 4 and pos + 6 == len(parts):
            try:
                return str(ipaddress.IPv4Address(bytes(parts[pos + 2 :]))), parts[:pos]
            except ValueError:
                pass
        if subtype == 2 and length == 16 and pos + 18 == len(parts):
            try:
                return str(ipaddress.IPv6Address(bytes(parts[pos + 2 :]))), parts[:pos]
            except ValueError:
                pass
    return None, parts


def _identifier_value_present(value: object | None) -> bool:
    """Return whether a mandatory LLDP OCTET STRING contains usable bytes/text."""

    if value is None:
        return False
    if isinstance(value, bytes):
        return bool(value)
    return bool(str(value).strip())


def _validate_remote_row(
    *,
    protocol: str,
    index: tuple[int, ...],
    cols: dict[int, object],
    chassis_subtype_column: int,
    chassis_id_column: int,
    port_subtype_column: int,
    port_id_column: int,
) -> None:
    """Reject a remote row missing mandatory chassis or port identity fields.

    IEEE LLDP remote entries require both chassis-ID and port-ID subtype/value
    pairs.  A row that exposes later columns while one of these four values is
    absent is therefore not safe host/topology evidence.  Fail the whole
    protocol snapshot so the worker can re-walk it coherently instead of
    retaining a partially assembled endpoint.
    """

    missing: list[str] = []
    if _integer(cols.get(chassis_subtype_column)) is None:
        missing.append("chassis_id_subtype")
    if not _identifier_value_present(cols.get(chassis_id_column)):
        missing.append("chassis_id")
    if _integer(cols.get(port_subtype_column)) is None:
        missing.append("port_id_subtype")
    if not _identifier_value_present(cols.get(port_id_column)):
        missing.append("port_id")
    if missing:
        rendered_index = ".".join(str(item) for item in index)
        raise LldpSnapshotIncompleteError(
            f"{protocol} remote table row {rendered_index} missing mandatory " + ", ".join(missing)
        )


def _format_lldpv2_dest_mac(indexes: tuple[int, ...]) -> str | None:
    """Render the LLDPv2 local destination-MAC index when it is six octets.

    Depending on the agent/index encoding, the fixed-length MAC can appear as
    six octets or as an explicit length followed by six octets.  Preserve only
    a clearly decodable MAC in the diagnostic details; the full numeric index is
    still retained internally for row grouping either way.
    """

    if len(indexes) < 4:
        return None
    components = list(indexes[2:-1])
    if len(components) == 7 and components[0] == 6:
        components = components[1:]
    if len(components) != 6 or any(item < 0 or item > 255 for item in components):
        return None
    return ":".join(f"{item:02x}" for item in components)


class LldpCollection(list[NeighborObservation]):
    """List-compatible protocol result with independently measured subtables."""

    def __init__(
        self,
        values: list[NeighborObservation],
        *,
        subtable_coverage: dict[str, CollectionCoverage],
    ) -> None:
        super().__init__(values)
        self.subtable_coverage = dict(subtable_coverage)


class LldpSubtableCollectionError(RuntimeError):
    """Fallback wrapper when a backend exception cannot carry coverage attrs."""

    def __init__(
        self,
        exc: BaseException,
        coverage: dict[str, CollectionCoverage],
    ) -> None:
        self.original_exception = exc
        self.lldp_subtable_coverage = coverage
        super().__init__(str(exc))


def _subtable_status(exc: BaseException) -> str:
    """Map one walk failure to the discovery coverage vocabulary."""

    if isinstance(exc, SnmpAccessRestrictedError):
        return "access_restricted"
    if is_snmp_timeout(exc):
        return "timeout"
    name = exc.__class__.__name__.casefold()
    if "nosuch" in name or "unsupported" in name:
        return "unsupported"
    return "failed"


def _coverage(
    *,
    status: str,
    attempts: int = 1,
    object_count: int = 0,
    row_count: int | None = None,
    duration_ms: float = 0.0,
    message: str | None = None,
    valid_address_count: int | None = None,
    ipv4_address_count: int | None = None,
    ipv6_address_count: int | None = None,
    rejected_address_count: int | None = None,
    malformed_index_count: int | None = None,
) -> CollectionCoverage:
    """Build one subtable result without importing worker policy."""

    if status == "not_attempted":
        resolution_status = "not_applicable"
    elif status == "complete":
        resolution_status = "resolved"
    elif status == "partial":
        resolution_status = "partial"
    else:
        resolution_status = "unresolved"
    return CollectionCoverage(
        status=status,  # type: ignore[arg-type]
        attempts=max(1, int(attempts)),
        object_count=max(0, int(object_count)),
        row_count=row_count,
        resolution_status=resolution_status,  # type: ignore[arg-type]
        message=message,
        duration_ms=round(max(0.0, float(duration_ms)), 3),
        valid_address_count=valid_address_count,
        ipv4_address_count=ipv4_address_count,
        ipv6_address_count=ipv6_address_count,
        rejected_address_count=rejected_address_count,
        malformed_index_count=malformed_index_count,
    )


def _adaptive_events(client: object) -> list[object]:
    """Return retry events from an adaptive client or project trace wrapper."""

    current: object | None = client
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        state = getattr(current, "state", None)
        events = getattr(state, "events", None)
        if isinstance(events, list):
            return events
        current = getattr(current, "_client", None)
    return []


def _walk_attempts(events: list[object], start: int, oid: str) -> int:
    """Count the initial walk plus adaptive retries that sent another request."""

    retries = sum(
        1
        for event in events[start:]
        if bool(getattr(event, "retry_allowed", False))
        and getattr(event, "logical_operation", None) == "WALK"
        and getattr(event, "root_oid", None) == oid
    )
    return 1 + retries


async def _walk_subtable(
    client: Walker,
    oid: str,
) -> tuple[list[tuple[str, object]] | None, CollectionCoverage, BaseException | None]:
    """Walk one root and measure its independent success/failure boundary."""

    events = _adaptive_events(client)
    event_start = len(events)
    started = time.perf_counter()
    try:
        rows = await client.walk(oid)
    except Exception as exc:
        return (
            None,
            _coverage(
                status=_subtable_status(exc),
                attempts=_walk_attempts(events, event_start, oid),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                message=f"{exc.__class__.__name__}: {exc}",
            ),
            exc,
        )
    return (
        rows,
        _coverage(
            status="complete",
            attempts=_walk_attempts(events, event_start, oid),
            object_count=len(rows),
            row_count=len(rows),
            duration_ms=(time.perf_counter() - started) * 1000.0,
        ),
        None,
    )


def _merge_attempt_coverage(
    prior: CollectionCoverage | None,
    current: CollectionCoverage,
) -> CollectionCoverage:
    """Accumulate work while keeping the latest attempt's factual outcome."""

    if prior is None:
        return current
    return CollectionCoverage(
        status=current.status,
        attempts=prior.attempts + current.attempts,
        object_count=prior.object_count + current.object_count,
        row_count=current.row_count,
        resolution_status=current.resolution_status,
        message=current.message,
        duration_ms=round(prior.duration_ms + current.duration_ms, 3),
        valid_address_count=current.valid_address_count,
        ipv4_address_count=current.ipv4_address_count,
        ipv6_address_count=current.ipv6_address_count,
        rejected_address_count=current.rejected_address_count,
        malformed_index_count=current.malformed_index_count,
        subtables=dict(current.subtables),
    )


def _covered_exception(
    exc: BaseException,
    coverage: dict[str, CollectionCoverage],
) -> BaseException:
    """Attach partial subtable facts without changing ordinary exception types."""

    try:
        setattr(exc, "lldp_subtable_coverage", dict(coverage))  # noqa: B010 - ty: dynamic attribute on exception
    except (AttributeError, TypeError):
        return LldpSubtableCollectionError(exc, dict(coverage))
    return exc


def _raise_covered(
    exc: BaseException,
    coverage: dict[str, CollectionCoverage],
) -> None:
    """Raise ``exc`` with coverage, preserving its class whenever possible."""

    covered = _covered_exception(exc, coverage)
    if covered is exc:
        raise exc
    raise covered from exc


def _parse_local_port_rows(
    rows: list[tuple[str, object]],
) -> dict[int, tuple[str, str]]:
    """Decode one successfully collected LLDP local-port table."""

    grouped: dict[int, dict[int, object]] = defaultdict(dict)
    for oid, value in rows:
        suffix = oid[len(LLDP_LOC_PORT_ENTRY) :].lstrip(".").split(".")
        if len(suffix) < 2 or not suffix[0].isdigit() or not suffix[1].isdigit():
            continue
        column, local_port = int(suffix[0]), int(suffix[1])
        grouped[local_port][column] = value
    result: dict[int, tuple[str, str]] = {}
    for local_port, cols in grouped.items():
        raw = _text(cols.get(3)) or _text(cols.get(4))
        if not raw:
            continue
        result[local_port] = (raw, display_interface_name(raw) or raw)
    return result


async def _local_port_map_with_retry(
    client: Walker,
) -> tuple[dict[int, tuple[str, str]], CollectionCoverage]:
    """Collect LLDP local ports with the existing one bounded local retry.

    A persistent failure, including an access restriction, is retained as a
    subtable result while remote-neighbor topology remains collectible.  Access
    denials are not retried; all other failures retain the pre-0.32.5 single
    local-map retry and therefore do not expand the configured SNMP budgets.
    """

    aggregate: CollectionCoverage | None = None
    for attempt in (1, 2):
        rows, coverage, exc = await _walk_subtable(client, LLDP_LOC_PORT_ENTRY)
        if rows is not None:
            parsed = _parse_local_port_rows(rows)
            coverage.row_count = len(parsed)
            return parsed, _merge_attempt_coverage(aggregate, coverage)
        aggregate = _merge_attempt_coverage(aggregate, coverage)
        if isinstance(exc, SnmpAccessRestrictedError) or attempt == 2:
            break
    assert aggregate is not None
    return {}, aggregate


def _not_attempted(message: str) -> CollectionCoverage:
    return _coverage(status="not_attempted", message=message)


def _remote_rows_original(
    rows: list[tuple[str, object]],
) -> dict[tuple[int, int, int], dict[int, object]]:
    grouped: dict[tuple[int, int, int], dict[int, object]] = defaultdict(dict)
    for oid, value in rows:
        suffix = oid[len(LLDP_REM_ENTRY) :].lstrip(".").split(".")
        if len(suffix) < 4 or not all(x.isdigit() for x in suffix[:4]):
            continue
        column, timemark, local_port, rem_index = map(int, suffix[:4])
        grouped[(timemark, local_port, rem_index)][column] = value
    return grouped


def _remote_rows_v2(
    rows: list[tuple[str, object]],
) -> dict[tuple[int, ...], dict[int, object]]:
    grouped: dict[tuple[int, ...], dict[int, object]] = defaultdict(dict)
    for oid, value in rows:
        suffix = oid[len(LLDPV2_REM_ENTRY) :].lstrip(".").split(".")
        if len(suffix) < 5 or not all(x.isdigit() for x in suffix):
            continue
        grouped[tuple(int(x) for x in suffix[1:])][int(suffix[0])] = value
    return grouped


def _validate_original_remote_rows(
    grouped: dict[tuple[int, int, int], dict[int, object]],
) -> None:
    for key, cols in grouped.items():
        _validate_remote_row(
            protocol="lldp",
            index=key,
            cols=cols,
            chassis_subtype_column=4,
            chassis_id_column=5,
            port_subtype_column=6,
            port_id_column=7,
        )


def _validate_v2_remote_rows(
    grouped: dict[tuple[int, ...], dict[int, object]],
) -> None:
    for key, cols in grouped.items():
        _validate_remote_row(
            protocol="lldpv2",
            index=key,
            cols=cols,
            chassis_subtype_column=5,
            chassis_id_column=6,
            port_subtype_column=7,
            port_id_column=8,
        )


def _management_rows(
    rows: list[tuple[str, object]],
    *,
    root_oid: str,
    minimum_prefix: int,
) -> tuple[dict[tuple[int, ...], list[str]], CollectionCoverage]:
    """Decode management indexes and account malformed/rejected addresses."""

    management: dict[tuple[int, ...], list[str]] = defaultdict(list)
    valid_rows: set[tuple[tuple[int, ...], str]] = set()
    rejected_rows: set[tuple[int, ...]] = set()
    malformed_rows: set[tuple[str, ...]] = set()
    logical_indexes: set[tuple[str, ...]] = set()

    for oid, _value in rows:
        suffix = tuple(oid[len(root_oid) :].lstrip(".").split("."))
        index_text = suffix[1:] if suffix else suffix
        logical_indexes.add(index_text)
        if len(suffix) < minimum_prefix + 4 or not all(x.isdigit() for x in suffix):
            malformed_rows.add(index_text)
            continue
        indexes = [int(x) for x in suffix[1:]]
        address, prefix = _extract_indexed_ip(indexes)
        if not address or len(prefix) < minimum_prefix:
            malformed_rows.add(index_text)
            continue
        key = tuple(prefix[:minimum_prefix]) if minimum_prefix == 3 else tuple(prefix)
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            malformed_rows.add(index_text)
            continue
        row_key = (key, str(parsed))
        if not is_usable_host_address(str(parsed)):
            rejected_rows.add(tuple(indexes))
            continue
        valid_rows.add(row_key)
        if str(parsed) not in management[key]:
            management[key].append(str(parsed))

    ipv4_count = sum(1 for _key, value in valid_rows if ":" not in value)
    ipv6_count = len(valid_rows) - ipv4_count
    malformed_count = len(malformed_rows)
    status = "partial" if malformed_count else "complete"
    message = (
        f"{malformed_count} malformed management-address index row(s) rejected"
        if malformed_count
        else None
    )
    coverage = _coverage(
        status=status,
        object_count=len(rows),
        row_count=len(logical_indexes),
        valid_address_count=len(valid_rows),
        ipv4_address_count=ipv4_count,
        ipv6_address_count=ipv6_count,
        rejected_address_count=len(rejected_rows),
        malformed_index_count=malformed_count,
        message=message,
    )
    return management, coverage


async def collect_lldp(client: Walker, interfaces: dict[int, tuple[str, str]]) -> LldpCollection:
    """Collect original LLDP with independent local/remote/management coverage."""

    del interfaces  # Original LLDP local ports use lldpLocPortTable, not IF-MIB.
    local_ports, local_coverage = await _local_port_map_with_retry(client)
    subtable_coverage = {"local_port": local_coverage}

    rows, remote_coverage, remote_exc = await _walk_subtable(client, LLDP_REM_ENTRY)
    subtable_coverage["remote_neighbor"] = remote_coverage
    if rows is None:
        subtable_coverage["remote_management_address"] = _not_attempted(
            "remote-neighbor table did not complete"
        )
        assert remote_exc is not None
        _raise_covered(remote_exc, subtable_coverage)
    assert rows is not None
    grouped = _remote_rows_original(rows)
    remote_coverage.row_count = len(grouped)
    try:
        _validate_original_remote_rows(grouped)
    except LldpSnapshotIncompleteError as exc:
        remote_coverage.status = "structurally_invalid"
        remote_coverage.resolution_status = "unresolved"
        remote_coverage.message = str(exc)
        subtable_coverage["remote_management_address"] = _not_attempted(
            "remote-neighbor snapshot was structurally invalid"
        )
        _raise_covered(exc, subtable_coverage)

    man_rows, man_walk_coverage, man_exc = await _walk_subtable(client, LLDP_REM_MAN_ADDR_ENTRY)
    if man_rows is None:
        subtable_coverage["remote_management_address"] = man_walk_coverage
        assert man_exc is not None
        _raise_covered(man_exc, subtable_coverage)
    assert man_rows is not None
    management, management_coverage = _management_rows(
        man_rows,
        root_oid=LLDP_REM_MAN_ADDR_ENTRY,
        minimum_prefix=3,
    )
    management_coverage.duration_ms = man_walk_coverage.duration_ms
    subtable_coverage["remote_management_address"] = management_coverage

    result: list[NeighborObservation] = []
    local_port_map_failed = local_coverage.status != "complete"
    for key, cols in grouped.items():
        timemark, local_port, rem_index = key
        local_mapping = local_ports.get(local_port)
        local_resolved = local_mapping is not None
        local_raw, local_display = local_mapping or (
            f"lldpLocalPort:{local_port}",
            f"lldpLocalPort:{local_port}",
        )
        chassis_subtype_id, chassis_subtype = _chassis_id_subtype(cols.get(4))
        port_subtype_id, port_subtype = _port_id_subtype(cols.get(6))
        port_id = lldp_port_id(cols.get(7), port_subtype_id)
        port_description = _text(cols.get(8))
        remote_port_raw = port_id or port_description
        result.append(
            NeighborObservation(
                protocol="lldp",
                local_interface=local_display,
                local_interface_raw=local_raw,
                remote_name=_text(cols.get(9)),
                remote_interface=display_interface_name(remote_port_raw),
                remote_interface_raw=remote_port_raw,
                remote_addresses=management.get(key, []),
                remote_description=_text(cols.get(10)),
                remote_platform=None,
                capabilities=_capabilities(cols.get(12) or cols.get(11)),
                chassis_id=lldp_chassis_id(cols.get(5), chassis_subtype_id),
                chassis_id_subtype=chassis_subtype,
                chassis_id_subtype_id=chassis_subtype_id,
                details={
                    "time_mark": timemark,
                    "local_port_num": local_port,
                    "local_interface_resolved": local_resolved,
                    "local_interface_namespace": "lldpLocalPort",
                    "local_port_map_failed": local_port_map_failed,
                    "remote_index": rem_index,
                    "port_id": port_id,
                    "port_id_subtype": port_subtype,
                    "port_id_subtype_id": port_subtype_id,
                    "port_description": port_description,
                },
            )
        )
    return LldpCollection(result, subtable_coverage=subtable_coverage)


async def collect_lldpv2(client: Walker, interfaces: dict[int, tuple[str, str]]) -> LldpCollection:
    """Collect LLDPv2 with remote and management subtable coverage."""

    subtable_coverage: dict[str, CollectionCoverage] = {}
    rows, remote_coverage, remote_exc = await _walk_subtable(client, LLDPV2_REM_ENTRY)
    subtable_coverage["remote_neighbor"] = remote_coverage
    if rows is None:
        subtable_coverage["remote_management_address"] = _not_attempted(
            "remote-neighbor table did not complete"
        )
        assert remote_exc is not None
        _raise_covered(remote_exc, subtable_coverage)
    assert rows is not None
    grouped = _remote_rows_v2(rows)
    remote_coverage.row_count = len(grouped)
    try:
        _validate_v2_remote_rows(grouped)
    except LldpSnapshotIncompleteError as exc:
        remote_coverage.status = "structurally_invalid"
        remote_coverage.resolution_status = "unresolved"
        remote_coverage.message = str(exc)
        subtable_coverage["remote_management_address"] = _not_attempted(
            "remote-neighbor snapshot was structurally invalid"
        )
        _raise_covered(exc, subtable_coverage)

    man_rows, man_walk_coverage, man_exc = await _walk_subtable(client, LLDPV2_REM_MAN_ADDR_ENTRY)
    if man_rows is None:
        subtable_coverage["remote_management_address"] = man_walk_coverage
        assert man_exc is not None
        _raise_covered(man_exc, subtable_coverage)
    assert man_rows is not None
    management, management_coverage = _management_rows(
        man_rows,
        root_oid=LLDPV2_REM_MAN_ADDR_ENTRY,
        minimum_prefix=4,
    )
    management_coverage.duration_ms = man_walk_coverage.duration_ms
    subtable_coverage["remote_management_address"] = management_coverage

    result: list[NeighborObservation] = []
    for key, cols in grouped.items():
        timemark = key[0]
        local_ifindex = key[1]
        rem_index = key[-1]
        local_mapping = interfaces.get(local_ifindex)
        local_resolved = local_mapping is not None
        local_raw, local_display = local_mapping or (
            f"ifIndex:{local_ifindex}",
            f"ifIndex:{local_ifindex}",
        )
        chassis_subtype_id, chassis_subtype = _chassis_id_subtype(cols.get(5))
        port_subtype_id, port_subtype = _port_id_subtype(cols.get(7))
        port_id = lldp_port_id(cols.get(8), port_subtype_id)
        port_description = _text(cols.get(9))
        remote_port_raw = port_id or port_description
        result.append(
            NeighborObservation(
                protocol="lldpv2",
                local_interface=local_display,
                local_interface_raw=local_raw,
                remote_name=_text(cols.get(10)),
                remote_interface=display_interface_name(remote_port_raw),
                remote_interface_raw=remote_port_raw,
                remote_addresses=management.get(key, []),
                remote_description=_text(cols.get(11)),
                remote_platform=None,
                capabilities=_capabilities(cols.get(13) or cols.get(12)),
                chassis_id=lldp_chassis_id(cols.get(6), chassis_subtype_id),
                chassis_id_subtype=chassis_subtype,
                chassis_id_subtype_id=chassis_subtype_id,
                details={
                    "time_mark": timemark,
                    "local_ifindex": local_ifindex,
                    "local_interface_resolved": local_resolved,
                    "local_interface_namespace": "ifIndex",
                    "local_dest_mac": _format_lldpv2_dest_mac(key),
                    "remote_index": rem_index,
                    "port_id": port_id,
                    "port_id_subtype": port_subtype,
                    "port_id_subtype_id": port_subtype_id,
                    "port_description": port_description,
                },
            )
        )
    return LldpCollection(result, subtable_coverage=subtable_coverage)
