"""CISCO-CDP-MIB neighbor collector with complete-snapshot validation.

CDP cache rows are assembled from a column-oriented SNMP walk.  A device can
repopulate or age the cache while that walk is in progress, leaving a row with
only later columns from the new snapshot.  Such a row is diagnostic evidence,
not safe endpoint identity.  The collector therefore validates the complete
snapshot before materializing any host or relationship and asks the worker to
restart the table when the snapshot is structurally inconsistent.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Protocol

from lldp_runner.collectors.interfaces import display_interface_name
from lldp_runner.identity import is_usable_host_address
from lldp_runner.models import NeighborObservation
from lldp_runner.textutil import snmp_text

CDP_CACHE_ENTRY = "1.3.6.1.4.1.9.9.23.1.2.1.1"


class Walker(Protocol):
    async def walk(self, oid: str) -> list[tuple[str, object]]: ...


class CdpSnapshotIncompleteError(RuntimeError):
    """Raised when one CDP cache walk cannot represent a coherent snapshot.

    The worker treats this as a structural table failure.  It discards every row
    from the failed attempt, restarts the complete CDP cache from its root under
    the target's degraded transport profile, and records ``structurally_invalid``
    coverage if the bounded retry is also invalid.
    """

    def __init__(self, message: str, *, partial_row_count: int = 1) -> None:
        super().__init__(message)
        self.partial_row_count = max(1, int(partial_row_count))


def _text(value: object | None) -> str | None:
    """Normalize a CDP field intended to contain text."""

    return snmp_text(value)


def _bytes(value: object | None) -> bytes | None:
    if isinstance(value, bytes):
        return value
    return None


def _integer(value: object | None) -> int | None:
    """Return one non-boolean integer from a CDP index/value field."""

    if value is None or isinstance(value, bool):
        return None
    try:
        if isinstance(value, bytes):
            if not value:
                return None
            try:
                return int(value.decode("ascii").strip())
            except (UnicodeDecodeError, ValueError):
                return int.from_bytes(value, byteorder="big", signed=False)
        return int(value)  # ty: ignore[invalid-argument-type]
    except (TypeError, ValueError, OverflowError):
        return None


def _address(value: object | None) -> str | None:
    raw = _bytes(value)
    if raw and len(raw) in {4, 16}:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return None
    text = _text(value)
    if text:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            return None
    return None


def _capabilities(value: object | None) -> list[str]:
    raw = _bytes(value)
    if raw:
        number = int.from_bytes(raw, "big")
    else:
        try:
            number = int(value)  # ty: ignore[invalid-argument-type]
        except (TypeError, ValueError):
            return []
    mapping = {
        0x01: "router",
        0x02: "transparentBridge",
        0x04: "sourceRouteBridge",
        0x08: "switch",
        0x10: "host",
        0x20: "igmp",
        0x40: "repeater",
    }
    return [name for bit, name in mapping.items() if number & bit]


def _validate_cdp_row(index: tuple[int, int], cols: dict[int, object]) -> None:
    """Reject one row that lacks mandatory identity or disagrees with its index.

    ``cdpCacheDeviceId`` and ``cdpCacheDevicePort`` are the minimum safe
    endpoint/edge identity boundary.  The optional first two columns mirror the
    table indexes on agents that implement them; when present they must agree so
    columns from different cache generations cannot be silently combined.
    """

    ifindex, device_index = index
    mismatches: list[str] = []
    if 1 in cols and _integer(cols.get(1)) != ifindex:
        mismatches.append(f"cdpCacheIfIndex={_integer(cols.get(1))!r} expected {ifindex}")
    if 2 in cols and _integer(cols.get(2)) != device_index:
        mismatches.append(f"cdpCacheDeviceIndex={_integer(cols.get(2))!r} expected {device_index}")

    missing: list[str] = []
    if not _text(cols.get(6)):
        missing.append("device_id")
    if not _text(cols.get(7)):
        missing.append("remote_port")

    if mismatches or missing:
        details: list[str] = []
        if mismatches:
            details.append("index mismatch: " + ", ".join(mismatches))
        if missing:
            details.append("missing mandatory " + ", ".join(missing))
        raise CdpSnapshotIncompleteError(
            f"cdp cache row {ifindex}.{device_index} " + "; ".join(details)
        )


def _assemble_snapshot(
    rows: list[tuple[str, object]],
) -> dict[tuple[int, int], dict[int, object]]:
    """Assemble and validate CDP column/index structure before row decoding."""

    grouped: dict[tuple[int, int], dict[int, object]] = defaultdict(dict)
    for oid, value in rows:
        text_oid = str(oid)
        suffix = text_oid[len(CDP_CACHE_ENTRY) :].lstrip(".").split(".")
        if len(suffix) != 3 or not all(part.isdigit() for part in suffix):
            raise CdpSnapshotIncompleteError(
                f"cdp cache returned malformed index for OID {text_oid!r}"
            )
        column, ifindex, device_index = map(int, suffix)
        key = (ifindex, device_index)
        previous = grouped[key].get(column)
        if previous is not None and previous != value:
            raise CdpSnapshotIncompleteError(
                "cdp cache returned conflicting duplicate column "
                f"{column} for row {ifindex}.{device_index}"
            )
        grouped[key][column] = value

    for index, cols in sorted(grouped.items()):
        _validate_cdp_row(index, cols)
    return grouped


async def collect_cdp(
    client: Walker, interfaces: dict[int, tuple[str, str]]
) -> list[NeighborObservation]:
    """Collect and normalize one structurally complete CDP cache snapshot.

    Textual OCTET STRING values pass through the shared sanitizer before they
    are used as identity, interface, classification, or output evidence.  No
    endpoint is materialized until every parsed cache row passes the mandatory
    device-ID, remote-port, and index-consistency boundary.
    """

    rows = await client.walk(CDP_CACHE_ENTRY)
    grouped = _assemble_snapshot(rows)

    observations: list[NeighborObservation] = []
    for (ifindex, device_index), cols in sorted(grouped.items()):
        interface = interfaces.get(ifindex)
        local_resolved = interface is not None
        local_raw, local_display = interface or (
            f"ifIndex:{ifindex}",
            f"ifIndex:{ifindex}",
        )
        remote_port_raw = _text(cols.get(7))
        addr = _address(cols.get(4))
        platform = _text(cols.get(8))
        device_id = _text(cols.get(6))
        # The structural validator established these two values.  Keep the
        # defensive assertion close to materialization so a future refactor
        # cannot accidentally weaken the identity-empty-shell boundary.
        if not device_id or not remote_port_raw:
            raise AssertionError("validated CDP row lost mandatory identity")

        # cdpCacheAddress can encode an empty CDP Entry address as 0.0.0.0.
        # Preserve the parsed MIB value for diagnostics, but only promote an
        # address with remote-host semantics into observed identity evidence.
        entry_addresses = [addr] if addr else []
        remote_addresses = (
            entry_addresses if addr is not None and is_usable_host_address(addr) else []
        )
        observations.append(
            NeighborObservation(
                protocol="cdp",
                local_interface=local_display,
                local_interface_raw=local_raw,
                remote_name=device_id,
                remote_interface=display_interface_name(remote_port_raw),
                remote_interface_raw=remote_port_raw,
                remote_addresses=remote_addresses,
                remote_description=_text(cols.get(5)),
                remote_platform=platform,
                capabilities=_capabilities(cols.get(9)),
                details={
                    "ifindex": ifindex,
                    "local_interface_resolved": local_resolved,
                    "local_interface_namespace": "ifIndex",
                    "device_index": device_index,
                    "address_type": _text(cols.get(3)),
                    # ``cdpCacheAddress`` is the CDP entry address, which is not
                    # necessarily the Primary Management Address displayed by
                    # Cisco CLI.  Keep the historical remote-address behavior,
                    # but label the source explicitly for structured consumers.
                    "device_id": device_id,
                    "entry_addresses": entry_addresses,
                },
            )
        )
    return observations
