"""Interface table collection and display-name normalization."""

from __future__ import annotations

import re
from typing import Protocol

from lldp_runner.snmp.resilience import SnmpAccessRestrictedError
from lldp_runner.textutil import snmp_text

IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"
IF_DESCR = "1.3.6.1.2.1.2.2.1.2"

_INTERFACE_PREFIXES: list[tuple[str, str]] = [
    ("HundredGigE", "Hu"),
    ("HundredGigabitEthernet", "Hu"),
    ("FortyGigabitEthernet", "Fo"),
    ("TwentyFiveGigE", "Twe"),
    ("TwentyFiveGigabitEthernet", "Twe"),
    ("TenGigabitEthernet", "Te"),
    ("TenGigE", "Te"),
    ("GigabitEthernet", "Gi"),
    ("FastEthernet", "Fa"),
    ("Port-channel", "Po"),
    ("Port-Channel", "Po"),
    ("Ethernet", "Eth"),
]


class Walker(Protocol):
    async def walk(self, oid: str) -> list[tuple[str, object]]: ...


class InterfaceCollectionError(RuntimeError):
    """Raised when neither IF-MIB naming table can be collected.

    A missing interface map is not harmless when CDP/LLDP rows are later joined
    by local port.  Preserve the underlying failures so the worker can retry and
    record incomplete interface-resolution coverage instead of silently emitting
    bare integers that look like stable interface names.
    """


def display_interface_name(name: str | None) -> str | None:
    if not name:
        return name
    value = name.strip()
    for long_name, short_name in _INTERFACE_PREFIXES:
        if value.startswith(long_name):
            suffix = value[len(long_name) :]
            if suffix and re.match(r"^[0-9/]", suffix):
                return f"{short_name}{suffix}"
    return value


def _index(oid: str, base: str) -> int | None:
    suffix = oid[len(base) :].lstrip(".")
    first = suffix.split(".", 1)[0]
    return int(first) if first.isdigit() else None


async def collect_interfaces(client: Walker) -> dict[int, tuple[str, str]]:
    """Return `ifIndex -> (raw, display)` names using safe textual values.

    IF-MIB data is an important join key for CDP/LLDP topology.  Sanitizing it
    here prevents malformed interface labels from contaminating edge identity.
    """

    result: dict[int, tuple[str, str]] = {}
    failures: list[BaseException] = []
    try:
        rows = await client.walk(IF_NAME)
    except SnmpAccessRestrictedError:
        raise
    except Exception as exc:
        failures.append(exc)
        rows = []
    for oid, raw in rows:
        idx = _index(oid, IF_NAME)
        if idx is None:
            continue
        name = _to_text(raw)
        result[idx] = (name, display_interface_name(name) or name)
    if result:
        return result
    try:
        rows = await client.walk(IF_DESCR)
    except SnmpAccessRestrictedError:
        raise
    except Exception as exc:
        failures.append(exc)
        message = (
            "both IF-MIB ifName and ifDescr walks failed"
            if len(failures) == 2
            else "IF-MIB ifName produced no mappings and ifDescr walk failed"
        )
        raise InterfaceCollectionError(message) from exc
    for oid, raw in rows:
        idx = _index(oid, IF_DESCR)
        if idx is None:
            continue
        name = _to_text(raw)
        result[idx] = (name, display_interface_name(name) or name)
    if not result and failures:
        raise InterfaceCollectionError(
            "IF-MIB naming tables produced no usable mappings after a walk failure"
        ) from failures[0]
    return result


def _to_text(value: object) -> str:
    """Normalize IF-MIB names while guaranteeing a usable display string."""

    # Interface values are expected to be textual.  If an agent returns binary
    # data, snmp_text() converts it to a printable ``hex:`` form rather than
    # allowing control bytes into topology keys or CSV output.
    return snmp_text(value) or ""
