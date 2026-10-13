#!/usr/bin/env -S uv run --script

"""Compare direct Gufo SNMP behavior for unbracketed and bracketed IPv6.

This deliberately small diagnostic bypasses LLDP-Runner. It accepts either an
unbracketed IPv6 literal or a hostname that resolves to one or more IPv6
addresses. IPv4 literals are intentionally rejected, and hostname resolution
never falls back to IPv4.

For every selected IPv6 destination, the script performs the same SNMPv2c GET
twice: first with the canonical unbracketed address and then with brackets added
only at the Gufo transport boundary. The SNMP community is read from SNMPCOMM
and is never printed.

Examples:

    SNMPCOMM='community' ./gufo-ipv6-test.py 2001:db8::10
    SNMPCOMM='community' ./gufo-ipv6-test.py switch.example.net

Exit status:

* 0: every address produced a conclusive verdict that brackets are required or
  are not required;
* 1: a bracketed probe failed, probe outcomes were inconsistent, or no
  conclusive comparison was possible;
* 2: usage, IPv6 validation, DNS, credential, or Gufo import/configuration
  error; and
* 130: operator interruption.

Run this script in the same Python or uv environment and under the same
operating-system account as LLDP-Runner so the result reflects the deployed
Gufo SNMP runtime.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import ipaddress
import os
import socket
import sys
from dataclasses import dataclass
from typing import Any, Callable, Sequence

OID = "1.3.6.1.2.1.1.1.0"
EXIT_OK = 0
EXIT_INCONCLUSIVE = 1
EXIT_CONFIGURATION_ERROR = 2
EXIT_INTERRUPTED = 130

Resolver = Callable[..., list[tuple[Any, ...]]]


@dataclass(frozen=True, slots=True)
class ProbeResult:
    """Outcome of one Gufo session construction/open/GET sequence."""

    success: bool
    phase: str
    exception_type: str | None = None
    message: str | None = None
    known_invalid_address: bool = False


@dataclass(frozen=True, slots=True)
class AddressComparison:
    """Verdict for one canonical IPv6 destination."""

    address: str
    verdict: str


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser without importing Gufo SNMP."""

    parser = argparse.ArgumentParser(
        description=(
            "Compare Gufo SNMP session behavior for one IPv6 destination "
            "passed unbracketed and bracketed."
        )
    )
    parser.add_argument(
        "target",
        metavar="TARGET",
        help="unbracketed IPv6 literal or hostname with at least one AAAA result",
    )
    return parser


def _canonical_ipv6(value: str) -> str:
    """Return one normalized IPv6 string or raise ValueError."""

    parsed = ipaddress.ip_address(value)
    if not isinstance(parsed, ipaddress.IPv6Address):
        raise ValueError("IPv4 is not supported by this IPv6-only diagnostic")
    return str(parsed)


def resolve_ipv6_targets(
    target: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> list[str]:
    """Resolve an IPv6 literal or hostname to canonical, ordered unique addresses."""

    try:
        parsed = ipaddress.ip_address(target)
    except ValueError:
        parsed = None

    if parsed is not None:
        if isinstance(parsed, ipaddress.IPv4Address):
            raise ValueError(
                f"TARGET {target!r} is an IPv4 literal; this diagnostic requires IPv6"
            )
        return [str(parsed)]

    try:
        records = resolver(
            target,
            None,
            family=socket.AF_INET6,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except socket.gaierror as exc:
        detail = exc.strerror or str(exc)
        raise ValueError(f"IPv6 DNS resolution failed for {target!r}: {detail}") from exc
    except OSError as exc:
        raise ValueError(f"IPv6 DNS resolution failed for {target!r}: {exc}") from exc

    addresses: list[str] = []
    seen: set[str] = set()
    for record in records:
        if len(record) < 5 or record[0] != socket.AF_INET6:
            continue
        sockaddr = record[4]
        if not isinstance(sockaddr, tuple) or not sockaddr:
            continue
        try:
            address = _canonical_ipv6(str(sockaddr[0]))
        except ValueError:
            continue
        if address in seen:
            continue
        seen.add(address)
        addresses.append(address)

    if not addresses:
        raise ValueError(f"TARGET {target!r} resolved to no IPv6 destination")
    return addresses


def load_gufo_session_class() -> Any:
    """Import Gufo only after command-line help and local validation are complete."""

    try:
        module = importlib.import_module("gufo.snmp")
        session_class = getattr(module, "SnmpSession")
    except (ImportError, AttributeError) as exc:
        raise RuntimeError(f"Gufo SNMP import failed: {exc}") from exc
    return session_class


def _redact(text: str, community: str) -> str:
    """Remove the configured community from operator-visible diagnostics."""

    return text.replace(community, "<redacted:SNMPCOMM>") if community else text


async def probe(
    *,
    label: str,
    address: str,
    community: str,
    session_class: Any,
) -> ProbeResult:
    """Run one direct Gufo probe while reporting its exact transport address."""

    print(f"\n=== {label} ===")
    print(f"addr={address!r}")

    phase = "session_construct"
    try:
        session = session_class(
            addr=address,
            port=161,
            community=community,
            timeout=5.0,
        )
        print("session_construct: SUCCESS")

        phase = "session_open"
        async with session:
            print("session_open: SUCCESS")
            phase = f"get:{OID}"
            value = await session.get(OID)
            print(f"GET: SUCCESS: {value!r}")
    except Exception as exc:
        exception_type = f"{type(exc).__module__}.{type(exc).__qualname__}"
        message = _redact(str(exc), community)
        print(f"FAILURE ({phase}): {exception_type}: {message}")
        return ProbeResult(
            success=False,
            phase=phase,
            exception_type=exception_type,
            message=message,
            known_invalid_address=(
                phase == "session_construct"
                and isinstance(exc, OSError)
                and "invalid address" in str(exc).lower()
            ),
        )

    return ProbeResult(success=True, phase="complete")


async def compare_address(
    address: str,
    *,
    community: str,
    session_class: Any,
) -> AddressComparison:
    """Probe one canonical address in both forms and classify the comparison."""

    print(f"\n##### IPv6 destination {address} #####")
    unbracketed = await probe(
        label="Unbracketed IPv6",
        address=address,
        community=community,
        session_class=session_class,
    )
    bracketed = await probe(
        label="Bracketed IPv6",
        address=f"[{address}]",
        community=community,
        session_class=session_class,
    )

    if unbracketed.success and bracketed.success:
        verdict = "brackets not required"
    elif unbracketed.known_invalid_address and bracketed.success:
        verdict = "brackets required"
    else:
        verdict = "inconclusive"

    print(f"VERDICT for {address}: {verdict}")
    return AddressComparison(address=address, verdict=verdict)


async def run_comparison(
    addresses: Sequence[str],
    *,
    community: str,
    session_class: Any,
) -> int:
    """Run all selected destinations and emit one stable aggregate verdict."""

    results = [
        await compare_address(
            address,
            community=community,
            session_class=session_class,
        )
        for address in addresses
    ]
    verdicts = {result.verdict for result in results}

    if verdicts == {"brackets required"}:
        print("\nFINAL VERDICT: brackets required")
        return EXIT_OK
    if verdicts == {"brackets not required"}:
        print("\nFINAL VERDICT: brackets not required")
        return EXIT_OK

    print("\nFINAL VERDICT: inconclusive or inconsistent results")
    return EXIT_INCONCLUSIVE


def _run_main(
    argv: Sequence[str] | None,
    *,
    resolver: Resolver,
    session_class: Any | None,
) -> int:
    """Execute one diagnostic after the interruption wrapper is established."""

    args = build_parser().parse_args(argv)

    try:
        addresses = resolve_ipv6_targets(args.target, resolver=resolver)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR

    community = os.environ.get("SNMPCOMM", "")
    if not community:
        print("ERROR: SNMPCOMM is not set or is empty", file=sys.stderr)
        return EXIT_CONFIGURATION_ERROR

    if session_class is None:
        try:
            session_class = load_gufo_session_class()
        except RuntimeError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_CONFIGURATION_ERROR

    return asyncio.run(
        run_comparison(
            addresses,
            community=community,
            session_class=session_class,
        )
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    resolver: Resolver = socket.getaddrinfo,
    session_class: Any | None = None,
) -> int:
    """Run the command-line diagnostic and return its documented exit status."""

    try:
        return _run_main(
            argv,
            resolver=resolver,
            session_class=session_class,
        )
    except KeyboardInterrupt:
        print("\nInterrupted", file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    raise SystemExit(main())
