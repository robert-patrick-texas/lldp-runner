"""Single-device LLDP/CDP inspection without recursive discovery state.

The inspect path exists for two related operator needs:

* provide a fast ``get-neighbors TARGET`` troubleshooting command; and
* exercise the same DNS, policy, credential, ICMP, SNMP, and neighbor collectors
  used by a full LLDP-Runner discovery before launching a larger run.

Inspection deliberately does not create SQLite state, run directories, scoreboards,
or recursive work.  The explicitly named target may be outside
``discovery.boundaries``; that fact is reported, while query-policy deny rules remain
authoritative.  This distinction makes inspection useful for diagnostics without
turning it into a bypass for explicit no-query policy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from lldp_runner.classify import Classifier
from lldp_runner.config import AppConfig
from lldp_runner.identity import is_ip, resolve_seed, unique_preserve
from lldp_runner.models import (
    Candidate,
    DeviceResult,
    DeviceTask,
    NeighborObservation,
    TargetAttempt,
)
from lldp_runner.policy import PolicyEngine
from lldp_runner.snmp.trace import SnmpTrace
from lldp_runner.timeutil import iso_now
from lldp_runner.worker import process_single_device


@dataclass(slots=True)
class AddressPolicy:
    """Effective inspect policy for one resolved management-address candidate."""

    address: str
    boundary_allowed: bool
    boundary_reason: str
    query_allowed: bool
    query_reason: str
    credential_profile: str | None
    credential_reason: str | None


@dataclass(slots=True)
class ReverseDnsResult:
    """Reverse DNS result retained for human and JSON diagnostics."""

    address: str
    name: str | None = None
    error: str | None = None


@dataclass(slots=True)
class InspectionResult:
    """Complete in-memory result for one non-recursive device inspection."""

    input_target: str
    preferred_name: str
    names: list[str]
    addresses: list[str]
    forward_dns: list[str]
    reverse_dns: list[ReverseDnsResult]
    dns_errors: list[str]
    policies: list[AddressPolicy]
    dry_run: bool
    status: str
    system_only: bool = False
    boundary_override: bool = True
    device: DeviceResult | None = None
    dns_duration_ms: float = 0.0
    query_duration_ms: float = 0.0
    total_duration_ms: float = 0.0
    probe_timings: dict[str, float] = field(default_factory=dict)
    collected_at: str = field(default_factory=iso_now)

    @property
    def exit_code(self) -> int:
        """Return a shell-friendly result code without treating zero neighbors as failure."""

        if self.dry_run:
            return 0
        return 0 if self.device is not None and self.device.status == "success" else 1


class _NeverPaused:
    """Minimal pause-event interface used by the worker probe primitives."""

    @staticmethod
    def is_set() -> bool:
        """Return ``False`` because an interactive inspection is never paused.

        Returns:
            Always ``False``. The worker probe accepts the same pause-event
            interface used by recursive discovery, so this stand-in keeps the
            shared call path free of inspection-specific branching.
        """

        return False


def _elapsed_ms(start: float) -> float:
    """Return elapsed monotonic time in milliseconds for inspection telemetry.

    Args:
        start: Earlier :func:`time.perf_counter` value.

    Returns:
        Milliseconds elapsed since ``start``, rounded to three decimal places.
    """

    return round((time.perf_counter() - start) * 1000.0, 3)


def _finalize_result(result: InspectionResult, overall_start: float) -> InspectionResult:
    """Finalize duration and one stable presentation timestamp for an inspection.

    A successful SNMP access uses the worker's most recent SNMP ``last_seen`` so
    the displayed collection time reflects actual device access. Results without
    successful SNMP access use the current configured-timezone clock when the
    result is finalized. Reusing one value keeps table/detail/CSV output aligned.
    """

    result.total_duration_ms = _elapsed_ms(overall_start)
    device = result.device
    if device and device.last_seen_source == "snmp" and device.last_seen:
        result.collected_at = device.last_seen
    else:
        result.collected_at = iso_now()
    return result


def _ordered_addresses(config: AppConfig, addresses: list[str]) -> list[str]:
    """Apply the same IPv4/IPv6 management-address preference used by discovery."""

    preference = {name: index for index, name in enumerate(config.discovery.address_preference)}

    def key(value: str) -> tuple[int, int]:
        """Return configured address-family priority plus numeric IP ordering."""

        ip = ipaddress.ip_address(value)
        family = "ipv4" if ip.version == 4 else "ipv6"
        return preference.get(family, 99), int(ip)

    return sorted(dict.fromkeys(addresses), key=key)


def _reverse_dns(addresses: list[str], *, trace: SnmpTrace | None = None) -> list[ReverseDnsResult]:
    """Resolve PTR names while retaining per-address failures for diagnostics.

    Args:
        addresses: IPv4/IPv6 address strings to resolve.

    Returns:
        One :class:`ReverseDnsResult` per input address, preserving either the
        resolved name or the operating-system resolver error text.
    """

    results: list[ReverseDnsResult] = []
    for address in addresses:
        number = None
        if trace is not None:
            number = trace.resolver_query(
                operation="gethostbyaddr",
                query_type="Reverse resolution",
                value_label="Address",
                value=address,
                source="inspection address reverse lookup",
            )
        try:
            name, aliases, returned_addresses = socket.gethostbyaddr(address)
            name = name.rstrip(".")
            results.append(ReverseDnsResult(address=address, name=name or None))
            if trace is not None and number is not None:
                rows: list[tuple[str, object]] = [("PTR name", name)]
                rows.extend(("Alias", item.rstrip(".")) for item in aliases)
                rows.extend(("Address", item) for item in returned_addresses)
                trace.resolver_response(number, rows)
        except OSError as exc:
            results.append(ReverseDnsResult(address=address, error=str(exc)))
            if trace is not None and number is not None:
                trace.resolver_no_response(number, f"{exc.__class__.__name__}: {exc}")
    return results


def _forward_dns_for_display(
    target: str,
    names: list[str],
    addresses: list[str],
    reverse_dns: list[ReverseDnsResult],
    *,
    trace: SnmpTrace | None = None,
) -> list[str]:
    """Return compact ``name -> address`` strings for inspection presentation.

    ``resolve_seed`` already performs authoritative seed resolution.  This helper
    records the relationship in an operator-friendly form and, for an IP input,
    forward-confirms the first PTR name when one exists.  Failure of that optional
    confirmation never removes the original address from the inspection target.
    """

    rows: list[str] = []
    if not is_ip(target):
        display_name = next((name for name in names if "." in name), target.rstrip("."))
        rows.extend(f"{display_name} -> {address}" for address in addresses)
        return rows

    ptr_name = next((item.name for item in reverse_dns if item.name), None)
    if not ptr_name:
        return rows
    number = None
    if trace is not None:
        number = trace.resolver_query(
            operation="getaddrinfo",
            query_type="Forward-confirmed reverse resolution",
            value_label="Name",
            value=ptr_name,
            source="PTR forward confirmation",
            address_family="IPv4 / IPv6",
        )
    try:
        infos = socket.getaddrinfo(ptr_name, None, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        if trace is not None and number is not None:
            trace.resolver_no_response(number, f"{exc.__class__.__name__}: {exc}")
        return rows
    confirmed: list[str] = []
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        if family in {socket.AF_INET, socket.AF_INET6}:
            confirmed.append(str(ipaddress.ip_address(sockaddr[0])))
    confirmed = unique_preserve(confirmed)
    if trace is not None and number is not None:
        trace.resolver_response(
            number,
            [("IPv6" if ":" in address else "IPv4", address) for address in confirmed],
        )
    rows.extend(f"{ptr_name} -> {address}" for address in confirmed)
    return rows


def _policy_rows(config: AppConfig, names: list[str], addresses: list[str]) -> list[AddressPolicy]:
    """Evaluate boundary and query/credential policy for inspect candidates.

    The boundary result is informational.  ``PolicyEngine.query_policy`` is called
    with boundary enforcement disabled because the operator explicitly supplied
    this one target.  Address/name deny rules still prevent any packet from being
    sent to that candidate.
    """

    policy = PolicyEngine(config)
    rows: list[AddressPolicy] = []
    for address in _ordered_addresses(config, addresses):
        boundary = policy.in_boundary(address)
        query = policy.query_policy(names, address, enforce_boundary=False)
        credential_profile: str | None = None
        credential_reason: str | None = None
        if config.credential_profiles:
            credential = policy.credential_profile(names, address)
            credential_profile = credential.profile.name
            credential_reason = credential.reason
        rows.append(
            AddressPolicy(
                address=address,
                boundary_allowed=boundary.allowed,
                boundary_reason=boundary.reason,
                query_allowed=query.allowed,
                query_reason=query.reason,
                credential_profile=credential_profile,
                credential_reason=credential_reason,
            )
        )
    return rows


def _build_task(config: AppConfig, result: InspectionResult) -> DeviceTask | None:
    """Build the worker-compatible task for queryable inspection candidates.

    Args:
        config: Effective configuration used to interpret credential profiles.
        result: Partially assembled inspection containing resolved addresses and
            policy/credential decisions.

    Returns:
        A non-recursive :class:`DeviceTask` when at least one address is both
        query-allowed and has a credential profile, otherwise ``None``.
    """

    attempts = [
        TargetAttempt(address=row.address, credential_profile=row.credential_profile)
        for row in result.policies
        if row.query_allowed and row.credential_profile is not None
    ]
    if not attempts:
        return None
    return DeviceTask(
        host_id=0,
        preferred_name=result.preferred_name,
        names=result.names,
        addresses=result.addresses,
        attempts=attempts,
        cohort=0,
    )


def _neighbor_candidate(obs: NeighborObservation) -> Candidate:
    """Translate one observation into the same evidence model used by discovery."""

    return Candidate(
        names=[obs.remote_name] if obs.remote_name else [],
        addresses=list(obs.remote_addresses),
        category="unknown_device",
        protocol=obs.protocol,
        local_interface=obs.local_interface,
        local_interface_raw=obs.local_interface_raw,
        remote_interface=obs.remote_interface,
        remote_interface_raw=obs.remote_interface_raw,
        remote_description=obs.remote_description,
        remote_platform=obs.remote_platform,
        capabilities=list(obs.capabilities),
        chassis_id=obs.chassis_id,
        chassis_id_subtype=obs.chassis_id_subtype,
        chassis_id_subtype_id=obs.chassis_id_subtype_id,
        protocols=list(dict.fromkeys([obs.protocol, *obs.details.get("protocols", [])])),
        details=dict(obs.details),
    )


def neighbor_record(config: AppConfig, obs: NeighborObservation) -> dict[str, Any]:
    """Render an inspect neighbor using discovery.json-compatible field names."""

    classifier = Classifier(config)
    candidate = _neighbor_candidate(obs)
    decision = classifier.classify_candidate(candidate)
    candidate.category = decision.category
    protocols = list(dict.fromkeys(obs.details.get("protocols", [obs.protocol])))
    order = {"cdp": 0, "lldp": 1, "lldpv2": 2}
    protocols = sorted(
        (str(item) for item in protocols), key=lambda item: (order.get(item, 99), item)
    )
    details = dict(obs.details)
    details.update(
        {
            "remote_description": obs.remote_description,
            "remote_platform": obs.remote_platform,
            "capabilities": list(obs.capabilities),
            "chassis_id": obs.chassis_id,
            "chassis_id_subtype": obs.chassis_id_subtype,
            "chassis_id_subtype_id": obs.chassis_id_subtype_id,
        }
    )
    return {
        "host_ref": None,
        "name": obs.remote_name
        or obs.chassis_id
        or (obs.remote_addresses[0] if obs.remote_addresses else "unknown"),
        "classification": decision.category,
        "classification_reason": decision.reasons,
        "local_interface": obs.local_interface,
        "local_interface_raw": obs.local_interface_raw,
        "remote_interface": obs.remote_interface,
        "remote_interface_raw": obs.remote_interface_raw,
        "protocols": protocols,
        "protocol_tag": f"[{','.join(protocols)}]",
        "observed_name": obs.remote_name,
        "observed_addresses": list(obs.remote_addresses),
        "details": {key: value for key, value in details.items() if value not in (None, "", [])},
    }


def inspection_json(config: AppConfig, result: InspectionResult) -> dict[str, Any]:
    """Return the rich JSON document used by the inspect JSON renderer."""

    device = result.device
    system = asdict(device.system) if device and device.system else {}
    pings = [asdict(item) for item in device.ping_probes] if device else []
    learned = [neighbor_record(config, item) for item in (device.neighbors if device else [])]
    snmp_sysname = system.get("sys_name") if system else None
    names = unique_preserve([*result.names, *([snmp_sysname] if snmp_sysname else [])])
    ipv4 = [address for address in result.addresses if ":" not in address]
    ipv6 = [address for address in result.addresses if ":" in address]
    status = result.status
    snmp = {
        "credential_profile": device.credential_profile if device else None,
        "credential_result": device.credential_result if device else None,
    }
    if device and device.collection_metrics:
        # Inspection always reports the lightweight metrics. Full discovery uses
        # snmp.report_metrics to decide whether the same structure is persisted.
        snmp["collection_metrics"] = {
            section: asdict(metric) for section, metric in device.collection_metrics.items()
        }
    if device and device.snmp_sessions:
        snmp["adaptive_sessions"] = [asdict(item) for item in device.snmp_sessions]
    if device and device.interface_observation_groups:
        snmp["interface_observation_groups"] = device.interface_observation_groups
    return {
        "inspection": {
            "input_target": result.input_target,
            "generated_status": status,
            "dry_run": result.dry_run,
            "collection_mode": "system_only" if result.system_only else "full",
            "boundary_enforced": False,
            "dns": {
                "forward": list(result.forward_dns),
                "reverse": [asdict(item) for item in result.reverse_dns],
                "errors": list(result.dns_errors),
            },
            "policy": [asdict(item) for item in result.policies],
            "timings_ms": {
                "dns": result.dns_duration_ms,
                "query": result.query_duration_ms,
                "total": result.total_duration_ms,
                **result.probe_timings,
            },
        },
        "host": {
            "id": None,
            "preferred_name": result.preferred_name,
            "queried_as": device.query_target if device else None,
            "snmp_sysname": snmp_sysname,
            "classification": "managed_device",
            "classification_reason": ["explicit inspect target"],
            "tags": [],
            "state": "COMPLETE" if device and device.status == "success" else status.upper(),
            "is_seed": True,
            "first_seen": None,
            "last_seen": device.last_seen if device else None,
            "last_seen_source": device.last_seen_source if device else None,
            "names": names,
            "addresses": {"ipv4": ipv4, "ipv6": ipv6},
            "chassis_id": None,
            "icmp": pings,
            "system": system,
            "snmp": snmp,
            "learned_neighbors": learned,
            "observed_by_neighbors": [],
        },
        "errors": [error.to_dict() for error in device.errors] if device else [],
    }


async def inspect_target(
    config: AppConfig,
    target: str,
    *,
    dry_run: bool = False,
    system_only: bool = False,
    trace: SnmpTrace | None = None,
) -> InspectionResult:
    """Inspect exactly one target and return an in-memory result.

    DNS and policy evaluation always run.  ``dry_run=True`` stops there and is
    guaranteed not to instantiate the ICMP or SNMP backends. ``trace`` optionally
    records resolver calls plus ICMP and logical SNMP operations performed by a
    normal inspection. A
    normal inspection uses the same wavefront basic probe and detailed collectors,
    but never schedules any neighbor for recursive polling.  ``system_only=True``
    stops after the initial SYSTEM-MIB probe and therefore avoids ENTITY-MIB,
    IF-MIB, LLDP, LLDPv2, and CDP collection.
    """

    overall_start = time.perf_counter()
    dns_start = time.perf_counter()
    if trace is None:
        # Keep the ordinary execution call shape unchanged. Besides avoiding
        # needless trace-aware branching in discovery helpers, this preserves
        # simple test doubles and downstream wrappers that use the historical
        # two-argument resolver contract.
        resolved = resolve_seed(target, config.discovery.dns_suffixes)
        reverse = _reverse_dns(resolved.addresses)
        forward = _forward_dns_for_display(target, resolved.names, resolved.addresses, reverse)
    else:
        resolved = resolve_seed(target, config.discovery.dns_suffixes, trace=trace)
        reverse = _reverse_dns(resolved.addresses, trace=trace)
        forward = _forward_dns_for_display(
            target,
            resolved.names,
            resolved.addresses,
            reverse,
            trace=trace,
        )
    dns_ms = _elapsed_ms(dns_start)
    policies = _policy_rows(config, resolved.names, resolved.addresses)
    result = InspectionResult(
        input_target=target,
        preferred_name=resolved.preferred_name,
        names=resolved.names,
        addresses=_ordered_addresses(config, resolved.addresses),
        forward_dns=forward,
        reverse_dns=reverse,
        dns_errors=resolved.errors,
        policies=policies,
        dry_run=dry_run,
        status="dry_run" if dry_run else "pending",
        system_only=system_only,
        dns_duration_ms=dns_ms,
    )
    if dry_run:
        return _finalize_result(result, overall_start)

    if not result.addresses:
        result.status = "unresolved"
        return _finalize_result(result, overall_start)

    task = _build_task(config, result)
    if task is None:
        result.status = (
            "denied" if any(not row.query_allowed for row in policies) else "no_credentials"
        )
        return _finalize_result(result, overall_start)

    query_start = time.perf_counter()
    probe_kwargs: dict[str, Any] = {"system_only": system_only}
    if trace is not None:
        # Keep the optional keyword out of the ordinary path. This preserves the
        # narrow worker execution contract and makes test doubles/future callers
        # that do not care about tracing remain simple.
        probe_kwargs["trace"] = trace
    device, probe_timings = await process_single_device(
        config, task, _NeverPaused(), **probe_kwargs
    )
    result.query_duration_ms = _elapsed_ms(query_start)
    result.probe_timings = probe_timings
    result.device = device
    if device.status == "success":
        result.status = "partial" if device.errors else "success"
    else:
        result.status = "failed"
    return _finalize_result(result, overall_start)


def inspect_target_sync(
    config: AppConfig,
    target: str,
    *,
    dry_run: bool = False,
    system_only: bool = False,
    trace: SnmpTrace | None = None,
) -> InspectionResult:
    """Synchronous CLI wrapper around :func:`inspect_target`."""

    return asyncio.run(
        inspect_target(
            config,
            target,
            dry_run=dry_run,
            system_only=system_only,
            trace=trace,
        )
    )
