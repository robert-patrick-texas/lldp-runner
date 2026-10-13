"""Multiprocess worker: wavefront ICMP/basic SNMP, then serial per-device detail."""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import logging
import multiprocessing as mp
import time
from collections.abc import Awaitable, Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from typing import Any, Literal

from lldp_runner.collectors import merge_neighbor_observations
from lldp_runner.collectors.cdp import (
    CDP_CACHE_ENTRY,
    CdpSnapshotIncompleteError,
    collect_cdp,
)
from lldp_runner.collectors.entity import enrich_system_from_entity_mib
from lldp_runner.collectors.interfaces import InterfaceCollectionError, collect_interfaces
from lldp_runner.collectors.lldp import (
    LLDP_REM_ENTRY,
    LLDPV2_REM_ENTRY,
    LldpSnapshotIncompleteError,
    collect_lldp,
    collect_lldpv2,
)
from lldp_runner.collectors.system import collect_basic_system
from lldp_runner.config import AppConfig, CredentialConfig
from lldp_runner.icmp import AsyncIcmpPinger
from lldp_runner.logging_setup import configure_worker_logging
from lldp_runner.models import (
    CollectionCoverage,
    CollectionMetric,
    DeviceResult,
    DeviceTask,
    DirectCredential,
    SnmpRetryEvent,
    SnmpSessionTelemetry,
    SystemDetails,
    WorkerError,
)
from lldp_runner.snmp import create_adaptive_snmp_state, create_snmp_client
from lldp_runner.snmp.base import (
    SnmpBackendCapabilityError,
    SnmpBackendError,
    SnmpSessionAddressError,
)
from lldp_runner.snmp.metrics import CountingSnmpClient
from lldp_runner.snmp.resilience import (
    AdaptiveSnmpClient,
    AdaptiveSnmpState,
    SnmpAccessRestrictedError,
    is_snmp_timeout,
)
from lldp_runner.snmp.trace import SnmpTrace, TraceContext
from lldp_runner.timeutil import configure_timezone, iso_now
from lldp_runner.topology_shadow import build_interface_observation_groups

LOG = logging.getLogger(__name__)

_NEIGHBOR_PROTOCOL_ROOTS = {
    "cdp": CDP_CACHE_ENTRY,
    "lldp": LLDP_REM_ENTRY,
    "lldpv2": LLDPV2_REM_ENTRY,
}


def _adaptive_collection_context(
    adaptive_client: AdaptiveSnmpClient | None,
    *,
    collector: str,
    table_name: str,
    collection_phase: str,
    root_oid: str | None = None,
):
    """Return a scoped retry-label context, or a no-op for injected test clients."""

    context_factory = getattr(adaptive_client, "collection_context", None)
    if not callable(context_factory):
        return nullcontext()
    return context_factory(
        collector=collector,
        table_name=table_name,
        collection_phase=collection_phase,
        root_oid=root_oid,
    )


def _add_collection_metric(
    result: DeviceResult, section: str, objects: int, duration_ms: float
) -> None:
    """Accumulate backend-neutral SNMP telemetry for one device section.

    Metrics are intentionally stored on :class:`DeviceResult` rather than in a
    collector-specific structure.  The same result object can therefore feed
    interactive inspection directly or be persisted by the coordinator when
    ``snmp.report_metrics`` is enabled for a full discovery run.
    """

    metric = result.collection_metrics.setdefault(section, CollectionMetric())
    metric.add(objects, duration_ms)


async def _measured_collection(
    section: str,
    result: DeviceResult | None,
    client: Any,
    collector: Callable[..., Awaitable[Any]],
    *args: Any,
) -> Any:
    """Run one collector and optionally count returned objects plus wall time.

    ``CountingSnmpClient`` wraps the already-open project-owned SNMP client, so
    collectors and the Gufo backend do not need telemetry-specific code.  The
    timer is finalized even when the collector raises; this makes slow failures
    visible while counting only varbinds that were actually returned.
    """

    if result is None:
        return await collector(client, *args)

    measured_client = CountingSnmpClient(client)
    started = time.perf_counter()
    try:
        return await collector(measured_client, *args)
    finally:
        _add_collection_metric(
            result,
            section,
            measured_client.objects,
            (time.perf_counter() - started) * 1000.0,
        )


@dataclass(slots=True)
class _ResolvedCredentialAttempt:
    """Concrete credential material and safe reporting metadata for one try."""

    address: str
    profile_name: str | None
    credential: CredentialConfig | DirectCredential
    credential_result: Literal["primary", "fallback", "direct"]
    credential_source: str
    credential_label: str | None


@dataclass(slots=True)
class _SuccessfulBasic:
    """Successful basic-SNMP attempt retained for the detail collection phase."""

    address: str
    profile_name: str | None
    credential: CredentialConfig | DirectCredential
    credential_result: Literal["primary", "fallback", "direct"]
    credential_source: str
    credential_label: str | None
    system: SystemDetails
    adaptive_state: AdaptiveSnmpState | None = None
    adaptive_telemetry_recorded: bool = False


def _exception_chain(exc: BaseException) -> list[BaseException]:
    """Return a cycle-safe backend/cause chain from outermost to root cause.

    ``SnmpBackendError`` normally reaches this function through ``raise ... from``.
    Its explicit ``original_exception`` attribute is also traversed so injected
    clients, deserialized diagnostics, and direct unit construction retain the
    same stable category semantics even when Python cause metadata is absent.
    """

    values: list[BaseException] = []
    pending: list[BaseException] = [exc]
    visited: set[int] = set()
    while pending:
        current = pending.pop(0)
        if id(current) in visited:
            continue
        visited.add(id(current))
        values.append(current)
        linked = current.__cause__ or current.__context__
        if linked is not None:
            pending.append(linked)
        original = getattr(current, "original_exception", None)
        if isinstance(original, BaseException):
            pending.append(original)
    return values


def _backend_error(exc: BaseException) -> SnmpBackendError | None:
    """Return phase metadata carried by the project-owned SNMP boundary."""

    return next(
        (current for current in _exception_chain(exc) if isinstance(current, SnmpBackendError)),
        None,
    )


def _original_exception(exc: BaseException) -> BaseException:
    """Return the backend's original exception rather than LLDP-Runner's wrapper."""

    backend = _backend_error(exc)
    if backend is not None:
        return backend.original_exception
    return exc


def _credential_secrets(
    credential: CredentialConfig | DirectCredential | None,
) -> tuple[str, ...]:
    """Return non-empty credential values that must never cross diagnostics."""

    if credential is None:
        return ()
    values: list[str] = []
    for field_name in (
        "community",
        "username",
        "auth_password",
        "priv_password",
    ):
        value = credential.secret(field_name)
        if value:
            values.append(value)
    return tuple(sorted(set(values), key=len, reverse=True))


def _redact_exception_text(
    value: object,
    credential: CredentialConfig | DirectCredential | None,
) -> str:
    """Render one bounded diagnostic value after deterministic secret removal."""

    text = str(value)
    for secret in _credential_secrets(credential):
        text = text.replace(secret, "<redacted>")
    if len(text) > 4096:
        return text[:4078] + "...<truncated>"
    return text


def _safe_exception_message(
    exc: BaseException,
    credential: CredentialConfig | DirectCredential | None = None,
) -> str:
    """Render the original backend exception while redacting credential values."""

    original = _original_exception(exc)
    qualified = f"{original.__class__.__module__}.{original.__class__.__qualname__}"
    message = _redact_exception_text(original, credential)
    return f"{qualified}: {message}" if message else qualified


def _address_family(value: str | None) -> Literal["ipv4", "ipv6"] | None:
    """Classify one normalized route without rewriting its canonical text."""

    if not value:
        return None
    candidate = value.strip().strip("[]").split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return "ipv4" if parsed.version == 4 else "ipv6"


def _worker_error(
    *,
    operation: str,
    category: str,
    message: str,
    credential: CredentialConfig | DirectCredential | None = None,
    exc: BaseException | None = None,
    attempted_target: str | None = None,
    phase: Literal[
        "resolve",
        "session_construct",
        "session_open",
        "request",
        "session_close",
    ]
    | None = None,
    credential_profile: str | None = None,
    credential_stage: str | None = None,
    credential_source: str | None = None,
    credential_label: str | None = None,
    attempt: int | None = None,
    collector: str | None = None,
    recoverable: bool = True,
) -> WorkerError:
    """Build one canonical worker error without message parsing downstream."""

    backend = _backend_error(exc) if exc is not None else None
    original = _original_exception(exc) if exc is not None else None
    route = backend.attempted_target if backend is not None else attempted_target
    family = backend.address_family if backend is not None else _address_family(route)
    resolved_phase = backend.phase if backend is not None else phase
    exception_type: str | None = None
    exception_errno: int | None = None
    exception_strerror: str | None = None
    exception_args: list[str] = []
    if original is not None:
        exception_type = f"{original.__class__.__module__}.{original.__class__.__qualname__}"
        raw_errno = getattr(original, "errno", None)
        if isinstance(raw_errno, int) and not isinstance(raw_errno, bool):
            exception_errno = raw_errno
        raw_strerror = getattr(original, "strerror", None)
        if raw_strerror is not None:
            exception_strerror = _redact_exception_text(raw_strerror, credential)
        exception_args = [
            _redact_exception_text(repr(value), credential)
            for value in getattr(original, "args", ())
        ]
    return WorkerError(
        operation=operation,
        category=category,
        message=message,
        timestamp=iso_now(),
        attempted_target=route,
        address_family=family,
        phase=resolved_phase,
        exception_type=exception_type,
        exception_errno=exception_errno,
        exception_strerror=exception_strerror,
        exception_args=exception_args,
        credential_profile=credential_profile,
        credential_stage=credential_stage,
        credential_source=credential_source,
        credential_label=credential_label,
        attempt=attempt,
        collector=collector,
        recoverable=recoverable,
    )


def _error_category(exc: BaseException) -> str:
    """Map backend exceptions to LLDP-Runner's stable worker error categories."""

    chain = _exception_chain(exc)
    if any(isinstance(current, SnmpSessionAddressError) for current in chain):
        return "snmp_session_address_error"
    if any(isinstance(current, SnmpAccessRestrictedError) for current in chain):
        return "snmp_access_restricted"
    if any(isinstance(current, SnmpBackendCapabilityError) for current in chain):
        return "snmp_backend_capability"
    if any(
        isinstance(
            current,
            (
                CdpSnapshotIncompleteError,
                LldpSnapshotIncompleteError,
                InterfaceCollectionError,
            ),
        )
        for current in chain
    ):
        return "incomplete_table"
    if is_snmp_timeout(exc):
        return "timeout"
    if any(isinstance(current, PermissionError) for current in chain):
        return "permission"
    if any(isinstance(current, OSError) for current in chain):
        return "transport"
    for current in chain:
        name = current.__class__.__name__.lower()
        if "auth" in name or "security" in name:
            return "authentication"
        if "nosuch" in name:
            return "unsupported_oid"
    if any("snmp" in current.__class__.__name__.lower() for current in chain):
        return "snmp_error"
    return "exception"


def _adaptive_event_start(adaptive_client: AdaptiveSnmpClient | None) -> int:
    """Return the event-list offset used to account one collector invocation."""

    if adaptive_client is None:
        return 0
    return len(adaptive_client.state.events)


def _collector_attempt_count(
    adaptive_client: AdaptiveSnmpClient | None,
    event_start: int,
    collector: str,
    *,
    attempt_offset: int = 0,
) -> int:
    """Count the initial pass plus actual retries issued for one collector.

    Exhaustion records are intentionally excluded. This keeps collection
    coverage from claiming an attempt that policy refused to send while making
    transport retries visible instead of reporting every collector as attempt 1.
    """

    retries = 0
    if adaptive_client is not None:
        retries = sum(
            1
            for event in adaptive_client.state.events[event_start:]
            if getattr(event, "collector", collector) == collector
            and getattr(event, "retry_allowed", True)
        )
    return max(0, int(attempt_offset)) + 1 + retries


def _finish_pending_retry_event(
    adaptive_client: AdaptiveSnmpClient | None,
    event_start: int,
    collector: str,
    *,
    outcome: Literal["succeeded", "failed"],
    exc: BaseException | None = None,
    active_event: SnmpRetryEvent | None = None,
) -> None:
    """Finalize the retry event responsible for the current collector pass."""

    event = active_event
    if event is None and adaptive_client is not None:
        for candidate in reversed(adaptive_client.state.events[event_start:]):
            if getattr(candidate, "collector", collector) != collector:
                continue
            if candidate.final_outcome == "pending":
                event = candidate
                break
    if event is None or event.final_outcome != "pending":
        return
    event.final_outcome = outcome
    if outcome == "failed" and exc is not None:
        event.outcome_type = exc.__class__.__name__


def _subtable_coverage_from(
    values: object | None,
    exc: BaseException | None,
) -> dict[str, CollectionCoverage]:
    """Extract LLDP subtable evidence from a successful list or exception."""

    for source, attribute in (
        (values, "subtable_coverage"),
        (exc, "lldp_subtable_coverage"),
    ):
        candidate = getattr(source, attribute, None) if source is not None else None
        if isinstance(candidate, dict) and all(
            isinstance(item, CollectionCoverage) for item in candidate.values()
        ):
            return dict(candidate)
    return {}


def _merge_subtable_coverage(
    prior: dict[str, CollectionCoverage],
    current: dict[str, CollectionCoverage],
) -> dict[str, CollectionCoverage]:
    """Accumulate retry work while retaining each final subtable outcome."""

    merged = dict(prior)
    for name, value in current.items():
        previous = merged.get(name)
        if previous is None:
            merged[name] = copy.deepcopy(value)
            continue
        replacement = copy.deepcopy(value)
        replacement.attempts += previous.attempts
        replacement.object_count += previous.object_count
        replacement.duration_ms = round(previous.duration_ms + replacement.duration_ms, 3)
        merged[name] = replacement
    return merged


def _publish_subtable_coverage(
    values: object | None,
    exc: BaseException | None,
    coverage: dict[str, CollectionCoverage],
) -> None:
    """Attach merged retry coverage to the final result boundary."""

    if not coverage:
        return
    if values is not None:
        try:
            setattr(values, "subtable_coverage", dict(coverage))  # noqa: B010 - ty: values may be None
            return
        except (AttributeError, TypeError):
            pass
    if exc is not None:
        try:
            setattr(exc, "lldp_subtable_coverage", dict(coverage))  # noqa: B010 - ty: dynamic attribute on exception
        except (AttributeError, TypeError):
            pass


async def _collect_neighbor_protocol(
    config: AppConfig,
    target: str,
    operation: str,
    metrics_result: DeviceResult | None,
    client: Any,
    collector: Callable[..., Awaitable[Any]],
    *args: Any,
    adaptive_client: AdaptiveSnmpClient | None = None,
    allow_structural_retry: bool = True,
    attempt_offset: int = 0,
    active_retry_event: SnmpRetryEvent | None = None,
) -> tuple[list[Any], BaseException | None, int]:
    """Collect one complete neighbor protocol with bounded adaptive repair.

    Ordinary transport retry remains inside :class:`AdaptiveSnmpClient`. A
    collector-detected structural failure can restart the whole protocol once
    through the normal fair-share policy. Delayed stability callers disable that
    structural layer and suppress nested transport retry, making the final pass
    exactly one complete protocol attempt.
    """

    structural_retries = 0
    subtable_coverage: dict[str, CollectionCoverage] = {}
    event_start = _adaptive_event_start(adaptive_client)
    with _adaptive_collection_context(
        adaptive_client,
        collector=operation,
        table_name=operation,
        collection_phase="detail",
        root_oid=_NEIGHBOR_PROTOCOL_ROOTS.get(operation),
    ):
        while True:
            try:
                values = await _measured_collection(
                    operation, metrics_result, client, collector, *args
                )
                attempt = _collector_attempt_count(
                    adaptive_client,
                    event_start,
                    operation,
                    attempt_offset=attempt_offset,
                )
                _finish_pending_retry_event(
                    adaptive_client,
                    event_start,
                    operation,
                    outcome="succeeded",
                    active_event=active_retry_event,
                )
                subtable_coverage = _merge_subtable_coverage(
                    subtable_coverage,
                    _subtable_coverage_from(values, None),
                )
                # LLDP results are list subclasses so retain their attached
                # coverage. Generic collectors are normalized to a plain list.
                normalized_values = values if isinstance(values, list) else list(values)
                _publish_subtable_coverage(normalized_values, None, subtable_coverage)
                return normalized_values, None, attempt
            except Exception as exc:
                subtable_coverage = _merge_subtable_coverage(
                    subtable_coverage,
                    _subtable_coverage_from(None, exc),
                )
                category = _error_category(exc)
                if (
                    allow_structural_retry
                    and category == "incomplete_table"
                    and structural_retries < config.snmp.structural_table_retry
                    and adaptive_client is not None
                ):
                    try:
                        prepared = await adaptive_client.prepare_collection_retry(
                            operation=operation.upper(),
                            category=category,
                            root_oid=_NEIGHBOR_PROTOCOL_ROOTS.get(operation),
                        )
                    except Exception as retry_exc:
                        exc = retry_exc
                        category = _error_category(retry_exc)
                    else:
                        if prepared:
                            structural_retries += 1
                            attempt = _collector_attempt_count(
                                adaptive_client,
                                event_start,
                                operation,
                                attempt_offset=attempt_offset,
                            )
                            LOG.info(
                                "SNMP target=%s neighbor collector restart "
                                "operation=%s category=%s attempt=%d",
                                target,
                                operation,
                                category,
                                attempt,
                            )
                            continue
                attempt = _collector_attempt_count(
                    adaptive_client,
                    event_start,
                    operation,
                    attempt_offset=attempt_offset,
                )
                _finish_pending_retry_event(
                    adaptive_client,
                    event_start,
                    operation,
                    outcome="failed",
                    exc=exc,
                    active_event=active_retry_event,
                )
                log = LOG.error if category == "snmp_access_restricted" else LOG.warning
                log(
                    "SNMP target=%s neighbor collector failed "
                    "operation=%s category=%s attempt=%d type=%s",
                    target,
                    operation,
                    category,
                    attempt,
                    exc.__class__.__name__,
                )
                _publish_subtable_coverage(None, exc, subtable_coverage)
                return [], exc, attempt


async def _collect_interface_map(
    config: AppConfig,
    target: str,
    metrics_result: DeviceResult | None,
    client: Any,
    *,
    adaptive_client: AdaptiveSnmpClient | None = None,
) -> tuple[dict[int, tuple[str, str]], BaseException | None, int]:
    """Collect IF-MIB names with bounded structural restart behavior."""

    structural_retries = 0
    event_start = _adaptive_event_start(adaptive_client)
    with _adaptive_collection_context(
        adaptive_client,
        collector="interfaces",
        table_name="IF-MIB interface map",
        collection_phase="detail",
    ):
        while True:
            try:
                values = await _measured_collection(
                    "interfaces", metrics_result, client, collect_interfaces
                )
                attempt = _collector_attempt_count(adaptive_client, event_start, "interfaces")
                _finish_pending_retry_event(
                    adaptive_client,
                    event_start,
                    "interfaces",
                    outcome="succeeded",
                )
                return dict(values), None, attempt
            except Exception as exc:
                category = _error_category(exc)
                if (
                    category == "incomplete_table"
                    and structural_retries < config.snmp.structural_table_retry
                    and adaptive_client is not None
                ):
                    try:
                        prepared = await adaptive_client.prepare_collection_retry(
                            operation="INTERFACES",
                            category=category,
                        )
                    except Exception as retry_exc:
                        exc = retry_exc
                        category = _error_category(retry_exc)
                    else:
                        if prepared:
                            structural_retries += 1
                            attempt = _collector_attempt_count(
                                adaptive_client, event_start, "interfaces"
                            )
                            LOG.info(
                                "SNMP target=%s interface collector restart category=%s attempt=%d",
                                target,
                                category,
                                attempt,
                            )
                            continue
                attempt = _collector_attempt_count(adaptive_client, event_start, "interfaces")
                _finish_pending_retry_event(
                    adaptive_client,
                    event_start,
                    "interfaces",
                    outcome="failed",
                    exc=exc,
                )
                log = LOG.error if category == "snmp_access_restricted" else LOG.warning
                log(
                    "SNMP target=%s interface collector failed category=%s attempt=%d type=%s",
                    target,
                    category,
                    attempt,
                    exc.__class__.__name__,
                )
                return {}, exc, attempt


def _unresolved_local_interface_count(values: list[Any]) -> int:
    """Count neighbor rows whose local-port namespace could not be resolved."""

    count = 0
    for value in values:
        details = getattr(value, "details", None)
        if isinstance(details, dict) and details.get("local_interface_resolved") is False:
            count += 1
    return count


def _coverage_status(exc: BaseException | None) -> str:
    """Map one collector exception to a stable coverage status."""

    if exc is None:
        return "complete"
    category = _error_category(exc)
    if category == "timeout":
        return "timeout"
    if category == "snmp_access_restricted":
        return "access_restricted"
    if category in {"unsupported", "unsupported_oid", "no_such_object"}:
        return "unsupported"
    if category == "incomplete_table":
        return "structurally_invalid"
    return "failed"


def _coverage_objects(result: DeviceResult | None, section: str) -> int:
    if result is None:
        return 0
    metric = result.collection_metrics.get(section)
    return metric.objects if metric is not None else 0


def _coverage_duration(result: DeviceResult | None, section: str) -> float:
    """Return the measured aggregate collector duration when available."""

    if result is None:
        return 0.0
    metric = result.collection_metrics.get(section)
    return metric.duration_ms if metric is not None else 0.0


def _set_collection_coverage(
    result: DeviceResult | None,
    section: str,
    *,
    exc: BaseException | None = None,
    attempts: int = 1,
    object_count: int | None = None,
    row_count: int | None = None,
    unresolved_rows: int = 0,
    status: str | None = None,
    message: str | None = None,
    duration_ms: float | None = None,
    valid_address_count: int | None = None,
    ipv4_address_count: int | None = None,
    ipv6_address_count: int | None = None,
    rejected_address_count: int | None = None,
    malformed_index_count: int | None = None,
    subtables: dict[str, CollectionCoverage] | None = None,
) -> None:
    """Record table coverage without confusing absence with collection failure.

    Aggregate protocol coverage can carry independently measured ``subtables``.
    That distinction lets diff classify an address-only disappearance using the
    management-address walk rather than treating a complete neighbor walk as
    proof that management-address absence was authoritative.
    """

    if result is None:
        return
    resolved_status = status or _coverage_status(exc)
    if resolved_status == "not_attempted":
        resolution_status = "not_applicable"
    elif unresolved_rows:
        resolution_status = "partial"
    elif resolved_status == "complete":
        resolution_status = "resolved"
    elif resolved_status == "partial":
        resolution_status = "partial"
    else:
        resolution_status = "unresolved"
    result.collection_coverage[section] = CollectionCoverage(
        status=resolved_status,  # ty: ignore[invalid-argument-type]
        attempts=max(1, int(attempts)),
        object_count=(
            _coverage_objects(result, section)
            if object_count is None
            else max(0, int(object_count))
        ),
        row_count=row_count,
        resolution_status=resolution_status,  # type: ignore[arg-type]
        message=message or (str(exc) if exc is not None else None),
        duration_ms=round(
            _coverage_duration(result, section)
            if duration_ms is None
            else max(0.0, float(duration_ms)),
            3,
        ),
        valid_address_count=valid_address_count,
        ipv4_address_count=ipv4_address_count,
        ipv6_address_count=ipv6_address_count,
        rejected_address_count=rejected_address_count,
        malformed_index_count=malformed_index_count,
        subtables=dict(subtables or {}),
    )


@dataclass(slots=True)
class _BasicState:
    """Mutable ordered credential/address state for the basic SNMP wave."""

    task: DeviceTask
    errors: list[WorkerError]
    target_index: int = 0
    stage: Literal["primary", "fallback", "direct"] = "primary"
    attempt: int = 1
    result: _SuccessfulBasic | None = None
    exhausted: bool = False
    pinged_address: str | None = None
    _last_adaptive_state: AdaptiveSnmpState | None = None
    _last_adaptive_route: tuple[str, str, str, str, str, str] | None = None

    def __post_init__(self) -> None:
        """Select direct versus profile stage for the first target route."""

        if self.task.attempts and self.task.attempts[0].direct_credential is not None:
            self.stage = "direct"

    def _target(self):
        return self.task.attempts[self.target_index]

    def _reset_stage_for_target(self) -> None:
        if self.exhausted:
            return
        target = self._target()
        self.stage = "direct" if target.direct_credential is not None else "primary"

    @staticmethod
    def _adaptive_route_key(
        resolved: _ResolvedCredentialAttempt,
    ) -> tuple[str, str, str, str, str, str]:
        """Identify one address/credential route across configured attempts."""

        return (
            resolved.address,
            resolved.credential.name,
            resolved.credential_result,
            resolved.profile_name or "",
            resolved.credential_label or "",
            resolved.credential_source,
        )

    def adaptive_state_for(
        self,
        config: AppConfig,
        resolved: _ResolvedCredentialAttempt,
    ) -> AdaptiveSnmpState:
        """Return the durable slowdown profile for the current basic route.

        A credential profile can request more than one outer attempt. Reusing the
        state prevents the second attempt from forgetting that the target already
        required a larger timeout, smaller GETBULK response, and slower pacing.
        """

        route = self._adaptive_route_key(resolved)
        if self._last_adaptive_state is None or self._last_adaptive_route != route:
            self._last_adaptive_state = create_adaptive_snmp_state(config, resolved.address)
            self._last_adaptive_route = route
        self._last_adaptive_state.set_route_context(
            credential_route="|".join(
                (
                    resolved.address,
                    resolved.credential_source,
                    resolved.credential_result,
                    resolved.credential_label or resolved.credential.name,
                )
            ),
            credential_profile=resolved.profile_name,
        )
        return self._last_adaptive_state

    def take_adaptive_telemetry(self) -> SnmpSessionTelemetry | None:
        """Detach the completed route's telemetry before moving to another route."""

        state = self._last_adaptive_state
        self._last_adaptive_state = None
        self._last_adaptive_route = None
        return state.telemetry() if state is not None else None

    def current(self, config: AppConfig) -> _ResolvedCredentialAttempt:
        """Resolve the concrete credential for the state's current route."""

        target = self._target()
        if target.direct_credential is not None:
            return _ResolvedCredentialAttempt(
                address=target.address,
                profile_name=None,
                credential=target.direct_credential,
                credential_result="direct",
                credential_source=target.credential_source,
                credential_label=target.credential_label,
            )
        if not target.credential_profile:
            raise RuntimeError("target attempt has neither profile nor direct credential")
        profile = config.credential_profiles[target.credential_profile]
        credential_name = profile.primary if self.stage == "primary" else profile.fallback
        if credential_name is None:
            raise RuntimeError("fallback stage selected without fallback credential")
        return _ResolvedCredentialAttempt(
            address=target.address,
            profile_name=profile.name,
            credential=config.credentials[credential_name],
            credential_result=self.stage,  # type: ignore[arg-type]
            credential_source=target.credential_source,
            credential_label=target.credential_label,
        )

    def advance(self, config: AppConfig) -> None:
        """Advance retry, fallback, credential route, or management address."""

        target = self._target()
        if target.direct_credential is not None:
            self.target_index += 1
            self.attempt = 1
        else:
            if not target.credential_profile:
                raise RuntimeError("target attempt has neither profile nor direct credential")
            profile = config.credential_profiles[target.credential_profile]
            limit = (
                profile.primary_attempts if self.stage == "primary" else profile.fallback_attempts
            )
            if self.attempt < limit:
                self.attempt += 1
                return
            if self.stage == "primary" and profile.fallback:
                self.stage = "fallback"
                self.attempt = 1
                return
            self.target_index += 1
            self.attempt = 1
        if self.target_index >= len(self.task.attempts):
            self.exhausted = True
            return
        self._reset_stage_for_target()


async def _ping_new_targets(
    config: AppConfig,
    states: list[_BasicState],
    results: dict[int, DeviceResult],
    pause_event: Any,
    pinger: AsyncIcmpPinger,
) -> bool:
    """Ping each newly selected address before its first SNMP attempt.

    Primary retries and fallback credentials reuse the same address and therefore
    do not trigger additional wake-up probes. When a state advances to a second
    or later address, that address receives its own configured probes before SNMP.
    """
    pending = [
        state
        for state in states
        if state.pinged_address != state.task.attempts[state.target_index].address
    ]
    if not pending:
        return False

    # Respect the ICMP feature switch. Mark the address as handled so primary
    # retries/fallbacks do not repeatedly revisit disabled ICMP logic.
    if not config.icmp.enabled or config.icmp.backend == "disabled":
        for state in pending:
            state.pinged_address = state.task.attempts[state.target_index].address
        return False

    for sequence in range(1, config.icmp.probes + 1):
        if pause_event.is_set():
            return False
        probes = await asyncio.gather(
            *(
                pinger.probe(state.task.attempts[state.target_index].address, sequence)
                for state in pending
            )
        )
        for state, probe in zip(pending, probes, strict=True):
            result = results[state.task.host_id]
            result.ping_probes.append(probe)
            if probe.status == "reply":
                result.last_seen = probe.timestamp
                result.last_seen_source = "icmp"
        if sequence < config.icmp.probes:
            await asyncio.sleep(config.icmp.inter_probe_delay_seconds)

    for state in pending:
        state.pinged_address = state.task.attempts[state.target_index].address
    return True


async def _basic_wavefront(
    config: AppConfig,
    tasks: list[DeviceTask],
    results: dict[int, DeviceResult],
    pause_event: Any,
    *,
    collect_metrics: bool = False,
    trace: SnmpTrace | None = None,
) -> list[tuple[DeviceTask, _SuccessfulBasic]]:
    """Drive concurrent ICMP/SYSTEM-MIB attempts until tasks succeed or exhaust.

    Args:
        config: Runtime transport, retry, ICMP, and credential settings.
        tasks: Device tasks with ordered address/profile attempts.
        results: Mutable per-host results used for errors, probes, and metrics.
        pause_event: Process-safe event checked between network operations.
        collect_metrics: Measure SYSTEM-MIB object counts/timing when ``True``.
        trace: Optional resolver/ICMP/SNMP operator trace used only by
            single-device inspection.

    Returns:
        Successful ``(task, basic_identity)`` pairs ready for detail collection.
    """

    states = [
        _BasicState(task=task, errors=results[task.host_id].errors)
        for task in tasks
        if task.attempts
    ]
    semaphore = asyncio.Semaphore(config.snmp.max_outstanding_devices_per_worker)
    pinger = (
        AsyncIcmpPinger(config.icmp) if trace is None else AsyncIcmpPinger(config.icmp, trace=trace)
    )

    async def one_attempt(
        state: _BasicState,
    ) -> tuple[_BasicState, SystemDetails | None, BaseException | None]:
        """Execute one SYSTEM-MIB attempt for a wavefront state.

        Args:
            state: Mutable retry/address state identifying the current attempt.

        Returns:
            ``(state, system, exception)``; exactly one of ``system`` or
            ``exception`` is normally populated unless a pause interrupted work.
        """

        if pause_event.is_set():
            return state, None, None
        resolved = state.current(config)
        address = resolved.address
        credential = resolved.credential
        async with semaphore:
            if pause_event.is_set():
                return state, None, None
            adaptive_state = state.adaptive_state_for(config, resolved)
            try:
                async with create_snmp_client(
                    config,
                    address,
                    credential,
                    adaptive_state=adaptive_state,
                ) as client:
                    traced_client = client
                    if trace is not None:
                        redactions = tuple(
                            value
                            for field_name in ("community", "auth_password", "priv_password")
                            if (value := credential.secret(field_name))
                        )
                        traced_client = trace.wrap(
                            client,
                            TraceContext(
                                address=address,
                                profile=resolved.profile_name or "-",
                                credential=resolved.credential_label or credential.name,
                                snmp_version=credential.version,
                                phase="basic SYSTEM-MIB",
                                stage=resolved.credential_result,
                                attempt=state.attempt,
                                redactions=redactions,
                            ),
                        )
                    with _adaptive_collection_context(
                        client if isinstance(client, AdaptiveSnmpClient) else None,
                        collector="system",
                        table_name="SYSTEM-MIB",
                        collection_phase="basic",
                    ):
                        system = await _measured_collection(
                            "sys",
                            results[state.task.host_id] if collect_metrics else None,
                            traced_client,
                            collect_basic_system,
                        )
                LOG.debug(
                    "SNMP target=%s basic success profile=%s stage=%s attempt=%d",
                    address,
                    resolved.profile_name or resolved.credential_source,
                    resolved.credential_result,
                    state.attempt,
                )
                return state, system, None
            except Exception as exc:
                return state, None, exc

    while True:
        active = [state for state in states if not state.exhausted and state.result is None]
        if not active or pause_event.is_set():
            break
        pinged = await _ping_new_targets(config, active, results, pause_event, pinger)
        if pause_event.is_set():
            break
        if pinged:
            await asyncio.sleep(config.snmp.inter_wave_delay_seconds)
        # One logical credential/query attempt per unresolved device in each wave.
        wave_results = await asyncio.gather(*(one_attempt(state) for state in active))
        for state, system, exc in wave_results:
            if system is not None:
                resolved = state.current(config)
                state.result = _SuccessfulBasic(
                    address=resolved.address,
                    profile_name=resolved.profile_name,
                    credential=resolved.credential,
                    credential_result=resolved.credential_result,
                    credential_source=resolved.credential_source,
                    credential_label=resolved.credential_label,
                    system=system,
                    adaptive_state=(
                        state._last_adaptive_state
                        or create_adaptive_snmp_state(config, resolved.address)
                    ),
                )
                continue
            if exc is None and pause_event.is_set():
                continue
            resolved = state.current(config)
            if exc is not None:
                state.errors.append(
                    _worker_error(
                        operation="snmp_basic",
                        category=_error_category(exc),
                        message=_safe_exception_message(exc, resolved.credential),
                        credential=resolved.credential,
                        exc=exc,
                        attempted_target=resolved.address,
                        phase="request",
                        credential_profile=resolved.profile_name,
                        credential_stage=resolved.credential_result,
                        credential_source=resolved.credential_source,
                        credential_label=resolved.credential_label,
                        attempt=state.attempt,
                        collector="system",
                        recoverable=True,
                    )
                )
                LOG.info(
                    "SNMP target=%s basic failed "
                    "source=%s profile=%s label=%s "
                    "stage=%s attempt=%d type=%s",
                    resolved.address,
                    resolved.credential_source,
                    resolved.profile_name or "-",
                    resolved.credential_label or "-",
                    resolved.credential_result,
                    state.attempt,
                    exc.__class__.__name__,
                )
                completed_route = state._adaptive_route_key(resolved)
                state.advance(config)
                next_route = (
                    None if state.exhausted else state._adaptive_route_key(state.current(config))
                )
                if next_route != completed_route:
                    telemetry = state.take_adaptive_telemetry()
                    if telemetry is not None:
                        results[state.task.host_id].snmp_sessions.append(telemetry)
        if any(not state.exhausted and state.result is None for state in states):
            await asyncio.sleep(config.snmp.inter_wave_delay_seconds)

    return [(state.task, state.result) for state in states if state.result is not None]


def _record_adaptive_telemetry(
    config: AppConfig,
    result: DeviceResult,
    basic: _SuccessfulBasic,
) -> None:
    """Retain one final adaptive-profile snapshot for a successful route."""

    if basic.adaptive_telemetry_recorded:
        return
    state = basic.adaptive_state or create_adaptive_snmp_state(config, basic.address)
    basic.adaptive_state = state
    result.snmp_sessions.append(state.telemetry())
    basic.adaptive_telemetry_recorded = True


@dataclass(frozen=True, slots=True)
class _NeighborProtocolSpec:
    """One enabled neighbor protocol and its operator-facing row vocabulary."""

    operation: Literal["lldp", "lldpv2", "cdp"]
    collector: Callable[..., Awaitable[Any]]
    display_name: str
    unresolved_identifier: str


@dataclass(slots=True)
class _NeighborProtocolOutcome:
    """Mutable final outcome for one first-pass plus optional stability pass."""

    spec: _NeighborProtocolSpec
    values: list[Any]
    exc: BaseException | None
    attempts: int
    subtable_coverage: dict[str, CollectionCoverage] = field(default_factory=dict)


async def _collect_neighbor_outcome(
    config: AppConfig,
    target: str,
    metrics_result: DeviceResult | None,
    client: Any,
    interfaces: dict[int, tuple[str, str]],
    spec: _NeighborProtocolSpec,
    *,
    adaptive_client: AdaptiveSnmpClient | None,
) -> _NeighborProtocolOutcome:
    """Run one enabled neighbor collector and preserve its provisional result."""

    values, exc, attempts = await _collect_neighbor_protocol(
        config,
        target,
        spec.operation,
        metrics_result,
        client,
        spec.collector,
        interfaces,
        adaptive_client=adaptive_client,
    )
    return _NeighborProtocolOutcome(
        spec=spec,
        values=values,
        exc=exc,
        attempts=attempts,
        subtable_coverage=_subtable_coverage_from(values, exc),
    )


def _stability_retry_eligible(exc: BaseException | None) -> bool:
    """Return whether a transient final outcome permits one delayed retry."""

    return exc is not None and _error_category(exc) in {
        "timeout",
        "incomplete_table",
    }


async def _run_delayed_neighbor_stability_pass(
    config: AppConfig,
    target: str,
    metrics_result: DeviceResult | None,
    client: Any,
    interfaces: dict[int, tuple[str, str]],
    outcomes: list[_NeighborProtocolOutcome],
    *,
    adaptive_client: AdaptiveSnmpClient | None,
) -> None:
    """Retry eligible failed protocols once after one target-wide quiet period.

    The first pass always attempts every enabled protocol before this function is
    entered. This sequencing makes delayed repair fair: a failed LLDP collector
    cannot consume CDP's final opportunity, and all affected protocols share one
    delay rather than sleeping independently.
    """

    if not config.snmp.neighbor_stability_retry or adaptive_client is None:
        return
    eligible = [outcome for outcome in outcomes if _stability_retry_eligible(outcome.exc)]
    if not eligible:
        return

    delay_seconds = float(config.snmp.neighbor_stability_retry_delay_seconds)
    operations = ",".join(outcome.spec.operation for outcome in eligible)
    LOG.info(
        "SNMP target=%s delayed neighbor stability window operations=%s delay_seconds=%.3f",
        target,
        operations,
        delay_seconds,
    )
    if delay_seconds > 0:
        await asyncio.sleep(delay_seconds)

    for outcome in eligible:
        spec = outcome.spec
        category = _error_category(outcome.exc) if outcome.exc is not None else "failed"
        next_attempt = outcome.attempts + 1
        with _adaptive_collection_context(
            adaptive_client,
            collector=spec.operation,
            table_name=spec.operation,
            collection_phase="detail",
            root_oid=_NEIGHBOR_PROTOCOL_ROOTS[spec.operation],
        ):
            try:
                prepared = await adaptive_client.prepare_stability_retry(
                    operation=spec.operation.upper(),
                    category=category,
                    attempt=next_attempt,
                    delay_seconds=delay_seconds,
                    root_oid=_NEIGHBOR_PROTOCOL_ROOTS[spec.operation],
                )
            except Exception as retry_exc:
                outcome.values = []
                outcome.exc = retry_exc
                outcome.attempts = next_attempt
                continue
        if not prepared:
            continue

        stability_event = adaptive_client.state.events[-1]
        with adaptive_client.suppress_normal_retries():
            values, exc, attempts = await _collect_neighbor_protocol(
                config,
                target,
                spec.operation,
                metrics_result,
                client,
                spec.collector,
                interfaces,
                adaptive_client=adaptive_client,
                allow_structural_retry=False,
                attempt_offset=outcome.attempts,
                active_retry_event=stability_event,
            )
        outcome.subtable_coverage = _merge_subtable_coverage(
            outcome.subtable_coverage,
            _subtable_coverage_from(values, exc),
        )
        outcome.values = values
        outcome.exc = exc
        outcome.attempts = attempts


def _record_neighbor_outcome(
    outcome: _NeighborProtocolOutcome,
    *,
    target: str,
    credential: CredentialConfig | DirectCredential,
    basic: _SuccessfulBasic,
    audit_result: DeviceResult | None,
    errors: list[WorkerError],
    observations: list[Any],
) -> None:
    """Publish one final protocol outcome to rows, coverage, and worker errors."""

    spec = outcome.spec
    observations.extend(outcome.values)
    unresolved = _unresolved_local_interface_count(outcome.values)
    if unresolved:
        LOG.warning(
            "SNMP target=%s local-interface resolution incomplete operation=%s rows=%d attempt=%d",
            target,
            spec.operation,
            unresolved,
            outcome.attempts,
        )
        errors.append(
            _worker_error(
                operation=f"{spec.operation}_interface_resolution",
                category="incomplete_table",
                message=(
                    f"{unresolved} {spec.display_name} neighbor row(s) retained "
                    f"an unresolved {spec.unresolved_identifier} identifier"
                ),
                attempted_target=target,
                phase="request",
                credential_profile=basic.profile_name,
                credential_stage=basic.credential_result,
                credential_source=basic.credential_source,
                credential_label=basic.credential_label,
                attempt=outcome.attempts,
                collector=spec.operation,
            )
        )
    aggregate_status: str | None = None
    aggregate_message: str | None = None
    if outcome.exc is None and outcome.subtable_coverage:
        incomplete_subtables = [
            (name, coverage)
            for name, coverage in outcome.subtable_coverage.items()
            if coverage.status != "complete"
        ]
        if incomplete_subtables:
            aggregate_status = "partial"
            aggregate_message = "; ".join(
                f"{name}={coverage.status}" + (f": {coverage.message}" if coverage.message else "")
                for name, coverage in incomplete_subtables
            )
    _set_collection_coverage(
        audit_result,
        spec.operation,
        exc=outcome.exc,
        attempts=outcome.attempts,
        row_count=len(outcome.values),
        unresolved_rows=unresolved,
        status=aggregate_status,
        message=aggregate_message,
        subtables=outcome.subtable_coverage,
    )
    if outcome.exc is not None:
        errors.append(
            _worker_error(
                operation=spec.operation,
                category=_error_category(outcome.exc),
                message=_safe_exception_message(outcome.exc, credential),
                credential=credential,
                exc=outcome.exc,
                attempted_target=target,
                phase="request",
                credential_profile=basic.profile_name,
                credential_stage=basic.credential_result,
                credential_source=basic.credential_source,
                credential_label=basic.credential_label,
                attempt=outcome.attempts,
                collector=spec.operation,
            )
        )


async def _collect_detail(
    config: AppConfig,
    task: DeviceTask,
    basic: _SuccessfulBasic,
    errors: list[WorkerError],
    *,
    metrics_result: DeviceResult | None = None,
    audit_result: DeviceResult | None = None,
    trace: SnmpTrace | None = None,
) -> list[Any]:
    """Collect optional ENTITY identity, interfaces, and neighbor protocols.

    Args:
        config: Runtime collector/protocol settings, including ENTITY-MIB mode.
        task: Device task used for host context and policy-derived attempts.
        basic: Successful address/credential and SYSTEM-MIB identity.
        errors: Mutable error list that receives non-fatal detail failures.
        metrics_result: Optional result that receives per-collector telemetry.
        audit_result: Optional result that receives adaptive-session telemetry
            and audit-only local-interface observation groups.
        trace: Optional resolver/ICMP/SNMP operator trace used only by
            single-device inspection.

    Returns:
        Merged neighbor observations collected from enabled protocols.

    ENTITY-MIB is intentionally optional; its failure is logged at debug level
    so interface/neighbor discovery can continue on agents with partial MIBs.
    """

    observations: list[Any] = []
    credential = basic.credential
    adaptive_state = basic.adaptive_state or create_adaptive_snmp_state(config, basic.address)
    adaptive_state.set_route_context(
        credential_route="|".join(
            (
                basic.address,
                basic.credential_source,
                basic.credential_result,
                basic.credential_label or basic.credential.name,
            )
        ),
        credential_profile=basic.profile_name,
    )
    basic.adaptive_state = adaptive_state
    try:
        async with create_snmp_client(
            config,
            basic.address,
            credential,
            adaptive_state=adaptive_state,
        ) as client:
            # Project backends return AdaptiveSnmpClient.  Keeping the local
            # variable optional makes the collector helpers independently
            # testable and preserves a clear failure path for injected tooling.
            adaptive_client = client if isinstance(client, AdaptiveSnmpClient) else None
            traced_client = client
            if trace is not None:
                redactions = tuple(
                    value
                    for field_name in ("community", "auth_password", "priv_password")
                    if (value := credential.secret(field_name))
                )
                traced_client = trace.wrap(
                    client,
                    TraceContext(
                        address=basic.address,
                        profile=basic.profile_name or "-",
                        credential=basic.credential_label or credential.name,
                        snmp_version=credential.version,
                        phase="detail collectors",
                        stage=basic.credential_result,
                        redactions=redactions,
                    ),
                )
            if config.snmp.collect_entity_mib:
                # The basic phase already populated manufacturer/sysDescr. Pass
                # that same mutable identity plus the configured mode so auto
                # can select a query plan without another identification probe.
                try:
                    with _adaptive_collection_context(
                        adaptive_client,
                        collector="entity",
                        table_name="ENTITY-MIB",
                        collection_phase="detail",
                    ):
                        await _measured_collection(
                            "entity",
                            metrics_result,
                            traced_client,
                            enrich_system_from_entity_mib,
                            basic.system,
                            config.snmp.entity_mib_mode,
                        )
                    _set_collection_coverage(
                        audit_result,
                        "entity",
                        row_count=len(basic.system.stack_members),
                    )
                except Exception as exc:
                    _set_collection_coverage(
                        audit_result,
                        "entity",
                        exc=exc,
                        row_count=len(basic.system.stack_members),
                    )
                    if isinstance(exc, SnmpAccessRestrictedError):
                        LOG.error(
                            "SNMP target=%s ENTITY-MIB access restricted message=%s",
                            basic.address,
                            _safe_exception_message(exc, credential),
                        )
                        errors.append(
                            _worker_error(
                                operation="entity",
                                category="snmp_access_restricted",
                                message=_safe_exception_message(exc, credential),
                                credential=credential,
                                exc=exc,
                                attempted_target=basic.address,
                                phase="request",
                                credential_profile=basic.profile_name,
                                credential_stage=basic.credential_result,
                                credential_source=basic.credential_source,
                                credential_label=basic.credential_label,
                                collector="entity",
                            )
                        )
                    else:
                        LOG.debug(
                            "SNMP target=%s optional ENTITY-MIB enrichment failed type=%s",
                            basic.address,
                            exc.__class__.__name__,
                        )
            else:
                _set_collection_coverage(
                    audit_result,
                    "entity",
                    status="not_attempted",
                    attempts=1,
                    row_count=None,
                    message="ENTITY-MIB collection disabled by configuration",
                )
            interfaces, interface_exc, interface_attempt = await _collect_interface_map(
                config,
                basic.address,
                metrics_result,
                traced_client,
                adaptive_client=adaptive_client,
            )
            _set_collection_coverage(
                audit_result,
                "interfaces",
                exc=interface_exc,
                attempts=interface_attempt,
                row_count=len(interfaces),
            )
            if interface_exc is not None:
                errors.append(
                    _worker_error(
                        operation="interfaces",
                        category=_error_category(interface_exc),
                        message=_safe_exception_message(interface_exc, credential),
                        credential=credential,
                        exc=interface_exc,
                        attempted_target=basic.address,
                        phase="request",
                        credential_profile=basic.profile_name,
                        credential_stage=basic.credential_result,
                        credential_source=basic.credential_source,
                        credential_label=basic.credential_label,
                        attempt=interface_attempt,
                        collector="interfaces",
                    )
                )

            protocol_specs: list[_NeighborProtocolSpec] = []
            if config.neighbors.enable_lldp:
                protocol_specs.append(
                    _NeighborProtocolSpec(
                        operation="lldp",
                        collector=collect_lldp,
                        display_name="LLDP",
                        unresolved_identifier="lldpLocalPort/ifIndex",
                    )
                )
            else:
                _set_collection_coverage(
                    audit_result,
                    "lldp",
                    status="not_attempted",
                    message="LLDP collection disabled by configuration",
                )

            if config.neighbors.enable_lldpv2:
                protocol_specs.append(
                    _NeighborProtocolSpec(
                        operation="lldpv2",
                        collector=collect_lldpv2,
                        display_name="LLDPv2",
                        unresolved_identifier="ifIndex",
                    )
                )
            else:
                _set_collection_coverage(
                    audit_result,
                    "lldpv2",
                    status="not_attempted",
                    message="LLDPv2 collection disabled by configuration",
                )

            manufacturer = (basic.system.manufacturer or "").casefold()
            cdp_manufacturers = {value.casefold() for value in config.neighbors.cdp_manufacturers}
            should_cdp = manufacturer in cdp_manufacturers or (
                config.neighbors.cdp_for_cisco and manufacturer == "cisco"
            )
            if should_cdp:
                protocol_specs.append(
                    _NeighborProtocolSpec(
                        operation="cdp",
                        collector=collect_cdp,
                        display_name="CDP",
                        unresolved_identifier="ifIndex",
                    )
                )
            else:
                _set_collection_coverage(
                    audit_result,
                    "cdp",
                    status="not_attempted",
                    message="CDP collection not enabled for this manufacturer",
                )

            protocol_outcomes: list[_NeighborProtocolOutcome] = []
            for spec in protocol_specs:
                protocol_outcomes.append(
                    await _collect_neighbor_outcome(
                        config,
                        basic.address,
                        metrics_result,
                        traced_client,
                        interfaces,
                        spec,
                        adaptive_client=adaptive_client,
                    )
                )

            await _run_delayed_neighbor_stability_pass(
                config,
                basic.address,
                metrics_result,
                traced_client,
                interfaces,
                protocol_outcomes,
                adaptive_client=adaptive_client,
            )
            for outcome in protocol_outcomes:
                _record_neighbor_outcome(
                    outcome,
                    target=basic.address,
                    credential=credential,
                    basic=basic,
                    audit_result=audit_result,
                    errors=errors,
                    observations=observations,
                )
    except Exception as exc:
        LOG.error(
            "SNMP target=%s detail session failed category=%s type=%s",
            basic.address,
            _error_category(exc),
            exc.__class__.__name__,
        )
        errors.append(
            _worker_error(
                operation="snmp_detail_session",
                category=_error_category(exc),
                message=_safe_exception_message(exc, credential),
                credential=credential,
                exc=exc,
                attempted_target=basic.address,
                phase="session_open",
                credential_profile=basic.profile_name,
                credential_stage=basic.credential_result,
                credential_source=basic.credential_source,
                credential_label=basic.credential_label,
                collector="system",
            )
        )
        if audit_result is not None:
            for section in ("entity", "interfaces", "lldp", "lldpv2", "cdp"):
                if section not in audit_result.collection_coverage:
                    _set_collection_coverage(
                        audit_result,
                        section,
                        exc=exc,
                        message=(
                            "detail SNMP session ended before this collector "
                            "produced a complete result"
                        ),
                    )
    # Preserve factual protocol rows before any CDP/LLDP reconciliation.  The
    # graph resolver can replay these rows and supersede an earlier merge without
    # reconstructing evidence from the compatibility edge.
    raw_observations = copy.deepcopy(observations)
    merged = merge_neighbor_observations(copy.deepcopy(observations))
    if audit_result is not None:
        audit_result.raw_neighbors = raw_observations
        audit_result.interface_observation_groups = build_interface_observation_groups(
            task.host_id, merged
        )
        _record_adaptive_telemetry(config, audit_result, basic)
    return merged


async def process_single_device(
    config: AppConfig,
    task: DeviceTask,
    pause_event: Any,
    *,
    system_only: bool = False,
    trace: SnmpTrace | None = None,
) -> tuple[DeviceResult, dict[str, float]]:
    """Probe one device using the same worker collectors without recursion.

    This is the reusable execution primitive behind both forms of the
    ``get-neighbors`` single-device command. The normal path calls the existing
    basic wavefront and detail collector chain so a quick inspection exercises
    the same ICMP/SNMP behavior as a full discovery worker. ``system_only``
    deliberately stops after the initial SYSTEM-MIB probe; ENTITY-MIB, IF-MIB,
    LLDP, LLDPv2, and CDP are not queried.
    That mode gives operators a nearly equivalent small probe across heterogeneous
    devices when comparing baseline SNMP response time.

    The returned timings are observational only and are not persisted into normal
    discovery state. ``trace`` is reserved for get-neighbors and does not affect
    recursive worker execution when omitted.
    """

    result = DeviceResult(host_id=task.host_id, status="deferred")
    results = {task.host_id: result}
    basic_start = time.perf_counter()
    basic_kwargs: dict[str, Any] = {"collect_metrics": True}
    if trace is not None:
        basic_kwargs["trace"] = trace
    successful = await _basic_wavefront(config, [task], results, pause_event, **basic_kwargs)
    basic_phase_ms = round((time.perf_counter() - basic_start) * 1000.0, 3)
    basic = successful[0][1] if successful else None
    if pause_event.is_set() and basic is None:
        result.status = "deferred"
        return result, {"basic_phase": basic_phase_ms, "detail_phase": 0.0}
    if basic is None:
        result.status = "failed"
        result.credential_result = "failed"
        if task.attempts:
            result.query_target = task.attempts[0].address
            result.credential_profile = task.attempts[0].credential_profile
            result.credential_source = task.attempts[0].credential_source
            result.credential_label = task.attempts[0].credential_label
        result.errors.append(
            _worker_error(
                operation="snmp_basic",
                category="no_response",
                message="device did not respond to any permitted credential attempt",
                collector="system",
                recoverable=False,
            )
        )
        _set_collection_coverage(
            result,
            "system",
            status="failed",
            message="no permitted address and credential route returned SYSTEM-MIB",
        )
        return result, {"basic_phase": basic_phase_ms, "detail_phase": 0.0}

    result.status = "success"
    result.query_target = basic.address
    result.credential_profile = basic.profile_name
    result.credential_source = basic.credential_source
    result.credential_label = basic.credential_label
    result.credential_result = basic.credential_result
    result.system = basic.system
    _set_collection_coverage(result, "system", row_count=1)
    result.last_seen = iso_now()
    result.last_seen_source = "snmp"

    detail_start = time.perf_counter()
    if pause_event.is_set():
        result.status = "deferred"
        _record_adaptive_telemetry(config, result, basic)
        detail_phase_ms = 0.0
    elif system_only:
        _record_adaptive_telemetry(config, result, basic)
        # A system-only inspection is intentionally not a "detail collection with
        # neighbor protocols disabled".  Skip the detail SNMP session completely
        # so ENTITY/IF-MIB differences cannot distort baseline device comparisons.
        for section in ("entity", "interfaces", "lldp", "lldpv2", "cdp"):
            _set_collection_coverage(
                result,
                section,
                status="not_attempted",
                message="system-only collection requested",
            )
        detail_phase_ms = 0.0
    else:
        detail_kwargs: dict[str, Any] = {
            "metrics_result": result,
            "audit_result": result,
        }
        if trace is not None:
            detail_kwargs["trace"] = trace
        result.neighbors = await _collect_detail(
            config, task, basic, result.errors, **detail_kwargs
        )
        result.last_seen = iso_now()
        result.last_seen_source = "snmp"
        detail_phase_ms = round((time.perf_counter() - detail_start) * 1000.0, 3)
    return result, {"basic_phase": basic_phase_ms, "detail_phase": detail_phase_ms}


async def process_batch(
    config: AppConfig,
    tasks: list[DeviceTask],
    pause_event: Any,
) -> list[DeviceResult]:
    """Process one worker cohort from basic reachability through detail collection.

    Args:
        config: Complete runtime configuration shared by this worker process.
        tasks: Cohort of independently queryable device tasks.
        pause_event: Process-safe event used to stop new network work cleanly.

    Returns:
        One :class:`DeviceResult` per input task, including failures/deferred work.
    """

    if not tasks:
        return []
    results: dict[int, DeviceResult] = {
        task.host_id: DeviceResult(host_id=task.host_id, status="deferred") for task in tasks
    }

    successful = await _basic_wavefront(
        config,
        tasks,
        results,
        pause_event,
        collect_metrics=config.snmp.report_metrics,
    )
    success_by_host = {task.host_id: basic for task, basic in successful}
    for task in tasks:
        result = results[task.host_id]
        basic = success_by_host.get(task.host_id)
        if pause_event.is_set() and basic is None:
            result.status = "deferred"
            continue
        if basic is None:
            result.status = "failed"
            result.credential_result = "failed"
            if task.attempts:
                result.query_target = task.attempts[0].address
                result.credential_profile = task.attempts[0].credential_profile
                result.credential_source = task.attempts[0].credential_source
                result.credential_label = task.attempts[0].credential_label
            result.errors.append(
                _worker_error(
                    operation="snmp_basic",
                    category="no_response",
                    message="device did not respond to any permitted credential attempt",
                    collector="system",
                    recoverable=False,
                )
            )
            _set_collection_coverage(
                result,
                "system",
                status="failed",
                message="no permitted address and credential route returned SYSTEM-MIB",
            )
            continue
        result.status = "success"
        result.query_target = basic.address
        result.credential_profile = basic.profile_name
        result.credential_source = basic.credential_source
        result.credential_label = basic.credential_label
        result.credential_result = basic.credential_result
        result.system = basic.system
        _set_collection_coverage(result, "system", row_count=1)
        result.last_seen = iso_now()
        result.last_seen_source = "snmp"

    semaphore = asyncio.Semaphore(config.snmp.max_outstanding_devices_per_worker)

    # Device-specific phase: one serial collector chain per device, multiple devices in flight.
    async def detail_one(task: DeviceTask, basic: _SuccessfulBasic) -> None:
        """Run the serial detail chain for one successfully identified device.

        Args:
            task: Original device task.
            basic: Successful SYSTEM-MIB/address/credential result.

        Returns:
            ``None``. The matching entry in ``results`` is updated in place.
        """

        result = results[task.host_id]
        if pause_event.is_set():
            result.status = "deferred"
            _record_adaptive_telemetry(config, result, basic)
            return
        async with semaphore:
            if pause_event.is_set():
                result.status = "deferred"
                _record_adaptive_telemetry(config, result, basic)
                return
            result.neighbors = await _collect_detail(
                config,
                task,
                basic,
                result.errors,
                metrics_result=result if config.snmp.report_metrics else None,
                audit_result=result,
            )
            result.last_seen = iso_now()
            result.last_seen_source = "snmp"

    await asyncio.gather(*(detail_one(task, basic) for task, basic in successful))
    return list(results.values())


def worker_main(
    worker_id: int,
    config: AppConfig,
    work_queue: mp.Queue,  # type: ignore[type-arg]
    result_queue: mp.Queue,  # type: ignore[type-arg]
    log_queue: mp.Queue,  # type: ignore[type-arg]
    pause_event: Any,
) -> None:
    """Run the long-lived multiprocessing worker queue loop.

    Args:
        worker_id: Stable worker identifier included in logs/results.
        config: Runtime configuration inherited by the worker process.
        work_queue: Coordinator queue carrying ``(batch_id, tasks)`` items.
        result_queue: Queue receiving worker batch results or fatal errors.
        log_queue: Multiprocessing log transport configured by the coordinator.
        pause_event: Shared event honored by batch/network routines.

    Returns:
        ``None`` after a ``None`` sentinel asks the worker to exit.
    """

    # Spawned workers start a fresh interpreter and do not inherit the
    # coordinator's process-local wall-clock policy. Configure time first so
    # worker log records and SNMP/ICMP observations use the same timezone.
    configure_timezone(config.time.timezone)
    configure_worker_logging(log_queue, config.logging.level)
    log = logging.getLogger(f"lldp_runner.worker.{worker_id}")
    log.info("worker %d started", worker_id)
    while True:
        item = work_queue.get()
        if item is None:
            break
        batch_id, tasks = item
        try:
            result = asyncio.run(process_batch(config, tasks, pause_event))
            result_queue.put((worker_id, batch_id, result, None))
        except BaseException as exc:
            log.exception("worker %d batch %s failed", worker_id, batch_id)
            result_queue.put((worker_id, batch_id, [], f"{exc.__class__.__name__}: {exc}"))
    log.info("worker %d stopped", worker_id)
