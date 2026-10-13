"""Adaptive SNMP transport profiles and explicit access-restriction handling.

LLDP-Runner keeps one mutable transport profile for the successful target
address and credential route during a device discovery.  The first eligible
timeout or incomplete table activates a slower profile.  Each logical operation
and collector family has a bounded retry allowance.  General collectors consume
one shared target cap, while LLDP-family and CDP collectors also have a protected
reserve that earlier identity/interface work cannot consume.  A final optional
stability pass is accounted separately and can restart each failed neighbor
protocol once after a shared quiet-period delay.  The factual profile and retry
outcome are exported as immutable discovery evidence.

Restarting an operation is important for tables: rows collected before a failed
GETBULK/GETNEXT exchange are discarded so a partial table cannot masquerade as a
complete snapshot.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from types import TracebackType
from typing import TypeVar

from lldp_runner.models import SnmpRetryEvent, SnmpSessionTelemetry
from lldp_runner.snmp.base import SnmpClient

LOG = logging.getLogger(__name__)

_T = TypeVar("_T")
_ACCESS_MARKERS = (
    "noaccess",
    "authorizationerror",
    "authorization error",
    "accessdenied",
    "access denied",
    "not in view",
    "notinview",
    "view restriction",
    "view restricted",
    "vacm",
)
_NEIGHBOR_COLLECTOR_FAMILIES = {
    "lldp": "lldp",
    "lldpv2": "lldp",
    "cdp": "cdp",
}
_NEIGHBOR_COLLECTOR_FAMILY_NAMES = frozenset(
    _NEIGHBOR_COLLECTOR_FAMILIES.values()
)


@dataclass(frozen=True, slots=True)
class SnmpTransportProfile:
    """Concrete backend settings for one open SNMP session."""

    timeout_seconds: float
    max_repetitions: int
    per_device_rps: float
    inter_pdu_delay_ms: float = 0.0


class SnmpAccessRestrictedError(PermissionError):
    """Authenticated SNMP request rejected by an ACL, VACM view, or policy."""

    def __init__(self, operation: str, oids: tuple[str, ...], detail: str) -> None:
        self.operation = operation
        self.oids = oids
        self.detail = detail
        target = ", ".join(oids) if oids else "requested OID"
        super().__init__(
            f"SNMP access restriction during {operation} for {target}: {detail}"
        )


def is_snmp_timeout(exc: BaseException) -> bool:
    """Return whether a backend exception represents a request timeout."""

    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, TimeoutError):
            return True
        name = current.__class__.__name__.casefold()
        message = str(current).casefold()
        if "timeout" in name or "timed out" in message or "noresponse" in name:
            return True
        current = current.__cause__ or current.__context__
    return False


def _compact_access_text(value: object) -> str:
    """Return lowercase alphanumeric text for an SNMP status comparison."""

    return "".join(
        character for character in str(value).casefold() if character.isalnum()
    )


def _exception_access_marker(value: BaseException) -> str | None:
    """Find an authorization marker in a backend exception or class name."""

    for text in (str(value), value.__class__.__name__):
        normalized = _compact_access_text(text)
        for marker in _ACCESS_MARKERS:
            if _compact_access_text(marker) in normalized:
                return text
    return None


def _returned_access_marker(value: object) -> str | None:
    """Recognize an explicit SNMP error value without matching ordinary text.

    Device-provided OCTET STRING values can legitimately contain words such as
    ``noaccess`` in a hostname, banner, or description. Returned values therefore
    require an exact status/class match; exception messages remain substring
    matched because backends commonly add transport context around the status.
    """

    exact_markers = {_compact_access_text(marker) for marker in _ACCESS_MARKERS}
    class_marker = _compact_access_text(value.__class__.__name__)
    if class_marker in exact_markers:
        return value.__class__.__name__
    if isinstance(value, str) and _compact_access_text(value.strip()) in exact_markers:
        return value
    return None


def snmp_access_restriction_detail(value: object) -> str | None:
    """Detect explicit access/view denials in exceptions or returned varbinds."""

    if isinstance(value, BaseException):
        current: BaseException | None = value
        visited: set[int] = set()
        while current is not None and id(current) not in visited:
            visited.add(id(current))
            marker = _exception_access_marker(current)
            if marker is not None:
                return marker
            current = current.__cause__ or current.__context__
        return None

    marker = _returned_access_marker(value)
    if marker is not None:
        return marker
    if isinstance(value, dict):
        for item in value.values():
            marker = snmp_access_restriction_detail(item)
            if marker is not None:
                return marker
    elif isinstance(value, (list, tuple)):
        for item in value:
            if isinstance(item, tuple) and len(item) == 2:
                marker = snmp_access_restriction_detail(item[1])
            else:
                marker = snmp_access_restriction_detail(item)
            if marker is not None:
                return marker
    return None


@dataclass(frozen=True, slots=True)
class _CollectionContext:
    """Safe operator context attached to retry telemetry for one collector."""

    collector: str = "unscoped"
    table_name: str = "unspecified"
    collection_phase: str = "unspecified"
    root_oid: str | None = None


class AdaptiveSnmpState:
    """Adaptive profile and bounded retry accounting for one target route.

    The state is shared by the basic and detail sessions for exactly one target
    address and credential route.  The first eligible timeout or structural
    table failure degrades the transport profile. Later operations reuse that
    same slower profile. Normal retries are bounded by operation, collector, and
    shared/protected pools; final neighbor stability retries have their own
    one-per-protocol accounting.
    """

    def __init__(
        self,
        *,
        target: str,
        timeout_seconds: float,
        max_repetitions: int,
        per_device_rps: float,
        retry_per_operation: int,
        retry_per_collector: int,
        retry_total_cap: int,
        retry_neighbor_reserve: int,
        structural_table_retry: int,
        timeout_multiplier: float,
        max_repetitions_multiplier: float,
        min_max_repetitions: int,
        retry_inter_pdu_delay_ms: float,
        credential_route: str | None = None,
        credential_profile: str | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("SNMP timeout must be positive")
        if max_repetitions < 1:
            raise ValueError("SNMP max_repetitions must be at least 1")
        if per_device_rps <= 0:
            raise ValueError("SNMP per-device RPS must be positive")
        for name, value in (
            ("retry_per_operation", retry_per_operation),
            ("retry_per_collector", retry_per_collector),
            ("retry_total_cap", retry_total_cap),
            ("retry_neighbor_reserve", retry_neighbor_reserve),
            ("structural_table_retry", structural_table_retry),
        ):
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"SNMP {name} cannot be negative")
        if retry_per_operation > retry_total_cap:
            raise ValueError("SNMP retry_per_operation exceeds retry_total_cap")
        if structural_table_retry > retry_total_cap:
            raise ValueError("SNMP structural_table_retry exceeds retry_total_cap")
        if retry_per_collector > retry_total_cap + retry_neighbor_reserve:
            raise ValueError(
                "SNMP retry_per_collector exceeds shared cap plus "
                "neighbor reserve"
            )
        if timeout_multiplier <= 1:
            raise ValueError("SNMP retry timeout multiplier must be greater than 1")
        if not 0 < max_repetitions_multiplier < 1:
            raise ValueError(
                "SNMP retry max-repetitions multiplier must be between 0 and 1"
            )
        if not 1 <= min_max_repetitions <= max_repetitions:
            raise ValueError(
                "SNMP retry minimum max_repetitions is outside the configured range"
            )
        if retry_inter_pdu_delay_ms < 0:
            raise ValueError("SNMP retry inter-PDU delay cannot be negative")

        self.target = target
        self.credential_route = credential_route
        self.credential_profile = credential_profile
        self.initial_timeout_seconds = float(timeout_seconds)
        self.initial_max_repetitions = int(max_repetitions)
        self.initial_per_device_rps = float(per_device_rps)
        self.timeout_seconds = float(timeout_seconds)
        self.max_repetitions = int(max_repetitions)
        self.per_device_rps = float(per_device_rps)
        self.inter_pdu_delay_ms = 0.0
        self.retry_per_operation = int(retry_per_operation)
        self.retry_per_collector = int(retry_per_collector)
        self.retry_total_cap = int(retry_total_cap)
        self.retry_neighbor_reserve = int(retry_neighbor_reserve)
        self.structural_table_retry = int(structural_table_retry)
        self.total_retries_used = 0
        self.shared_retries_used = 0
        self.neighbor_reserve_used = 0
        self.stability_retries_used = 0
        self.operation_retry_counts: dict[str, int] = {}
        self.collector_retry_counts: dict[str, int] = {}
        self.stability_retry_counts: dict[str, int] = {}
        self.timeout_multiplier = float(timeout_multiplier)
        self.max_repetitions_multiplier = float(max_repetitions_multiplier)
        self.min_max_repetitions = int(min_max_repetitions)
        self.retry_inter_pdu_delay_ms = float(retry_inter_pdu_delay_ms)
        self._degraded = False
        self.events: list[SnmpRetryEvent] = []

    def set_route_context(
        self,
        *,
        credential_route: str | None,
        credential_profile: str | None,
    ) -> None:
        """Attach safe credential-route labels before the route is queried.

        The mutable adaptive state is created before the credential wave opens
        an SNMP session.  Route labels are therefore supplied separately from
        transport settings, but must remain stable after the first retry event
        so one telemetry record cannot appear to describe multiple credentials.
        """

        if self.events and (
            credential_route != self.credential_route
            or credential_profile != self.credential_profile
        ):
            raise RuntimeError("cannot relabel an adaptive SNMP route after retry use")
        self.credential_route = credential_route
        self.credential_profile = credential_profile

    @property
    def degraded(self) -> bool:
        """Return whether this route has entered its persistent slow profile."""

        return self._degraded

    def profile(self) -> SnmpTransportProfile:
        """Return the concrete values used to construct the next backend session."""

        return SnmpTransportProfile(
            timeout_seconds=self.timeout_seconds,
            max_repetitions=self.max_repetitions,
            per_device_rps=self.per_device_rps,
            inter_pdu_delay_ms=self.inter_pdu_delay_ms,
        )

    def _retry_limit(self, retry_kind: str) -> int:
        """Return the operation-local allowance for one normal retry kind."""

        if retry_kind == "structural":
            return self.structural_table_retry
        return self.retry_per_operation

    @staticmethod
    def collector_family(collector: str) -> str:
        """Return the fair-share family used for collector retry accounting.

        Original LLDP and LLDPv2 are alternate MIB generations for the same
        protocol family, so they share one normal adaptive allowance. CDP has
        its own protected family. Other collectors retain their normalized name.
        """

        normalized = str(collector or "unscoped").strip().casefold() or "unscoped"
        return _NEIGHBOR_COLLECTOR_FAMILIES.get(normalized, normalized)

    @staticmethod
    def _is_neighbor_family(collector_family: str) -> bool:
        return collector_family in _NEIGHBOR_COLLECTOR_FAMILY_NAMES

    def _normal_retry_pool(self, collector_family: str) -> str | None:
        """Choose the protected neighbor reserve before the shared retry pool."""

        if (
            self._is_neighbor_family(collector_family)
            and self.neighbor_reserve_used < self.retry_neighbor_reserve
        ):
            return "neighbor_reserve"
        if self.shared_retries_used < self.retry_total_cap:
            return "shared"
        return None

    def _normal_retry_unavailable_reason(
        self, operation_key: str, *, retry_kind: str, collector_family: str
    ) -> str | None:
        """Explain which normal retry boundary rejected an operation."""

        if (
            self.operation_retry_counts.get(operation_key, 0)
            >= self._retry_limit(retry_kind)
        ):
            return "operation_retry_limit"
        if (
            collector_family != "unscoped"
            and self.collector_retry_counts.get(collector_family, 0)
            >= self.retry_per_collector
        ):
            return "collector_retry_limit"
        if self._normal_retry_pool(collector_family) is None:
            if self._is_neighbor_family(collector_family):
                return "neighbor_reserve_and_shared_cap"
            return "shared_retry_cap"
        return None

    def retry_available(
        self,
        operation_key: str,
        *,
        retry_kind: str,
        collector: str = "unscoped",
    ) -> bool:
        """Return whether operation, collector, and pool limits allow repair."""

        collector_family = self.collector_family(collector)
        return (
            self._normal_retry_unavailable_reason(
                operation_key,
                retry_kind=retry_kind,
                collector_family=collector_family,
            )
            is None
        )

    def _apply_degraded_profile_once(self) -> None:
        """Enter the route's persistent slow profile without compounding it."""

        if self._degraded:
            return
        old_rps = self.per_device_rps
        self.timeout_seconds *= self.timeout_multiplier
        self.max_repetitions = max(
            self.min_max_repetitions,
            int(
                math.ceil(
                    self.max_repetitions * self.max_repetitions_multiplier
                )
            ),
        )
        self.inter_pdu_delay_ms += self.retry_inter_pdu_delay_ms
        current_interval_ms = 1000.0 / old_rps
        self.per_device_rps = 1000.0 / (
            current_interval_ms + self.retry_inter_pdu_delay_ms
        )
        self._degraded = True

    def consume_retry(
        self,
        *,
        operation_key: str,
        retry_kind: str,
        collector: str,
        logical_operation: str,
        table_name: str,
        root_oid: str | None,
        collection_phase: str,
        category: str,
        partial_rows_discarded: bool,
    ) -> SnmpRetryEvent | None:
        """Consume one fair-share normal retry and retain the degraded profile."""

        collector_family = self.collector_family(collector)
        if (
            self._normal_retry_unavailable_reason(
                operation_key,
                retry_kind=retry_kind,
                collector_family=collector_family,
            )
            is not None
        ):
            return None
        retry_pool = self._normal_retry_pool(collector_family)
        if retry_pool is None:
            return None

        old_timeout = self.timeout_seconds
        old_max_repetitions = self.max_repetitions
        old_delay = self.inter_pdu_delay_ms
        old_rps = self.per_device_rps

        self._apply_degraded_profile_once()
        per_operation_count = self.operation_retry_counts.get(operation_key, 0) + 1
        self.operation_retry_counts[operation_key] = per_operation_count
        per_collector_count = (
            self.collector_retry_counts.get(collector_family, 0) + 1
        )
        self.collector_retry_counts[collector_family] = per_collector_count
        if retry_pool == "neighbor_reserve":
            self.neighbor_reserve_used += 1
        else:
            self.shared_retries_used += 1
        self.total_retries_used += 1

        event = SnmpRetryEvent(
            sequence=len(self.events) + 1,
            target=self.target,
            collector=collector,
            logical_operation=logical_operation,
            table_name=table_name,
            root_oid=root_oid,
            credential_route=self.credential_route,
            credential_profile=self.credential_profile,
            collection_phase=collection_phase,
            category=category,
            retry_kind=retry_kind,
            retry_allowed=True,
            attempt=per_operation_count + 1,
            per_operation_retry_count=per_operation_count,
            total_target_retry_count=self.total_retries_used,
            timeout_before_seconds=round(old_timeout, 6),
            timeout_after_seconds=round(self.timeout_seconds, 6),
            max_repetitions_before=old_max_repetitions,
            max_repetitions_after=self.max_repetitions,
            inter_pdu_delay_before_ms=round(old_delay, 3),
            inter_pdu_delay_after_ms=round(self.inter_pdu_delay_ms, 3),
            per_device_rps_before=round(old_rps, 6),
            per_device_rps_after=round(self.per_device_rps, 6),
            partial_rows_discarded=partial_rows_discarded,
            retry_pool=retry_pool,
            collector_family=collector_family,
            per_collector_retry_count=per_collector_count,
        )
        self.events.append(event)
        return event

    def record_retry_exhaustion(
        self,
        *,
        operation_key: str,
        retry_kind: str,
        collector: str,
        logical_operation: str,
        table_name: str,
        root_oid: str | None,
        collection_phase: str,
        category: str,
        partial_rows_discarded: bool,
    ) -> SnmpRetryEvent:
        """Record why an eligible normal retry could not be issued.

        Exhaustion is diagnostic evidence, not a retry. Counters and the active
        transport profile remain unchanged. The outcome identifies operation,
        collector-family, or pool exhaustion so operators can see whether a
        later topology collector retained its protected allowance.
        """

        collector_family = self.collector_family(collector)
        per_operation_count = self.operation_retry_counts.get(operation_key, 0)
        per_collector_count = self.collector_retry_counts.get(
            collector_family, 0
        )
        reason = self._normal_retry_unavailable_reason(
            operation_key,
            retry_kind=retry_kind,
            collector_family=collector_family,
        ) or "retry_unavailable"
        event = SnmpRetryEvent(
            sequence=len(self.events) + 1,
            target=self.target,
            collector=collector,
            logical_operation=logical_operation,
            table_name=table_name,
            root_oid=root_oid,
            credential_route=self.credential_route,
            credential_profile=self.credential_profile,
            collection_phase=collection_phase,
            category=category,
            retry_kind=retry_kind,
            retry_allowed=False,
            attempt=per_operation_count + 2,
            per_operation_retry_count=per_operation_count,
            total_target_retry_count=self.total_retries_used,
            timeout_before_seconds=round(self.timeout_seconds, 6),
            timeout_after_seconds=round(self.timeout_seconds, 6),
            max_repetitions_before=self.max_repetitions,
            max_repetitions_after=self.max_repetitions,
            inter_pdu_delay_before_ms=round(self.inter_pdu_delay_ms, 3),
            inter_pdu_delay_after_ms=round(self.inter_pdu_delay_ms, 3),
            per_device_rps_before=round(self.per_device_rps, 6),
            per_device_rps_after=round(self.per_device_rps, 6),
            partial_rows_discarded=partial_rows_discarded,
            retry_pool="none",
            collector_family=collector_family,
            per_collector_retry_count=per_collector_count,
            final_outcome="unavailable",
            outcome_type=reason,
        )
        self.events.append(event)
        return event

    def consume_stability_retry(
        self,
        *,
        collector: str,
        logical_operation: str,
        table_name: str,
        root_oid: str | None,
        collection_phase: str,
        category: str,
        attempt: int,
        delay_seconds: float,
    ) -> SnmpRetryEvent | None:
        """Consume the one delayed full-protocol retry allowed per collector.

        Stability retries are intentionally outside the normal shared/reserved
        pools. They occur only after all first-pass neighbor collectors finish,
        so an early LLDP failure cannot starve CDP and vice versa.
        """

        collector_key = str(collector).strip().casefold()
        collector_family = self.collector_family(collector_key)
        if not self._is_neighbor_family(collector_family):
            return None
        if self.stability_retry_counts.get(collector_key, 0) >= 1:
            return None

        old_timeout = self.timeout_seconds
        old_max_repetitions = self.max_repetitions
        old_delay = self.inter_pdu_delay_ms
        old_rps = self.per_device_rps
        self._apply_degraded_profile_once()

        self.stability_retry_counts[collector_key] = 1
        self.stability_retries_used += 1
        self.total_retries_used += 1
        per_collector_count = (
            self.collector_retry_counts.get(collector_family, 0) + 1
        )
        event = SnmpRetryEvent(
            sequence=len(self.events) + 1,
            target=self.target,
            collector=collector_key,
            logical_operation=logical_operation,
            table_name=table_name,
            root_oid=root_oid,
            credential_route=self.credential_route,
            credential_profile=self.credential_profile,
            collection_phase=collection_phase,
            category=category,
            retry_kind="stability",
            retry_allowed=True,
            attempt=max(2, int(attempt)),
            per_operation_retry_count=1,
            total_target_retry_count=self.total_retries_used,
            timeout_before_seconds=round(old_timeout, 6),
            timeout_after_seconds=round(self.timeout_seconds, 6),
            max_repetitions_before=old_max_repetitions,
            max_repetitions_after=self.max_repetitions,
            inter_pdu_delay_before_ms=round(old_delay, 3),
            inter_pdu_delay_after_ms=round(self.inter_pdu_delay_ms, 3),
            per_device_rps_before=round(old_rps, 6),
            per_device_rps_after=round(self.per_device_rps, 6),
            partial_rows_discarded=True,
            retry_pool="stability",
            collector_family=collector_family,
            per_collector_retry_count=per_collector_count,
            delay_before_retry_seconds=round(max(0.0, delay_seconds), 6),
        )
        self.events.append(event)
        return event

    def telemetry(self) -> SnmpSessionTelemetry:
        """Return a serializable snapshot for state and discovery output."""

        return SnmpSessionTelemetry(
            target=self.target,
            credential_route=self.credential_route,
            credential_profile=self.credential_profile,
            initial_timeout_seconds=round(self.initial_timeout_seconds, 6),
            effective_timeout_seconds=round(self.timeout_seconds, 6),
            initial_max_repetitions=self.initial_max_repetitions,
            effective_max_repetitions=self.max_repetitions,
            initial_per_device_rps=round(self.initial_per_device_rps, 6),
            effective_per_device_rps=round(self.per_device_rps, 6),
            effective_inter_pdu_delay_ms=round(self.inter_pdu_delay_ms, 3),
            retry_per_operation=self.retry_per_operation,
            structural_table_retry=self.structural_table_retry,
            retry_total_cap=self.retry_total_cap,
            total_retries_used=self.total_retries_used,
            degraded=self.degraded,
            operation_retry_counts=dict(sorted(self.operation_retry_counts.items())),
            events=list(self.events),
            retry_per_collector=self.retry_per_collector,
            retry_neighbor_reserve=self.retry_neighbor_reserve,
            shared_retries_used=self.shared_retries_used,
            neighbor_reserve_used=self.neighbor_reserve_used,
            stability_retries_used=self.stability_retries_used,
            collector_retry_counts=dict(sorted(self.collector_retry_counts.items())),
            stability_retry_counts=dict(
                sorted(self.stability_retry_counts.items())
            ),
        )


class AdaptiveSnmpClient:
    """Context-managed SNMP client with operation and target retry boundaries."""

    def __init__(
        self,
        factory: Callable[[SnmpTransportProfile], SnmpClient],
        *,
        state: AdaptiveSnmpState,
    ) -> None:
        self._factory = factory
        self.state = state
        self.address = state.target
        self._manager: SnmpClient | None = None
        self._client: SnmpClient | None = None
        self._context = _CollectionContext()
        self._operation_sequence = 0
        self._normal_retry_suppression_depth = 0

    @property
    def timeout_seconds(self) -> float:
        return self.state.timeout_seconds

    @property
    def max_repetitions(self) -> int:
        return self.state.max_repetitions

    @contextmanager
    def collection_context(
        self,
        *,
        collector: str,
        table_name: str,
        collection_phase: str,
        root_oid: str | None = None,
    ) -> Iterator[None]:
        """Attach safe collector/table context to retries inside one operation.

        A client is used serially for one device, so a simple scoped context is
        sufficient and avoids changing every collector's backend-neutral API.
        """

        previous = self._context
        self._context = _CollectionContext(
            collector=collector,
            table_name=table_name,
            collection_phase=collection_phase,
            root_oid=root_oid,
        )
        try:
            yield
        finally:
            self._context = previous

    @contextmanager
    def suppress_normal_retries(self) -> Iterator[None]:
        """Prevent nested transport/structural retries during a stability pass.

        A delayed stability retry is already the final bounded full-protocol
        attempt. Suppressing the ordinary adaptive layer keeps that pass from
        silently multiplying into another immediate retry sequence.
        """

        self._normal_retry_suppression_depth += 1
        try:
            yield
        finally:
            self._normal_retry_suppression_depth -= 1

    @property
    def normal_retries_suppressed(self) -> bool:
        """Return whether the current full-protocol pass forbids nested repair."""

        return self._normal_retry_suppression_depth > 0

    def _new_operation_key(
        self, logical_operation: str, root_oid: str | None, retry_kind: str
    ) -> str:
        """Return a unique invocation key with a stable operator-readable prefix."""

        self._operation_sequence += 1
        return (
            f"{self._context.collector}:{self._context.table_name}:"
            f"{logical_operation}:{root_oid or '-'}:{retry_kind}:"
            f"{self._operation_sequence}"
        )

    async def __aenter__(self) -> "AdaptiveSnmpClient":
        operation_key = self._new_operation_key("SESSION-OPEN", None, "transport")
        try:
            await self._open()
        except Exception as exc:
            detail = snmp_access_restriction_detail(exc)
            if detail is not None:
                self._log_access_restriction("SESSION-OPEN", (), detail)
                raise SnmpAccessRestrictedError("SESSION-OPEN", (), detail) from exc
            if not is_snmp_timeout(exc):
                raise
            if not await self._prepare_retry(
                operation_key=operation_key,
                retry_kind="transport",
                logical_operation="SESSION-OPEN",
                root_oid=None,
                category="timeout",
                exc=exc,
                partial_rows_discarded=False,
                reopen=False,
            ):
                raise
            event = self.state.events[-1]
            try:
                await self._open()
            except Exception as retry_exc:
                event.final_outcome = "failed"
                event.outcome_type = retry_exc.__class__.__name__
                detail = snmp_access_restriction_detail(retry_exc)
                if detail is not None:
                    self._log_access_restriction("SESSION-OPEN", (), detail)
                    raise SnmpAccessRestrictedError(
                        "SESSION-OPEN", (), detail
                    ) from retry_exc
                raise
            else:
                event.final_outcome = "succeeded"
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self._close(exc_type, exc, tb)

    async def _open(self) -> None:
        manager = self._factory(self.state.profile())
        try:
            client = await manager.__aenter__()
        except Exception:
            self._manager = None
            self._client = None
            raise
        self._manager = manager
        self._client = client

    async def _close(
        self,
        exc_type: type[BaseException] | None = None,
        exc: BaseException | None = None,
        tb: TracebackType | None = None,
    ) -> None:
        manager = self._manager
        self._manager = None
        self._client = None
        if manager is not None:
            await manager.__aexit__(exc_type, exc, tb)

    def _require_client(self) -> SnmpClient:
        if self._client is None:
            raise RuntimeError("SNMP client is not open")
        return self._client

    async def _pace_logical_operation(self) -> None:
        if self.state.degraded and self.state.inter_pdu_delay_ms > 0:
            await asyncio.sleep(self.state.inter_pdu_delay_ms / 1000.0)

    async def _reopen_after_retry(
        self,
        event: SnmpRetryEvent,
        *,
        logical_operation: str,
        exc: BaseException | None,
    ) -> None:
        """Close and reopen the backend with the state's effective profile."""

        try:
            await self._close(
                type(exc) if exc is not None else None,
                exc,
                exc.__traceback__ if exc is not None else None,
            )
        except Exception as close_exc:
            LOG.debug(
                "SNMP target=%s adaptive session close failed type=%s",
                self.address,
                close_exc.__class__.__name__,
            )
        try:
            await self._open()
        except Exception as reopen_exc:
            event.final_outcome = "failed"
            event.outcome_type = reopen_exc.__class__.__name__
            detail = snmp_access_restriction_detail(reopen_exc)
            if detail is not None:
                self._log_access_restriction(logical_operation, (), detail)
                raise SnmpAccessRestrictedError(
                    logical_operation, (), detail
                ) from reopen_exc
            raise

    async def _prepare_retry(
        self,
        *,
        operation_key: str,
        retry_kind: str,
        logical_operation: str,
        root_oid: str | None,
        category: str,
        exc: BaseException | None,
        partial_rows_discarded: bool,
        reopen: bool = True,
    ) -> bool:
        context = self._context
        event = self.state.consume_retry(
            operation_key=operation_key,
            retry_kind=retry_kind,
            collector=context.collector,
            logical_operation=logical_operation,
            table_name=context.table_name,
            root_oid=root_oid or context.root_oid,
            collection_phase=context.collection_phase,
            category=category,
            partial_rows_discarded=partial_rows_discarded,
        )
        if event is None:
            event = self.state.record_retry_exhaustion(
                operation_key=operation_key,
                retry_kind=retry_kind,
                collector=context.collector,
                logical_operation=logical_operation,
                table_name=context.table_name,
                root_oid=root_oid or context.root_oid,
                collection_phase=context.collection_phase,
                category=category,
                partial_rows_discarded=partial_rows_discarded,
            )
            LOG.warning(
                "SNMP target=%s adaptive retry unavailable collector=%s "
                "operation=%s table=%s root_oid=%s credential_route=%s "
                "credential_profile=%s phase=%s category=%s retry_kind=%s "
                "retry_pool=%s collector_family=%s attempt=%d "
                "per_operation_retry_count=%d per_collector_retry_count=%d "
                "total_target_retry_count=%d shared_retries=%d/%d "
                "neighbor_reserve=%d/%d "
                "timeout=%.3f->%.3f max_repetitions=%d->%d "
                "inter_pdu_delay_ms=%.3f->%.3f per_device_rps=%.3f->%.3f "
                "partial_rows_discarded=%s final_outcome=%s outcome_type=%s",
                self.address,
                context.collector,
                logical_operation,
                context.table_name,
                root_oid or context.root_oid or "-",
                event.credential_route or "-",
                event.credential_profile or "-",
                event.collection_phase,
                category,
                retry_kind,
                event.retry_pool,
                event.collector_family or "-",
                event.attempt,
                event.per_operation_retry_count,
                event.per_collector_retry_count,
                event.total_target_retry_count,
                self.state.shared_retries_used,
                self.state.retry_total_cap,
                self.state.neighbor_reserve_used,
                self.state.retry_neighbor_reserve,
                event.timeout_before_seconds,
                event.timeout_after_seconds,
                event.max_repetitions_before,
                event.max_repetitions_after,
                event.inter_pdu_delay_before_ms,
                event.inter_pdu_delay_after_ms,
                event.per_device_rps_before,
                event.per_device_rps_after,
                str(event.partial_rows_discarded).lower(),
                event.final_outcome,
                event.outcome_type,
            )
            return False
        LOG.info(
            "SNMP target=%s adaptive retry collector=%s operation=%s table=%s "
            "root_oid=%s credential_route=%s credential_profile=%s phase=%s "
            "category=%s retry_pool=%s collector_family=%s attempt=%d "
            "per_operation_retry_count=%d per_collector_retry_count=%d "
            "total_target_retry_count=%d shared_retries=%d/%d "
            "neighbor_reserve=%d/%d timeout=%.3f->%.3f "
            "max_repetitions=%d->%d inter_pdu_delay_ms=%.3f->%.3f "
            "per_device_rps=%.3f->%.3f partial_rows_discarded=%s",
            self.address,
            event.collector,
            event.logical_operation,
            event.table_name,
            event.root_oid or "-",
            event.credential_route or "-",
            event.credential_profile or "-",
            event.collection_phase,
            event.category,
            event.retry_pool,
            event.collector_family or "-",
            event.attempt,
            event.per_operation_retry_count,
            event.per_collector_retry_count,
            event.total_target_retry_count,
            self.state.shared_retries_used,
            self.state.retry_total_cap,
            self.state.neighbor_reserve_used,
            self.state.retry_neighbor_reserve,
            event.timeout_before_seconds,
            event.timeout_after_seconds,
            event.max_repetitions_before,
            event.max_repetitions_after,
            event.inter_pdu_delay_before_ms,
            event.inter_pdu_delay_after_ms,
            event.per_device_rps_before,
            event.per_device_rps_after,
            str(event.partial_rows_discarded).lower(),
        )
        if not reopen:
            return True
        await self._reopen_after_retry(
            event,
            logical_operation=logical_operation,
            exc=exc,
        )
        return True

    async def prepare_collection_retry(
        self,
        *,
        operation: str,
        category: str,
        root_oid: str | None = None,
    ) -> bool:
        """Adapt and reopen before one complete structural table restart."""

        operation_key = self._new_operation_key(
            operation, root_oid or self._context.root_oid, "structural"
        )
        try:
            return await self._prepare_retry(
                operation_key=operation_key,
                retry_kind="structural",
                logical_operation=operation,
                root_oid=root_oid,
                category=category,
                exc=None,
                partial_rows_discarded=True,
            )
        except Exception as exc:
            if self.state.events:
                event = self.state.events[-1]
                if event.final_outcome == "pending":
                    event.final_outcome = "failed"
                    event.outcome_type = exc.__class__.__name__
            raise

    async def prepare_stability_retry(
        self,
        *,
        operation: str,
        category: str,
        attempt: int,
        delay_seconds: float,
        root_oid: str | None = None,
    ) -> bool:
        """Reopen once for a delayed full LLDP-family or CDP stability pass."""

        context = self._context
        event = self.state.consume_stability_retry(
            collector=context.collector,
            logical_operation=operation,
            table_name=context.table_name,
            root_oid=root_oid or context.root_oid,
            collection_phase=context.collection_phase,
            category=category,
            attempt=attempt,
            delay_seconds=delay_seconds,
        )
        if event is None:
            LOG.warning(
                "SNMP target=%s stability retry unavailable collector=%s "
                "operation=%s category=%s",
                self.address,
                context.collector,
                operation,
                category,
            )
            return False
        LOG.info(
            "SNMP target=%s delayed neighbor stability retry collector=%s "
            "operation=%s table=%s root_oid=%s category=%s attempt=%d "
            "delay_seconds=%.3f total_target_retry_count=%d",
            self.address,
            event.collector,
            event.logical_operation,
            event.table_name,
            event.root_oid or "-",
            event.category,
            event.attempt,
            event.delay_before_retry_seconds,
            event.total_target_retry_count,
        )
        try:
            await self._reopen_after_retry(
                event,
                logical_operation=operation,
                exc=None,
            )
        except Exception:
            if event.final_outcome == "pending":
                event.final_outcome = "failed"
            raise
        return True

    def _log_access_restriction(
        self, operation: str, oids: tuple[str, ...], detail: str
    ) -> None:
        LOG.error(
            "SNMP target=%s access restriction operation=%s oids=%s detail=%s",
            self.address,
            operation,
            ",".join(oids) if oids else "-",
            detail,
        )

    def _raise_access_restriction(
        self, operation: str, oids: tuple[str, ...], value: object
    ) -> None:
        detail = snmp_access_restriction_detail(value)
        if detail is None:
            return
        self._log_access_restriction(operation, oids, detail)
        raise SnmpAccessRestrictedError(operation, oids, detail)

    async def _run(
        self,
        operation: str,
        oids: tuple[str, ...],
        call: Callable[[SnmpClient], Awaitable[_T]],
        *,
        partial_rows_discarded: bool,
    ) -> _T:
        root_oid = oids[0] if oids else self._context.root_oid
        operation_key = self._new_operation_key(operation, root_oid, "transport")
        await self._pace_logical_operation()
        client = self._require_client()
        try:
            result = await call(client)
        except Exception as exc:
            detail = snmp_access_restriction_detail(exc)
            if detail is not None:
                self._log_access_restriction(operation, oids, detail)
                raise SnmpAccessRestrictedError(operation, oids, detail) from exc
            if not is_snmp_timeout(exc):
                raise
            if self.normal_retries_suppressed:
                raise
            prepared = await self._prepare_retry(
                operation_key=operation_key,
                retry_kind="transport",
                logical_operation=operation,
                root_oid=root_oid,
                category="timeout",
                exc=exc,
                partial_rows_discarded=partial_rows_discarded,
            )
            if not prepared:
                raise
            event = self.state.events[-1]
            await self._pace_logical_operation()
            client = self._require_client()
            try:
                result = await call(client)
                self._raise_access_restriction(operation, oids, result)
            except Exception as retry_exc:
                event.final_outcome = "failed"
                event.outcome_type = retry_exc.__class__.__name__
                detail = snmp_access_restriction_detail(retry_exc)
                if detail is not None and not isinstance(
                    retry_exc, SnmpAccessRestrictedError
                ):
                    self._log_access_restriction(operation, oids, detail)
                    raise SnmpAccessRestrictedError(
                        operation, oids, detail
                    ) from retry_exc
                raise
            else:
                event.final_outcome = "succeeded"
                return result
        self._raise_access_restriction(operation, oids, result)
        return result

    async def get(self, oid: str) -> object:
        return await self._run(
            "GET",
            (oid,),
            lambda client: client.get(oid),
            partial_rows_discarded=False,
        )

    async def _get_many_chunked(
        self, client: SnmpClient, requested: tuple[str, ...]
    ) -> dict[str, object]:
        if not requested:
            return {}
        if not self.state.degraded or len(requested) == 1:
            return await client.get_many(list(requested))
        chunk_size = max(
            1,
            int(math.ceil(len(requested) * self.state.max_repetitions_multiplier)),
        )
        result: dict[str, object] = {}
        for index in range(0, len(requested), chunk_size):
            if index and self.state.inter_pdu_delay_ms > 0:
                await asyncio.sleep(self.state.inter_pdu_delay_ms / 1000.0)
            chunk = list(requested[index : index + chunk_size])
            result.update(await client.get_many(chunk))
        return result

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        requested = tuple(oids)
        return await self._run(
            "GET-MANY",
            requested,
            lambda client: self._get_many_chunked(client, requested),
            # A later chunk can fail after earlier values were returned.  The
            # local aggregate is abandoned and the full logical operation is
            # restarted, so telemetry must state that partial results vanished.
            partial_rows_discarded=True,
        )

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        return await self._run(
            "WALK",
            (oid,),
            lambda client: client.walk(oid),
            partial_rows_discarded=True,
        )

    def engine_id_hex(self) -> str | None:
        return self._require_client().engine_id_hex()

    def telemetry(self) -> SnmpSessionTelemetry:
        return self.state.telemetry()
