"""Project-owned SNMP client abstraction and backend failure metadata."""

from __future__ import annotations

from types import TracebackType
from typing import Any, Literal, Protocol, Self

type SnmpPhase = Literal[
    "resolve",
    "session_construct",
    "session_open",
    "request",
    "session_close",
]


class SnmpNormalizedError(RuntimeError):
    """Base class for backend-neutral SNMP failure semantics."""


class SnmpTimeoutError(TimeoutError, SnmpNormalizedError):
    """The selected backend did not receive a response before its deadline."""


class SnmpTransportError(OSError, SnmpNormalizedError):
    """The selected backend failed at the UDP/address transport boundary."""


class SnmpAuthenticationError(SnmpNormalizedError):
    """SNMP security authentication or privacy negotiation failed."""


class SnmpAuthorizationError(PermissionError, SnmpNormalizedError):
    """An authenticated request was denied by ACL/VACM/PDU policy."""


class SnmpBackendCapabilityError(SnmpNormalizedError):
    """The selected backend lacks a required local runtime capability."""


class SnmpEngineResponseError(SnmpNormalizedError):
    """The SNMP engine returned a non-PDU protocol/security indication."""


class SnmpPduResponseError(SnmpNormalizedError):
    """The remote agent returned a truthy SNMP PDU error status."""


class SnmpMalformedResponseError(SnmpNormalizedError):
    """A backend response could not satisfy the project varbind contract."""


class SnmpBackendError(RuntimeError):
    """Preserve backend exception structure plus the exact SNMP route phase.

    Backend libraries do not expose a common exception hierarchy. LLDP-Runner
    therefore wraps a failure only at its project-owned transport boundary and
    retains the original exception as ``__cause__``. Worker/state/output code
    can consume the stable attributes below without parsing a human message,
    while timeout/authentication/access classifiers can still inspect the cause
    chain and preserve the backend's original type and OS fields.
    """

    def __init__(
        self,
        *,
        phase: SnmpPhase,
        attempted_target: str,
        address_family: Literal["ipv4", "ipv6"] | None,
        operation: str | None,
        exc: BaseException,
    ) -> None:
        self.phase = phase
        self.attempted_target = attempted_target
        self.address_family = address_family
        self.operation = operation
        self.original_exception = exc
        cls = exc.__class__
        self.exception_type = f"{cls.__module__}.{cls.__qualname__}"
        self.exception_errno = getattr(exc, "errno", None)
        self.exception_strerror = getattr(exc, "strerror", None)
        self.exception_args: tuple[Any, ...] = tuple(getattr(exc, "args", ()))
        super().__init__(f"{cls.__name__}: {exc}")


class SnmpSessionAddressError(SnmpBackendError):
    """A normalized destination was rejected during backend construction."""

    def __init__(
        self,
        *,
        attempted_target: str,
        address_family: Literal["ipv4", "ipv6"] | None,
        exc: BaseException,
        initial_exception: BaseException | None = None,
    ) -> None:
        self.initial_exception = initial_exception
        super().__init__(
            phase="session_construct",
            attempted_target=attempted_target,
            address_family=address_family,
            operation="SESSION-CONSTRUCT",
            exc=exc,
        )


class SnmpClient(Protocol):
    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None: ...

    async def get(self, oid: str) -> object: ...

    async def get_many(self, oids: list[str]) -> dict[str, object]: ...

    async def walk(self, oid: str) -> list[tuple[str, object]]: ...

    def engine_id_hex(self) -> str | None: ...
