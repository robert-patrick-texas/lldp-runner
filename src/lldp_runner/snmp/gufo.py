"""Gufo SNMP backend for the project-owned :class:`SnmpClient` abstraction.

Gufo SNMP 0.12.0 constructs its native destination as ``f"{addr}:{port}"``.
That is valid for IPv4 but ambiguous for an unbracketed IPv6 literal. The
compatibility path below deliberately tries the canonical unbracketed address
first and retries *construction only* with brackets solely for Gufo's exact
``OSError("invalid address")`` signature. Identity, scheduling, state, logs,
errors, JSON, and CSV retain the original unbracketed address.
"""

from __future__ import annotations

import importlib.metadata
import ipaddress
import logging
import os
import platform
from types import TracebackType
from typing import Any, Literal, Self

from gufo.snmp import Aes128Key, DesKey, Md5Key, Sha1Key, SnmpSession, User

from lldp_runner.config import CredentialConfig, SnmpConfig
from lldp_runner.models import DirectCredential
from lldp_runner.snmp.base import SnmpBackendError, SnmpSessionAddressError
from lldp_runner.snmp.resilience import SnmpTransportProfile
from lldp_runner.snmp.selection import validate_snmp_v3_protocols

LOG = logging.getLogger(__name__)


def _gufo_distribution_version() -> str:
    """Return installed Gufo SNMP version without making diagnostics fragile."""

    try:
        return importlib.metadata.version("gufo-snmp")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _canonical_target_and_family(
    address: str,
) -> tuple[str, Literal["ipv4", "ipv6"] | None]:
    """Return unbracketed input plus its literal family when determinable.

    IPv6 scope identifiers are part of the transport address but are not
    accepted by :func:`ipaddress.ip_address` on every supported Python build, so
    family detection removes only the ``%zone`` suffix. The returned target is
    never compressed or otherwise rewritten; upstream normalization remains the
    canonical source of identity text.
    """

    candidate = str(address).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    probe = candidate.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(probe)
    except ValueError:
        return candidate, None
    return candidate, "ipv4" if parsed.version == 4 else "ipv6"


def _is_gufo_ipv6_invalid_address(exc: BaseException) -> bool:
    """Match only Gufo 0.12.0's confirmed raw-IPv6 constructor signature."""

    return isinstance(exc, OSError) and str(exc) == "invalid address"


class GufoSnmpClient:
    """One Gufo session with phase-aware failures and IPv6 containment."""

    def __init__(
        self,
        address: str,
        credential: CredentialConfig | DirectCredential,
        snmp_config: SnmpConfig,
        *,
        transport_profile: SnmpTransportProfile | None = None,
    ) -> None:
        self.address, self.address_family = _canonical_target_and_family(address)
        self.credential = credential
        self.snmp_config = snmp_config
        self.transport_profile = transport_profile or SnmpTransportProfile(
            timeout_seconds=snmp_config.timeout_seconds,
            max_repetitions=snmp_config.max_repetitions,
            per_device_rps=snmp_config.per_device_rps,
        )
        self._session: SnmpSession | None = None
        self._gufo_version = _gufo_distribution_version()

    def _security_kwargs(self) -> dict[str, object]:
        """Build Gufo security arguments without emitting credential values."""

        version = str(self.credential.version).strip().casefold()
        if version == "v2c":
            community = self.credential.secret("community", os.environ)
            if not community:
                raise RuntimeError(f"missing community for credential {self.credential.name}")
            return {"community": community}

        if version != "v3":
            raise RuntimeError(
                f"unsupported SNMP credential version for {self.credential.name!r}: "
                f"{self.credential.version!r}"
            )

        username = self.credential.secret("username", os.environ)
        auth_password = self.credential.secret("auth_password", os.environ)
        priv_password = self.credential.secret("priv_password", os.environ)
        if not username or not auth_password or not priv_password:
            raise RuntimeError(f"missing authPriv secret for credential {self.credential.name}")
        auth_protocol, priv_protocol = validate_snmp_v3_protocols(
            "gufo",
            auth_protocol=self.credential.auth_protocol,
            priv_protocol=self.credential.priv_protocol,
        )
        auth_cls = {"sha1": Sha1Key, "md5": Md5Key}[auth_protocol]
        priv_cls = {"aes128": Aes128Key, "des": DesKey}[priv_protocol]
        return {
            "user": User(
                username,
                auth_key=auth_cls(auth_password.encode()),
                priv_key=priv_cls(priv_password.encode()),
            )
        }

    def _session_kwargs(self, *, transport_address: str) -> dict[str, object]:
        """Return the complete Gufo constructor mapping for one text form."""

        return {
            "addr": transport_address,
            "port": self.snmp_config.port,
            "timeout": self.transport_profile.timeout_seconds,
            "max_repetitions": self.transport_profile.max_repetitions,
            "limit_rps": self.transport_profile.per_device_rps,
            **self._security_kwargs(),
        }

    def _log_phase_failure(
        self,
        *,
        phase: str,
        operation: str,
        exc: BaseException,
    ) -> None:
        """Log safe environment and route structure without exception secrets."""

        LOG.warning(
            "SNMP backend failure target=%s address_family=%s phase=%s "
            "operation=%s exception_type=%s errno=%s gufo_snmp_version=%s "
            "python_version=%s",
            self.address,
            self.address_family or "unknown",
            phase,
            operation,
            f"{exc.__class__.__module__}.{exc.__class__.__qualname__}",
            getattr(exc, "errno", None),
            self._gufo_version,
            platform.python_version(),
        )

    def _construct_session(self) -> SnmpSession:
        """Construct Gufo once raw, then apply the exact IPv6 bracket workaround."""

        try:
            return SnmpSession(**self._session_kwargs(transport_address=self.address))
        except Exception as raw_exc:
            if not (self.address_family == "ipv6" and _is_gufo_ipv6_invalid_address(raw_exc)):
                self._log_phase_failure(
                    phase="session_construct",
                    operation="SESSION-CONSTRUCT",
                    exc=raw_exc,
                )
                wrapped: SnmpBackendError
                if isinstance(raw_exc, OSError):
                    wrapped = SnmpSessionAddressError(
                        attempted_target=self.address,
                        address_family=self.address_family,
                        exc=raw_exc,
                    )
                else:
                    wrapped = SnmpBackendError(
                        phase="session_construct",
                        attempted_target=self.address,
                        address_family=self.address_family,
                        operation="SESSION-CONSTRUCT",
                        exc=raw_exc,
                    )
                raise wrapped from raw_exc

            bracketed = f"[{self.address}]"
            LOG.info(
                "SNMP target=%s address_family=ipv6 phase=session_construct "
                "gufo_ipv6_bracket_compatibility=activated "
                "gufo_snmp_version=%s python_version=%s",
                self.address,
                self._gufo_version,
                platform.python_version(),
            )
            try:
                return SnmpSession(**self._session_kwargs(transport_address=bracketed))
            except Exception as bracket_exc:
                self._log_phase_failure(
                    phase="session_construct",
                    operation="SESSION-CONSTRUCT-BRACKETED",
                    exc=bracket_exc,
                )
                wrapped = SnmpSessionAddressError(
                    attempted_target=self.address,
                    address_family="ipv6",
                    exc=bracket_exc,
                    initial_exception=raw_exc,
                )
                bracket_exc.add_note(
                    "initial unbracketed Gufo construction failed with "
                    f"{raw_exc.__class__.__name__}: {raw_exc}"
                )
                raise wrapped from bracket_exc

    async def __aenter__(self) -> Self:
        """Construct and open one session while preserving phase boundaries."""

        self._session = self._construct_session()
        try:
            await self._session.__aenter__()
        except Exception as exc:
            self._log_phase_failure(phase="session_open", operation="SESSION-OPEN", exc=exc)
            self._session = None
            raise SnmpBackendError(
                phase="session_open",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="SESSION-OPEN",
                exc=exc,
            ) from exc
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close the session and label close failures independently."""

        session = self._session
        self._session = None
        if session is None:
            return
        try:
            await session.__aexit__(exc_type, exc, tb)
        except Exception as close_exc:
            self._log_phase_failure(phase="session_close", operation="SESSION-CLOSE", exc=close_exc)
            raise SnmpBackendError(
                phase="session_close",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="SESSION-CLOSE",
                exc=close_exc,
            ) from close_exc

    def _require_session(self) -> SnmpSession:
        if self._session is None:
            raise RuntimeError("SNMP client is not open")
        return self._session

    async def _request(self, operation: str, call: Any) -> Any:
        """Run one Gufo operation and preserve request-phase OS/SNMP details."""

        try:
            return await call()
        except Exception as exc:
            self._log_phase_failure(phase="request", operation=operation, exc=exc)
            raise SnmpBackendError(
                phase="request",
                attempted_target=self.address,
                address_family=self.address_family,
                operation=operation,
                exc=exc,
            ) from exc

    async def get(self, oid: str) -> object:
        session = self._require_session()
        return await self._request("GET", lambda: session.get(oid))

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        session = self._require_session()
        result = await self._request("GET-MANY", lambda: session.get_many(oids))
        return dict(result)

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        rows: list[tuple[str, object]] = []

        async def fetch_all() -> list[tuple[str, object]]:
            async for row_oid, value in self._require_session().fetch(oid):
                rows.append((str(row_oid), value))
            return rows

        return await self._request("WALK", fetch_all)

    def engine_id_hex(self) -> str | None:
        if self._session is None or self.credential.version != "v3":
            return None
        try:
            return self._session.get_engine_id().hex()
        except Exception:
            return None
