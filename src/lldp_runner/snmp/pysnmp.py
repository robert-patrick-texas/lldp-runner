"""PySNMP 7.1 asyncio backend for LLDP-Runner's neutral SNMP interface.

The adapter intentionally owns one :class:`SnmpEngine` per opened backend
session.  Every transport target is built with ``retries=0`` because retry
budgets belong exclusively to :mod:`lldp_runner.snmp.resilience`.  The engine
observer records the authoritative *remote* SNMPv3 engine ID from the response
security context; the local manager engine ID is never used as device identity.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import ipaddress
import logging
import os
import re
import warnings
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Final, Literal, Self

from lldp_runner.config import CredentialConfig, SnmpConfig
from lldp_runner.models import DirectCredential
from lldp_runner.snmp.base import (
    SnmpAuthenticationError,
    SnmpAuthorizationError,
    SnmpBackendCapabilityError,
    SnmpBackendError,
    SnmpEngineResponseError,
    SnmpMalformedResponseError,
    SnmpPduResponseError,
    SnmpSessionAddressError,
    SnmpTimeoutError,
    SnmpTransportError,
)
from lldp_runner.snmp.resilience import SnmpTransportProfile
from lldp_runner.snmp.selection import validate_snmp_v3_protocols

LOG = logging.getLogger(__name__)
_RESPONSE_EXECUTION_POINT = "rfc3412.prepareDataElements:response"
_CRYPTOGRAPHY_MINIMUM = (50, 0)
_PYSNMP_AES_CFB_DEPRECATION_MESSAGE = (
    "CFB has been moved to cryptography.hazmat.decrepit.ciphers.modes.CFB "
    "and will be removed from cryptography.hazmat.primitives.ciphers.modes "
    "in 49.0.0."
)
_PYSNMP_AES_CFB_WARNING_MODULE = r"^pysnmp\.proto\.secmod\.rfc3826\.priv\.aes$"
_PYSNMP_AES_KEY_LENGTHS: Final[dict[str, int]] = {
    "aes128": 16,
    # PySNMP's USM_PRIV_CFB256_AES uses Reeder key localization, commonly
    # called AES-256-Cisco. The Blumenthal mapping uses the same local AES-256
    # primitive but a different key-localization method inside PySNMP.
    "aes256": 32,
    "aes256-blumenthal": 32,
}


@dataclass(frozen=True, slots=True)
class _PySnmpApi:
    """Validated slice of the live-tested PySNMP 7.1 asyncio v3arch API."""

    snmp_engine: Any
    community_data: Any
    usm_user_data: Any
    udp_target: Any
    udp6_target: Any
    context_data: Any
    object_identity: Any
    object_type: Any
    get_cmd: Any
    bulk_walk_cmd: Any
    auth_sha1: Any
    auth_md5: Any
    auth_sha256: Any
    priv_aes128: Any
    priv_aes256: Any
    priv_aes256_blumenthal: Any
    priv_des: Any


def _load_pysnmp_api() -> _PySnmpApi:
    """Import and validate only the supported PySNMP 7.1 asyncio API surface."""

    module_name = "pysnmp.hlapi.v3arch.asyncio"
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise RuntimeError(
            "cannot import pysnmp.hlapi.v3arch.asyncio; install the exact "
            "LLDP-Runner Linux dependency set"
        ) from exc

    names = {
        "snmp_engine": "SnmpEngine",
        "community_data": "CommunityData",
        "usm_user_data": "UsmUserData",
        "udp_target": "UdpTransportTarget",
        "udp6_target": "Udp6TransportTarget",
        "context_data": "ContextData",
        "object_identity": "ObjectIdentity",
        "object_type": "ObjectType",
        "get_cmd": "get_cmd",
        "bulk_walk_cmd": "bulk_walk_cmd",
        "auth_sha1": "USM_AUTH_HMAC96_SHA",
        "auth_md5": "USM_AUTH_HMAC96_MD5",
        "auth_sha256": "USM_AUTH_HMAC192_SHA256",
        "priv_aes128": "USM_PRIV_CFB128_AES",
        "priv_aes256": "USM_PRIV_CFB256_AES",
        "priv_aes256_blumenthal": "USM_PRIV_CFB256_AES_BLUMENTHAL",
        "priv_des": "USM_PRIV_CBC56_DES",
    }
    missing = [public for public in names.values() if not hasattr(module, public)]
    if missing:
        raise RuntimeError(
            "installed PySNMP module lacks required 7.1 asyncio API objects: " + ", ".join(missing)
        )
    return _PySnmpApi(**{field: getattr(module, public) for field, public in names.items()})


def _canonical_target_and_family(
    address: str,
) -> tuple[str, Literal["ipv4", "ipv6"]]:
    """Return canonical unbracketed transport text and its IP family."""

    candidate = str(address).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    probe = candidate.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(probe)
    except ValueError as exc:
        raise SnmpSessionAddressError(
            attempted_target=candidate,
            address_family=None,
            exc=ValueError("PySNMP backend requires a resolved IPv4 or IPv6 address"),
        ) from exc
    return candidate, "ipv4" if parsed.version == 4 else "ipv6"


def _pretty_text(value: object) -> str:
    """Return stable PyASN1/PySNMP text without requiring concrete value types."""

    pretty = getattr(value, "prettyPrint", None)
    if callable(pretty):
        try:
            return str(pretty())
        except Exception:
            pass
    return str(value)


def _normalize_oid(value: object) -> str:
    """Normalize a numeric OID to the collector-facing dotted string form."""

    text = _pretty_text(value).strip()
    return text[1:] if text.startswith(".") else text


def _normalize_value(value: object) -> object:
    """Convert PyASN1 native values to the same primitives collectors expect.

    Octet-like values become ``bytes`` so binary chassis/port identifiers remain
    lossless. Integer application types become ``int``. OID and IP address types
    become strings. SNMP exception sentinels are intentionally retained because
    the resilience layer recognizes their concrete class/status names.
    """

    if value is None or isinstance(value, (bytes, str, int, float, bool)):
        return value
    class_name = value.__class__.__name__.casefold()
    if class_name in {"nosuchobject", "nosuchinstance", "endofmibview"}:
        return value
    if "objectidentifier" in class_name or class_name == "objectname":
        return _normalize_oid(value)
    if class_name in {"ipaddress", "ipaddressvalue"}:
        return _pretty_text(value)
    numeric_markers = (
        "integer",
        "counter",
        "gauge",
        "unsigned",
        "timeticks",
    )
    if any(marker in class_name for marker in numeric_markers):
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError, OverflowError):
            pass
    as_octets = getattr(value, "asOctets", None)
    if callable(as_octets):
        try:
            return bytes(as_octets())
        except Exception:
            pass
    pretty = getattr(value, "prettyPrint", None)
    if callable(pretty):
        return _pretty_text(value)
    return value


def _varbind_pairs(var_binds: object) -> list[tuple[str, object]]:
    """Validate and normalize one PySNMP varbind sequence."""

    if isinstance(var_binds, (str, bytes)) or not isinstance(var_binds, Sequence):
        raise SnmpMalformedResponseError("SNMP response varbinds are not a sequence")
    result: list[tuple[str, object]] = []
    for index, var_bind in enumerate(var_binds):
        try:
            if len(var_bind) != 2:  # type: ignore[arg-type]
                raise ValueError
            oid, value = var_bind[0], var_bind[1]  # type: ignore[index]
        except Exception as exc:
            raise SnmpMalformedResponseError(
                f"SNMP response varbind {index} is not an OID/value pair"
            ) from exc
        normalized_oid = _normalize_oid(oid)
        if not normalized_oid:
            raise SnmpMalformedResponseError(f"SNMP response varbind {index} has an empty OID")
        result.append((normalized_oid, _normalize_value(value)))
    return result


def _compact(value: object) -> str:
    """Return lowercase alphanumeric text for conservative error classification."""

    return "".join(character for character in _pretty_text(value).casefold() if character.isalnum())


_TIMEOUT_MARKERS = ("timeout", "timedout", "noresponse", "requesttimedout")
_AUTHENTICATION_MARKERS = (
    "authenticationfailure",
    "unknownusername",
    "unknownsecurityname",
    "wrongdigest",
    "decryptionerror",
    "unsupportedsecuritylevel",
    "authenticationerror",
)
_AUTHORIZATION_MARKERS = (
    "authorizationerror",
    "noaccess",
    "accessdenied",
    "notinview",
    "viewrestriction",
    "vacm",
)
_TRANSPORT_MARKERS = (
    "transport",
    "socket",
    "networkunreachable",
    "noroutetohost",
    "connectionrefused",
    "invalidaddress",
    "addressfamily",
    "dns",
)
_CAPABILITY_MARKERS = (
    "cipheringservicesnotavailable",
    "cipheringservicenotavailable",
    "encryptionservicesnotavailable",
    "cryptographyprovidernotavailable",
)


def _numeric_version_prefix(value: str) -> tuple[int, ...]:
    """Parse the leading numeric release components without a runtime helper.

    ``packaging`` is intentionally not a published runtime dependency.  The
    cryptography floor only needs a conservative major/minor comparison, so a
    bounded numeric prefix avoids expanding the application dependency surface.
    """

    match = re.match(r"^(\d+)(?:\.(\d+))?", value.strip())
    if match is None:
        return ()
    return tuple(int(part) for part in match.groups(default="0"))


def _installed_cryptography_version() -> str:
    """Return the installed provider version or a truthful absence marker."""

    try:
        return importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"
    except Exception:
        return "unknown"


def _install_temporary_pysnmp_cfb_warning_filter() -> None:
    """Hide only PySNMP's known cryptography CFB namespace warning.

    PySNMP 7.1.29 implements the required RFC 3826 AES-CFB128 operation but
    still imports ``CFB`` through cryptography's deprecated primitives
    namespace.  The warning is upstream-only and does not indicate an unsafe or
    different on-wire cipher.  Install one process-level filter constrained by
    the exact warning category, complete message, and originating PySNMP module.
    Any changed or unrelated cryptography warning remains visible.

    Remove this compatibility filter once LLDP-Runner's minimum PySNMP release
    imports ``cryptography.hazmat.decrepit.ciphers.modes.CFB`` itself.
    """

    try:
        cryptography_utils = importlib.import_module("cryptography.utils")
        category = cryptography_utils.CryptographyDeprecationWarning
    except (ImportError, AttributeError):
        # PySNMP authPriv preflight reports missing/invalid cryptography.  Do not
        # turn warning-filter setup into a separate failure path.
        return

    # ``filterwarnings`` compiles message expressions case-insensitively.  The
    # scoped inline flag restores case-sensitive, full-message matching.
    message_pattern = rf"(?-i:^{re.escape(_PYSNMP_AES_CFB_DEPRECATION_MESSAGE)}$)"
    warnings.filterwarnings(
        "ignore",
        message=message_pattern,
        category=category,
        module=_PYSNMP_AES_CFB_WARNING_MODULE,
    )


def _probe_cryptography_privacy_protocol(protocol: str) -> None:
    """Construct and execute the local cipher primitive used by one mapping.

    The probe uses fixed non-secret bytes and never touches an operator key.  It
    catches installations where distribution metadata exists but the native
    OpenSSL/provider bindings or an algorithm implementation are unusable.
    """

    ciphers = importlib.import_module("cryptography.hazmat.primitives.ciphers")
    cipher_type = ciphers.Cipher

    aes_key_length = _PYSNMP_AES_KEY_LENGTHS.get(protocol)
    if aes_key_length is not None:
        algorithms = getattr(ciphers, "algorithms")  # noqa: B009 - ty: submodule is not imported explicitly
        decrepit_modes = importlib.import_module("cryptography.hazmat.decrepit.ciphers.modes")
        algorithm = algorithms.AES(bytes(range(aes_key_length)))
        mode = decrepit_modes.CFB(bytes(16))
        plaintext = bytes(16)
    elif protocol == "des":
        modes = getattr(ciphers, "modes")  # noqa: B009 - ty: submodule is not imported explicitly
        try:
            decrepit = importlib.import_module("cryptography.hazmat.decrepit.ciphers.algorithms")
            triple_des = decrepit.TripleDES
        except (ImportError, AttributeError):
            # Keep a narrow compatibility path for cryptography releases that
            # still exported TripleDES from the original algorithms namespace.
            algorithms = getattr(ciphers, "algorithms")  # noqa: B009 - ty: submodule is not imported explicitly
            triple_des = algorithms.TripleDES
        algorithm = triple_des(bytes(range(24)))
        mode = modes.CBC(bytes(8))
        plaintext = bytes(8)
    else:  # Protocol validation should make this unreachable.
        raise ValueError(f"unsupported PySNMP privacy protocol {protocol!r}")

    encryptor = cipher_type(algorithm, mode).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    if len(ciphertext) != len(plaintext):
        raise RuntimeError(f"cryptography returned an unexpected {protocol} ciphertext length")


def preflight_pysnmp_authpriv(protocols: Sequence[str]) -> None:
    """Verify PySNMP and cryptography can perform all required authPriv ciphers.

    This is deliberately a local, deterministic startup check.  It does not
    create a transport, consume a retry, resolve a secret, or contact a device.
    """

    normalized = tuple(sorted({str(value).strip().casefold() for value in protocols}))
    if not normalized:
        return

    # Validate the exact public PySNMP API before constructing any run state.
    try:
        _load_pysnmp_api()
    except Exception as exc:
        raise SnmpBackendCapabilityError(
            "PySNMP authPriv preflight failed: the supported PySNMP 7.1 asyncio "
            "API is unavailable; install the exact LLDP-Runner Linux constraints"
        ) from exc

    version = _installed_cryptography_version()
    parsed = _numeric_version_prefix(version)
    if not parsed or parsed[:2] < _CRYPTOGRAPHY_MINIMUM:
        raise SnmpBackendCapabilityError(
            "PySNMP authPriv preflight failed: cryptography>=50.0 is required "
            f"(installed: {version})"
        )

    for protocol in normalized:
        # Reuse the backend mapping validator so a direct caller cannot probe an
        # algorithm the adapter itself would reject.
        validate_snmp_v3_protocols(
            "pysnmp",
            auth_protocol="sha1",
            priv_protocol=protocol,
        )
        try:
            _probe_cryptography_privacy_protocol(protocol)
        except Exception as exc:
            raise SnmpBackendCapabilityError(
                "PySNMP authPriv preflight failed: local cipher capability "
                f"{protocol!r} is unavailable with cryptography {version}; "
                "install the exact LLDP-Runner Linux constraints"
            ) from exc


def _transport_error(message: str, *, errno: int | None = None) -> SnmpTransportError:
    """Build a readable normalized transport error while preserving errno."""

    if errno is None:
        return SnmpTransportError(message)
    return SnmpTransportError(errno, message)


class PySnmpClient:
    """One deterministic PySNMP engine/dispatcher session for a target route."""

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
        try:
            self._api = _load_pysnmp_api()
        except Exception as exc:
            raise SnmpBackendError(
                phase="session_construct",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="SESSION-CONSTRUCT",
                exc=SnmpEngineResponseError(str(exc)),
            ) from exc
        self._engine: Any | None = None
        self._security_data: Any | None = None
        self._transport_target: Any | None = None
        self._observer_callback: Any | None = None
        self._remote_engine_id: bytes | None = None
        self._redactions = self._credential_redactions()

    def _credential_redactions(self) -> tuple[str, ...]:
        """Return non-empty credential material for exception-message redaction."""

        values: list[str] = []
        for field_name in ("community", "username", "auth_password", "priv_password"):
            value = self.credential.secret(field_name, os.environ)
            if value and value not in values:
                values.append(value)
        return tuple(sorted(values, key=len, reverse=True))

    def _safe_text(self, value: object) -> str:
        """Render backend text after removing every configured credential value."""

        text = _pretty_text(value)
        for secret in self._redactions:
            text = text.replace(secret, "<redacted>")
        return text

    def _normalized_exception(self, exc: BaseException) -> BaseException:
        """Map a raised backend exception to stable transport/error semantics."""

        if isinstance(
            exc,
            (
                SnmpTimeoutError,
                SnmpTransportError,
                SnmpAuthenticationError,
                SnmpAuthorizationError,
                SnmpBackendCapabilityError,
                SnmpEngineResponseError,
                SnmpPduResponseError,
                SnmpMalformedResponseError,
            ),
        ):
            return exc
        safe = self._safe_text(exc) or exc.__class__.__name__
        compact = _compact(safe)
        type_compact = _compact(exc.__class__.__name__)
        combined = compact + type_compact
        if any(marker in combined for marker in _CAPABILITY_MARKERS):
            return SnmpBackendCapabilityError(safe)
        if isinstance(exc, TimeoutError) or any(marker in combined for marker in _TIMEOUT_MARKERS):
            return SnmpTimeoutError(safe)
        if any(marker in combined for marker in _AUTHENTICATION_MARKERS):
            return SnmpAuthenticationError(safe)
        if any(marker in combined for marker in _AUTHORIZATION_MARKERS):
            return SnmpAuthorizationError(safe)
        if isinstance(exc, OSError) or any(marker in combined for marker in _TRANSPORT_MARKERS):
            return _transport_error(safe, errno=getattr(exc, "errno", None))
        return SnmpEngineResponseError(safe)

    def _normalized_indication(self, indication: object) -> BaseException:
        """Map a truthy PySNMP engine indication without retaining unsafe text."""

        if isinstance(indication, BaseException):
            return self._normalized_exception(indication)
        safe = self._safe_text(indication) or indication.__class__.__name__
        compact = _compact(safe) + _compact(indication.__class__.__name__)
        if any(marker in compact for marker in _CAPABILITY_MARKERS):
            return SnmpBackendCapabilityError(safe)
        if any(marker in compact for marker in _TIMEOUT_MARKERS):
            return SnmpTimeoutError(safe)
        if any(marker in compact for marker in _AUTHENTICATION_MARKERS):
            return SnmpAuthenticationError(safe)
        if any(marker in compact for marker in _AUTHORIZATION_MARKERS):
            return SnmpAuthorizationError(safe)
        if any(marker in compact for marker in _TRANSPORT_MARKERS):
            return _transport_error(safe)
        return SnmpEngineResponseError(safe)

    def _security(self) -> object:
        """Build v2c/v3 auth data with the validated diagnostic-script mapping."""

        version = str(self.credential.version).strip().casefold()
        if version == "v2c":
            community = self.credential.secret("community", os.environ)
            if not community:
                raise SnmpAuthenticationError(
                    f"missing community for credential {self.credential.name}"
                )
            return self._api.community_data(community, mpModel=1)

        if version != "v3":
            raise SnmpAuthenticationError(
                f"unsupported SNMP credential version for {self.credential.name!r}: "
                f"{self.credential.version!r}"
            )

        username = self.credential.secret("username", os.environ)
        auth_password = self.credential.secret("auth_password", os.environ)
        priv_password = self.credential.secret("priv_password", os.environ)
        if not username or not auth_password or not priv_password:
            raise SnmpAuthenticationError(
                f"missing authPriv secret for credential {self.credential.name}"
            )
        auth_name, priv_name = validate_snmp_v3_protocols(
            "pysnmp",
            auth_protocol=self.credential.auth_protocol,
            priv_protocol=self.credential.priv_protocol,
        )
        auth_protocol = {
            "sha1": self._api.auth_sha1,
            "md5": self._api.auth_md5,
            "sha256": self._api.auth_sha256,
        }[auth_name]
        priv_protocol = {
            "aes128": self._api.priv_aes128,
            # ``aes256`` deliberately means the common Reeder/Cisco mapping.
            # The Blumenthal localization remains a separate explicit choice;
            # LLDP-Runner never negotiates or falls back between them.
            "aes256": self._api.priv_aes256,
            "aes256-blumenthal": self._api.priv_aes256_blumenthal,
            "des": self._api.priv_des,
        }[priv_name]
        if priv_name in _PYSNMP_AES_KEY_LENGTHS:
            # PySNMP 7.1.29 emits one known namespace deprecation while doing
            # an AES-CFB operation. Install the exact temporary filter only for
            # a route that can invoke that upstream implementation.
            _install_temporary_pysnmp_cfb_warning_filter()
        return self._api.usm_user_data(
            username,
            authKey=auth_password,
            privKey=priv_password,
            authProtocol=auth_protocol,
            privProtocol=priv_protocol,
        )

    @staticmethod
    def _engine_id_bytes(value: object) -> bytes | None:
        """Convert a response securityEngineId value without consulting local ID."""

        if isinstance(value, bytes):
            return value
        as_octets = getattr(value, "asOctets", None)
        if callable(as_octets):
            try:
                return bytes(as_octets())
            except Exception:
                return None
        as_numbers = getattr(value, "asNumbers", None)
        if callable(as_numbers):
            try:
                return bytes(as_numbers())
            except Exception:
                return None
        return None

    def _register_response_observer(self) -> None:
        """Capture authoritative remote SNMPv3 engine IDs from response context."""

        version = str(self.credential.version).strip().casefold()
        if version != "v3" or self._engine is None:
            return

        def observe(
            _engine: object,
            _execution_point: str,
            variables: Mapping[str, object],
            _context: object,
        ) -> None:
            value = variables.get("securityEngineId")
            encoded = self._engine_id_bytes(value) if value is not None else None
            if encoded:
                self._remote_engine_id = encoded

        # A closure avoids relying on the legacy cbCtx/cb_ctx keyword spelling.
        self._engine.observer.register_observer(observe, _RESPONSE_EXECUTION_POINT)
        self._observer_callback = observe

    async def __aenter__(self) -> Self:
        """Construct engine/security/target and clean partial setup on all exits."""

        try:
            self._engine = self._api.snmp_engine()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            normalized = self._normalized_exception(exc)
            raise SnmpBackendError(
                phase="session_construct",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="SESSION-CONSTRUCT",
                exc=normalized,
            ) from normalized

        try:
            self._register_response_observer()
            self._security_data = self._security()
            target_class = (
                self._api.udp_target if self.address_family == "ipv4" else self._api.udp6_target
            )
            self._transport_target = await target_class.create(
                (self.address, self.snmp_config.port),
                timeout=self.transport_profile.timeout_seconds,
                retries=0,
            )
        except asyncio.CancelledError:
            self._close_engine_safely()
            raise
        except Exception as exc:
            normalized = self._normalized_exception(exc)
            self._close_engine_safely()
            raise SnmpBackendError(
                phase="session_open",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="SESSION-OPEN",
                exc=normalized,
            ) from normalized
        return self

    def _close_engine_safely(self) -> BaseException | None:
        """Unregister the observer and close the dispatcher exactly once."""

        engine = self._engine
        callback = self._observer_callback
        self._engine = None
        self._security_data = None
        self._transport_target = None
        self._observer_callback = None
        if engine is None:
            return None
        first_error: BaseException | None = None
        if callback is not None:
            try:
                engine.observer.unregister_observer(callback)
            except Exception as exc:
                first_error = self._normalized_exception(exc)
        try:
            engine.close_dispatcher()
        except Exception as exc:
            if first_error is None:
                first_error = self._normalized_exception(exc)
        return first_error

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close dispatcher deterministically without masking an active failure."""

        close_error = self._close_engine_safely()
        if close_error is None or exc is not None:
            if close_error is not None:
                LOG.warning(
                    "PySNMP cleanup failed while preserving active exception "
                    "target=%s exception_type=%s",
                    self.address,
                    close_error.__class__.__name__,
                )
            return
        raise SnmpBackendError(
            phase="session_close",
            attempted_target=self.address,
            address_family=self.address_family,
            operation="SESSION-CLOSE",
            exc=close_error,
        ) from close_error

    def _require_open(self) -> tuple[object, object, object]:
        """Return engine/security/target or fail before issuing a request."""

        if self._engine is None or self._security_data is None or self._transport_target is None:
            raise RuntimeError("SNMP client is not open")
        return self._engine, self._security_data, self._transport_target

    def _response_parts(self, result: object, *, operation: str) -> list[tuple[str, object]]:
        """Normalize one complete engine/PDU response tuple."""

        if not isinstance(result, tuple) or len(result) != 4:
            raise SnmpMalformedResponseError(
                f"PySNMP {operation} returned an unexpected response shape"
            )
        indication, status, error_index, var_binds = result
        if indication:
            raise self._normalized_indication(indication)
        if status:
            status_text = self._safe_text(status) or status.__class__.__name__
            try:
                index = int(error_index)
            except (TypeError, ValueError, OverflowError):
                index = 0
            detail = f"{status_text} at error_index={index}"
            compact = _compact(status_text) + _compact(status.__class__.__name__)
            if any(marker in compact for marker in _AUTHORIZATION_MARKERS):
                raise SnmpAuthorizationError(detail)
            if any(marker in compact for marker in _AUTHENTICATION_MARKERS):
                raise SnmpAuthenticationError(detail)
            raise SnmpPduResponseError(detail)
        return _varbind_pairs(var_binds)

    async def _request(
        self,
        operation: str,
        call: Callable[[], Any],
    ) -> list[tuple[str, object]]:
        """Create/await one request and wrap stable request-phase metadata."""

        try:
            result = await call()
            return self._response_parts(result, operation=operation)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            normalized = self._normalized_exception(exc)
            raise SnmpBackendError(
                phase="request",
                attempted_target=self.address,
                address_family=self.address_family,
                operation=operation,
                exc=normalized,
            ) from normalized

    async def get(self, oid: str) -> object:
        """Issue one GET and return the first normalized response value."""

        engine, security, target = self._require_open()
        rows = await self._request(
            "GET",
            lambda: self._api.get_cmd(
                engine,
                security,
                target,
                self._api.context_data(),
                self._api.object_type(self._api.object_identity(oid)),
                lookupMib=False,
            ),
        )
        if not rows:
            raise SnmpBackendError(
                phase="request",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="GET",
                exc=SnmpMalformedResponseError("PySNMP GET returned no varbinds"),
            )
        return rows[0][1]

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        """Issue one multi-OID GET and key normalized values by response OID."""

        engine, security, target = self._require_open()
        if not oids:
            return {}
        objects = [self._api.object_type(self._api.object_identity(oid)) for oid in oids]
        rows = await self._request(
            "GET-MANY",
            lambda: self._api.get_cmd(
                engine,
                security,
                target,
                self._api.context_data(),
                *objects,
                lookupMib=False,
            ),
        )
        return dict(rows)

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        """Consume one GETBULK walk into normalized collector-facing rows."""

        engine, security, target = self._require_open()

        async def iterate() -> list[tuple[str, object]]:
            rows: list[tuple[str, object]] = []
            generator: AsyncIterator[object] = self._api.bulk_walk_cmd(
                engine,
                security,
                target,
                self._api.context_data(),
                0,
                self.transport_profile.max_repetitions,
                self._api.object_type(self._api.object_identity(oid)),
                lookupMib=False,
                lexicographicMode=False,
            )
            async for result in generator:
                rows.extend(self._response_parts(result, operation="WALK"))
            return rows

        try:
            return await iterate()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            normalized = self._normalized_exception(exc)
            raise SnmpBackendError(
                phase="request",
                attempted_target=self.address,
                address_family=self.address_family,
                operation="WALK",
                exc=normalized,
            ) from normalized

    def engine_id_hex(self) -> str | None:
        """Return only the authoritative remote SNMPv3 response engine ID."""

        if self.credential.version != "v3" or self._remote_engine_id is None:
            return None
        return self._remote_engine_id.hex()
