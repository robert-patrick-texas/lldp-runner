"""Resolve and freeze the process-wide SNMP backend selection.

The configuration value is operator input.  ``selected_backend`` and
``selected_backend_version`` are runtime-only fields bound once after validation
and copied unchanged into worker processes.  Keeping that distinction explicit
prevents a mutable configuration object from silently switching transport
implementations in the middle of a discovery run.
"""

from __future__ import annotations

import importlib.metadata
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from lldp_runner.config import SnmpConfig

SUPPORTED_SNMP_BACKENDS: Final[tuple[str, ...]] = ("gufo", "pysnmp")
_BACKEND_DISTRIBUTIONS: Final[dict[str, str]] = {
    "gufo": "gufo-snmp",
    "pysnmp": "pysnmp",
}


@dataclass(frozen=True, slots=True)
class SnmpCredentialCapabilities:
    """Credential algorithms intentionally supported by one backend adapter.

    LLDP-Runner exposes one shared credential model, but the concrete mapping is
    owned by each transport implementation.  Keeping the accepted names in this
    backend-indexed registry prevents a new algorithm from being admitted by
    generic configuration validation before both adapters deliberately support
    it.
    """

    auth_protocols: tuple[str, ...]
    priv_protocols: tuple[str, ...]


_BACKEND_CREDENTIAL_CAPABILITIES: Final[
    dict[str, SnmpCredentialCapabilities]
] = {
    "gufo": SnmpCredentialCapabilities(
        auth_protocols=("sha1", "md5"),
        priv_protocols=("aes128", "des"),
    ),
    "pysnmp": SnmpCredentialCapabilities(
        auth_protocols=("sha1", "md5", "sha256"),
        priv_protocols=("aes128", "aes256", "aes256-blumenthal", "des"),
    ),
}


@dataclass(frozen=True, slots=True)
class SnmpBackendSelection:
    """Immutable backend identity retained for one process/run invocation."""

    name: str
    version: str


def normalize_snmp_backend(value: object) -> str:
    """Normalize one operator-provided backend name and reject unknown values."""

    name = str(value).strip().casefold()
    if name not in SUPPORTED_SNMP_BACKENDS:
        supported = ", ".join(SUPPORTED_SNMP_BACKENDS)
        raise ValueError(
            f"unsupported SNMP backend {value!r}; expected one of: {supported}"
        )
    return name


def snmp_backend_credential_capabilities(
    name: str,
) -> SnmpCredentialCapabilities:
    """Return the explicitly supported v3 algorithms for ``name``."""

    return _BACKEND_CREDENTIAL_CAPABILITIES[normalize_snmp_backend(name)]


def validate_snmp_v3_protocols(
    backend: str,
    *,
    auth_protocol: object,
    priv_protocol: object,
) -> tuple[str, str]:
    """Normalize and validate one authPriv mapping for a selected backend.

    Returns:
        ``(auth_protocol, priv_protocol)`` as canonical lowercase names.

    Raises:
        ValueError: If either configured algorithm is unsupported by the
            selected implementation.
    """

    normalized_backend = normalize_snmp_backend(backend)
    capabilities = _BACKEND_CREDENTIAL_CAPABILITIES[normalized_backend]
    auth = str(auth_protocol).strip().casefold()
    privacy = str(priv_protocol).strip().casefold()
    if auth not in capabilities.auth_protocols:
        expected = ", ".join(capabilities.auth_protocols)
        raise ValueError(
            f"SNMP backend {normalized_backend!r} does not support "
            f"auth_protocol {auth_protocol!r}; expected one of: {expected}"
        )
    if privacy not in capabilities.priv_protocols:
        expected = ", ".join(capabilities.priv_protocols)
        raise ValueError(
            f"SNMP backend {normalized_backend!r} does not support "
            f"priv_protocol {priv_protocol!r}; expected one of: {expected}"
        )
    return auth, privacy


def installed_snmp_backend_version(name: str) -> str:
    """Return the installed distribution version without importing the backend.

    Selection must be safe before worker startup and must not accidentally load a
    second transport implementation.  Package metadata supplies the diagnostic
    version without importing Gufo or PySNMP.  ``not-installed`` is retained as a
    truthful diagnostic for source/test environments; actual backend construction
    will still fail clearly if its selected package is absent.
    """

    normalized = normalize_snmp_backend(name)
    distribution = _BACKEND_DISTRIBUTIONS[normalized]
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"
    except Exception:
        # Metadata lookup is diagnostic.  Never make an otherwise valid config
        # unusable because a third-party package metadata provider is unhealthy.
        return "unknown"


def select_snmp_backend(config: SnmpConfig) -> SnmpBackendSelection:
    """Bind ``config`` to exactly one backend, or reject an attempted switch.

    The selected fields are runtime-only dataclass members.  They survive pickle
    boundaries into spawned workers but cannot be supplied through TOML.  Calling
    this helper repeatedly is intentional and safe: it returns the first binding,
    while detecting any later mutation of the operator-facing ``backend`` value.
    """

    configured = normalize_snmp_backend(config.backend)
    selected = config.selected_backend
    if selected is None:
        version = installed_snmp_backend_version(configured)
        config.backend = configured
        config.selected_backend = configured
        config.selected_backend_version = version
        return SnmpBackendSelection(configured, version)

    if configured != selected:
        raise ValueError(
            "SNMP backend selection is fixed for this run: "
            f"selected {selected!r}, later configuration requested {configured!r}"
        )
    version = config.selected_backend_version or installed_snmp_backend_version(
        selected
    )
    config.selected_backend_version = version
    return SnmpBackendSelection(selected, version)


def selected_snmp_backend(config: SnmpConfig) -> SnmpBackendSelection:
    """Return the immutable selection, binding it defensively when necessary."""

    return select_snmp_backend(config)
