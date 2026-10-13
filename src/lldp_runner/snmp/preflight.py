"""Pre-discovery capability checks for the immutable selected SNMP backend.

Configuration validation proves that credential names and protocol mappings are
supported by the selected adapter.  This module performs the separate runtime
capability check that can depend on optional/native third-party components.  It
never resolves or receives credential secret values.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING

from lldp_runner.models import DirectCredential
from lldp_runner.snmp.selection import selected_snmp_backend

if TYPE_CHECKING:
    from lldp_runner.config import AppConfig, CredentialConfig


def _configured_route_credentials(config: AppConfig) -> Iterator[CredentialConfig]:
    """Yield configured credentials reachable through any named profile once.

    Every profile can be selected by the ordinary policy rules or referenced by
    a protected seed-credential overlay.  Unreferenced credential definitions
    are deliberately ignored so a dormant definition cannot impose a runtime
    dependency on an otherwise unrelated run.
    """

    names: set[str] = set()
    for profile in config.credential_profiles.values():
        names.add(profile.primary)
        if profile.fallback:
            names.add(profile.fallback)
    for name in sorted(names):
        credential = config.credentials.get(name)
        if credential is not None:
            yield credential


def required_authpriv_protocols(
    config: AppConfig,
    *,
    direct_credentials: Iterable[DirectCredential] = (),
) -> tuple[str, ...]:
    """Return distinct SNMPv3 privacy algorithms that this invocation may use.

    The result is derived only from non-secret credential metadata.  Configured
    credentials are limited to profile-reachable definitions; direct seed
    credentials are supplied explicitly by the coordinator after secure overlay
    parsing.
    """

    protocols: set[str] = set()
    credentials: tuple[CredentialConfig | DirectCredential, ...] = (
        *_configured_route_credentials(config),
        *direct_credentials,
    )
    for credential in credentials:
        if str(credential.version).strip().casefold() != "v3":
            continue
        protocol = str(credential.priv_protocol).strip().casefold()
        if protocol:
            protocols.add(protocol)
    return tuple(sorted(protocols))


def preflight_snmp_backend(
    config: AppConfig,
    *,
    direct_credentials: Iterable[DirectCredential] = (),
) -> tuple[str, ...]:
    """Verify local runtime capabilities required before network discovery.

    Gufo has no additional local capability probe.  PySNMP SNMPv2c likewise
    needs no privacy provider.  A PySNMP invocation that may use SNMPv3 authPriv
    constructively probes every selected privacy algorithm before workers or a
    single-device inspection contact the network.

    Returns:
        The sorted privacy protocol names that were checked.  An empty tuple
        means no authPriv capability probe was required.

    Raises:
        SnmpBackendCapabilityError: If PySNMP or its cryptography provider cannot
            perform one of the required local cipher operations.
    """

    selection = selected_snmp_backend(config.snmp)
    protocols = required_authpriv_protocols(
        config,
        direct_credentials=direct_credentials,
    )
    if selection.name != "pysnmp" or not protocols:
        return ()

    # Import only after the immutable backend choice and only for an invocation
    # that can actually use authPriv.  Stored-data readers never call this path.
    from lldp_runner.snmp.pysnmp import preflight_pysnmp_authpriv

    preflight_pysnmp_authpriv(protocols)
    return protocols
