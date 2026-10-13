"""SNMP backend selection, factory wiring, and adaptive state construction."""

from __future__ import annotations

from lldp_runner.config import AppConfig, CredentialConfig
from lldp_runner.models import DirectCredential
from lldp_runner.snmp.base import SnmpClient
from lldp_runner.snmp.preflight import preflight_snmp_backend as preflight_snmp_backend
from lldp_runner.snmp.resilience import AdaptiveSnmpClient, AdaptiveSnmpState
from lldp_runner.snmp.selection import (
    SnmpBackendSelection,
    selected_snmp_backend,
)


def create_adaptive_snmp_state(config: AppConfig, address: str) -> AdaptiveSnmpState:
    """Build the transport state shared by one successful target discovery."""

    return AdaptiveSnmpState(
        target=address,
        timeout_seconds=config.snmp.timeout_seconds,
        max_repetitions=config.snmp.max_repetitions,
        per_device_rps=config.snmp.per_device_rps,
        retry_per_operation=config.snmp.retry_per_operation,
        retry_per_collector=config.snmp.retry_per_collector,
        retry_total_cap=config.snmp.retry_total_cap,
        retry_neighbor_reserve=config.snmp.retry_neighbor_reserve,
        structural_table_retry=config.snmp.structural_table_retry,
        timeout_multiplier=config.snmp.retry_timeout_multiplier,
        max_repetitions_multiplier=config.snmp.retry_max_repetitions_multiplier,
        min_max_repetitions=config.snmp.retry_min_max_repetitions,
        retry_inter_pdu_delay_ms=config.snmp.retry_inter_pdu_delay_ms,
    )


def snmp_backend_selection(config: AppConfig) -> SnmpBackendSelection:
    """Return the once-bound backend identity used by this runtime config."""

    return selected_snmp_backend(config.snmp)


def create_snmp_client(
    config: AppConfig,
    address: str,
    credential: CredentialConfig | DirectCredential,
    *,
    adaptive_state: AdaptiveSnmpState | None = None,
) -> SnmpClient:
    """Create a client for the run's immutable selected SNMP backend.

    There is deliberately no exception-driven fallback.  Failure to import,
    construct, open, or query the selected backend remains a failure of that
    route and cannot introduce mixed-backend evidence into one logical run.
    """

    selection = selected_snmp_backend(config.snmp)
    state = adaptive_state or create_adaptive_snmp_state(config, address)
    if state.target != address:
        raise ValueError(f"adaptive SNMP state target {state.target!r} does not match {address!r}")

    if selection.name == "gufo":
        from lldp_runner.snmp.gufo import GufoSnmpClient

        backend_type = GufoSnmpClient
    elif selection.name == "pysnmp":
        from lldp_runner.snmp.pysnmp import PySnmpClient

        backend_type = PySnmpClient
    else:  # Defensive: validation and selection reject this before discovery.
        raise ValueError(f"unsupported SNMP backend {selection.name!r}")

    return AdaptiveSnmpClient(
        lambda profile: backend_type(
            address,
            credential,
            config.snmp,
            transport_profile=profile,
        ),
        state=state,
    )
