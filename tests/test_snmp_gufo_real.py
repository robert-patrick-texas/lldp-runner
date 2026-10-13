"""Optional constructor smoke test against the installed Gufo distribution."""

from __future__ import annotations

import importlib
import importlib.metadata
import sys

import pytest


def test_real_gufo_ipv6_constructor_smoke(config) -> None:
    """Exercise the containment layer with real Gufo when it is installed.

    Construction is local and sends no SNMP request. The release environment
    can therefore verify both loopback and a production-shaped global literal
    without requiring either address to be reachable from the test host.
    """

    try:
        importlib.metadata.version("gufo-snmp")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("gufo-snmp is not installed in this test environment")

    # The deterministic fake-Gufo unit tests import this module with temporary
    # stubs. Force a clean import from the installed distribution for this smoke
    # test rather than reusing an earlier module-cache entry.
    for name in ("lldp_runner.snmp.gufo", "gufo.snmp", "gufo"):
        sys.modules.pop(name, None)
    module = importlib.import_module("lldp_runner.snmp.gufo")
    credential = config.credentials["specific-v2"]

    for address in ("::1", "2001:db8:8000:da02::1"):
        client = module.GufoSnmpClient(address, credential, config.snmp)
        session = client._construct_session()
        assert session is not None
