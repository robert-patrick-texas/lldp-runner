"""Deterministic coverage for the standalone Gufo IPv6 bracket diagnostic."""

from __future__ import annotations

import importlib.util
import socket
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "gufo-ipv6-test.py"


def _load_script() -> ModuleType:
    """Load the hyphenated operator script as an isolated test module."""

    name = "lldp_runner_gufo_ipv6_test_script"
    sys.modules.pop(name, None)
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _record(family: int, address: str) -> tuple[Any, ...]:
    """Build the relevant shape returned by socket.getaddrinfo()."""

    if family == socket.AF_INET6:
        return (family, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (address, 0, 0, 0))
    return (family, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (address, 0))


class FakeSession:
    """Minimal asynchronous Gufo session with address-specific failures."""

    calls: list[str] = []
    failures: dict[str, BaseException] = {}

    def __init__(
        self,
        *,
        addr: str,
        port: int,
        community: str,
        timeout: float,
    ) -> None:
        assert port == 161
        assert timeout == 5.0
        assert community
        self.addr = addr
        type(self).calls.append(addr)
        failure = type(self).failures.get(addr)
        if failure is not None:
            raise failure

    async def __aenter__(self) -> FakeSession:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def get(self, oid: str) -> bytes:
        assert oid == "1.3.6.1.2.1.1.1.0"
        return b"fixture"


@pytest.fixture(autouse=True)
def _reset_fake_session() -> None:
    """Prevent call/failure state from leaking between diagnostic tests."""

    FakeSession.calls = []
    FakeSession.failures = {}


def test_help_exits_before_gufo_import(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """--help remains usable when gufo-snmp is not installed."""

    module = _load_script()
    monkeypatch.setattr(
        module.importlib,
        "import_module",
        lambda _name: (_ for _ in ()).throw(AssertionError("Gufo import attempted")),
    )

    with pytest.raises(SystemExit) as exc_info:
        module.main(["--help"])

    assert exc_info.value.code == 0
    assert "TARGET" in capsys.readouterr().out


def test_direct_ipv6_literal_is_normalized() -> None:
    """Literal input uses ipaddress canonical unbracketed rendering."""

    module = _load_script()
    assert module.resolve_ipv6_targets("2001:0DB8:0:0::0001") == ["2001:db8::1"]


def test_dns_hostname_with_one_aaaa_result() -> None:
    """A hostname may select one canonical IPv6 resolver result."""

    module = _load_script()

    def resolver(*_args: object, **kwargs: object) -> list[tuple[Any, ...]]:
        assert kwargs["family"] == socket.AF_INET6
        return [_record(socket.AF_INET6, "2001:0db8::0005")]

    assert module.resolve_ipv6_targets("switch.example", resolver=resolver) == ["2001:db8::5"]


def test_dns_results_are_normalized_deduplicated_and_ordered() -> None:
    """Multiple AAAA results retain resolver order after canonical deduplication."""

    module = _load_script()

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        return [
            _record(socket.AF_INET6, "2001:db8::2"),
            _record(socket.AF_INET6, "2001:0db8:0:0:0:0:0:2"),
            _record(socket.AF_INET6, "2001:db8::1"),
        ]

    assert module.resolve_ipv6_targets("switch.example", resolver=resolver) == [
        "2001:db8::2",
        "2001:db8::1",
    ]


def test_ipv4_literal_is_rejected(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """The focused diagnostic never silently switches to IPv4."""

    module = _load_script()
    monkeypatch.setenv("SNMPCOMM", "testing")

    assert module.main(["192.0.2.10"], session_class=FakeSession) == 2
    captured = capsys.readouterr()
    assert "IPv4 literal" in captured.err
    assert FakeSession.calls == []


def test_hostname_with_no_ipv6_result_is_rejected(capsys) -> None:
    """IPv4-only or empty resolver output is a clear configuration error."""

    module = _load_script()

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        return [_record(socket.AF_INET, "192.0.2.10")]

    assert module.main(["switch.example"], resolver=resolver, session_class=FakeSession) == 2
    assert "resolved to no IPv6 destination" in capsys.readouterr().err


def test_resolver_failure_is_exit_two(capsys) -> None:
    """Name-resolution failures are reported without a traceback."""

    module = _load_script()

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        raise socket.gaierror(socket.EAI_NONAME, "name not known")

    assert module.main(["missing.example"], resolver=resolver, session_class=FakeSession) == 2
    assert "IPv6 DNS resolution failed" in capsys.readouterr().err


def test_missing_community_is_configuration_error(monkeypatch: pytest.MonkeyPatch, capsys) -> None:
    """An absent or empty SNMPCOMM never becomes a raw KeyError."""

    module = _load_script()
    monkeypatch.delenv("SNMPCOMM", raising=False)

    assert module.main(["2001:db8::1"], session_class=FakeSession) == 2
    assert "SNMPCOMM is not set or is empty" in capsys.readouterr().err


def test_both_success_passes_exact_unbracketed_and_bracketed_values(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    """A modern Gufo runtime produces a successful brackets-not-required verdict."""

    module = _load_script()
    monkeypatch.setenv("SNMPCOMM", "testing")

    result = module.main(["2001:0db8::0001"], session_class=FakeSession)

    assert result == 0
    assert FakeSession.calls == ["2001:db8::1", "[2001:db8::1]"]
    assert "FINAL VERDICT: brackets not required" in capsys.readouterr().out


def test_known_unbracketed_invalid_address_means_brackets_required(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    """The Gufo 0.12.0 constructor symptom is a conclusive successful diagnostic."""

    module = _load_script()
    monkeypatch.setenv("SNMPCOMM", "testing")
    FakeSession.failures = {"2001:db8::1": OSError("invalid address")}

    result = module.main(["2001:db8::1"], session_class=FakeSession)

    assert result == 0
    assert "VERDICT for 2001:db8::1: brackets required" in capsys.readouterr().out


def test_bracketed_failure_is_inconclusive_exit_one(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    """A failed bracketed probe cannot establish transport bracket behavior."""

    module = _load_script()
    monkeypatch.setenv("SNMPCOMM", "testing")
    FakeSession.failures = {"[2001:db8::1]": TimeoutError("timed out")}

    result = module.main(["2001:db8::1"], session_class=FakeSession)

    assert result == 1
    assert "FINAL VERDICT: inconclusive" in capsys.readouterr().out


def test_mixed_address_verdicts_are_inconsistent(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    """Different library behavior across selected addresses is not overclaimed."""

    module = _load_script()
    monkeypatch.setenv("SNMPCOMM", "testing")
    FakeSession.failures = {"2001:db8::1": OSError("invalid address")}

    result = module.main(
        ["switch.example"],
        resolver=lambda *_args, **_kwargs: [
            _record(socket.AF_INET6, "2001:db8::1"),
            _record(socket.AF_INET6, "2001:db8::2"),
        ],
        session_class=FakeSession,
    )

    assert result == 1
    assert "inconclusive or inconsistent" in capsys.readouterr().out


def test_credential_is_redacted_from_failure_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    """Exception text cannot echo the SNMP community."""

    module = _load_script()
    secret = "very-secret-community"
    monkeypatch.setenv("SNMPCOMM", secret)
    FakeSession.failures = {
        "2001:db8::1": RuntimeError(f"failed using {secret}"),
        "[2001:db8::1]": RuntimeError(f"failed using {secret}"),
    }

    assert module.main(["2001:db8::1"], session_class=FakeSession) == 1
    captured = capsys.readouterr()
    assert secret not in captured.out
    assert secret not in captured.err
    assert "<redacted:SNMPCOMM>" in captured.out


def test_keyboard_interrupt_during_resolution_returns_130(capsys) -> None:
    """The interruption wrapper covers DNS as well as asynchronous probes."""

    module = _load_script()

    def resolver(*_args: object, **_kwargs: object) -> list[tuple[Any, ...]]:
        raise KeyboardInterrupt

    assert module.main(["switch.example"], resolver=resolver) == 130
    assert "Interrupted" in capsys.readouterr().err


def test_keyboard_interrupt_returns_130(
    monkeypatch: pytest.MonkeyPatch,
    capsys,
) -> None:
    """Operator interruption uses the conventional shell exit status."""

    module = _load_script()
    monkeypatch.setenv("SNMPCOMM", "testing")
    FakeSession.failures = {"2001:db8::1": KeyboardInterrupt()}

    assert module.main(["2001:db8::1"], session_class=FakeSession) == 130
    assert "Interrupted" in capsys.readouterr().err
