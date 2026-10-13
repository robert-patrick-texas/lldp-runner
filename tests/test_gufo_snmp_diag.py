"""Deterministic tests for the standalone direct-Gufo diagnostic."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

TOOL = Path(__file__).parents[1] / "tools" / "gufo_snmp_diag.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("gufo_snmp_diag_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _args(*, snmp_version: str = "2c") -> SimpleNamespace:
    return SimpleNamespace(
        target="2001:db8::1",
        ipv4=False,
        ipv6=True,
        snmp_version=snmp_version,
        oid=["1.3.6.1.2.1.1.1.0"],
        port=161,
        timeout=5.0,
        repeat=1,
        delay=0.0,
        first_address=False,
        auth_protocol="sha1",
        priv_protocol="aes128",
        traceback=False,
    )


class _Session:
    construct_error: BaseException | None = None
    open_error: BaseException | None = None
    request_error: BaseException | None = None
    close_error: BaseException | None = None
    value: object = b"system description"
    calls: list[tuple[str, object]] = []

    def __init__(self, **kwargs: object) -> None:
        type(self).calls.append(("construct", kwargs["addr"]))
        if type(self).construct_error is not None:
            raise type(self).construct_error

    async def __aenter__(self):
        type(self).calls.append(("open", None))
        if type(self).open_error is not None:
            raise type(self).open_error
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        type(self).calls.append(("close", None))
        if type(self).close_error is not None:
            raise type(self).close_error

    async def get(self, oid: str) -> object:
        type(self).calls.append(("get", oid))
        if type(self).request_error is not None:
            raise type(self).request_error
        return type(self).value

    def get_engine_id(self) -> bytes:
        return b"\x80\x00"


def _reset_session(**values: object) -> None:
    _Session.construct_error = values.get("construct_error")  # type: ignore[assignment]
    _Session.open_error = values.get("open_error")  # type: ignore[assignment]
    _Session.request_error = values.get("request_error")  # type: ignore[assignment]
    _Session.close_error = values.get("close_error")  # type: ignore[assignment]
    _Session.value = values.get("value", b"system description")
    _Session.calls = []


def _api(module, session_class: Any = _Session):
    class Key:
        def __init__(self, value: bytes) -> None:
            self.value = value

    class User:
        def __init__(self, username: str, **kwargs: object) -> None:
            self.username = username
            self.kwargs = kwargs

    return module.GufoApi(
        module=SimpleNamespace(__file__=str(TOOL)),
        session_class=session_class,
        user_class=User,
        sha1_key_class=Key,
        md5_key_class=Key,
        aes128_key_class=Key,
        des_key_class=Key,
        distribution_version="0.12.0-fake",
    )


def _target(module):
    return module.ResolvedTarget(
        address="2001:db8::1",
        family=socket.AF_INET6,
        source="numeric-literal",
        normalized="2001:db8::1",
    )


def _probe(module, capsys, **session_values: object):
    _reset_session(**session_values)
    totals = module.ProbeTotals()
    result = asyncio.run(
        module.probe_once(
            args=_args(),
            target=_target(module),
            gufo=_api(module),
            security_kwargs={"community": "not-printed"},
            attempt_number=1,
            totals=totals,
            redactor=module.SecretRedactor(
                replacements=(("not-printed", "<redacted:SNMPCOMM>"),)
            ),
        )
    )
    captured = capsys.readouterr()
    return result, totals, captured.out, captured.err


def test_help_does_not_import_gufo() -> None:
    result = subprocess.run(
        [sys.executable, str(TOOL), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert result.returncode == 0
    assert "Query a device directly with Gufo SNMP" in result.stdout
    assert result.stderr == ""


def test_success_reports_all_phases() -> None:
    # Explicit local loading keeps the standalone tool outside package imports.
    module = _load_tool()
    _reset_session()
    totals = module.ProbeTotals()
    result = asyncio.run(
        module.probe_once(
            args=_args(),
            target=_target(module),
            gufo=_api(module),
            security_kwargs={"community": "secret"},
            attempt_number=1,
            totals=totals,
            redactor=module.SecretRedactor(
                replacements=(("secret", "<redacted:SNMPCOMM>"),)
            ),
        )
    )
    assert result is True
    assert totals.sessions_succeeded == 1
    assert totals.gets_succeeded == 1
    assert [name for name, _ in _Session.calls] == [
        "construct",
        "open",
        "get",
        "close",
    ]


@pytest.mark.parametrize(
    ("session_values", "phase", "exception_type"),
    [
        (
            {"construct_error": OSError("invalid address")},
            "session_construct",
            "builtins.OSError",
        ),
        (
            {"open_error": OSError(101, "network unreachable")},
            "session_open",
            "builtins.OSError",
        ),
        (
            {"request_error": TimeoutError("request timed out")},
            "get:1.3.6.1.2.1.1.1.0",
            "builtins.TimeoutError",
        ),
        (
            {"request_error": OSError(113, "no route to host")},
            "get:1.3.6.1.2.1.1.1.0",
            "builtins.OSError",
        ),
        (
            {"close_error": OSError(5, "close failed")},
            "session_close",
            "builtins.OSError",
        ),
    ],
)
def test_failures_report_exact_phase_and_original_exception(
    capsys,
    session_values: dict[str, object],
    phase: str,
    exception_type: str,
) -> None:
    module = _load_tool()
    result, totals, stdout, stderr = _probe(
        module, capsys, **session_values
    )
    assert result is False
    assert totals.sessions_failed == 1
    assert f"phase: {phase}" in stderr
    assert f"exception_type: {exception_type}" in stderr
    assert "address: 2001:db8::1" in stderr
    assert "result: FAILURE" in stdout


def test_dns_family_filter_is_forwarded_and_literal_mismatch_rejected(monkeypatch) -> None:
    module = _load_tool()
    calls: list[int] = []

    def fake_getaddrinfo(host: str, port: int, **kwargs: object):
        calls.append(int(kwargs["family"]))
        return [
            (
                socket.AF_INET6,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                "",
                ("2001:db8::10", port, 0, 0),
            )
        ]

    monkeypatch.setattr(module.socket, "getaddrinfo", fake_getaddrinfo)
    kind, targets = module.resolve_target(
        "switch.example.test",
        port=161,
        family=socket.AF_INET6,
        first_address=False,
    )
    assert calls == [socket.AF_INET6]
    assert kind == "dns-name"
    assert [target.address for target in targets] == ["2001:db8::10"]
    with pytest.raises(ValueError, match="IPv4 was forced"):
        module.resolve_target(
            "2001:db8::10",
            port=161,
            family=socket.AF_INET,
            first_address=False,
        )


def test_snmpv3_security_path_uses_environment_without_printing_secrets(
    monkeypatch,
) -> None:
    module = _load_tool()
    values = {
        "SNMPUSER": "diagnostic-user",
        "SNMPAUTH": "diagnostic-auth-secret",
        "SNMPPRIV": "diagnostic-priv-secret",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    api = _api(module)
    kwargs = module.build_security_kwargs(_args(snmp_version="3"), api)
    assert set(kwargs) == {"user"}
    user = kwargs["user"]
    assert user.username == values["SNMPUSER"]
    redactor = module.SecretRedactor.from_environment()
    rendered = redactor.redact(" ".join(values.values()))
    assert "diagnostic-" not in rendered
    assert rendered == (
        "<redacted:SNMPUSER> <redacted:SNMPAUTH> <redacted:SNMPPRIV>"
    )
