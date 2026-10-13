"""Deterministic Gufo-boundary tests without requiring a native Gufo install."""

from __future__ import annotations

import asyncio
import importlib
import sys
import types
from dataclasses import dataclass, field
from typing import Any

import pytest

from lldp_runner.config import SnmpConfig
from lldp_runner.models import DirectCredential
from lldp_runner.snmp.base import SnmpBackendError, SnmpSessionAddressError
from lldp_runner.snmp.resilience import AdaptiveSnmpClient, AdaptiveSnmpState
from lldp_runner.worker import _error_category, _worker_error


@dataclass
class _Behavior:
    """Script constructor/session outcomes and retain non-secret call structure."""

    construct_errors: dict[str, list[BaseException]] = field(default_factory=dict)
    open_error: BaseException | None = None
    get_error: BaseException | None = None
    get_many_error: BaseException | None = None
    walk_error: BaseException | None = None
    close_error: BaseException | None = None
    calls: list[dict[str, Any]] = field(default_factory=list)

    def constructor_error(self, address: str) -> BaseException | None:
        values = self.construct_errors.get(address, [])
        return values.pop(0) if values else None


def _load_gufo(monkeypatch: pytest.MonkeyPatch, behavior: _Behavior):
    """Install the minimum public Gufo API consumed by ``GufoSnmpClient``."""

    class FakeKey:
        def __init__(self, value: bytes) -> None:
            self.value = value

    class FakeUser:
        def __init__(
            self,
            username: str,
            *,
            auth_key: object,
            priv_key: object,
        ) -> None:
            self.username = username
            self.auth_key = auth_key
            self.priv_key = priv_key

    class FakeSession:
        def __init__(self, **kwargs: Any) -> None:
            behavior.calls.append(dict(kwargs))
            error = behavior.constructor_error(str(kwargs["addr"]))
            if error is not None:
                raise error

        async def __aenter__(self) -> FakeSession:
            if behavior.open_error is not None:
                raise behavior.open_error
            return self

        async def __aexit__(self, *_args: object) -> None:
            if behavior.close_error is not None:
                raise behavior.close_error

        async def get(self, oid: str) -> bytes:
            if behavior.get_error is not None:
                raise behavior.get_error
            return oid.encode()

        async def get_many(self, oids: list[str]) -> list[tuple[str, bytes]]:
            if behavior.get_many_error is not None:
                raise behavior.get_many_error
            return [(oid, oid.encode()) for oid in oids]

        async def fetch(self, oid: str):
            if behavior.walk_error is not None:
                raise behavior.walk_error
            yield f"{oid}.1", b"value"

        def get_engine_id(self) -> bytes:
            return b"\x80\x00\x00\x09"

    gufo_pkg = types.ModuleType("gufo")
    gufo_pkg.__path__ = []  # type: ignore[attr-defined]
    snmp_pkg = types.ModuleType("gufo.snmp")
    for name, value in {
        "Aes128Key": FakeKey,
        "DesKey": FakeKey,
        "Md5Key": FakeKey,
        "Sha1Key": FakeKey,
        "SnmpSession": FakeSession,
        "User": FakeUser,
    }.items():
        setattr(snmp_pkg, name, value)
    monkeypatch.setitem(sys.modules, "gufo", gufo_pkg)
    monkeypatch.setitem(sys.modules, "gufo.snmp", snmp_pkg)
    sys.modules.pop("lldp_runner.snmp.gufo", None)
    module = importlib.import_module("lldp_runner.snmp.gufo")
    monkeypatch.setattr(module, "_gufo_distribution_version", lambda: "0.12.0")
    return module


def _v2() -> DirectCredential:
    return DirectCredential(
        name="test-v2",
        version="v2c",
        community="not-a-real-community",
    )


def _v3() -> DirectCredential:
    return DirectCredential(
        name="test-v3",
        version="v3",
        username="operator",
        auth_password="not-a-real-auth-password",
        priv_password="not-a-real-privacy-password",
    )


def _config() -> SnmpConfig:
    return SnmpConfig(
        timeout_seconds=2.0,
        max_repetitions=25,
        per_device_rps=5.0,
    )


@pytest.mark.parametrize(
    "address",
    [
        "2001:db8:8000:2e22::1000:16",
        "2001:db8:33d:1220::1000:198",
        "2001:db8:8000:da02::1",
        "2001:db8:8000:da02::65",
        "2001:db8:8000:da02::66",
        "2001:db8:8000:da02::67",
        "2001:db8:8000:da02::68",
        "2001:db8:8000:da02::69",
        "2001:db8:8000:19:d304::1",
        "2001:db8:8000:2020::1000:58",
        "2001:db8:8000:1120::1000:256",
        "2001:db8:183d:970::1000:13",
        "2001:db8:183d:970::1000:12",
        "2001:db8:8000:da02:0000:0000:0000:0001",
        "fe80::1%eth0",
    ],
)
def test_ipv6_constructor_fallback_is_raw_then_bracketed(
    monkeypatch: pytest.MonkeyPatch,
    address: str,
) -> None:
    behavior = _Behavior(construct_errors={address: [OSError("invalid address")]})
    module = _load_gufo(monkeypatch, behavior)

    async def exercise() -> bytes:
        async with module.GufoSnmpClient(address, _v2(), _config()) as client:
            value = await client.get("1.3.6.1.2.1.1.1.0")
            assert isinstance(value, bytes)
            return value

    assert asyncio.run(exercise()) == b"1.3.6.1.2.1.1.1.0"
    assert [call["addr"] for call in behavior.calls] == [address, f"[{address}]"]
    assert all("[" not in address for _call in behavior.calls)


def test_ipv6_raw_constructor_success_does_not_add_brackets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = _Behavior()
    module = _load_gufo(monkeypatch, behavior)
    address = "2001:db8:8000:da02::1"

    async def exercise() -> None:
        async with module.GufoSnmpClient(address, _v2(), _config()) as client:
            await client.get("1")

    asyncio.run(exercise())
    assert [call["addr"] for call in behavior.calls] == [address]


def test_ipv4_never_uses_bracket_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = "192.0.2.10"
    behavior = _Behavior(construct_errors={address: [OSError("invalid address")]})
    module = _load_gufo(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.GufoSnmpClient(address, _v2(), _config()):
            pass

    with pytest.raises(SnmpSessionAddressError) as raised:
        asyncio.run(exercise())
    assert raised.value.phase == "session_construct"
    assert raised.value.attempted_target == address
    assert raised.value.address_family == "ipv4"
    assert [call["addr"] for call in behavior.calls] == [address]


def test_unrelated_ipv6_constructor_error_does_not_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = "2001:db8::10"
    behavior = _Behavior(construct_errors={address: [OSError(13, "permission denied")]})
    module = _load_gufo(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.GufoSnmpClient(address, _v2(), _config()):
            pass

    with pytest.raises(SnmpSessionAddressError) as raised:
        asyncio.run(exercise())
    original = raised.value.original_exception
    assert isinstance(original, OSError)
    assert original.errno == 13
    assert [call["addr"] for call in behavior.calls] == [address]


def test_double_constructor_failure_preserves_both_exceptions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = "2001:db8::11"
    first = OSError("invalid address")
    second = RuntimeError("bracketed constructor failed")
    behavior = _Behavior(construct_errors={address: [first], f"[{address}]": [second]})
    module = _load_gufo(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.GufoSnmpClient(address, _v2(), _config()):
            pass

    with pytest.raises(SnmpSessionAddressError) as raised:
        asyncio.run(exercise())
    error = raised.value
    assert error.original_exception is second
    assert error.initial_exception is first
    assert error.__cause__ is second
    assert error.attempted_target == address


@pytest.mark.parametrize(
    ("failure_point", "expected_phase"),
    [
        ("open_error", "session_open"),
        ("get_error", "request"),
        ("get_many_error", "request"),
        ("walk_error", "request"),
        ("close_error", "session_close"),
    ],
)
def test_backend_failure_phase_is_preserved(
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
    expected_phase: str,
) -> None:
    behavior = _Behavior()
    setattr(behavior, failure_point, OSError(101, failure_point))
    module = _load_gufo(monkeypatch, behavior)
    address = "2001:db8::12"

    async def exercise() -> None:
        async with module.GufoSnmpClient(address, _v2(), _config()) as client:
            if failure_point == "get_error":
                await client.get("1")
            elif failure_point == "get_many_error":
                await client.get_many(["1", "2"])
            elif failure_point == "walk_error":
                await client.walk("1")

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())
    error = raised.value
    assert error.phase == expected_phase
    assert error.attempted_target == address
    assert error.address_family == "ipv6"
    assert error.exception_type == "builtins.OSError"
    assert error.exception_errno == 101


def test_v3_uses_same_ipv6_transport_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = "2001:db8::13"
    behavior = _Behavior(construct_errors={address: [OSError("invalid address")]})
    module = _load_gufo(monkeypatch, behavior)

    async def exercise() -> str | None:
        async with module.GufoSnmpClient(address, _v3(), _config()) as client:
            await client.walk("1.3.6")
            return client.engine_id_hex()

    assert asyncio.run(exercise()) == "80000009"
    assert [call["addr"] for call in behavior.calls] == [address, f"[{address}]"]
    assert "user" in behavior.calls[-1]
    assert "community" not in behavior.calls[-1]


@pytest.mark.parametrize(
    ("auth_protocol", "priv_protocol", "field"),
    [
        ("sha256", "aes128", "auth_protocol"),
        ("sha1", "aes256", "priv_protocol"),
        ("sha1", "aes256-blumenthal", "priv_protocol"),
    ],
)
def test_invalid_v3_protocol_is_rejected_instead_of_silently_remapped(
    monkeypatch: pytest.MonkeyPatch,
    auth_protocol: str,
    priv_protocol: str,
    field: str,
) -> None:
    """The adapter remains strict even when callers bypass config validation."""

    module = _load_gufo(monkeypatch, _Behavior())
    credential = _v3()
    credential.auth_protocol = auth_protocol
    credential.priv_protocol = priv_protocol

    with pytest.raises(SnmpBackendError, match=field):
        module.GufoSnmpClient("192.0.2.40", credential, _config())._construct_session()


def test_unsupported_credential_version_is_rejected_at_adapter_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller bypassing config validation must not be treated as SNMPv3."""

    module = _load_gufo(monkeypatch, _Behavior())
    credential = _v2()
    credential.version = "v1"

    with pytest.raises(SnmpBackendError, match="unsupported SNMP credential version"):
        module.GufoSnmpClient("192.0.2.41", credential, _config())._construct_session()


def _adaptive_state(address: str) -> AdaptiveSnmpState:
    return AdaptiveSnmpState(
        target=address,
        timeout_seconds=2.0,
        max_repetitions=25,
        per_device_rps=5.0,
        retry_per_operation=1,
        retry_per_collector=1,
        retry_total_cap=3,
        retry_neighbor_reserve=2,
        structural_table_retry=1,
        timeout_multiplier=1.5,
        max_repetitions_multiplier=0.5,
        min_max_repetitions=1,
        retry_inter_pdu_delay_ms=100.0,
    )


def test_bracket_compatibility_does_not_consume_adaptive_retry_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    address = "2001:db8::14"
    behavior = _Behavior(construct_errors={address: [OSError("invalid address")]})
    module = _load_gufo(monkeypatch, behavior)
    state = _adaptive_state(address)
    client = AdaptiveSnmpClient(
        lambda profile: module.GufoSnmpClient(
            address,
            _v2(),
            _config(),
            transport_profile=profile,
        ),
        state=state,
    )

    async def exercise() -> None:
        async with client:
            await client.get("1")

    asyncio.run(exercise())
    assert [call["addr"] for call in behavior.calls] == [address, f"[{address}]"]
    assert state.total_retries_used == 0
    assert state.events == []


def test_wrapped_timeout_and_authentication_keep_stable_categories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AuthenticationError(RuntimeError):
        pass

    module = _load_gufo(monkeypatch, _Behavior())
    timeout = SnmpBackendError(
        phase="request",
        attempted_target="2001:db8::15",
        address_family="ipv6",
        operation="GET",
        exc=TimeoutError("request timed out"),
    )
    authentication = SnmpBackendError(
        phase="session_open",
        attempted_target="2001:db8::15",
        address_family="ipv6",
        operation="SESSION-OPEN",
        exc=AuthenticationError("bad credentials"),
    )
    assert module is not None
    assert _error_category(timeout) == "timeout"
    assert _error_category(authentication) == "authentication"


def test_worker_error_redacts_secrets_and_preserves_os_fields() -> None:
    credential = _v3()
    original = OSError(
        101,
        "network failure not-a-real-auth-password not-a-real-privacy-password",
    )
    wrapped = SnmpBackendError(
        phase="request",
        attempted_target="2001:db8::16",
        address_family="ipv6",
        operation="GET",
        exc=original,
    )
    error = _worker_error(
        operation="snmp_basic",
        category=_error_category(wrapped),
        message="safe outer message",
        credential=credential,
        exc=wrapped,
        credential_profile="default",
        credential_stage="primary",
        credential_source="policy-profile",
        collector="system",
    )

    serialized = str(error.to_dict())
    assert error.attempted_target == "2001:db8::16"
    assert error.phase == "request"
    assert error.exception_type == "builtins.OSError"
    assert error.exception_errno == 101
    assert "not-a-real-auth-password" not in serialized
    assert "not-a-real-privacy-password" not in serialized
    assert "<redacted>" in serialized
