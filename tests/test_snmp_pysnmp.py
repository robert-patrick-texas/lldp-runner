"""Deterministic PySNMP 7.1 asyncio backend tests using a fake public API."""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import sys
import types
import warnings
from dataclasses import dataclass, field
from typing import Any

import pytest

from lldp_runner.config import SnmpConfig
from lldp_runner.models import DirectCredential
from lldp_runner.snmp.base import (
    SnmpAuthenticationError,
    SnmpAuthorizationError,
    SnmpBackendCapabilityError,
    SnmpBackendError,
    SnmpEngineResponseError,
    SnmpMalformedResponseError,
    SnmpPduResponseError,
    SnmpTimeoutError,
    SnmpTransportError,
)
from lldp_runner.snmp.resilience import AdaptiveSnmpClient, AdaptiveSnmpState
from lldp_runner.worker import _error_category


class ObjectName:
    def __init__(self, value: str) -> None:
        self.value = value

    def prettyPrint(self) -> str:
        return self.value


class OctetString:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def asOctets(self) -> bytes:
        return self.value

    def prettyPrint(self) -> str:
        return self.value.decode("utf-8", errors="replace")


class Integer32:
    def __init__(self, value: int) -> None:
        self.value = value

    def __int__(self) -> int:
        return self.value

    def prettyPrint(self) -> str:
        return str(self.value)


class ObjectIdentifier:
    def __init__(self, value: str) -> None:
        self.value = value

    def prettyPrint(self) -> str:
        return self.value


class IpAddress:
    def __init__(self, value: str) -> None:
        self.value = value

    def prettyPrint(self) -> str:
        return self.value


class EngineId:
    def __init__(self, value: bytes) -> None:
        self.value = value

    def asOctets(self) -> bytes:
        return self.value


@dataclass
class Behavior:
    engines: list[Any] = field(default_factory=list)
    targets: list[dict[str, Any]] = field(default_factory=list)
    security: list[Any] = field(default_factory=list)
    get_calls: list[tuple[Any, ...]] = field(default_factory=list)
    walk_calls: list[tuple[Any, ...]] = field(default_factory=list)
    responses: list[object] = field(default_factory=list)
    walk_responses: list[object] = field(default_factory=list)
    engine_error: BaseException | None = None
    observer_error: BaseException | None = None
    target_error: BaseException | None = None
    target_cancel: bool = False
    request_error: BaseException | None = None
    walk_error: BaseException | None = None
    close_error: BaseException | None = None
    remote_engine_id: bytes = b"\x80\x00\x00\x7f"


class _Identity:
    def __init__(self, oid: str) -> None:
        self.oid = oid


class _ObjectType:
    def __init__(self, identity: _Identity) -> None:
        self.identity = identity


class _Observer:
    def __init__(self, behavior: Behavior, engine: Any) -> None:
        self.behavior = behavior
        self.engine = engine
        self.callbacks: list[tuple[Any, tuple[str, ...]]] = []

    def register_observer(self, callback: Any, *points: str) -> None:
        if self.behavior.observer_error is not None:
            raise self.behavior.observer_error
        self.callbacks.append((callback, points))

    def unregister_observer(self, callback: Any) -> None:
        self.callbacks = [item for item in self.callbacks if item[0] is not callback]

    def emit_response(self) -> None:
        for callback, points in list(self.callbacks):
            if "rfc3412.prepareDataElements:response" in points:
                callback(
                    self.engine,
                    "rfc3412.prepareDataElements:response",
                    {"securityEngineId": EngineId(self.behavior.remote_engine_id)},
                    None,
                )


def _install_fake_pysnmp(monkeypatch: pytest.MonkeyPatch, behavior: Behavior):
    """Install the exact current public module path consumed by the adapter."""

    class FakeEngine:
        def __init__(self) -> None:
            if behavior.engine_error is not None:
                raise behavior.engine_error
            self.local_engine_id = b"LOCAL-MANAGER-ID"
            self.closed = False
            self.observer = _Observer(behavior, self)
            behavior.engines.append(self)

        def close_dispatcher(self) -> None:
            self.closed = True
            if behavior.close_error is not None:
                raise behavior.close_error

    class CommunityData:
        def __init__(self, community: str, *, mpModel: int) -> None:
            self.community = community
            self.mpModel = mpModel
            behavior.security.append(self)

    class UsmUserData:
        def __init__(self, username: str, **kwargs: Any) -> None:
            self.username = username
            self.kwargs = kwargs
            behavior.security.append(self)

    class UdpTransportTarget:
        family = "ipv4"

        @classmethod
        async def create(cls, destination: tuple[str, int], **kwargs: Any) -> Any:
            behavior.targets.append({"family": cls.family, "destination": destination, **kwargs})
            if behavior.target_cancel:
                raise asyncio.CancelledError
            if behavior.target_error is not None:
                raise behavior.target_error
            return {"family": cls.family, "destination": destination, **kwargs}

    class Udp6TransportTarget(UdpTransportTarget):
        family = "ipv6"

    class ContextData:
        pass

    async def get_cmd(*args: Any, **kwargs: Any) -> object:
        behavior.get_calls.append((*args, kwargs))
        engine = args[0]
        engine.observer.emit_response()
        if behavior.request_error is not None:
            raise behavior.request_error
        if behavior.responses:
            return behavior.responses.pop(0)
        objects = args[4:]
        return (
            None,
            0,
            0,
            [
                (ObjectName(item.identity.oid), OctetString(item.identity.oid.encode()))
                for item in objects
            ],
        )

    async def bulk_walk_cmd(*args: Any, **kwargs: Any):
        behavior.walk_calls.append((*args, kwargs))
        engine = args[0]
        engine.observer.emit_response()
        if behavior.walk_error is not None:
            raise behavior.walk_error
        responses = behavior.walk_responses or [
            (None, 0, 0, [(ObjectName("1.3.6.1.2.1.1.1.0"), OctetString(b"row"))])
        ]
        for response in responses:
            yield response

    module = types.ModuleType("pysnmp.hlapi.v3arch.asyncio")
    public = {
        "SnmpEngine": FakeEngine,
        "CommunityData": CommunityData,
        "UsmUserData": UsmUserData,
        "UdpTransportTarget": UdpTransportTarget,
        "Udp6TransportTarget": Udp6TransportTarget,
        "ContextData": ContextData,
        "ObjectIdentity": _Identity,
        "ObjectType": _ObjectType,
        "get_cmd": get_cmd,
        "bulk_walk_cmd": bulk_walk_cmd,
        "USM_AUTH_HMAC96_SHA": "AUTH-SHA1",
        "USM_AUTH_HMAC96_MD5": "AUTH-MD5",
        "USM_AUTH_HMAC192_SHA256": "AUTH-SHA256",
        "USM_PRIV_CFB128_AES": "PRIV-AES128",
        "USM_PRIV_CFB256_AES": "PRIV-AES256",
        "USM_PRIV_CFB256_AES_BLUMENTHAL": "PRIV-AES256-BLUMENTHAL",
        "USM_PRIV_CBC56_DES": "PRIV-DES",
    }
    for name, value in public.items():
        setattr(module, name, value)

    parents = {
        "pysnmp": types.ModuleType("pysnmp"),
        "pysnmp.hlapi": types.ModuleType("pysnmp.hlapi"),
        "pysnmp.hlapi.v3arch": types.ModuleType("pysnmp.hlapi.v3arch"),
    }
    for parent in parents.values():
        parent.__path__ = []  # type: ignore[attr-defined]
    for name, parent in parents.items():
        monkeypatch.setitem(sys.modules, name, parent)
    monkeypatch.setitem(sys.modules, "pysnmp.hlapi.v3arch.asyncio", module)
    sys.modules.pop("lldp_runner.snmp.pysnmp", None)
    return importlib.import_module("lldp_runner.snmp.pysnmp")


def _config() -> SnmpConfig:
    return SnmpConfig(
        backend="pysnmp",
        timeout_seconds=2.5,
        max_repetitions=17,
        per_device_rps=5.0,
    )


def _v2() -> DirectCredential:
    return DirectCredential(name="v2", version="v2c", community="private-value")


def _v3(*, auth: str = "sha1", priv: str = "aes128") -> DirectCredential:
    return DirectCredential(
        name="v3",
        version="v3",
        username="network-user",
        auth_password="auth-secret",
        priv_password="priv-secret",
        auth_protocol=auth,
        priv_protocol=priv,
    )


def test_authpriv_preflight_probes_each_distinct_supported_cipher(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The local startup probe is deterministic and never opens a transport."""

    behavior = Behavior()
    module = _install_fake_pysnmp(monkeypatch, behavior)
    checked: list[str] = []
    monkeypatch.setattr(module, "_installed_cryptography_version", lambda: "50.0.1")
    monkeypatch.setattr(
        module,
        "_probe_cryptography_privacy_protocol",
        checked.append,
    )

    module.preflight_pysnmp_authpriv(("des", "aes256", "aes128", "aes256-blumenthal", "aes128"))

    assert checked == ["aes128", "aes256", "aes256-blumenthal", "des"]
    assert behavior.engines == []
    assert behavior.targets == []


@pytest.mark.parametrize("version", ["not-installed", "unknown", "49.9.9"])
def test_authpriv_preflight_rejects_missing_or_old_cryptography(
    monkeypatch: pytest.MonkeyPatch,
    version: str,
) -> None:
    behavior = Behavior()
    module = _install_fake_pysnmp(monkeypatch, behavior)
    monkeypatch.setattr(module, "_installed_cryptography_version", lambda: version)

    with pytest.raises(
        SnmpBackendCapabilityError,
        match=r"cryptography>=50\.0 is required",
    ):
        module.preflight_pysnmp_authpriv(("aes128",))

    assert behavior.engines == []
    assert behavior.targets == []


@pytest.mark.parametrize(
    ("protocol", "key_length"),
    [
        ("aes128", 16),
        ("aes256", 32),
        ("aes256-blumenthal", 32),
    ],
)
def test_aes_capability_probe_uses_decrepit_cfb_namespace_and_key_size(
    monkeypatch: pytest.MonkeyPatch,
    protocol: str,
    key_length: int,
) -> None:
    """Each AES mapping probes CFB with its actual key size and supported import."""

    module = _install_fake_pysnmp(monkeypatch, Behavior())
    imports: list[str] = []
    cipher_calls: list[tuple[object, object]] = []

    class Algorithms:
        @staticmethod
        def AES(key: bytes) -> tuple[str, bytes]:
            return ("aes", key)

    class PrimitiveModes:
        @staticmethod
        def CFB(_iv: bytes) -> object:
            raise AssertionError("deprecated primitives CFB path was used")

    class DecrepitModes:
        @staticmethod
        def CFB(iv: bytes) -> tuple[str, bytes]:
            return ("cfb", iv)

    class Encryptor:
        def update(self, value: bytes) -> bytes:
            return value

        def finalize(self) -> bytes:
            return b""

    class Cipher:
        def __init__(self, algorithm: object, mode: object) -> None:
            cipher_calls.append((algorithm, mode))

        def encryptor(self) -> Encryptor:
            return Encryptor()

    ciphers = types.SimpleNamespace(
        Cipher=Cipher,
        algorithms=Algorithms,
        modes=PrimitiveModes,
    )
    real_import = module.importlib.import_module

    def fake_import(name: str) -> object:
        imports.append(name)
        if name == "cryptography.hazmat.primitives.ciphers":
            return ciphers
        if name == "cryptography.hazmat.decrepit.ciphers.modes":
            return DecrepitModes
        return real_import(name)

    monkeypatch.setattr(module.importlib, "import_module", fake_import)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        module._probe_cryptography_privacy_protocol(protocol)

    assert imports[:2] == [
        "cryptography.hazmat.primitives.ciphers",
        "cryptography.hazmat.decrepit.ciphers.modes",
    ]
    assert cipher_calls == [
        (("aes", bytes(range(key_length))), ("cfb", bytes(16))),
    ]


def test_temporary_pysnmp_cfb_warning_filter_is_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only the known PySNMP warning is hidden; all nearby warnings remain visible."""

    module = _install_fake_pysnmp(monkeypatch, Behavior())

    class FakeCryptographyDeprecationWarning(Warning):
        pass

    cryptography_utils = types.SimpleNamespace(
        CryptographyDeprecationWarning=FakeCryptographyDeprecationWarning
    )
    real_import = module.importlib.import_module

    def fake_import(name: str) -> object:
        if name == "cryptography.utils":
            return cryptography_utils
        return real_import(name)

    monkeypatch.setattr(module.importlib, "import_module", fake_import)
    exact_module = "pysnmp.proto.secmod.rfc3826.priv.aes"
    exact_message = module._PYSNMP_AES_CFB_DEPRECATION_MESSAGE

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        module._install_temporary_pysnmp_cfb_warning_filter()
        warnings.warn_explicit(
            exact_message,
            FakeCryptographyDeprecationWarning,
            filename="pysnmp/proto/secmod/rfc3826/priv/aes.py",
            lineno=174,
            module=exact_module,
            registry={},
        )
        warnings.warn_explicit(
            f"{exact_message} changed",
            FakeCryptographyDeprecationWarning,
            filename="pysnmp/proto/secmod/rfc3826/priv/aes.py",
            lineno=175,
            module=exact_module,
            registry={},
        )
        warnings.warn_explicit(
            exact_message,
            FakeCryptographyDeprecationWarning,
            filename="other.py",
            lineno=1,
            module="other.module",
            registry={},
        )
        warnings.warn_explicit(
            exact_message,
            UserWarning,
            filename="pysnmp/proto/secmod/rfc3826/priv/aes.py",
            lineno=176,
            module=exact_module,
            registry={},
        )

    assert [item.category for item in caught] == [
        FakeCryptographyDeprecationWarning,
        FakeCryptographyDeprecationWarning,
        UserWarning,
    ]
    assert str(caught[0].message).endswith(" changed")


def test_warning_filter_is_installed_only_for_pysnmp_v3_aes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SNMPv2c and DES skip the filter; every supported AES mapping installs it."""

    module = _install_fake_pysnmp(monkeypatch, Behavior())
    calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_install_temporary_pysnmp_cfb_warning_filter",
        lambda: calls.append("aes"),
    )

    module.PySnmpClient("192.0.2.30", _v2(), _config())._security()
    module.PySnmpClient("192.0.2.31", _v3(priv="des"), _config())._security()
    assert calls == []

    for index, protocol in enumerate(
        ("aes128", "aes256", "aes256-blumenthal"),
        start=32,
    ):
        module.PySnmpClient(
            f"192.0.2.{index}",
            _v3(priv=protocol),
            _config(),
        )._security()

    assert calls == ["aes", "aes", "aes"]


def test_authpriv_preflight_normalizes_provider_failure_without_secret_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = Behavior()
    module = _install_fake_pysnmp(monkeypatch, behavior)
    monkeypatch.setattr(module, "_installed_cryptography_version", lambda: "50.0.1")

    def fail_probe(_protocol: str) -> None:
        raise RuntimeError("provider rejected fixed probe bytes")

    monkeypatch.setattr(module, "_probe_cryptography_privacy_protocol", fail_probe)

    with pytest.raises(SnmpBackendCapabilityError) as raised:
        module.preflight_pysnmp_authpriv(("aes128",))

    assert "provider rejected" not in str(raised.value)
    assert "auth-secret" not in str(raised.value)
    assert "priv-secret" not in str(raised.value)
    assert behavior.targets == []


def test_v2c_mapping_ipv4_target_and_retries_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    behavior = Behavior()
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> bytes:
        async with module.PySnmpClient("192.0.2.10", _v2(), _config()) as client:
            return await client.get("1.3.6.1.2.1.1.1.0")

    assert asyncio.run(exercise()) == b"1.3.6.1.2.1.1.1.0"
    security = behavior.security[0]
    assert security.community == "private-value"
    assert security.mpModel == 1
    assert behavior.targets == [
        {
            "family": "ipv4",
            "destination": ("192.0.2.10", 161),
            "timeout": 2.5,
            "retries": 0,
        }
    ]
    assert behavior.engines[0].closed is True


@pytest.mark.parametrize(
    ("auth", "priv", "expected_auth", "expected_priv"),
    [
        ("sha1", "aes128", "AUTH-SHA1", "PRIV-AES128"),
        ("md5", "des", "AUTH-MD5", "PRIV-DES"),
        ("sha256", "aes256", "AUTH-SHA256", "PRIV-AES256"),
        (
            "sha256",
            "aes256-blumenthal",
            "AUTH-SHA256",
            "PRIV-AES256-BLUMENTHAL",
        ),
    ],
)
def test_v3_mapping_ipv6_target_and_remote_engine_id(
    monkeypatch: pytest.MonkeyPatch,
    auth: str,
    priv: str,
    expected_auth: str,
    expected_priv: str,
) -> None:
    behavior = Behavior(remote_engine_id=b"\x80\x00\xaa\x55")
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> str | None:
        async with module.PySnmpClient(
            "[2001:db8::10]",
            _v3(auth=auth, priv=priv),
            _config(),
        ) as client:
            await client.get("1.3.6.1.2.1.1.1.0")
            return client.engine_id_hex()

    assert asyncio.run(exercise()) == "8000aa55"
    security = behavior.security[0]
    assert security.username == "network-user"
    assert security.kwargs == {
        "authKey": "auth-secret",
        "privKey": "priv-secret",
        "authProtocol": expected_auth,
        "privProtocol": expected_priv,
    }
    assert behavior.targets[0] == {
        "family": "ipv6",
        "destination": ("2001:db8::10", 161),
        "timeout": 2.5,
        "retries": 0,
    }
    # The fake local manager ID differs intentionally; it must never be reported.
    assert behavior.engines[0].local_engine_id.hex() != "8000aa55"


@pytest.mark.parametrize(
    ("auth", "priv", "field"),
    [
        ("sha512", "aes128", "auth_protocol"),
        ("sha1", "aes192", "priv_protocol"),
        ("sha1", "aes256-reeder", "priv_protocol"),
    ],
)
def test_invalid_v3_protocol_is_rejected_instead_of_silently_remapped(
    monkeypatch: pytest.MonkeyPatch,
    auth: str,
    priv: str,
    field: str,
) -> None:
    """Direct embedders cannot bypass the adapter's capability mapping."""

    behavior = Behavior()
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.PySnmpClient(
            "192.0.2.42",
            _v3(auth=auth, priv=priv),
            _config(),
        ):
            pass

    with pytest.raises(SnmpBackendError, match=field):
        asyncio.run(exercise())
    assert behavior.engines[0].closed is True


def test_unsupported_credential_version_is_rejected_and_engine_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller bypassing config validation must not be treated as SNMPv3."""

    behavior = Behavior()
    module = _install_fake_pysnmp(monkeypatch, behavior)
    credential = _v2()
    credential.version = "v1"

    async def exercise() -> None:
        async with module.PySnmpClient("192.0.2.43", credential, _config()):
            pass

    with pytest.raises(SnmpBackendError, match="unsupported SNMP credential version"):
        asyncio.run(exercise())
    assert behavior.engines[0].closed is True


def test_get_many_and_walk_normalize_native_varbind_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = Behavior(
        responses=[
            (
                None,
                0,
                0,
                [
                    (ObjectName(".1.3.6.1"), OctetString(b"bytes")),
                    (ObjectName("1.3.6.2"), Integer32(42)),
                    (ObjectName("1.3.6.3"), ObjectIdentifier("1.3.6.1.4.1")),
                    (ObjectName("1.3.6.4"), IpAddress("192.0.2.44")),
                ],
            )
        ],
        walk_responses=[
            (None, 0, 0, [(ObjectName(".1.3.6.9.1"), OctetString(b"one"))]),
            (None, 0, 0, [(ObjectName("1.3.6.9.2"), Integer32(2))]),
        ],
    )
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> tuple[dict[str, object], list[tuple[str, object]]]:
        async with module.PySnmpClient("192.0.2.11", _v2(), _config()) as client:
            many = await client.get_many(["1", "2", "3", "4"])
            walked = await client.walk("1.3.6.9")
            return many, walked

    many, walked = asyncio.run(exercise())
    assert many == {
        "1.3.6.1": b"bytes",
        "1.3.6.2": 42,
        "1.3.6.3": "1.3.6.1.4.1",
        "1.3.6.4": "192.0.2.44",
    }
    assert walked == [("1.3.6.9.1", b"one"), ("1.3.6.9.2", 2)]
    walk_args = behavior.walk_calls[0]
    assert walk_args[4:7] == (0, 17, walk_args[6])
    assert walk_args[-1] == {"lookupMib": False, "lexicographicMode": False}


@pytest.mark.parametrize(
    ("response", "error_type"),
    [
        (("No SNMP response received before timeout", 0, 0, []), SnmpTimeoutError),
        (("Ciphering services not available", 0, 0, []), SnmpBackendCapabilityError),
        (("unknownUserName", 0, 0, []), SnmpAuthenticationError),
        (("unknownEngineID", 0, 0, []), SnmpEngineResponseError),
        ((None, "authorizationError", 1, []), SnmpAuthorizationError),
        ((None, "genErr", 1, []), SnmpPduResponseError),
        ((None, 0, 0, "not-varbinds"), SnmpMalformedResponseError),
    ],
)
def test_response_error_normalization(
    monkeypatch: pytest.MonkeyPatch,
    response: object,
    error_type: type[BaseException],
) -> None:
    behavior = Behavior(responses=[response])
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.PySnmpClient("192.0.2.12", _v2(), _config()) as client:
            await client.get("1")

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())
    assert isinstance(raised.value.original_exception, error_type)
    assert behavior.engines[0].closed is True


@pytest.mark.parametrize(
    ("error", "error_type"),
    [
        (TimeoutError("timed out"), SnmpTimeoutError),
        (OSError(101, "network unreachable"), SnmpTransportError),
        (RuntimeError("authentication failure for auth-secret"), SnmpAuthenticationError),
        (
            RuntimeError("Ciphering services not available for priv-secret"),
            SnmpBackendCapabilityError,
        ),
    ],
)
def test_raised_request_errors_are_normalized_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
    error: BaseException,
    error_type: type[BaseException],
) -> None:
    behavior = Behavior(request_error=error)
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.PySnmpClient("192.0.2.13", _v3(), _config()) as client:
            await client.get("1")

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())
    assert isinstance(raised.value.original_exception, error_type)
    assert "auth-secret" not in str(raised.value)
    assert "priv-secret" not in str(raised.value)
    assert behavior.engines[0].closed is True


@pytest.mark.parametrize("failure", ["observer", "target"])
def test_partial_open_failure_closes_dispatcher(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    behavior = Behavior()
    if failure == "observer":
        behavior.observer_error = RuntimeError("observer failed")
    else:
        behavior.target_error = OSError(22, "target failed")
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.PySnmpClient("192.0.2.14", _v3(), _config()):
            pass

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())
    assert raised.value.phase == "session_open"
    assert behavior.engines[0].closed is True


def test_engine_constructor_failure_is_labeled_without_cleanup_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = Behavior(engine_error=RuntimeError("engine constructor failed"))
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.PySnmpClient("192.0.2.15", _v2(), _config()):
            pass

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())
    assert raised.value.phase == "session_construct"
    assert behavior.engines == []


def test_open_and_request_cancellation_preserve_cancelled_error_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    open_behavior = Behavior(target_cancel=True)
    open_module = _install_fake_pysnmp(monkeypatch, open_behavior)

    async def cancel_open() -> None:
        async with open_module.PySnmpClient("192.0.2.16", _v2(), _config()):
            pass

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancel_open())
    assert open_behavior.engines[0].closed is True

    request_behavior = Behavior(request_error=asyncio.CancelledError())
    request_module = _install_fake_pysnmp(monkeypatch, request_behavior)

    async def cancel_request() -> None:
        async with request_module.PySnmpClient("192.0.2.17", _v2(), _config()) as client:
            await client.get("1")

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(cancel_request())
    assert request_behavior.engines[0].closed is True


def test_close_failure_is_normalized_after_dispatcher_close_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = Behavior(close_error=OSError(5, "close failed"))
    module = _install_fake_pysnmp(monkeypatch, behavior)

    async def exercise() -> None:
        async with module.PySnmpClient("192.0.2.18", _v2(), _config()):
            pass

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())
    assert raised.value.phase == "session_close"
    assert isinstance(raised.value.original_exception, SnmpTransportError)
    assert behavior.engines[0].closed is True


def _adaptive_state(address: str) -> AdaptiveSnmpState:
    return AdaptiveSnmpState(
        target=address,
        timeout_seconds=2.5,
        max_repetitions=17,
        per_device_rps=5.0,
        retry_per_operation=1,
        retry_per_collector=1,
        retry_total_cap=3,
        retry_neighbor_reserve=2,
        structural_table_retry=1,
        timeout_multiplier=1.5,
        max_repetitions_multiplier=0.5,
        min_max_repetitions=1,
        retry_inter_pdu_delay_ms=0.0,
    )


def test_lldp_runner_owns_retry_and_every_reopened_target_uses_retries_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    behavior = Behavior(
        responses=[
            ("No SNMP response received before timeout", 0, 0, []),
            (None, 0, 0, [(ObjectName("1"), OctetString(b"ok"))]),
        ]
    )
    module = _install_fake_pysnmp(monkeypatch, behavior)
    address = "192.0.2.19"
    state = _adaptive_state(address)
    client = AdaptiveSnmpClient(
        lambda profile: module.PySnmpClient(
            address,
            _v2(),
            _config(),
            transport_profile=profile,
        ),
        state=state,
    )

    async def exercise() -> object:
        async with client:
            return await client.get("1")

    assert asyncio.run(exercise()) == b"ok"
    assert state.total_retries_used == 1
    assert len(behavior.targets) == 2
    assert all(target["retries"] == 0 for target in behavior.targets)


def test_local_cipher_capability_failure_consumes_no_request_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A deterministic local provider failure must not spend network retry budget."""

    behavior = Behavior(request_error=RuntimeError("Ciphering services not available"))
    module = _install_fake_pysnmp(monkeypatch, behavior)
    address = "192.0.2.20"
    state = _adaptive_state(address)
    client = AdaptiveSnmpClient(
        lambda profile: module.PySnmpClient(
            address,
            _v3(),
            _config(),
            transport_profile=profile,
        ),
        state=state,
    )

    async def exercise() -> None:
        async with client:
            await client.get("1")

    with pytest.raises(SnmpBackendError) as raised:
        asyncio.run(exercise())

    assert isinstance(raised.value.original_exception, SnmpBackendCapabilityError)
    assert _error_category(raised.value) == "snmp_backend_capability"
    assert state.total_retries_used == 0
    assert len(behavior.targets) == 1
    assert behavior.targets[0]["retries"] == 0


def test_installed_pysnmp_authpriv_crypto_when_available() -> None:
    """Exercise both privacy primitives in a fully synchronized release environment."""

    try:
        importlib.metadata.version("pysnmp")
        cryptography_version = importlib.metadata.version("cryptography")
    except importlib.metadata.PackageNotFoundError as exc:
        pytest.skip(f"installed PySNMP authPriv dependencies unavailable: {exc}")
    if tuple(int(part) for part in cryptography_version.split(".")[:2]) < (50, 0):
        pytest.skip(
            f"installed cryptography predates the 0.37.0 release constraint: {cryptography_version}"
        )

    module = importlib.import_module("lldp_runner.snmp.pysnmp")
    module.preflight_pysnmp_authpriv(("aes128", "aes256", "aes256-blumenthal", "des"))
