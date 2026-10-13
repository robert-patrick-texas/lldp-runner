"""Deterministic tests for the standalone direct-PySNMP diagnostic."""

from __future__ import annotations

import asyncio
import importlib.util
import os
import socket
import subprocess
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

TOOL = Path(__file__).parents[1] / "scripts" / "pysnmp-snmp-diag.py"


def _load_tool():
    """Load the standalone script without importing LLDP-Runner."""

    spec = importlib.util.spec_from_file_location("pysnmp_snmp_diag_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _args(*, snmp_version: str = "2c") -> SimpleNamespace:
    """Return the stable subset of parsed arguments used by probe tests."""

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


class _Pretty:
    """Small PyASN1-like value used by the fake response."""

    def __init__(self, text: str, octets: bytes | None = None) -> None:
        self.text = text
        self.octets = octets

    def prettyPrint(self) -> str:
        return self.text

    def asOctets(self) -> bytes:
        if self.octets is None:
            raise TypeError("value has no octet representation")
        return self.octets

    def __repr__(self) -> str:
        return f"_Pretty({self.text!r})"


class _Status:
    """Boolean and integer-compatible fake PDU status/index value."""

    def __init__(self, value: int, text: str = "noError") -> None:
        self.value = value
        self.text = text

    def __bool__(self) -> bool:
        return bool(self.value)

    def __int__(self) -> int:
        return self.value

    def prettyPrint(self) -> str:
        return self.text


class _Engine:
    """Fake engine recording construction and dispatcher closure."""

    construct_error: BaseException | None = None
    close_error: BaseException | None = None
    calls: ClassVar[list[tuple[str, object]]] = []

    def __init__(self) -> None:
        type(self).calls.append(("engine_construct", None))
        if type(self).construct_error is not None:
            raise type(self).construct_error

    def close_dispatcher(self) -> None:
        type(self).calls.append(("dispatcher_close", None))
        if type(self).close_error is not None:
            raise type(self).close_error


class _TransportBase:
    """Fake async transport-target factory shared by IPv4 and IPv6."""

    create_error: BaseException | None = None
    calls: ClassVar[list[tuple[type[object], tuple[str, int], float, int]]] = []

    @classmethod
    async def create(
        cls,
        address: tuple[str, int],
        *,
        timeout: float,
        retries: int,
    ) -> object:
        cls.calls.append((cls, address, timeout, retries))
        if cls.create_error is not None:
            raise cls.create_error
        return SimpleNamespace(address=address, timeout=timeout, retries=retries)


class _UdpTarget(_TransportBase):
    pass


class _Udp6Target(_TransportBase):
    pass


class _CommunityData:
    """Capture SNMPv2c construction without exposing a real secret."""

    calls: ClassVar[list[tuple[str, int]]] = []

    def __init__(self, community: str, *, mpModel: int) -> None:
        type(self).calls.append((community, mpModel))
        self.community = community
        self.mp_model = mpModel


class _UsmUserData:
    """Capture SNMPv3 construction and protocol mapping."""

    calls: ClassVar[list[tuple[str, dict[str, object]]]] = []

    def __init__(self, username: str, **kwargs: object) -> None:
        type(self).calls.append((username, kwargs))
        self.username = username
        self.kwargs = kwargs


class _ContextData:
    pass


class _ObjectIdentity:
    def __init__(self, oid: str) -> None:
        self.oid = oid


class _ObjectType:
    def __init__(self, identity: _ObjectIdentity) -> None:
        self.identity = identity


class _FakeApiState:
    """Mutable result and call capture for the fake get_cmd coroutine."""

    def __init__(self) -> None:
        self.result: tuple[object, object, object, object] = (
            None,
            _Status(0),
            _Status(0),
            [
                (
                    _Pretty("1.3.6.1.2.1.1.1.0"),
                    _Pretty("system description", b"system description"),
                )
            ],
        )
        self.error: BaseException | None = None
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def get_cmd(self, *args: object, **kwargs: object):
        self.calls.append((args, kwargs))
        if self.error is not None:
            raise self.error
        return self.result


def _reset_fakes() -> None:
    """Reset mutable fake state so tests do not influence one another."""

    _Engine.construct_error = None
    _Engine.close_error = None
    _Engine.calls = []
    _TransportBase.create_error = None
    _TransportBase.calls = []
    _CommunityData.calls = []
    _UsmUserData.calls = []


def _api(module, state: _FakeApiState | None = None):
    """Build the script's runtime API record from deterministic fakes."""

    state = state or _FakeApiState()
    return module.PySnmpApi(
        module=SimpleNamespace(__file__=str(TOOL)),
        snmp_engine_class=_Engine,
        community_data_class=_CommunityData,
        usm_user_data_class=_UsmUserData,
        udp_target_class=_UdpTarget,
        udp6_target_class=_Udp6Target,
        context_data_class=_ContextData,
        object_identity_class=_ObjectIdentity,
        object_type_class=_ObjectType,
        get_cmd=state.get_cmd,
        auth_sha1="AUTH-SHA1",
        auth_md5="AUTH-MD5",
        auth_sha256="AUTH-SHA256",
        priv_aes128="PRIV-AES128",
        priv_aes256="PRIV-AES256",
        priv_aes256_blumenthal="PRIV-AES256-BLUMENTHAL",
        priv_des="PRIV-DES",
        distribution_version="7.1.29-fake",
    ), state


def _target(module):
    return module.ResolvedTarget(
        address="2001:db8::1",
        family=socket.AF_INET6,
        source="numeric-literal",
        normalized="2001:db8::1",
    )


def _probe(module, capsys, *, state: _FakeApiState | None = None):
    _reset_fakes()
    api, state = _api(module, state)
    totals = module.ProbeTotals()
    result = asyncio.run(
        module.probe_once(
            args=_args(),
            target=_target(module),
            pysnmp=api,
            security_data=SimpleNamespace(kind="community"),
            attempt_number=1,
            totals=totals,
            redactor=module.SecretRedactor(replacements=(("not-printed", "<redacted:SNMPCOMM>"),)),
        )
    )
    captured = capsys.readouterr()
    return result, totals, captured.out, captured.err, state


def test_parser_accepts_sha256_and_both_aes256_names() -> None:
    """Operator spellings are explicit and do not expose an aes256-reeder alias."""

    module = _load_tool()
    parser = module.build_parser()
    for privacy in ("aes256", "aes256-blumenthal"):
        args = parser.parse_args(
            [
                "192.0.2.1",
                "--snmp-version",
                "3",
                "--auth-protocol",
                "sha256",
                "--priv-protocol",
                privacy,
            ]
        )
        assert args.auth_protocol == "sha256"
        assert args.priv_protocol == privacy
    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "192.0.2.1",
                "--snmp-version",
                "3",
                "--priv-protocol",
                "aes256-reeder",
            ]
        )


def test_help_does_not_import_pysnmp() -> None:
    """The usage path must work before dependencies are installed."""

    result = subprocess.run(
        [sys.executable, str(TOOL), "--help"],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", "")},
    )
    assert result.returncode == 0
    assert "Query a device directly with PySNMP" in result.stdout
    assert result.stderr == ""


def test_success_uses_ipv6_target_zero_retries_and_closes_dispatcher(capsys) -> None:
    """A successful probe should exercise every PySNMP lifecycle boundary."""

    module = _load_tool()
    result, totals, stdout, stderr, state = _probe(module, capsys)

    assert result is True
    assert totals.sessions_attempted == 1
    assert totals.sessions_succeeded == 1
    assert totals.sessions_failed == 0
    assert totals.gets_succeeded == 1
    assert totals.gets_failed == 0
    assert _Engine.calls == [
        ("engine_construct", None),
        ("dispatcher_close", None),
    ]
    assert _TransportBase.calls == [(_Udp6Target, ("2001:db8::1", 161), 5.0, 0)]
    assert len(state.calls) == 1
    positional, keyword = state.calls[0]
    assert len(positional) == 5
    assert isinstance(positional[3], _ContextData)
    assert isinstance(positional[4], _ObjectType)
    assert positional[4].identity.oid == "1.3.6.1.2.1.1.1.0"
    assert keyword == {"lookupMib": False}
    assert "transport_target_construct: success" in stdout
    assert "GET 1.3.6.1.2.1.1.1.0: success" in stdout
    assert "returned_oid=1.3.6.1.2.1.1.1.0" in stdout
    assert "hex=73:79:73:74:65:6d" in stdout
    assert "dispatcher_close: success" in stdout
    assert "result: SUCCESS" in stdout
    assert stderr == ""


@pytest.mark.parametrize(
    ("failure", "phase", "exception_type"),
    [
        ("engine", "engine_construct", "builtins.OSError"),
        ("target", "transport_target_construct", "builtins.OSError"),
        ("request", "get:1.3.6.1.2.1.1.1.0", "builtins.TimeoutError"),
        ("close", "dispatcher_close", "builtins.OSError"),
    ],
)
def test_failures_report_phase_and_original_exception(
    capsys,
    failure: str,
    phase: str,
    exception_type: str,
) -> None:
    """Construction, request, and close failures remain distinguishable."""

    module = _load_tool()
    _reset_fakes()
    state = _FakeApiState()
    if failure == "engine":
        _Engine.construct_error = OSError("engine failed")
    elif failure == "target":
        _TransportBase.create_error = OSError(101, "network unreachable")
    elif failure == "request":
        state.error = TimeoutError("request timed out")
    elif failure == "close":
        _Engine.close_error = OSError(5, "close failed")

    api, state = _api(module, state)
    totals = module.ProbeTotals()
    result = asyncio.run(
        module.probe_once(
            args=_args(),
            target=_target(module),
            pysnmp=api,
            security_data=SimpleNamespace(kind="community"),
            attempt_number=1,
            totals=totals,
            redactor=module.SecretRedactor(replacements=()),
        )
    )
    captured = capsys.readouterr()

    assert result is False
    assert totals.sessions_failed == 1
    assert f"phase: {phase}" in captured.err
    assert f"exception_type: {exception_type}" in captured.err
    assert "address: 2001:db8::1" in captured.err
    assert "result: FAILURE" in captured.out
    if failure == "engine":
        assert _Engine.calls == [("engine_construct", None)]
        assert _TransportBase.calls == []
    elif failure == "target":
        assert _Engine.calls[-1] == ("dispatcher_close", None)
    else:
        assert _Engine.calls[-1] == ("dispatcher_close", None)


def test_engine_and_pdu_response_errors_are_reported_and_closed(capsys) -> None:
    """Both errorIndication and PDU errorStatus paths fail the GET cleanly."""

    module = _load_tool()

    engine_state = _FakeApiState()
    engine_state.result = (
        _Pretty("No SNMP response received before timeout"),
        _Status(0),
        _Status(0),
        [],
    )
    result, totals, _stdout, stderr, _state = _probe(
        module,
        capsys,
        state=engine_state,
    )
    assert result is False
    assert totals.gets_failed == 1
    assert "PySnmpEngineResponseError" in stderr
    assert "No SNMP response received before timeout" in stderr
    assert _Engine.calls[-1] == ("dispatcher_close", None)

    pdu_state = _FakeApiState()
    pdu_state.result = (
        None,
        _Status(16, "authorizationError"),
        _Status(1, "1"),
        [(_Pretty("1.3.6.1.2.1.1.1.0"), _Pretty("", b""))],
    )
    result, totals, _stdout, stderr, _state = _probe(
        module,
        capsys,
        state=pdu_state,
    )
    assert result is False
    assert totals.gets_failed == 1
    assert "PySnmpPduResponseError" in stderr
    assert "authorizationError at 1.3.6.1.2.1.1.1.0" in stderr
    assert _Engine.calls[-1] == ("dispatcher_close", None)


def test_v2c_security_uses_mp_model_one_and_redacts_community(monkeypatch) -> None:
    """SNMPv2c uses CommunityData without printing the environment value."""

    module = _load_tool()
    _reset_fakes()
    monkeypatch.setenv("SNMPCOMM", "diagnostic-community-secret")
    api, _state = _api(module)
    warning_filter_calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_install_temporary_pysnmp_cfb_warning_filter",
        lambda: warning_filter_calls.append("aes128"),
    )

    security = module.build_security_data(_args(), api)

    assert isinstance(security, _CommunityData)
    assert warning_filter_calls == []
    assert _CommunityData.calls == [("diagnostic-community-secret", 1)]
    redactor = module.SecretRedactor.from_environment()
    rendered = redactor.redact("failure: diagnostic-community-secret")
    assert rendered == "failure: <redacted:SNMPCOMM>"


def test_v3_security_maps_existing_auth_priv_options_and_redacts(monkeypatch) -> None:
    """The diagnostic supports the same four v3 algorithms as LLDP-Runner."""

    module = _load_tool()
    _reset_fakes()
    values = {
        "SNMPUSER": "diagnostic-user",
        "SNMPAUTH": "diagnostic-auth-secret",
        "SNMPPRIV": "diagnostic-priv-secret",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    api, _state = _api(module)
    args = _args(snmp_version="3")
    args.auth_protocol = "md5"
    args.priv_protocol = "des"
    warning_filter_calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_install_temporary_pysnmp_cfb_warning_filter",
        lambda: warning_filter_calls.append("aes128"),
    )

    security = module.build_security_data(args, api)

    assert isinstance(security, _UsmUserData)
    assert warning_filter_calls == []
    username, kwargs = _UsmUserData.calls[-1]
    assert username == values["SNMPUSER"]
    assert kwargs == {
        "authKey": values["SNMPAUTH"],
        "privKey": values["SNMPPRIV"],
        "authProtocol": "AUTH-MD5",
        "privProtocol": "PRIV-DES",
    }
    redactor = module.SecretRedactor.from_environment()
    rendered = redactor.redact(" ".join(values.values()))
    assert rendered == ("<redacted:SNMPUSER> <redacted:SNMPAUTH> <redacted:SNMPPRIV>")


@pytest.mark.parametrize(
    ("priv_protocol", "expected_priv"),
    [
        ("aes256", "PRIV-AES256"),
        ("aes256-blumenthal", "PRIV-AES256-BLUMENTHAL"),
    ],
)
def test_v3_security_maps_sha256_and_aes256_variants(
    monkeypatch,
    priv_protocol: str,
    expected_priv: str,
) -> None:
    """The diagnostic maps the new names to distinct PySNMP public constants."""

    module = _load_tool()
    _reset_fakes()
    for name, value in {
        "SNMPUSER": "diagnostic-user",
        "SNMPAUTH": "diagnostic-auth-secret",
        "SNMPPRIV": "diagnostic-priv-secret",
    }.items():
        monkeypatch.setenv(name, value)
    api, _state = _api(module)
    args = _args(snmp_version="3")
    args.auth_protocol = "sha256"
    args.priv_protocol = priv_protocol
    monkeypatch.setattr(
        module,
        "_install_temporary_pysnmp_cfb_warning_filter",
        lambda: None,
    )

    security = module.build_security_data(args, api)

    assert isinstance(security, _UsmUserData)
    username, kwargs = _UsmUserData.calls[-1]
    assert username == "diagnostic-user"
    assert kwargs == {
        "authKey": "diagnostic-auth-secret",
        "privKey": "diagnostic-priv-secret",
        "authProtocol": "AUTH-SHA256",
        "privProtocol": expected_priv,
    }


@pytest.mark.parametrize("priv_protocol", ["aes128", "aes256", "aes256-blumenthal"])
def test_v3_aes_security_installs_known_warning_filter(
    monkeypatch,
    priv_protocol: str,
) -> None:
    """The diagnostic installs the compatibility filter only for AES authPriv."""

    module = _load_tool()
    _reset_fakes()
    for name, value in {
        "SNMPUSER": "diagnostic-user",
        "SNMPAUTH": "diagnostic-auth-secret",
        "SNMPPRIV": "diagnostic-priv-secret",
    }.items():
        monkeypatch.setenv(name, value)
    api, _state = _api(module)
    calls: list[str] = []
    monkeypatch.setattr(
        module,
        "_install_temporary_pysnmp_cfb_warning_filter",
        lambda: calls.append("aes128"),
    )

    args = _args(snmp_version="3")
    args.priv_protocol = priv_protocol
    module.build_security_data(args, api)

    assert calls == ["aes128"]


@pytest.mark.parametrize(
    ("protocol", "key_length"),
    [
        ("aes128", 16),
        ("aes256", 32),
        ("aes256-blumenthal", 32),
    ],
)
def test_diagnostic_aes_probe_uses_decrepit_cfb_namespace_and_key_size(
    monkeypatch,
    protocol: str,
    key_length: int,
) -> None:
    """The standalone preflight mirrors each integrated AES primitive probe."""

    module = _load_tool()
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

    ciphers = SimpleNamespace(
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
        module._probe_privacy_cipher(protocol)

    assert imports[:2] == [
        "cryptography.hazmat.primitives.ciphers",
        "cryptography.hazmat.decrepit.ciphers.modes",
    ]
    assert cipher_calls == [
        (("aes", bytes(range(key_length))), ("cfb", bytes(16))),
    ]


def test_diagnostic_temporary_cfb_warning_filter_is_exact(monkeypatch) -> None:
    """The standalone diagnostic leaves every unrelated warning observable."""

    module = _load_tool()

    class FakeCryptographyDeprecationWarning(Warning):
        pass

    cryptography_utils = SimpleNamespace(
        CryptographyDeprecationWarning=FakeCryptographyDeprecationWarning
    )
    real_import = module.importlib.import_module

    def fake_import(name: str) -> object:
        if name == "cryptography.utils":
            return cryptography_utils
        return real_import(name)

    monkeypatch.setattr(module.importlib, "import_module", fake_import)
    exact_module = "pysnmp.proto.secmod.rfc3826.priv.aes"
    exact_message = module.PYSNMP_AES_CFB_DEPRECATION_MESSAGE

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


def test_v3_crypto_preflight_is_local_deterministic_and_sanitized(monkeypatch) -> None:
    """The diagnostic should expose provider failure before DNS or SNMP work."""

    module = _load_tool()
    checked: list[str] = []
    monkeypatch.setattr(
        module,
        "package_version",
        lambda distribution: "50.0.1" if distribution == "cryptography" else "unknown",
    )
    monkeypatch.setattr(module, "_probe_privacy_cipher", checked.append)

    assert module.preflight_authpriv("aes128") == "50.0.1"
    assert checked == ["aes128"]

    monkeypatch.setattr(module, "package_version", lambda _distribution: "49.0.0")
    with pytest.raises(
        module.PySnmpCryptoCapabilityError,
        match=r"cryptography>=50\.0",
    ):
        module.preflight_authpriv("des")


def test_ciphering_services_error_has_local_capability_category() -> None:
    module = _load_tool()

    assert (
        module.classify_exception(RuntimeError("Ciphering services not available"))
        == "local_crypto_capability"
    )


def test_dns_family_filter_and_literal_mismatch(monkeypatch) -> None:
    """Resolution honors -4/-6 and never brackets canonical IPv6 input."""

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
    assert targets[0].normalized == "2001:db8::10"

    kind, targets = module.resolve_target(
        "[2001:db8::10]",
        port=161,
        family=socket.AF_INET6,
        first_address=False,
    )
    assert kind == "numeric-literal"
    assert targets[0].address == "2001:db8::10"

    with pytest.raises(ValueError, match="IPv4 was forced"):
        module.resolve_target(
            "2001:db8::10",
            port=161,
            family=socket.AF_INET,
            first_address=False,
        )


def test_load_pysnmp_rejects_incomplete_api(monkeypatch) -> None:
    """An incompatible installed package should fail before any network request."""

    module = _load_tool()
    fake_module = SimpleNamespace(SnmpEngine=object)
    monkeypatch.setattr(module.importlib, "import_module", lambda _name: fake_module)

    with pytest.raises(RuntimeError, match=r"lacks required 7\.1 asyncio API"):
        module.load_pysnmp()


def test_installed_pysnmp_exposes_required_api_when_available() -> None:
    """Exercise the real package API in release environments that installed it."""

    module = _load_tool()
    try:
        api = module.load_pysnmp()
    except RuntimeError as exc:
        pytest.skip(f"pysnmp is not installed in this test environment: {exc}")

    assert api.distribution_version != "unknown"
    assert callable(api.snmp_engine_class)
    assert callable(api.get_cmd)
    assert callable(api.udp_target_class.create)
    assert callable(api.udp6_target_class.create)
    assert module.preflight_authpriv("aes128") != "unknown"
    assert module.preflight_authpriv("aes256") != "unknown"
    assert module.preflight_authpriv("aes256-blumenthal") != "unknown"
    assert module.preflight_authpriv("des") != "unknown"
