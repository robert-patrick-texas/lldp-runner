#!/usr/bin/env -S uv run --script

"""Run a direct PySNMP GET diagnostic against IPv4 and/or IPv6 targets.

The script deliberately bypasses LLDP-Runner and does not select or alter the
application's discovery backend. It resolves a literal address or DNS name,
prints the exact address passed to PySNMP, creates a fresh SNMP engine and
transport target, and performs one or more SNMP GET requests. Failures
identify the phase in which they occurred and include exception class,
errno-style fields, arguments, and optional traceback details.

Credentials are read only from environment variables and are never printed:

* SNMPv2c: SNMPCOMM
* SNMPv3 authPriv: SNMPUSER, SNMPAUTH, SNMPPRIV

Examples:

    SNMPCOMM='community' ./pysnmp-snmp-diag.py 192.0.2.10
    SNMPCOMM='community' ./pysnmp-snmp-diag.py 2001:db8::10
    SNMPCOMM='community' ./pysnmp-snmp-diag.py switch.example.net -6
    SNMPUSER='user' SNMPAUTH='authpass' SNMPPRIV='privpass' \
        ./pysnmp-snmp-diag.py switch.example.net --snmp-version 3 -6
    SNMPUSER='user' SNMPAUTH='authpass' SNMPPRIV='privpass' \
        ./pysnmp-snmp-diag.py switch.example.net --snmp-version 3 \
        --auth-protocol sha256 --priv-protocol aes256

By default the script queries sysDescr.0 (1.3.6.1.2.1.1.1.0). Repeat --oid to
query additional numeric OIDs. DNS names are resolved to all matching addresses
in resolver order unless --first-address is used. PySNMP transport retries are
set to zero; no application-level retry is performed unless --repeat is
explicitly greater than one. `aes256` means the common Reeder/Cisco key
localization; `aes256-blumenthal` is the separate Blumenthal mapping. The script
never negotiates or falls back between them. For AES authPriv, it suppresses
only PySNMP 7.1.29's exact known CFB namespace deprecation; unrelated warnings
remain visible.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import importlib.metadata
import ipaddress
import os
import platform
import re
import socket
import sys
import time
import traceback
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_OID = "1.3.6.1.2.1.1.1.0"
CRYPTOGRAPHY_MINIMUM = (50, 0)
PYSNMP_AES_CFB_DEPRECATION_MESSAGE = (
    "CFB has been moved to cryptography.hazmat.decrepit.ciphers.modes.CFB "
    "and will be removed from cryptography.hazmat.primitives.ciphers.modes "
    "in 49.0.0."
)
PYSNMP_AES_CFB_WARNING_MODULE = r"^pysnmp\.proto\.secmod\.rfc3826\.priv\.aes$"
PYSNMP_AES_KEY_LENGTHS = {
    "aes128": 16,
    # USM_PRIV_CFB256_AES is the common Reeder/Cisco localization. The
    # Blumenthal alternative uses the same AES-256 primitive with a different
    # key-localization method inside PySNMP.
    "aes256": 32,
    "aes256-blumenthal": 32,
}
EXIT_OK = 0
EXIT_QUERY_FAILED = 1
EXIT_CONFIGURATION_ERROR = 2


class PySnmpEngineResponseError(RuntimeError):
    """Represent a truthy PySNMP errorIndication response."""


class PySnmpPduResponseError(RuntimeError):
    """Represent a truthy SNMP PDU errorStatus response."""


class PySnmpCryptoCapabilityError(RuntimeError):
    """Represent a missing or unusable local PySNMP privacy provider."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """One concrete destination that will be passed to PySNMP."""

    address: str
    family: int
    source: str
    normalized: str
    canonical_name: str | None = None

    @property
    def family_name(self) -> str:
        """Return an operator-facing address-family name."""

        if self.family == socket.AF_INET:
            return "IPv4"
        if self.family == socket.AF_INET6:
            return "IPv6"
        return f"family-{self.family}"


@dataclass(frozen=True, slots=True)
class PySnmpApi:
    """PySNMP objects imported at runtime so --help works without the package."""

    module: Any
    snmp_engine_class: Any
    community_data_class: Any
    usm_user_data_class: Any
    udp_target_class: Any
    udp6_target_class: Any
    context_data_class: Any
    object_identity_class: Any
    object_type_class: Any
    get_cmd: Any
    auth_sha1: Any
    auth_md5: Any
    auth_sha256: Any
    priv_aes128: Any
    priv_aes256: Any
    priv_aes256_blumenthal: Any
    priv_des: Any
    distribution_version: str


@dataclass(slots=True)
class ProbeTotals:
    """Aggregate success and failure counts across addresses and repetitions."""

    sessions_attempted: int = 0
    sessions_succeeded: int = 0
    sessions_failed: int = 0
    gets_succeeded: int = 0
    gets_failed: int = 0


@dataclass(frozen=True, slots=True)
class SecretRedactor:
    """Remove configured credential values from exception diagnostics."""

    replacements: tuple[tuple[str, str], ...]

    @classmethod
    def from_environment(cls) -> SecretRedactor:
        """Build deterministic longest-first replacements for known credentials."""

        by_value: dict[str, str] = {}
        for name in ("SNMPCOMM", "SNMPUSER", "SNMPAUTH", "SNMPPRIV"):
            value = os.environ.get(name)
            if value:
                by_value.setdefault(value, f"<redacted:{name}>")
        replacements = tuple(sorted(by_value.items(), key=lambda item: len(item[0]), reverse=True))
        return cls(replacements=replacements)

    def redact(self, value: str) -> str:
        """Return text with every known credential value replaced."""

        redacted = value
        for secret, replacement in self.replacements:
            redacted = redacted.replace(secret, replacement)
        return redacted


def positive_int(value: str) -> int:
    """Parse a strictly positive integer for argparse."""

    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def nonnegative_float(value: str) -> float:
    """Parse a finite non-negative float for argparse."""

    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0 or parsed == float("inf") or parsed != parsed:
        raise argparse.ArgumentTypeError("must be a finite value greater than or equal to zero")
    return parsed


def positive_float(value: str) -> float:
    """Parse a finite positive float for argparse."""

    parsed = nonnegative_float(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def port_number(value: str) -> int:
    """Parse a valid UDP port number for argparse."""

    parsed = positive_int(value)
    if parsed > 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return parsed


def numeric_oid(value: str) -> str:
    """Validate and normalize a numeric OID without a leading dot."""

    candidate = value.strip()
    if candidate.startswith("."):
        candidate = candidate[1:]
    parts = candidate.split(".")
    if len(parts) < 2 or any(not part.isdigit() for part in parts):
        raise argparse.ArgumentTypeError("must be a numeric dotted OID such as 1.3.6.1.2.1.1.1.0")
    return ".".join(str(int(part)) for part in parts)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""

    parser = argparse.ArgumentParser(
        description=(
            "Query a device directly with PySNMP and report detailed IPv4/IPv6 "
            "resolution, engine, transport, GET, and exception diagnostics."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Credential environment variables:\n"
            "  SNMPv2c: SNMPCOMM\n"
            "  SNMPv3:  SNMPUSER, SNMPAUTH, SNMPPRIV\n\n"
            "Exit status:\n"
            "  0  every attempted engine/transport and GET succeeded\n"
            "  1  at least one PySNMP engine/transport or GET failed\n"
            "  2  usage, resolution, credential, or import error"
        ),
    )
    parser.add_argument(
        "target",
        help="IPv4 address, IPv6 address, or DNS name",
    )
    family = parser.add_mutually_exclusive_group()
    family.add_argument(
        "-4",
        "--ipv4",
        action="store_true",
        help="resolve/query only IPv4 addresses",
    )
    family.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help="resolve/query only IPv6 addresses",
    )
    parser.add_argument(
        "--snmp-version",
        "--version",
        dest="snmp_version",
        choices=("2c", "3"),
        default="2c",
        help="SNMP version (default: 2c)",
    )
    parser.add_argument(
        "--oid",
        action="append",
        type=numeric_oid,
        metavar="OID",
        help=(f"numeric OID to GET; may be repeated (default: sysDescr.0, {DEFAULT_OID})"),
    )
    parser.add_argument(
        "--port",
        type=port_number,
        default=161,
        help="SNMP UDP port (default: 161)",
    )
    parser.add_argument(
        "--timeout",
        type=positive_float,
        default=5.0,
        metavar="SECONDS",
        help="PySNMP request timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--repeat",
        type=positive_int,
        default=1,
        metavar="COUNT",
        help=("create a fresh engine/transport and repeat each address COUNT times (default: 1)"),
    )
    parser.add_argument(
        "--delay",
        type=nonnegative_float,
        default=0.0,
        metavar="SECONDS",
        help="delay between repeated fresh-engine attempts (default: 0)",
    )
    parser.add_argument(
        "--first-address",
        action="store_true",
        help="for a DNS name, query only the first matching resolved address",
    )
    parser.add_argument(
        "--auth-protocol",
        choices=("sha1", "md5", "sha256"),
        default="sha1",
        help="SNMPv3 authentication protocol (default: sha1)",
    )
    parser.add_argument(
        "--priv-protocol",
        choices=("aes128", "aes256", "aes256-blumenthal", "des"),
        default="aes128",
        help=(
            "SNMPv3 privacy protocol; aes256 is the common Reeder/Cisco mapping (default: aes128)"
        ),
    )
    parser.add_argument(
        "--traceback",
        action="store_true",
        help="print complete Python tracebacks for failures",
    )
    return parser


def forced_family(args: argparse.Namespace) -> int:
    """Return the socket family selected by command-line flags."""

    if args.ipv4:
        return socket.AF_INET
    if args.ipv6:
        return socket.AF_INET6
    return socket.AF_UNSPEC


def strip_ipv6_brackets(value: str) -> str:
    """Accept shell-friendly bracketed IPv6 literals without passing brackets."""

    candidate = value.strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        return candidate[1:-1]
    return candidate


def resolve_target(
    target: str,
    *,
    port: int,
    family: int,
    first_address: bool,
) -> tuple[str, list[ResolvedTarget]]:
    """Resolve a literal or DNS name to concrete PySNMP destination strings."""

    candidate = strip_ipv6_brackets(target)
    try:
        literal = ipaddress.ip_address(candidate)
    except ValueError:
        literal = None

    if literal is not None:
        literal_family = socket.AF_INET if literal.version == 4 else socket.AF_INET6
        if family not in (socket.AF_UNSPEC, literal_family):
            requested = "IPv4" if family == socket.AF_INET else "IPv6"
            actual = "IPv4" if literal.version == 4 else "IPv6"
            raise ValueError(f"target is an {actual} literal but {requested} was forced")
        return "numeric-literal", [
            ResolvedTarget(
                address=candidate,
                family=literal_family,
                source="numeric-literal",
                normalized=literal.compressed,
            )
        ]

    try:
        answers = socket.getaddrinfo(
            candidate,
            port,
            family=family,
            type=socket.SOCK_DGRAM,
            proto=socket.IPPROTO_UDP,
        )
    except socket.gaierror as exc:
        raise RuntimeError(f"DNS/address resolution failed for {candidate!r}: {exc}") from exc

    resolved: list[ResolvedTarget] = []
    seen: set[tuple[int, str]] = set()
    for answer_family, _socktype, _proto, canonical_name, sockaddr in answers:
        if answer_family not in (socket.AF_INET, socket.AF_INET6):
            continue
        address = str(sockaddr[0])
        if answer_family == socket.AF_INET6 and len(sockaddr) == 4:
            scope_id = int(sockaddr[3])
            if scope_id and "%" not in address:
                try:
                    zone = socket.if_indextoname(scope_id)
                except OSError:
                    zone = str(scope_id)
                address = f"{address}%{zone}"
        key = (answer_family, address)
        if key in seen:
            continue
        seen.add(key)
        try:
            normalized = ipaddress.ip_address(address).compressed
        except ValueError:
            normalized = address
        resolved.append(
            ResolvedTarget(
                address=address,
                family=answer_family,
                source="dns",
                normalized=normalized,
                canonical_name=canonical_name or None,
            )
        )

    if not resolved:
        family_text = {
            socket.AF_INET: "IPv4",
            socket.AF_INET6: "IPv6",
            socket.AF_UNSPEC: "IPv4 or IPv6",
        }.get(family, str(family))
        raise RuntimeError(
            f"resolution returned no usable {family_text} UDP addresses for {candidate!r}"
        )
    if first_address:
        resolved = resolved[:1]
    return "dns-name", resolved


def package_version(distribution: str) -> str:
    """Return installed distribution version without failing diagnostics."""

    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _numeric_version_prefix(value: str) -> tuple[int, ...]:
    """Return the leading major/minor numbers needed by the release floor."""

    match = re.match(r"^(\d+)(?:\.(\d+))?", value.strip())
    if match is None:
        return ()
    return tuple(int(part) for part in match.groups(default="0"))


def _install_temporary_pysnmp_cfb_warning_filter() -> None:
    """Hide only PySNMP 7.1.29's known AES-CFB namespace warning.

    This process-level filter is constrained by the exact cryptography warning
    class, complete text, and originating PySNMP module.  It is intentionally
    temporary; changed or unrelated warnings remain visible and should be
    investigated normally.
    """

    try:
        cryptography_utils = importlib.import_module("cryptography.utils")
        category = cryptography_utils.CryptographyDeprecationWarning
    except (ImportError, AttributeError):
        return
    message_pattern = rf"(?-i:^{re.escape(PYSNMP_AES_CFB_DEPRECATION_MESSAGE)}$)"
    warnings.filterwarnings(
        "ignore",
        message=message_pattern,
        category=category,
        module=PYSNMP_AES_CFB_WARNING_MODULE,
    )


def _probe_privacy_cipher(protocol: str) -> None:
    """Execute one fixed-byte AES/DES primitive without operator secrets."""

    ciphers = importlib.import_module("cryptography.hazmat.primitives.ciphers")
    cipher_type = ciphers.Cipher
    aes_key_length = PYSNMP_AES_KEY_LENGTHS.get(protocol)
    if aes_key_length is not None:
        algorithms = getattr(ciphers, "algorithms")  # noqa: B009 - ty: submodule is not imported explicitly
        decrepit_modes = importlib.import_module("cryptography.hazmat.decrepit.ciphers.modes")
        algorithm = algorithms.AES(bytes(range(aes_key_length)))
        mode = decrepit_modes.CFB(bytes(16))
        plaintext = bytes(16)
    elif protocol == "des":
        modes = getattr(ciphers, "modes")  # noqa: B009 - ty: submodule is not imported explicitly
        decrepit = importlib.import_module("cryptography.hazmat.decrepit.ciphers.algorithms")
        algorithm = decrepit.TripleDES(bytes(range(24)))
        mode = modes.CBC(bytes(8))
        plaintext = bytes(8)
    else:
        raise ValueError(f"unsupported privacy protocol {protocol!r}")
    encryptor = cipher_type(algorithm, mode).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    if len(ciphertext) != len(plaintext):
        raise RuntimeError("unexpected ciphertext length")


def preflight_authpriv(priv_protocol: str) -> str:
    """Fail before DNS/SNMP when the selected privacy cipher is unavailable."""

    version = package_version("cryptography")
    parsed = _numeric_version_prefix(version)
    if not parsed or parsed < CRYPTOGRAPHY_MINIMUM:
        raise PySnmpCryptoCapabilityError(
            f"PySNMP authPriv requires cryptography>=50.0 (installed: {version})"
        )
    try:
        _probe_privacy_cipher(priv_protocol)
    except Exception as exc:
        raise PySnmpCryptoCapabilityError(
            "PySNMP authPriv local cipher capability is unavailable for "
            f"{priv_protocol!r} with cryptography {version}"
        ) from exc
    return version


def load_pysnmp() -> PySnmpApi:
    """Import the PySNMP asyncio v3arch API and provide a clear package error."""

    module_name = "pysnmp.hlapi.v3arch.asyncio"
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise RuntimeError(
            "cannot import pysnmp.hlapi.v3arch.asyncio; install the project "
            "dependencies in this Python environment (install with: "
            "python -m pip install pysnmp)"
        ) from exc

    required = (
        "SnmpEngine",
        "CommunityData",
        "UsmUserData",
        "UdpTransportTarget",
        "Udp6TransportTarget",
        "ContextData",
        "ObjectIdentity",
        "ObjectType",
        "get_cmd",
        "USM_AUTH_HMAC96_SHA",
        "USM_AUTH_HMAC96_MD5",
        "USM_AUTH_HMAC192_SHA256",
        "USM_PRIV_CFB128_AES",
        "USM_PRIV_CFB256_AES",
        "USM_PRIV_CFB256_AES_BLUMENTHAL",
        "USM_PRIV_CBC56_DES",
    )
    missing = [name for name in required if not hasattr(module, name)]
    if missing:
        raise RuntimeError(
            "installed PySNMP module lacks required 7.1 asyncio API objects: " + ", ".join(missing)
        )
    return PySnmpApi(
        module=module,
        snmp_engine_class=module.SnmpEngine,
        community_data_class=module.CommunityData,
        usm_user_data_class=module.UsmUserData,
        udp_target_class=module.UdpTransportTarget,
        udp6_target_class=module.Udp6TransportTarget,
        context_data_class=module.ContextData,
        object_identity_class=module.ObjectIdentity,
        object_type_class=module.ObjectType,
        get_cmd=module.get_cmd,
        auth_sha1=module.USM_AUTH_HMAC96_SHA,
        auth_md5=module.USM_AUTH_HMAC96_MD5,
        auth_sha256=module.USM_AUTH_HMAC192_SHA256,
        priv_aes128=module.USM_PRIV_CFB128_AES,
        priv_aes256=module.USM_PRIV_CFB256_AES,
        priv_aes256_blumenthal=module.USM_PRIV_CFB256_AES_BLUMENTHAL,
        priv_des=module.USM_PRIV_CBC56_DES,
        distribution_version=package_version("pysnmp"),
    )


def require_environment(name: str) -> str:
    """Return one non-empty credential environment variable."""

    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"required credential environment variable {name} is not set")
    return value


def build_security_data(args: argparse.Namespace, pysnmp: PySnmpApi) -> Any:
    """Build PySNMP security data without logging secret values."""

    if args.snmp_version == "2c":
        return pysnmp.community_data_class(
            require_environment("SNMPCOMM"),
            mpModel=1,
        )

    username = require_environment("SNMPUSER")
    auth_password = require_environment("SNMPAUTH")
    priv_password = require_environment("SNMPPRIV")
    auth_protocol = {
        "sha1": pysnmp.auth_sha1,
        "md5": pysnmp.auth_md5,
        "sha256": pysnmp.auth_sha256,
    }[args.auth_protocol]
    priv_protocol = {
        "aes128": pysnmp.priv_aes128,
        # ``aes256`` is the common Reeder/Cisco localization. The alternative
        # Blumenthal localization must be selected explicitly.
        "aes256": pysnmp.priv_aes256,
        "aes256-blumenthal": pysnmp.priv_aes256_blumenthal,
        "des": pysnmp.priv_des,
    }[args.priv_protocol]
    if args.priv_protocol in PYSNMP_AES_KEY_LENGTHS:
        _install_temporary_pysnmp_cfb_warning_filter()
    return pysnmp.usm_user_data_class(
        username,
        authKey=auth_password,
        privKey=priv_password,
        authProtocol=auth_protocol,
        privProtocol=priv_protocol,
    )


def qualified_type(exc: BaseException) -> str:
    """Return module-qualified exception type."""

    cls = exc.__class__
    return f"{cls.__module__}.{cls.__qualname__}"


def classify_exception(exc: BaseException) -> str:
    """Assign a compact diagnostic category without hiding the original type."""

    if isinstance(exc, PySnmpEngineResponseError):
        return "pysnmp_engine_error"
    if isinstance(exc, PySnmpPduResponseError):
        return "snmp_pdu_error"
    if isinstance(exc, PySnmpCryptoCapabilityError):
        return "local_crypto_capability"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "name_resolution"
    if isinstance(exc, OSError):
        return "os_error"
    type_text = qualified_type(exc).casefold()
    message = str(exc).casefold()
    compact_message = "".join(character for character in message if character.isalnum())
    if "cipheringservicesnotavailable" in compact_message:
        return "local_crypto_capability"
    if "auth" in type_text or "authentication" in message or "authorization" in message:
        return "authentication_or_authorization"
    if "nosuch" in type_text or "no such" in message:
        return "no_such_object_or_instance"
    if "pysnmp" in type_text or "snmp" in type_text:
        return "snmp_error"
    if isinstance(exc, ValueError):
        return "value_error"
    if isinstance(exc, RuntimeError):
        return "runtime_error"
    return "unexpected_error"


def limited_repr(value: Any, limit: int = 4096) -> str:
    """Return bounded repr text suitable for terminal diagnostics."""

    text = repr(value)
    if len(text) <= limit:
        return text
    return text[: limit - 18] + "...<truncated>"


def pretty_text(value: Any) -> str:
    """Return PySNMP/PyASN1 pretty text with a safe generic fallback."""

    pretty = getattr(value, "prettyPrint", None)
    if callable(pretty):
        try:
            return str(pretty())
        except Exception:
            pass
    return str(value)


def exception_details(
    exc: BaseException,
    *,
    redactor: SecretRedactor,
) -> list[tuple[str, str]]:
    """Extract useful generic and OSError-specific exception fields."""

    details = [
        ("category", classify_exception(exc)),
        ("exception_type", qualified_type(exc)),
        ("message", redactor.redact(str(exc)) if str(exc) else "<empty>"),
        ("repr", redactor.redact(limited_repr(exc))),
        ("args", redactor.redact(limited_repr(exc.args))),
    ]
    for name in ("errno", "strerror", "filename", "filename2", "winerror"):
        if hasattr(exc, name):
            value = getattr(exc, name)
            details.append((name, redactor.redact(limited_repr(value))))
    if exc.__cause__ is not None:
        details.append(("cause_type", qualified_type(exc.__cause__)))
        details.append(("cause", redactor.redact(str(exc.__cause__)) or "<empty>"))
    if exc.__context__ is not None and exc.__context__ is not exc.__cause__:
        details.append(("context_type", qualified_type(exc.__context__)))
        details.append(("context", redactor.redact(str(exc.__context__)) or "<empty>"))
    return details


def print_exception(
    *,
    phase: str,
    address: str,
    family_name: str,
    elapsed: float,
    exc: BaseException,
    include_traceback: bool,
    redactor: SecretRedactor,
) -> None:
    """Render a detailed failure record without credential values."""

    print("  FAILURE", file=sys.stderr, flush=True)
    print(f"    phase: {phase}", file=sys.stderr, flush=True)
    print(f"    address: {address}", file=sys.stderr, flush=True)
    print(f"    address_family: {family_name}", file=sys.stderr, flush=True)
    print(f"    elapsed_seconds: {elapsed:.6f}", file=sys.stderr, flush=True)
    for name, value in exception_details(exc, redactor=redactor):
        print(f"    {name}: {value}", file=sys.stderr, flush=True)
    if include_traceback:
        print("    traceback:", file=sys.stderr, flush=True)
        rendered = traceback.TracebackException.from_exception(exc).format(chain=True)
        for line in rendered:
            for physical_line in line.rstrip("\n").splitlines():
                print(
                    f"      {redactor.redact(physical_line)}",
                    file=sys.stderr,
                    flush=True,
                )


def render_value(value: Any, limit: int = 8192) -> list[str]:
    """Render a PySNMP value with type, pretty text, and byte diagnostics."""

    lines = [f"type={value.__class__.__module__}.{value.__class__.__qualname__}"]
    if isinstance(value, bytes):
        octets = value
    else:
        as_octets = getattr(value, "asOctets", None)
        if callable(as_octets):
            try:
                octets = bytes(as_octets())
            except Exception:
                octets = None
        else:
            octets = None

    pretty = pretty_text(value)
    lines.append(f"pretty={limited_repr(pretty, limit)}")
    if octets is not None:
        decoded = octets.decode("utf-8", errors="backslashreplace")
        lines.append(f"text={limited_repr(decoded, limit)}")
        hex_text = octets.hex(":")
        suffix = "...<truncated>" if len(hex_text) > limit else ""
        lines.append(f"hex={hex_text[:limit]}{suffix}")
    lines.append(f"repr={limited_repr(value, limit)}")
    return lines


def module_path(module: Any) -> str:
    """Return the PySNMP module path when available."""

    value = getattr(module, "__file__", None)
    if value is None:
        return "unknown"
    try:
        return str(Path(value).resolve())
    except OSError:
        return str(value)


def print_header(
    args: argparse.Namespace,
    *,
    target_kind: str,
    targets: Sequence[ResolvedTarget],
    pysnmp: PySnmpApi,
) -> None:
    """Print runtime, resolver, and non-secret SNMP configuration metadata."""

    family_text = "automatic"
    if args.ipv4:
        family_text = "IPv4 forced"
    elif args.ipv6:
        family_text = "IPv6 forced"
    oids = args.oid or [DEFAULT_OID]
    print("PySNMP diagnostic")
    print(f"timestamp_utc: {datetime.now(UTC).isoformat(timespec='milliseconds')}")
    print(f"target_input: {args.target}")
    print(f"target_kind: {target_kind}")
    print(f"address_family_selection: {family_text}")
    print(f"resolved_address_count: {len(targets)}")
    print(f"snmp_version: {args.snmp_version}")
    print(f"snmp_port: {args.port}")
    print(f"timeout_seconds: {args.timeout}")
    print(f"repeat_count: {args.repeat}")
    print(f"oids: {', '.join(oids)}")
    print(f"python_version: {platform.python_version()}")
    print(f"python_executable: {sys.executable}")
    print(f"platform: {platform.platform()}")
    print(f"socket_has_ipv6: {socket.has_ipv6}")
    print(f"pysnmp_version: {pysnmp.distribution_version}")
    print(f"cryptography_version: {package_version('cryptography')}")
    print(f"pysnmp_module_path: {module_path(pysnmp.module)}")
    print("pysnmp_api: pysnmp.hlapi.v3arch.asyncio")
    print("pysnmp_transport_retries: 0")
    if args.snmp_version == "2c":
        print("credentials: SNMPCOMM=<set>; value not displayed")
    else:
        print("credentials: SNMPUSER/SNMPAUTH/SNMPPRIV=<set>; values not displayed")
        print(f"snmpv3_auth_protocol: {args.auth_protocol}")
        print(f"snmpv3_priv_protocol: {args.priv_protocol}")
        print(
            "snmpv3_authoritative_engine_id: not reported by this standalone high-level diagnostic"
        )
    print("application_retries: disabled (use --repeat for fresh-engine repetitions)")
    print()
    print("Resolved destinations")
    for index, target in enumerate(targets, start=1):
        extra = ""
        if target.canonical_name:
            extra = f" canonical_name={target.canonical_name}"
        print(
            f"  {index}. address={target.address} family={target.family_name} "
            f"source={target.source} normalized={target.normalized}{extra}"
        )
    print(flush=True)


async def create_transport_target(
    args: argparse.Namespace,
    target: ResolvedTarget,
    pysnmp: PySnmpApi,
) -> Any:
    """Create an IPv4 or IPv6 PySNMP target with hidden retries disabled."""

    target_class = (
        pysnmp.udp_target_class if target.family == socket.AF_INET else pysnmp.udp6_target_class
    )
    return await target_class.create(
        (target.address, args.port),
        timeout=args.timeout,
        retries=0,
    )


def close_engine(
    engine: Any,
    *,
    address: str,
    family_name: str,
    include_traceback: bool,
    redactor: SecretRedactor,
) -> bool:
    """Close a PySNMP dispatcher and report close failures separately."""

    started = time.perf_counter()
    try:
        engine.close_dispatcher()
    except Exception as exc:
        print_exception(
            phase="dispatcher_close",
            address=address,
            family_name=family_name,
            elapsed=time.perf_counter() - started,
            exc=exc,
            include_traceback=include_traceback,
            redactor=redactor,
        )
        return False
    print(f"  dispatcher_close: success ({time.perf_counter() - started:.6f}s)")
    return True


def pdu_error_message(
    error_status: Any,
    error_index: Any,
    var_binds: Sequence[Any],
) -> str:
    """Build a stable message for a truthy SNMP PDU error status."""

    status = pretty_text(error_status) or limited_repr(error_status)
    try:
        index = int(error_index)
    except (TypeError, ValueError, OverflowError):
        index = 0
    location = "?"
    if 1 <= index <= len(var_binds):
        try:
            location = pretty_text(var_binds[index - 1][0])
        except Exception:
            location = "?"
    return f"{status} at {location} (error_index={index})"


async def query_oid(
    *,
    oid: str,
    engine: Any,
    security_data: Any,
    transport_target: Any,
    pysnmp: PySnmpApi,
) -> tuple[str, Any]:
    """Issue one numeric-OID GET and return the response OID and value."""

    object_type = pysnmp.object_type_class(pysnmp.object_identity_class(oid))
    result = await pysnmp.get_cmd(
        engine,
        security_data,
        transport_target,
        pysnmp.context_data_class(),
        object_type,
        lookupMib=False,
    )
    if not isinstance(result, tuple) or len(result) != 4:
        raise RuntimeError(
            f"PySNMP get_cmd returned an unexpected result shape: {limited_repr(result)}"
        )
    error_indication, error_status, error_index, var_binds = result
    if error_indication:
        message = pretty_text(error_indication) or limited_repr(error_indication)
        raise PySnmpEngineResponseError(message)
    if error_status:
        raise PySnmpPduResponseError(pdu_error_message(error_status, error_index, var_binds))
    if not var_binds:
        raise RuntimeError("PySNMP GET response contained no variable bindings")
    try:
        returned_oid = pretty_text(var_binds[0][0])
        value = var_binds[0][1]
    except Exception as exc:
        raise RuntimeError(
            "PySNMP GET response contained an unreadable variable binding: "
            f"{limited_repr(var_binds[0])}"
        ) from exc
    return returned_oid, value


async def probe_once(
    *,
    args: argparse.Namespace,
    target: ResolvedTarget,
    pysnmp: PySnmpApi,
    security_data: Any,
    attempt_number: int,
    totals: ProbeTotals,
    redactor: SecretRedactor,
) -> bool:
    """Create one fresh PySNMP engine/target and run all requested GETs."""

    totals.sessions_attempted += 1
    print(
        f"Attempt {attempt_number}/{args.repeat}: address={target.address} "
        f"family={target.family_name}",
        flush=True,
    )

    phase_started = time.perf_counter()
    try:
        engine = pysnmp.snmp_engine_class()
    except Exception as exc:
        totals.sessions_failed += 1
        print_exception(
            phase="engine_construct",
            address=target.address,
            family_name=target.family_name,
            elapsed=time.perf_counter() - phase_started,
            exc=exc,
            include_traceback=args.traceback,
            redactor=redactor,
        )
        print("  result: FAILURE", flush=True)
        print(flush=True)
        return False
    print(f"  engine_construct: success ({time.perf_counter() - phase_started:.6f}s)")

    phase_started = time.perf_counter()
    try:
        transport_target = await create_transport_target(args, target, pysnmp)
    except Exception as exc:
        print_exception(
            phase="transport_target_construct",
            address=target.address,
            family_name=target.family_name,
            elapsed=time.perf_counter() - phase_started,
            exc=exc,
            include_traceback=args.traceback,
            redactor=redactor,
        )
        close_engine(
            engine,
            address=target.address,
            family_name=target.family_name,
            include_traceback=args.traceback,
            redactor=redactor,
        )
        totals.sessions_failed += 1
        print("  result: FAILURE", flush=True)
        print(flush=True)
        return False
    print(f"  transport_target_construct: success ({time.perf_counter() - phase_started:.6f}s)")

    attempt_success = True
    for oid in args.oid or [DEFAULT_OID]:
        phase_started = time.perf_counter()
        try:
            returned_oid, value = await query_oid(
                oid=oid,
                engine=engine,
                security_data=security_data,
                transport_target=transport_target,
                pysnmp=pysnmp,
            )
        except Exception as exc:
            attempt_success = False
            totals.gets_failed += 1
            print_exception(
                phase=f"get:{oid}",
                address=target.address,
                family_name=target.family_name,
                elapsed=time.perf_counter() - phase_started,
                exc=exc,
                include_traceback=args.traceback,
                redactor=redactor,
            )
            break
        totals.gets_succeeded += 1
        elapsed = time.perf_counter() - phase_started
        print(f"  GET {oid}: success ({elapsed:.6f}s)")
        print(f"    returned_oid={returned_oid}")
        for line in render_value(value):
            print(f"    {line}")

    close_ok = close_engine(
        engine,
        address=target.address,
        family_name=target.family_name,
        include_traceback=args.traceback,
        redactor=redactor,
    )
    if not close_ok:
        attempt_success = False

    if attempt_success:
        totals.sessions_succeeded += 1
        print("  result: SUCCESS", flush=True)
    else:
        totals.sessions_failed += 1
        print("  result: FAILURE", flush=True)
    print(flush=True)
    return attempt_success


async def run_probes(
    args: argparse.Namespace,
    targets: Sequence[ResolvedTarget],
    pysnmp: PySnmpApi,
    security_data: Any,
    redactor: SecretRedactor,
) -> ProbeTotals:
    """Run addresses and repetitions sequentially for unambiguous diagnostics."""

    totals = ProbeTotals()
    for target_index, target in enumerate(targets, start=1):
        print(
            f"Destination {target_index}/{len(targets)}: {target.address} ({target.family_name})",
            flush=True,
        )
        for attempt_number in range(1, args.repeat + 1):
            await probe_once(
                args=args,
                target=target,
                pysnmp=pysnmp,
                security_data=security_data,
                attempt_number=attempt_number,
                totals=totals,
                redactor=redactor,
            )
            if attempt_number < args.repeat and args.delay:
                print(
                    f"Delay before next fresh engine: {args.delay:.3f}s",
                    flush=True,
                )
                await asyncio.sleep(args.delay)
    return totals


def print_configuration_error(
    exc: BaseException,
    *,
    include_traceback: bool,
    redactor: SecretRedactor,
) -> None:
    """Render a pre-query configuration/import/resolution failure."""

    print("ERROR: diagnostic could not start", file=sys.stderr)
    for name, value in exception_details(exc, redactor=redactor):
        print(f"  {name}: {value}", file=sys.stderr)
    if include_traceback:
        print("  traceback:", file=sys.stderr)
        rendered = traceback.TracebackException.from_exception(exc).format(chain=True)
        for line in rendered:
            for physical_line in line.rstrip("\n").splitlines():
                print(
                    f"    {redactor.redact(physical_line)}",
                    file=sys.stderr,
                )


def main(argv: Sequence[str] | None = None) -> int:
    """Parse arguments, run diagnostics, and return a stable process exit code."""

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)  # ty: ignore[unresolved-attribute]
        except (AttributeError, OSError):
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    redactor = SecretRedactor.from_environment()
    try:
        pysnmp = load_pysnmp()
        if args.snmp_version == "3":
            preflight_authpriv(args.priv_protocol)
        security_data = build_security_data(args, pysnmp)
        target_kind, targets = resolve_target(
            args.target,
            port=args.port,
            family=forced_family(args),
            first_address=args.first_address,
        )
    except Exception as exc:
        print_configuration_error(
            exc,
            include_traceback=args.traceback,
            redactor=redactor,
        )
        return EXIT_CONFIGURATION_ERROR

    print_header(
        args,
        target_kind=target_kind,
        targets=targets,
        pysnmp=pysnmp,
    )
    try:
        totals = asyncio.run(
            run_probes(
                args,
                targets,
                pysnmp,
                security_data,
                redactor,
            )
        )
    except KeyboardInterrupt:
        print("Interrupted by operator", file=sys.stderr)
        return 130

    print("Summary")
    print(f"  sessions_attempted: {totals.sessions_attempted}")
    print(f"  sessions_succeeded: {totals.sessions_succeeded}")
    print(f"  sessions_failed: {totals.sessions_failed}")
    print(f"  gets_succeeded: {totals.gets_succeeded}")
    print(f"  gets_failed: {totals.gets_failed}")
    if totals.sessions_failed or totals.gets_failed:
        print("  overall_result: FAILURE")
        return EXIT_QUERY_FAILED
    print("  overall_result: SUCCESS")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
