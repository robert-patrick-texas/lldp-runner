#!/usr/bin/env python3
"""Run a direct Gufo SNMP GET diagnostic against IPv4 and/or IPv6 targets.

The script deliberately bypasses LLDP-Runner. It resolves a literal address or
DNS name, prints the exact address passed to Gufo SNMP, creates a fresh session,
and performs one or more SNMP GET requests. Failures identify the phase in which
they occurred and include exception class, errno-style fields, arguments, and
optional traceback details.

Credentials are read only from environment variables and are never printed:

* SNMPv2c: SNMPCOMM
* SNMPv3 authPriv: SNMPUSER, SNMPAUTH, SNMPPRIV

Examples:

    SNMPCOMM='community' ./gufo_snmp_diag.py 192.0.2.10
    SNMPCOMM='community' ./gufo_snmp_diag.py 2001:db8::10
    SNMPCOMM='community' ./gufo_snmp_diag.py switch.example.net -6
    SNMPUSER='user' SNMPAUTH='authpass' SNMPPRIV='privpass' \
        ./gufo_snmp_diag.py switch.example.net --snmp-version 3 -6

By default the script queries sysDescr.0 (1.3.6.1.2.1.1.1.0). Repeat --oid to
query additional numeric OIDs. DNS names are resolved to all matching addresses
in resolver order unless --first-address is used. No application-level retry is
performed unless --repeat is explicitly greater than one.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import importlib.metadata
import ipaddress
import os
import platform
import socket
import sys
import time
import traceback
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_OID = "1.3.6.1.2.1.1.1.0"
EXIT_OK = 0
EXIT_QUERY_FAILED = 1
EXIT_CONFIGURATION_ERROR = 2


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """One concrete destination that will be passed to Gufo SNMP."""

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
class GufoApi:
    """Gufo objects imported at runtime so --help works without the package."""

    module: Any
    session_class: Any
    user_class: Any
    sha1_key_class: Any
    md5_key_class: Any
    aes128_key_class: Any
    des_key_class: Any
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
            "Query a device directly with Gufo SNMP and report detailed IPv4/IPv6 "
            "resolution, session, GET, and exception diagnostics."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Credential environment variables:\n"
            "  SNMPv2c: SNMPCOMM\n"
            "  SNMPv3:  SNMPUSER, SNMPAUTH, SNMPPRIV\n\n"
            "Exit status:\n"
            "  0  every attempted session and GET succeeded\n"
            "  1  at least one Gufo session or GET failed\n"
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
        help="Gufo request timeout in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--repeat",
        type=positive_int,
        default=1,
        metavar="COUNT",
        help="create a fresh session and repeat each address COUNT times (default: 1)",
    )
    parser.add_argument(
        "--delay",
        type=nonnegative_float,
        default=0.0,
        metavar="SECONDS",
        help="delay between repeated fresh-session attempts (default: 0)",
    )
    parser.add_argument(
        "--first-address",
        action="store_true",
        help="for a DNS name, query only the first matching resolved address",
    )
    parser.add_argument(
        "--auth-protocol",
        choices=("sha1", "md5"),
        default="sha1",
        help="SNMPv3 authentication protocol (default: sha1)",
    )
    parser.add_argument(
        "--priv-protocol",
        choices=("aes128", "des"),
        default="aes128",
        help="SNMPv3 privacy protocol (default: aes128)",
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
    """Resolve a literal or DNS name to concrete Gufo destination strings."""

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


def load_gufo() -> GufoApi:
    """Import the Gufo SNMP API and provide a clear package error."""

    try:
        module = importlib.import_module("gufo.snmp")
    except Exception as exc:
        raise RuntimeError(
            "cannot import gufo.snmp; install Gufo SNMP in this Python environment "
            "(install with: python -m pip install gufo-snmp)"
        ) from exc

    required = (
        "SnmpSession",
        "User",
        "Sha1Key",
        "Md5Key",
        "Aes128Key",
        "DesKey",
    )
    missing = [name for name in required if not hasattr(module, name)]
    if missing:
        raise RuntimeError(
            "installed gufo.snmp module lacks required API objects: " + ", ".join(missing)
        )
    return GufoApi(
        module=module,
        session_class=module.SnmpSession,
        user_class=module.User,
        sha1_key_class=module.Sha1Key,
        md5_key_class=module.Md5Key,
        aes128_key_class=module.Aes128Key,
        des_key_class=module.DesKey,
        distribution_version=package_version("gufo-snmp"),
    )


def require_environment(name: str) -> str:
    """Return one non-empty credential environment variable."""

    value = os.environ.get(name)
    if value is None or not value:
        raise RuntimeError(f"required credential environment variable {name} is not set")
    return value


def build_security_kwargs(args: argparse.Namespace, gufo: GufoApi) -> dict[str, Any]:
    """Build Gufo session security arguments without logging secret values."""

    if args.snmp_version == "2c":
        return {"community": require_environment("SNMPCOMM")}

    username = require_environment("SNMPUSER")
    auth_password = require_environment("SNMPAUTH")
    priv_password = require_environment("SNMPPRIV")
    auth_class = gufo.sha1_key_class if args.auth_protocol == "sha1" else gufo.md5_key_class
    priv_class = gufo.aes128_key_class if args.priv_protocol == "aes128" else gufo.des_key_class
    return {
        "user": gufo.user_class(
            username,
            auth_key=auth_class(auth_password.encode("utf-8")),
            priv_key=priv_class(priv_password.encode("utf-8")),
        )
    }


def qualified_type(exc: BaseException) -> str:
    """Return module-qualified exception type."""

    cls = exc.__class__
    return f"{cls.__module__}.{cls.__qualname__}"


def classify_exception(exc: BaseException) -> str:
    """Assign a compact diagnostic category without hiding the original type."""

    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, socket.gaierror):
        return "name_resolution"
    if isinstance(exc, OSError):
        return "os_error"
    type_text = qualified_type(exc).casefold()
    message = str(exc).casefold()
    if "auth" in type_text or "authentication" in message or "authorization" in message:
        return "authentication_or_authorization"
    if "nosuch" in type_text or "no such" in message:
        return "no_such_object_or_instance"
    if "snmp" in type_text:
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
    """Render an SNMP value with type information and safe byte diagnostics."""

    lines = [f"type={value.__class__.__module__}.{value.__class__.__qualname__}"]
    if isinstance(value, bytes):
        decoded = value.decode("utf-8", errors="backslashreplace")
        lines.append(f"text={limited_repr(decoded, limit)}")
        hex_text = value.hex(":")
        suffix = "...<truncated>" if len(hex_text) > limit else ""
        lines.append(f"hex={hex_text[:limit]}{suffix}")
    else:
        lines.append(f"value={limited_repr(value, limit)}")
    return lines


def module_path(module: Any) -> str:
    """Return the Gufo module path when available."""

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
    gufo: GufoApi,
) -> None:
    """Print runtime, resolver, and non-secret SNMP configuration metadata."""

    family_text = "automatic"
    if args.ipv4:
        family_text = "IPv4 forced"
    elif args.ipv6:
        family_text = "IPv6 forced"
    oids = args.oid or [DEFAULT_OID]
    print("Gufo SNMP diagnostic")
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
    print(f"gufo_snmp_version: {gufo.distribution_version}")
    print(f"gufo_module_path: {module_path(gufo.module)}")
    if args.snmp_version == "2c":
        print("credentials: SNMPCOMM=<set>; value not displayed")
    else:
        print("credentials: SNMPUSER/SNMPAUTH/SNMPPRIV=<set>; values not displayed")
        print(f"snmpv3_auth_protocol: {args.auth_protocol}")
        print(f"snmpv3_priv_protocol: {args.priv_protocol}")
    print("application_retries: disabled (use --repeat for fresh-session repetitions)")
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


async def close_session(
    session: Any,
    *,
    address: str,
    family_name: str,
    active_exception: BaseException | None,
    include_traceback: bool,
    redactor: SecretRedactor,
) -> bool:
    """Close a Gufo session and report close failures separately."""

    started = time.perf_counter()
    try:
        await session.__aexit__(
            type(active_exception) if active_exception is not None else None,
            active_exception,
            active_exception.__traceback__ if active_exception is not None else None,
        )
    except Exception as exc:
        print_exception(
            phase="session_close",
            address=address,
            family_name=family_name,
            elapsed=time.perf_counter() - started,
            exc=exc,
            include_traceback=include_traceback,
            redactor=redactor,
        )
        return False
    print(f"  session_close: success ({time.perf_counter() - started:.6f}s)")
    return True


async def probe_once(
    *,
    args: argparse.Namespace,
    target: ResolvedTarget,
    gufo: GufoApi,
    security_kwargs: dict[str, Any],
    attempt_number: int,
    totals: ProbeTotals,
    redactor: SecretRedactor,
) -> bool:
    """Create one fresh Gufo session and run all requested GET operations."""

    totals.sessions_attempted += 1
    print(
        f"Attempt {attempt_number}/{args.repeat}: address={target.address} "
        f"family={target.family_name}",
        flush=True,
    )
    session_kwargs: dict[str, Any] = {
        "addr": target.address,
        "port": args.port,
        "timeout": args.timeout,
        **security_kwargs,
    }

    phase_started = time.perf_counter()
    try:
        session = gufo.session_class(**session_kwargs)
    except Exception as exc:
        totals.sessions_failed += 1
        print_exception(
            phase="session_construct",
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
    print(f"  session_construct: success ({time.perf_counter() - phase_started:.6f}s)")

    phase_started = time.perf_counter()
    try:
        entered = await session.__aenter__()
    except Exception as exc:
        totals.sessions_failed += 1
        print_exception(
            phase="session_open",
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
    active_session = entered if entered is not None else session
    print(f"  session_open: success ({time.perf_counter() - phase_started:.6f}s)")

    active_exception: BaseException | None = None
    attempt_success = True
    try:
        for oid in args.oid or [DEFAULT_OID]:
            phase_started = time.perf_counter()
            try:
                value = await active_session.get(oid)
            except Exception as exc:
                active_exception = exc
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
            for line in render_value(value):
                print(f"    {line}")

        if attempt_success and args.snmp_version == "3":
            try:
                engine_id = active_session.get_engine_id()
            except Exception as exc:
                print(
                    "  snmpv3_engine_id: unavailable "
                    f"({qualified_type(exc)}: "
                    f"{redactor.redact(str(exc)) or '<empty>'})"
                )
            else:
                print(f"  snmpv3_engine_id: {bytes(engine_id).hex()}")
    finally:
        close_ok = await close_session(
            session,
            address=target.address,
            family_name=target.family_name,
            active_exception=active_exception,
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
    gufo: GufoApi,
    security_kwargs: dict[str, Any],
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
                gufo=gufo,
                security_kwargs=security_kwargs,
                attempt_number=attempt_number,
                totals=totals,
                redactor=redactor,
            )
            if attempt_number < args.repeat and args.delay:
                print(f"Delay before next fresh session: {args.delay:.3f}s", flush=True)
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
        target_kind, targets = resolve_target(
            args.target,
            port=args.port,
            family=forced_family(args),
            first_address=args.first_address,
        )
        gufo = load_gufo()
        security_kwargs = build_security_kwargs(args, gufo)
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
        gufo=gufo,
    )
    try:
        totals = asyncio.run(
            run_probes(
                args,
                targets,
                gufo,
                security_kwargs,
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
