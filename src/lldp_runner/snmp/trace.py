"""Operator-readable network tracing for single-device inspection.

The trace stream follows the same resolver, ICMP, and SNMP operations used by
``get-neighbors``.  SNMP deliberately wraps LLDP-Runner's project-owned
:class:`SnmpClient` protocol rather than the concrete Gufo backend. This keeps
SNMP tracing at the logical GET/GET-MANY/WALK level without depending on Gufo's
private GETNEXT/GETBULK packet strategy. Resolver entries describe operating-
system resolver calls rather than claiming that literal DNS packets were sent.

Trace output is diagnostic text, not a machine-readable API.  Values pass through
the same defensive text sanitation used by normal output so malformed OCTET
STRING data cannot inject terminal controls.  Credential material is never
printed; known secrets are replaced with ``<redacted>`` if a backend happens to
include them in an exception message.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Protocol, TextIO

from lldp_runner.textutil import safe_output_text, snmp_text
from lldp_runner.timeutil import iso_now


class TraceableSnmpClient(Protocol):
    """Already-open SNMP operations required by the tracing facade."""

    async def get(self, oid: str) -> object: ...

    async def get_many(self, oids: list[str]) -> dict[str, object]: ...

    async def walk(self, oid: str) -> list[tuple[str, object]]: ...

    def engine_id_hex(self) -> str | None: ...


@dataclass(frozen=True, slots=True)
class OidDescription:
    """Human-readable metadata for one known scalar, column, or table root."""

    oid: str
    name: str
    description: str
    section: str


# Longest-prefix matching lets one registry describe both requested table roots
# and returned row instances.  More-specific column roots are listed alongside
# their containing tables; :func:`describe_oid` chooses the longest match.
_OIDS: tuple[OidDescription, ...] = (
    OidDescription("1.3.6.1.2.1.1.1.0", "sysDescr", "System description", "SYSTEM-MIB"),
    OidDescription("1.3.6.1.2.1.1.2.0", "sysObjectID", "System object identifier", "SYSTEM-MIB"),
    OidDescription("1.3.6.1.2.1.1.3.0", "sysUpTime", "System uptime ticks", "SYSTEM-MIB"),
    OidDescription("1.3.6.1.2.1.1.4.0", "sysContact", "System contact", "SYSTEM-MIB"),
    OidDescription("1.3.6.1.2.1.1.5.0", "sysName", "System name", "SYSTEM-MIB"),
    OidDescription("1.3.6.1.2.1.1.6.0", "sysLocation", "System location", "SYSTEM-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.2", "entPhysicalDescr", "Physical entity description", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.4", "entPhysicalContainedIn", "Containing physical entity index", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.5", "entPhysicalClass", "Physical entity class", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.6", "entPhysicalParentRelPos", "Relative position within parent", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.7", "entPhysicalName", "Physical entity name", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.8", "entPhysicalHardwareRev", "Physical entity hardware revision", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.9", "entPhysicalFirmwareRev", "Physical entity firmware revision", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.10", "entPhysicalSoftwareRev", "Physical entity software revision", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.11", "entPhysicalSerialNum", "Physical entity serial number", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.12", "entPhysicalMfgName", "Physical entity manufacturer", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1.13", "entPhysicalModelName", "Physical entity model name", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.47.1.1.1.1", "entPhysicalEntry", "ENTITY-MIB physical inventory table", "ENTITY-MIB"),
    OidDescription("1.3.6.1.2.1.31.1.1.1.1", "ifName", "Interface name table", "IF-MIB"),
    OidDescription("1.3.6.1.2.1.2.2.1.2", "ifDescr", "Interface description table", "IF-MIB"),
    OidDescription("1.0.8802.1.1.2.1.3.7.1.2", "lldpLocPortIdSubtype", "Local LLDP Port ID subtype", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.3.7.1.3", "lldpLocPortId", "Local LLDP Port ID", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.3.7.1.4", "lldpLocPortDesc", "Local LLDP port description", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.3.7.1", "lldpLocPortEntry", "Local LLDP port table", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.4", "lldpRemChassisIdSubtype", "Remote chassis ID subtype", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.5", "lldpRemChassisId", "Remote chassis ID", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.6", "lldpRemPortIdSubtype", "Remote Port ID subtype", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.7", "lldpRemPortId", "Remote Port ID", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.8", "lldpRemPortDesc", "Remote port description", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.9", "lldpRemSysName", "Remote system name", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.10", "lldpRemSysDesc", "Remote system description", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.11", "lldpRemSysCapSupported", "Remote supported capabilities", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1.12", "lldpRemSysCapEnabled", "Remote enabled capabilities", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.1.1", "lldpRemEntry", "Remote LLDP neighbor table", "LLDP-MIB"),
    OidDescription("1.0.8802.1.1.2.1.4.2.1", "lldpRemManAddrEntry", "Remote LLDP management-address table", "LLDP-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.5", "lldpV2RemChassisIdSubtype", "Remote LLDPv2 chassis ID subtype", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.6", "lldpV2RemChassisId", "Remote LLDPv2 chassis ID", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.7", "lldpV2RemPortIdSubtype", "Remote LLDPv2 Port ID subtype", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.8", "lldpV2RemPortId", "Remote LLDPv2 Port ID", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.9", "lldpV2RemPortDesc", "Remote LLDPv2 port description", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.10", "lldpV2RemSysName", "Remote LLDPv2 system name", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.11", "lldpV2RemSysDesc", "Remote LLDPv2 system description", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.12", "lldpV2RemSysCapSupported", "Remote LLDPv2 supported capabilities", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1.13", "lldpV2RemSysCapEnabled", "Remote LLDPv2 enabled capabilities", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.1.1", "lldpV2RemEntry", "Remote LLDPv2 neighbor table", "LLDPv2-MIB"),
    OidDescription("1.3.111.2.802.1.1.13.1.4.2.1", "lldpV2RemManAddrEntry", "Remote LLDPv2 management-address table", "LLDPv2-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.3", "cdpCacheAddressType", "CDP neighbor address type", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.4", "cdpCacheAddress", "CDP neighbor management address", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.5", "cdpCacheVersion", "CDP neighbor software/version description", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.6", "cdpCacheDeviceId", "CDP neighbor device ID", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.7", "cdpCacheDevicePort", "CDP neighbor remote port", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.8", "cdpCachePlatform", "CDP neighbor platform", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1.9", "cdpCacheCapabilities", "CDP neighbor capabilities", "CISCO-CDP-MIB"),
    OidDescription("1.3.6.1.4.1.9.9.23.1.2.1.1", "cdpCacheEntry", "Cisco CDP neighbor cache table", "CISCO-CDP-MIB"),
)


_UNKNOWN = OidDescription("", "unknownOID", "Unregistered numeric OID", "SNMP")


def describe_oid(oid: str) -> OidDescription:
    """Return the most-specific known operator description for ``oid``."""

    best = _UNKNOWN
    for item in _OIDS:
        if oid == item.oid or oid.startswith(item.oid + "."):
            if len(item.oid) > len(best.oid):
                best = item
    return best


def _trace_value(value: object) -> str:
    """Render one backend value as safe single-line diagnostic text."""

    if isinstance(value, (bytes, bytearray, memoryview)):
        rendered = snmp_text(value)
        return rendered if rendered is not None else "<empty>"
    rendered = safe_output_text(value)
    return rendered if rendered else "<empty>"


def _sanitize_error(exc: BaseException, redactions: tuple[str, ...]) -> str:
    """Return an exception name/message with known credential values removed."""

    message = safe_output_text(f"{exc.__class__.__name__}: {exc}")
    for secret in redactions:
        if secret:
            message = message.replace(secret, "<redacted>")
    return message


@dataclass(frozen=True, slots=True)
class TraceContext:
    """Connection/credential metadata safe to expose in one trace session."""

    address: str
    profile: str
    credential: str
    snmp_version: str
    phase: str
    stage: str | None = None
    attempt: int | None = None
    redactions: tuple[str, ...] = field(default=(), repr=False)


class SnmpTrace:
    """Fan out an operator-readable network trace to one or more text streams.

    The historical class name is retained internally because SNMP wrapping is
    still its most specialized behavior. The emitted interface is a broader
    get-neighbors network trace that also records resolver and ICMP operations.
    """

    def __init__(self, streams: list[TextIO], *, input_target: str) -> None:
        if not streams:
            raise ValueError("network trace requires at least one output stream")
        self._streams = streams
        self._query_number = 0
        self._resolver_number = 0
        self._icmp_number = 0
        self._session_number = 0
        self._started_monotonic = time.monotonic()
        self._line("LLDP-Runner get-neighbors network trace")
        self._line(f"Target: {safe_output_text(input_target)}")
        self._line(f"Started: {iso_now()}")
        self._line(
            "Trace level: OS resolver calls, ICMP probe attempts/results, and "
            "LLDP-Runner logical SNMP operations/returned varbinds"
        )
        self._line(
            "Resolver note: entries describe getaddrinfo/gethostbyaddr/getfqdn "
            "results and do not imply literal DNS wire packets"
        )
        self._line("")

    def _line(self, text: str) -> None:
        for stream in self._streams:
            stream.write(text + "\n")
            stream.flush()

    def _separator(self, character: str = "=") -> None:
        self._line(character * 72)

    def resolver_query(
        self,
        *,
        operation: str,
        query_type: str,
        value_label: str,
        value: str,
        source: str | None = None,
        address_family: str | None = None,
    ) -> int:
        """Start one operating-system resolver operation and return its number."""

        self._resolver_number += 1
        number = self._resolver_number
        self._separator("-")
        self._line(f"DNS / RESOLVER QUERY {number:04d}")
        self._separator("-")
        self._line("QUERY")
        self._line(f"  Type:        {safe_output_text(query_type)}")
        self._line(f"  Operation:   {safe_output_text(operation)}")
        self._line(f"  {value_label + ':':<12} {safe_output_text(value)}")
        if source:
            self._line(f"  Source:      {safe_output_text(source)}")
        if address_family:
            self._line(f"  Address family: {safe_output_text(address_family)}")
        self._line("")
        return number

    def resolver_response(
        self, number: int, rows: list[tuple[str, object]]
    ) -> None:
        """Write the values returned by one resolver operation."""

        del number  # Number is carried by the preceding query header.
        self._line("RESPONSE")
        if not rows:
            self._line("  NO RESPONSE")
            self._line("  Reason:      resolver returned no values")
        else:
            for label, value in rows:
                self._line(
                    f"  {safe_output_text(label) + ':':<12} "
                    f"{safe_output_text(value)}"
                )
        self._line("")

    def resolver_no_response(self, number: int, reason: object) -> None:
        """Write an explicit resolver failure for one previously emitted query."""

        del number
        self._line("RESPONSE")
        self._line("  NO RESPONSE")
        self._line(f"  Reason:      {safe_output_text(reason)}")
        self._line("")

    def icmp_query(
        self,
        *,
        address: str,
        sequence: int,
        protocol: str,
        backend: str,
        timeout_seconds: float,
        identifier: int | None = None,
    ) -> int:
        """Start one concrete ICMP backend attempt and return its trace number."""

        self._icmp_number += 1
        number = self._icmp_number
        self._separator("-")
        self._line(f"ICMP PROBE {number:04d}")
        self._separator("-")
        self._line("QUERY")
        self._line("  Type:        Echo request")
        self._line(f"  Address:     {safe_output_text(address)}")
        self._line(f"  Protocol:    {safe_output_text(protocol)}")
        self._line(f"  Backend:     {safe_output_text(backend)}")
        if identifier is not None:
            self._line(f"  Identifier:  {identifier}")
        self._line(f"  Sequence:    {sequence}")
        self._line(f"  Timeout:     {timeout_seconds:.3f}s")
        self._line("")
        return number

    def icmp_response(
        self,
        number: int,
        *,
        address: str,
        sequence: int,
        backend: str,
        status: str,
        rtt_ms: float | None = None,
        reason: str | None = None,
    ) -> None:
        """Write one ICMP backend result without implying unavailable packet data."""

        del number
        self._line("RESPONSE")
        if status == "reply":
            self._line("  Type:        Echo reply")
        else:
            self._line("  NO RESPONSE")
        self._line(f"  Address:     {safe_output_text(address)}")
        self._line(f"  Backend:     {safe_output_text(backend)}")
        self._line(f"  Sequence:    {sequence}")
        if rtt_ms is not None:
            self._line(f"  RTT:         {rtt_ms:.3f} ms")
        result = {
            "reply": "REPLY",
            "no-response": "TIMEOUT",
            "error": "ERROR",
            "skipped": "SKIPPED",
        }.get(status, status.upper())
        self._line(f"  Result:      {safe_output_text(result)}")
        if reason:
            self._line(f"  Reason:      {safe_output_text(reason)}")
        self._line("")

    def icmp_note(self, text: str) -> None:
        """Record a backend-selection note, such as raw-to-system fallback."""

        self._line(f"ICMP note: {safe_output_text(text)}")
        self._line("")

    def wrap(self, client: TraceableSnmpClient, context: TraceContext) -> "TracingSnmpClient":
        """Return a tracing facade for one already-open project SNMP client."""

        self._session_number += 1
        self._separator()
        self._line(f"SNMP SESSION {self._session_number}")
        self._separator()
        self._line(f"Phase:       {context.phase}")
        self._line(f"Address:     {safe_output_text(context.address)}")
        self._line(f"Profile:     {safe_output_text(context.profile)}")
        self._line(f"Credential:  {safe_output_text(context.credential)}")
        self._line(f"SNMP version: {safe_output_text(context.snmp_version)}")
        if context.stage is not None:
            self._line(f"Stage:       {safe_output_text(context.stage)}")
        if context.attempt is not None:
            self._line(f"Attempt:     {context.attempt}")
        self._line("")
        return TracingSnmpClient(client, self, context)

    def next_query(self) -> int:
        self._query_number += 1
        return self._query_number

    def finish(self) -> None:
        """Write a stable summary after inspection completes or fails."""

        elapsed = time.monotonic() - self._started_monotonic
        self._separator()
        self._line("TRACE SUMMARY")
        self._separator()
        self._line(f"Trace complete:       {iso_now()}")
        self._line(f"DNS/resolver queries: {self._resolver_number}")
        self._line(f"ICMP probes:          {self._icmp_number}")
        self._line(f"Logical SNMP queries: {self._query_number}")
        self._line(f"Total elapsed:        {elapsed:.3f}s")


class TracingSnmpClient:
    """Delegate SNMP calls while emitting every logical query and returned value."""

    def __init__(
        self,
        client: TraceableSnmpClient,
        trace: SnmpTrace,
        context: TraceContext,
    ) -> None:
        self._client = client
        self._trace = trace
        self._context = context

    def _query_header(self, operation: str, oid: str) -> None:
        number = self._trace.next_query()
        info = describe_oid(oid)
        self._trace._separator("-")
        self._trace._line(f"SNMP QUERY {number:04d} | {info.section}")
        self._trace._separator("-")
        self._trace._line("QUERY")
        self._trace._line(f"  Name:        {info.name}")
        self._trace._line(f"  Description: {info.description}")
        self._trace._line(f"  Operation:   {operation}")
        self._trace._line(f"  OID:         {oid}")
        self._trace._line("")

    def _response(self, oid: str, value: object) -> None:
        info = describe_oid(oid)
        self._trace._line("RESPONSE")
        self._trace._line(f"  Name:        {info.name}")
        self._trace._line(f"  Description: {info.description}")
        self._trace._line(f"  OID:         {oid}")
        self._trace._line(f"  Value:       {_trace_value(value)}")
        self._trace._line("")

    def _no_response(self, reason: str, *, oid: str | None = None) -> None:
        self._trace._line("RESPONSE")
        if oid is not None:
            info = describe_oid(oid)
            self._trace._line(f"  Name:        {info.name}")
            self._trace._line(f"  Description: {info.description}")
            self._trace._line(f"  OID:         {oid}")
        self._trace._line("  NO RESPONSE")
        self._trace._line(f"  Reason:      {reason}")
        self._trace._line("")

    async def get(self, oid: str) -> object:
        self._query_header("GET", oid)
        try:
            value = await self._client.get(oid)
        except Exception as exc:
            self._no_response(_sanitize_error(exc, self._context.redactions), oid=oid)
            raise
        self._response(oid, value)
        return value

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        # A backend may encode these scalars into one PDU.  Number each logical
        # requested OID separately so missing varbinds remain obvious to NetOps.
        for oid in oids:
            self._query_header("GET", oid)
        try:
            values = await self._client.get_many(oids)
        except Exception as exc:
            reason = _sanitize_error(exc, self._context.redactions)
            for oid in oids:
                self._no_response(reason, oid=oid)
            raise

        for oid in oids:
            if oid in values:
                self._response(oid, values[oid])
            else:
                self._no_response("requested OID returned no varbind", oid=oid)
        # Preserve visibility if a backend unexpectedly returns extra varbinds.
        for oid, value in values.items():
            if oid not in oids:
                self._response(oid, value)
        return values

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        self._query_header("WALK", oid)
        try:
            rows = await self._client.walk(oid)
        except Exception as exc:
            self._no_response(_sanitize_error(exc, self._context.redactions), oid=oid)
            raise
        if not rows:
            self._no_response("walk returned no varbinds", oid=oid)
            return rows
        for row_oid, value in rows:
            self._response(row_oid, value)
        return rows

    def engine_id_hex(self) -> str | None:
        return self._client.engine_id_hex()
