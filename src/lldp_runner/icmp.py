"""Asynchronous ICMP wake-up probes with raw-socket and system-ping backends."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shutil
import socket
import struct
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lldp_runner.config import IcmpConfig
from lldp_runner.models import PingProbe
from lldp_runner.timeutil import iso_now

if TYPE_CHECKING:
    from lldp_runner.snmp.trace import SnmpTrace

_RTT_RE = re.compile(rb"time[=<]([0-9.]+)\s*ms", re.IGNORECASE)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


@dataclass(slots=True)
class AsyncIcmpPinger:
    """Perform configured ICMP probes, optionally emitting operator trace detail."""

    config: IcmpConfig
    trace: SnmpTrace | None = None

    async def probe(self, address: str, sequence: int) -> PingProbe:
        """Probe one address using the configured raw/system backend policy."""

        if not self.config.enabled or self.config.backend == "disabled":
            return PingProbe(status="skipped", timestamp=iso_now(), address=address)
        backend = self.config.backend
        if backend in {"auto", "raw"}:
            try:
                return await self._raw_probe(address, sequence)
            except PermissionError as exc:
                if backend == "raw":
                    return PingProbe(
                        status="error",
                        timestamp=iso_now(),
                        address=address,
                        error=str(exc),
                    )
                if self.trace is not None:
                    self.trace.icmp_note(
                        "raw backend unavailable; falling back to system ping "
                        f"({exc.__class__.__name__}: {exc})"
                    )
            except OSError as exc:
                if backend == "raw":
                    return PingProbe(
                        status="error",
                        timestamp=iso_now(),
                        address=address,
                        error=str(exc),
                    )
                if self.trace is not None:
                    self.trace.icmp_note(
                        "raw backend failed; falling back to system ping "
                        f"({exc.__class__.__name__}: {exc})"
                    )
        if backend in {"auto", "system"}:
            return await self._system_probe(address, sequence)
        return PingProbe(
            status="error",
            timestamp=iso_now(),
            address=address,
            error=f"unsupported ICMP backend {backend}",
        )

    async def _raw_probe(self, address: str, sequence: int) -> PingProbe:
        ip = ipaddress.ip_address(address)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        proto = socket.IPPROTO_ICMPV6 if ip.version == 6 else socket.IPPROTO_ICMP
        identifier = os.getpid() & 0xFFFF
        trace_number = None
        if self.trace is not None:
            trace_number = self.trace.icmp_query(
                address=address,
                sequence=sequence,
                protocol="ICMP IPv6" if ip.version == 6 else "ICMP IPv4",
                backend="raw",
                timeout_seconds=self.config.timeout_seconds,
                identifier=identifier,
            )
        try:
            sock = socket.socket(family, socket.SOCK_RAW, proto)
        except (PermissionError, OSError) as exc:
            if self.trace is not None and trace_number is not None:
                self.trace.icmp_response(
                    trace_number,
                    address=address,
                    sequence=sequence,
                    backend="raw",
                    status="error",
                    reason=f"{exc.__class__.__name__}: {exc}",
                )
            raise
        try:
            sock.setblocking(False)
            payload = struct.pack("!d", time.monotonic()) + b"lldp-runner"
            if ip.version == 4:
                header = struct.pack(
                    "!BBHHH", 8, 0, 0, identifier, sequence & 0xFFFF
                )
                checksum = _checksum(header + payload)
                packet = struct.pack(
                    "!BBHHH", 8, 0, checksum, identifier, sequence & 0xFFFF
                ) + payload
            else:
                # Linux computes the ICMPv6 checksum for IPPROTO_ICMPV6 raw sockets.
                packet = struct.pack(
                    "!BBHHH", 128, 0, 0, identifier, sequence & 0xFFFF
                ) + payload
            sock.connect((address, 0))
            loop = asyncio.get_running_loop()
            started = time.monotonic()
            await loop.sock_sendall(sock, packet)
            deadline = started + self.config.timeout_seconds
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    probe = PingProbe(
                        status="no-response", timestamp=iso_now(), address=address
                    )
                    self._trace_probe_response(
                        trace_number, probe, sequence=sequence, backend="raw"
                    )
                    return probe
                try:
                    data = await asyncio.wait_for(loop.sock_recv(sock, 65535), remaining)
                except TimeoutError:
                    probe = PingProbe(
                        status="no-response", timestamp=iso_now(), address=address
                    )
                    self._trace_probe_response(
                        trace_number, probe, sequence=sequence, backend="raw"
                    )
                    return probe
                if ip.version == 4:
                    if len(data) < 28:
                        continue
                    ihl = (data[0] & 0x0F) * 4
                    if len(data) < ihl + 8:
                        continue
                    icmp_type, _code, _csum, response_id, response_seq = struct.unpack(
                        "!BBHHH", data[ihl : ihl + 8]
                    )
                    if (
                        icmp_type != 0
                        or response_id != identifier
                        or response_seq != sequence & 0xFFFF
                    ):
                        continue
                else:
                    if len(data) < 8:
                        continue
                    icmp_type, _code, _csum, response_id, response_seq = struct.unpack(
                        "!BBHHH", data[:8]
                    )
                    if (
                        icmp_type != 129
                        or response_id != identifier
                        or response_seq != sequence & 0xFFFF
                    ):
                        continue
                rtt = (time.monotonic() - started) * 1000.0
                probe = PingProbe(
                    status="reply",
                    timestamp=iso_now(),
                    address=address,
                    rtt_ms=round(rtt, 3),
                )
                self._trace_probe_response(
                    trace_number, probe, sequence=sequence, backend="raw"
                )
                return probe
        except (PermissionError, OSError) as exc:
            if self.trace is not None and trace_number is not None:
                self.trace.icmp_response(
                    trace_number,
                    address=address,
                    sequence=sequence,
                    backend="raw",
                    status="error",
                    reason=f"{exc.__class__.__name__}: {exc}",
                )
            raise
        finally:
            sock.close()

    async def _system_probe(self, address: str, sequence: int) -> PingProbe:
        ip = ipaddress.ip_address(address)
        trace_number = None
        if self.trace is not None:
            trace_number = self.trace.icmp_query(
                address=address,
                sequence=sequence,
                protocol="ICMP IPv6" if ip.version == 6 else "ICMP IPv4",
                backend="system ping",
                timeout_seconds=self.config.timeout_seconds,
            )
        binary = shutil.which("ping")
        if binary is None:
            probe = PingProbe(
                status="error",
                timestamp=iso_now(),
                address=address,
                error="system ping command is not installed",
            )
            self._trace_probe_response(
                trace_number, probe, sequence=sequence, backend="system ping"
            )
            return probe
        timeout = max(1, int(self.config.timeout_seconds + 0.999))
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-n",
            "-c",
            "1",
            "-W",
            str(timeout),
            address,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), self.config.timeout_seconds + 1.0
            )
        except TimeoutError:
            proc.kill()
            await proc.wait()
            probe = PingProbe(
                status="no-response", timestamp=iso_now(), address=address
            )
            self._trace_probe_response(
                trace_number, probe, sequence=sequence, backend="system ping"
            )
            return probe
        if proc.returncode == 0:
            match = _RTT_RE.search(stdout)
            rtt = float(match.group(1)) if match else None
            probe = PingProbe(
                status="reply", timestamp=iso_now(), address=address, rtt_ms=rtt
            )
            self._trace_probe_response(
                trace_number, probe, sequence=sequence, backend="system ping"
            )
            return probe
        if proc.returncode == 1:
            probe = PingProbe(
                status="no-response", timestamp=iso_now(), address=address
            )
            self._trace_probe_response(
                trace_number, probe, sequence=sequence, backend="system ping"
            )
            return probe
        message = (
            stderr.decode("utf-8", errors="replace").strip()
            or f"ping exit {proc.returncode}"
        )
        probe = PingProbe(
            status="error", timestamp=iso_now(), address=address, error=message
        )
        self._trace_probe_response(
            trace_number, probe, sequence=sequence, backend="system ping"
        )
        return probe

    def _trace_probe_response(
        self,
        trace_number: int | None,
        probe: PingProbe,
        *,
        sequence: int,
        backend: str,
    ) -> None:
        """Emit one trace result without affecting ordinary discovery probes."""

        if self.trace is None or trace_number is None:
            return
        self.trace.icmp_response(
            trace_number,
            address=probe.address or "",
            sequence=sequence,
            backend=backend,
            status=probe.status,
            rtt_ms=probe.rtt_ms,
            reason=probe.error,
        )
