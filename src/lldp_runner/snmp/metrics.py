"""Backend-neutral SNMP object-count telemetry helpers.

The metrics layer intentionally sits above the concrete SNMP backend.  Collectors
already consume the project-owned :class:`SnmpClient` protocol, so wrapping an
open client here lets LLDP-Runner count returned variable bindings without
reaching into Gufo's GETBULK implementation details.  This keeps the telemetry
portable if another backend is introduced later.
"""

from __future__ import annotations

from typing import Any

from lldp_runner.snmp.base import SnmpClient


class CountingSnmpClient:
    """Delegate SNMP calls while counting successfully returned objects.

    ``objects`` counts SNMP variable bindings returned to LLDP-Runner before a
    collector filters or groups them.  A successful scalar ``get`` contributes
    one object, ``get_many`` contributes the number of returned OID/value pairs,
    and ``walk`` contributes every returned table varbind.  Failed operations do
    not invent object counts; any objects from earlier successful calls in the
    same collector section remain counted.
    """

    def __init__(self, client: SnmpClient) -> None:
        self._client = client
        self.objects = 0

    async def get(self, oid: str) -> object:
        value = await self._client.get(oid)
        self.objects += 1
        return value

    async def get_many(self, oids: list[str]) -> dict[str, object]:
        values = await self._client.get_many(oids)
        self.objects += len(values)
        return values

    async def walk(self, oid: str) -> list[tuple[str, object]]:
        rows = await self._client.walk(oid)
        self.objects += len(rows)
        return rows

    def engine_id_hex(self) -> str | None:
        return self._client.engine_id_hex()

    def __getattr__(self, name: str) -> Any:
        """Delegate future non-measured helpers without coupling collectors here."""

        return getattr(self._client, name)
