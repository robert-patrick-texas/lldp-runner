"""Basic system details collected before vendor-specific discovery."""

from __future__ import annotations

from typing import Protocol

from lldp_runner.classify import infer_manufacturer, infer_model_version
from lldp_runner.models import SystemDetails
from lldp_runner.textutil import snmp_text

SYS_DESCR = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
SYS_NAME = "1.3.6.1.2.1.1.5.0"
SYS_LOCATION = "1.3.6.1.2.1.1.6.0"
SYSTEM_OIDS = [SYS_DESCR, SYS_OBJECT_ID, SYS_UPTIME, SYS_CONTACT, SYS_NAME, SYS_LOCATION]


class BasicClient(Protocol):
    async def get_many(self, oids: list[str]) -> dict[str, object]: ...

    def engine_id_hex(self) -> str | None: ...


def _text(value: object | None) -> str | None:
    """Normalize SYSTEM-MIB text before it reaches identity/output state."""

    return snmp_text(value)


def _int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)  # ty: ignore[invalid-argument-type]
    except (TypeError, ValueError):
        return None


async def collect_basic_system(client: BasicClient) -> SystemDetails:
    """Collect the small SYSTEM-MIB identity set used before deeper discovery.

    This is the first SNMP text most devices return, so values are normalized
    before manufacturer inference, DNS/name handling, state storage, or output.
    """

    values = await client.get_many(SYSTEM_OIDS)
    details = SystemDetails(
        sys_name=_text(values.get(SYS_NAME)),
        sys_descr=_text(values.get(SYS_DESCR)),
        sys_object_id=_text(values.get(SYS_OBJECT_ID)),
        sys_uptime_ticks=_int(values.get(SYS_UPTIME)),
        sys_contact=_text(values.get(SYS_CONTACT)),
        sys_location=_text(values.get(SYS_LOCATION)),
        snmp_engine_id=client.engine_id_hex(),
    )
    details.manufacturer = infer_manufacturer(details.sys_object_id, details.sys_descr)
    details.model, details.version = infer_model_version(details)
    return details
