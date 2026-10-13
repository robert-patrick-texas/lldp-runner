from lldp_runner.collectors.interfaces import display_interface_name


def test_interface_abbreviation():
    assert display_interface_name("GigabitEthernet1/0/23") == "Gi1/0/23"
    assert display_interface_name("TenGigabitEthernet2/1/1") == "Te2/1/1"
    assert display_interface_name("Ethernet2/3") == "Eth2/3"
    assert display_interface_name("xe-0/0/1") == "xe-0/0/1"


def test_collect_interfaces_falls_back_to_ifdescr_after_ifname_failure() -> None:
    import asyncio

    from lldp_runner.collectors.interfaces import IF_DESCR, IF_NAME, collect_interfaces

    class Walker:
        async def walk(self, oid: str):
            if oid == IF_NAME:
                raise TimeoutError("ifName timeout")
            assert oid == IF_DESCR
            return [(f"{IF_DESCR}.101", b"GigabitEthernet1/0/1")]

    result = asyncio.run(collect_interfaces(Walker()))

    assert result == {101: ("GigabitEthernet1/0/1", "Gi1/0/1")}


def test_collect_interfaces_raises_when_both_naming_tables_fail() -> None:
    import asyncio

    import pytest

    from lldp_runner.collectors.interfaces import InterfaceCollectionError, collect_interfaces

    class Walker:
        async def walk(self, oid: str):
            raise TimeoutError(f"{oid} timeout")

    with pytest.raises(InterfaceCollectionError, match="both IF-MIB"):
        asyncio.run(collect_interfaces(Walker()))


def test_collect_interfaces_raises_when_ifname_empty_and_ifdescr_fails() -> None:
    import asyncio

    import pytest

    from lldp_runner.collectors.interfaces import (
        IF_DESCR,
        IF_NAME,
        InterfaceCollectionError,
        collect_interfaces,
    )

    class Walker:
        async def walk(self, oid: str):
            if oid == IF_NAME:
                return []
            assert oid == IF_DESCR
            raise TimeoutError("ifDescr timeout")

    with pytest.raises(InterfaceCollectionError, match="ifName produced no mappings"):
        asyncio.run(collect_interfaces(Walker()))


def test_collect_interfaces_raises_when_fallback_is_empty_after_failure() -> None:
    import asyncio

    import pytest

    from lldp_runner.collectors.interfaces import (
        IF_DESCR,
        IF_NAME,
        InterfaceCollectionError,
        collect_interfaces,
    )

    class Walker:
        async def walk(self, oid: str):
            if oid == IF_NAME:
                raise TimeoutError("ifName timeout")
            assert oid == IF_DESCR
            return []

    with pytest.raises(InterfaceCollectionError, match="no usable mappings"):
        asyncio.run(collect_interfaces(Walker()))
