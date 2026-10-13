"""Host-address eligibility and identity-alias regression coverage."""

from __future__ import annotations

import pytest

from lldp_runner.identity import (
    alias_tuples,
    anonymous_endpoint_port_mac,
    canonical_mac,
    chassis_identity_value,
    cisco_ap_mac,
    cisco_sep_mac,
    host_address_rejection_reason,
    is_usable_host_address,
    normalize_host_address,
    resolve_seed,
    typed_port_id_mac,
    weak_mobility_mac,
)


@pytest.mark.parametrize(
    "value",
    [
        "198.51.100.1",
        "100.64.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "169.254.100.10",
        "fc00::1",
        "fe80::1",
        "2001:db8::1",
    ],
)
def test_host_address_filter_keeps_plausible_unicast_and_link_local(value: str) -> None:
    """Non-global address space remains usable when it can identify one host."""

    assert is_usable_host_address(value) is True
    assert normalize_host_address(value)
    assert host_address_rejection_reason(value) is None


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("not-an-address", "invalid IP address syntax"),
        ("0.0.0.0", "unspecified address"),
        ("0.0.0.1", "IPv4 this-network address"),
        ("127.0.0.1", "loopback address"),
        ("224.0.0.1", "multicast address"),
        ("240.0.0.1", "reserved IPv4 address"),
        ("255.255.255.255", "IPv4 limited-broadcast address"),
        ("::", "unspecified address"),
        ("::1", "loopback address"),
        ("ff02::1", "multicast address"),
        ("::ffff:255.255.255.255", "IPv4-mapped limited-broadcast address"),
        ("::ffff:240.0.0.1", "IPv4-mapped reserved address"),
    ],
)
def test_host_address_filter_rejects_non_host_identity_values(
    value: str, reason: str
) -> None:
    """Syntactically valid sentinel/group addresses must not identify a host."""

    assert is_usable_host_address(value) is False
    assert host_address_rejection_reason(value) == reason
    with pytest.raises(ValueError, match="not a usable host address"):
        normalize_host_address(value)



@pytest.mark.parametrize("value", ["0.0.0.0", "255.255.255.255", "::", "ff02::1"])
def test_literal_seed_rejects_non_host_ip_before_resolver_or_query(value: str) -> None:
    """An operator IP seed cannot schedule a non-host sentinel/group address."""

    with pytest.raises(ValueError, match="not a usable host address"):
        resolve_seed(value, [])

def test_alias_tuples_drop_bogus_addresses_but_keep_link_local() -> None:
    """Identity aliases are the final defense against collector/input mistakes."""

    aliases = alias_tuples(
        ["esxi-a.example.com"],
        ["0.0.0.0", "255.255.255.255", "::", "169.254.100.10", "fe80::1"],
    )

    assert ("name", "esxi-a.example.com") in aliases
    assert ("ipv4", "169.254.100.10") in aliases
    assert ("ipv6", "fe80::1") in aliases
    assert all(value not in {"0.0.0.0", "255.255.255.255", "::"} for _, value in aliases)


def test_network_address_chassis_id_must_also_be_host_eligible() -> None:
    """A network-address chassis subtype cannot bypass address eligibility."""

    assert chassis_identity_value("0.0.0.0", "network_address", 5) is None
    assert chassis_identity_value("255.255.255.255", "network_address", 5) is None
    assert chassis_identity_value("::", "network_address", 5) is None
    assert (
        chassis_identity_value("169.254.100.10", "network_address", 5)
        == "5:169.254.100.10"
    )

@pytest.mark.parametrize(
    "value",
    ["unknown", "none", "null", "n/a", "na", "-", "(none)", "(none).(none)", "not advertised"],
)
def test_alias_tuples_exclude_placeholder_identity_names(value: str) -> None:
    """Missing-value text remains diagnostic content, never a global name alias."""

    aliases = alias_tuples([value], ["198.18.0.10"])

    assert aliases == [("ipv4", "198.18.0.10")]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("SEP001234560004", "00:12:34:56:00:04"),
        ("SEP001234560004.voice-a.example.com", "00:12:34:56:00:04"),
        ("sep001234560004.voice-b.example.net.", "00:12:34:56:00:04"),
        ("SEP00123456000", None),
        ("SEP001234560004X", None),
        ("PHONE001234560004", None),
    ],
)
def test_cisco_sep_mac_is_strict_host_component_identity(
    value: str, expected: str | None
) -> None:
    """Only an exact SEP plus twelve-hex host component yields MAC identity."""

    assert cisco_sep_mac(value) == expected


def test_alias_tuples_add_same_mac_for_sep_short_and_fqdn_forms() -> None:
    """Cisco SEP short/FQDN names share durable canonical MAC evidence."""

    short = alias_tuples(["SEP001234560004"], [])
    fqdn = alias_tuples(["SEP001234560004.voice-a.example.com"], [])

    assert ("mac", "00:12:34:56:00:04") in short
    assert ("mac", "00:12:34:56:00:04") in fqdn
    assert ("name", "sep001234560004") in short
    assert ("name", "sep001234560004.voice-a.example.com") in fqdn


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AP0012.3456.A001", "00:12:34:56:a0:01"),
        ("AP0012.3456.A001.example.com", "00:12:34:56:a0:01"),
        ("AP00123456A001", "00:12:34:56:a0:01"),
        ("AP00123456A001.example.com", "00:12:34:56:a0:01"),
        ("AP0012.3456.A00", None),
        ("AP0012.3456.A001X", None),
        ("WAP0012.3456.A001", None),
    ],
)
def test_cisco_ap_mac_is_strict_hardware_identity(
    value: str, expected: str | None
) -> None:
    """Only strict Cisco AP MAC forms yield canonical hardware identity."""

    assert cisco_ap_mac(value) == expected


def test_alias_tuples_bridge_strict_ap_name_to_lldp_mac_chassis() -> None:
    """A Cisco AP CDP name and its exact LLDP chassis MAC share one token."""

    aliases = alias_tuples(["AP0012.3456.A001"], [])

    assert ("mac", "00:12:34:56:a0:01") in aliases
    assert ("chassis_id", "4:00:12:34:56:a0:01") in aliases


def test_alias_tuples_scope_network_and_interface_chassis_subtypes() -> None:
    """Address-like chassis values stay weak and device-local values stay scoped."""

    network = alias_tuples([], [], "198.51.100.29", "network_address", 5)
    interface = alias_tuples([], [], "vmnic2", "interface_name", 6)
    local = alias_tuples([], [], "hex:a1:00:00:00:00:00", "local", 7)

    assert network == []
    assert interface == []
    assert local == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("1098194D2F97", "10:98:19:4d:2f:97"),
        ("10:98:19:4D:2F:97", "10:98:19:4d:2f:97"),
        ("10-98-19-4D-2F-97", "10:98:19:4d:2f:97"),
        ("1098.194D.2F97", "10:98:19:4d:2f:97"),
        ("hex:10:98:19:4d:2f:97", None),
        ("endpoint-1098194D2F97", None),
        ("10:98:19:4d:2f", None),
    ],
)
def test_canonical_mac_accepts_only_complete_unambiguous_forms(
    value: str, expected: str | None
) -> None:
    """Malformed diagnostic text must not become global MAC identity."""

    assert canonical_mac(value) == expected


def test_typed_port_id_mac_requires_explicit_agreeing_mac_subtype() -> None:
    """Only one unambiguous typed LLDP/LLDPv2 Port ID is promotable."""

    assert typed_port_id_mac(
        {
            "port_id": "10:98:19:4d:2f:97",
            "port_id_subtype": "mac_address",
            "port_id_subtype_id": 3,
            "lldpv2.port_id": "1098.194d.2f97",
            "lldpv2.port_id_subtype": "mac_address",
            "lldpv2.port_id_subtype_id": 3,
        }
    ) == "10:98:19:4d:2f:97"
    assert typed_port_id_mac(
        {
            "port_id": "10:98:19:4d:2f:97",
            "port_id_subtype": "interface_name",
            "port_id_subtype_id": 5,
        }
    ) is None
    assert typed_port_id_mac(
        {
            "lldp.port_id": "10:98:19:4d:2f:97",
            "lldp.port_id_subtype_id": 3,
            "lldpv2.port_id": "08:92:04:f6:d6:f4",
            "lldpv2.port_id_subtype_id": 3,
        }
    ) is None


def test_anonymous_endpoint_port_mac_does_not_override_stronger_identity() -> None:
    """The Port-ID MAC fallback is limited to otherwise anonymous endpoints."""

    details = {
        "port_id": "10:98:19:4d:2f:97",
        "port_id_subtype": "mac_address",
        "port_id_subtype_id": 3,
    }
    anonymous = anonymous_endpoint_port_mac(
        names=[],
        addresses=[],
        chassis_id="hex:a1:00:00:00:00:00",
        chassis_id_subtype="local",
        chassis_id_subtype_id=7,
        details=details,
    )
    named = anonymous_endpoint_port_mac(
        names=["endpoint.example.com"],
        addresses=[],
        chassis_id="hex:a1:00:00:00:00:00",
        chassis_id_subtype="local",
        chassis_id_subtype_id=7,
        details=details,
    )

    assert anonymous == "10:98:19:4d:2f:97"
    assert named is None


def test_decorated_advertised_name_separates_base_and_serial_hint() -> None:
    """A trailing alphanumeric serial is metadata, not part of the logical name."""

    from lldp_runner.identity import normalized_advertised_name

    parsed = normalized_advertised_name(
        "hq-vdc2-7nx1.net.example.com(SERIAL000001)"
    )

    assert parsed is not None
    assert parsed.raw_name == "hq-vdc2-7nx1.net.example.com(SERIAL000001)"
    assert parsed.base_name == "hq-vdc2-7nx1.net.example.com"
    assert parsed.serial_hint == "SERIAL000001"


@pytest.mark.parametrize(
    "value",
    [
        "switch1.example.com(primary)",
        "switch1.example.com(ABCDEF)",
        "switch1.example.com(12345)",
        "switch1.example.com(serial-number)",
    ],
)
def test_parenthesized_text_that_is_not_plausible_serial_stays_in_name(
    value: str,
) -> None:
    """The parser must not strip generic labels or malformed serial text."""

    from lldp_runner.identity import normalized_advertised_name

    parsed = normalized_advertised_name(value)

    assert parsed is not None
    assert parsed.raw_name == value
    assert parsed.base_name == value
    assert parsed.serial_hint is None


def test_alias_tuples_include_decorated_logical_base_but_not_serial_as_alias() -> None:
    """Name matching can use the base while chassis linking remains deferred."""

    aliases = alias_tuples(["hq-vdc2-7nx1.net.example.com(SERIAL000001)"], [])

    assert ("name", "hq-vdc2-7nx1.net.example.com") in aliases
    assert ("name", "hq-vdc2-7nx1.net.example.com(serial000001)") in aliases
    assert all(value != "serial000001" for _kind, value in aliases)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("00:00:00:00:01:03", True),
        ("02:11:22:33:44:55", True),
        ("01:11:22:33:44:55", True),
        ("not-a-mac", True),
        ("00:11:22:33:44:55", False),
        ("8c:0f:6f:6b:81:30", False),
    ],
)
def test_weak_mobility_mac_boundary(value: str, expected: bool) -> None:
    """Mobility correlation rejects weak MAC evidence conservatively."""

    assert weak_mobility_mac(value) is expected
