from __future__ import annotations

from lldp_runner.textutil import lldp_chassis_id, lldp_port_id, safe_output_text, snmp_text


def test_snmp_text_preserves_unicode_and_normalizes_text_whitespace():
    assert snmp_text("Montréal Data Center") == "Montréal Data Center"
    assert snmp_text(b"line one\r\nline two\troom 4\x00") == "line one  line two room 4"


def test_snmp_text_uses_hex_for_embedded_controls_and_invalid_utf8():
    # This mirrors the malformed FLEXIDOME-style LLDP chassis ID that motivated
    # the sanitizer: the bytes are technically UTF-8-decodable but are not text.
    assert snmp_text(b"\x00\x07_{f4") == "hex:00:07:5f:7b:66:34"
    assert snmp_text(b"\xff\xfe\x01") == "hex:ff:fe:01"


def test_lldp_chassis_id_decodes_binary_subtypes():
    assert lldp_chassis_id(bytes.fromhex("8c04baa31a0d"), 4) == "8c:04:ba:a3:1a:0d"
    assert lldp_chassis_id(b"8C04.BAA3.1A0D", 4) == "8c:04:ba:a3:1a:0d"
    assert lldp_chassis_id(bytes([1, 198, 18, 20, 44]), 5) == "198.18.20.44"
    assert (
        lldp_chassis_id(bytes([2]) + bytes.fromhex("20010db8000000000000000000000044"), 5)
        == "2001:db8::44"
    )
    assert lldp_chassis_id(b"\x00\x07_{f4", 7) == "hex:00:07:5f:7b:66:34"


def test_lldp_port_id_decodes_binary_mac_and_network_subtypes():
    """Port-ID subtype numbers use the Port ID enumeration, not Chassis ID."""

    assert lldp_port_id(bytes.fromhex("8c04baa31a0d"), 3) == "8c:04:ba:a3:1a:0d"
    assert lldp_port_id(b"8C04.BAA3.1A0D", 3) == "8c:04:ba:a3:1a:0d"
    assert lldp_port_id(bytes([1, 198, 18, 20, 44]), 4) == "198.18.20.44"
    assert lldp_port_id(b"Ethernet1/48", 5) == "Ethernet1/48"


def test_safe_output_text_removes_controls_but_keeps_printable_unicode():
    value = "München\x00\x07\x1b\tRoom\n4\u0085"
    cleaned = safe_output_text(value)
    assert cleaned == "München Room 4"
    assert "\x00" not in cleaned
    assert "\x07" not in cleaned
    assert "\x1b" not in cleaned
    assert "\u0085" not in cleaned
