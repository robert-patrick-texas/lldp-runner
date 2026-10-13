"""Text and OCTET STRING normalization shared by SNMP collectors and outputs.

Network devices do not always honor the textual intent of an SNMP OCTET STRING.
Some agents return padded strings, embedded terminal-control bytes, or genuinely
binary identifiers.  Keeping those bytes in Python strings is risky because NUL
characters can make CSV output appear binary to command-line tools and other
control characters can affect terminals or line-oriented parsers.

This module establishes one normalization boundary for values that LLDP-Runner
intends to treat as text.  Collectors should use :func:`snmp_text` instead of
implementing their own decoder. LLDP chassis and port identifiers should use
:func:`lldp_chassis_id` and :func:`lldp_port_id`; both honor the advertised
subtype and keep binary identifiers printable. Output writers use
:func:`safe_output_text` as a second defensive layer in case a future code path
bypasses collector sanitation.
"""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any

# Horizontal tab and line breaks are meaningful textual whitespace, but they are
# inconvenient inside CSV cells and log lines.  They are normalized to ordinary
# spaces rather than treated as binary data.
_TEXT_WHITESPACE_CONTROLS = {"\t", "\n", "\r"}

# Textual MAC forms commonly advertised by LLDP agents.  When the chassis-ID
# subtype explicitly says "macAddress", normalize these representations so the
# same MAC address has a stable identity key.
_MAC_COLON_OR_DASH = re.compile(r"(?i)^[0-9a-f]{2}(?P<sep>[:-])[0-9a-f]{2}(?:(?P=sep)[0-9a-f]{2}){4}$")
_MAC_DOTTED = re.compile(r"(?i)^[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}$")


def _is_forbidden_control(character: str) -> bool:
    """Return True for control/surrogate code points unsafe in stored text.

    Unicode category ``Cc`` covers the C0/C1 control ranges, including NUL,
    BEL, ESC, DEL, and U+0080..U+009F.  ``Cs`` covers surrogate code points,
    which cannot be encoded as normal UTF-8 text and should never reach output.
    TAB/CR/LF are handled separately as whitespace.
    """

    if character in _TEXT_WHITESPACE_CONTROLS:
        return False
    return unicodedata.category(character) in {"Cc", "Cs"}


def _contains_forbidden_controls(value: str) -> bool:
    """Detect embedded controls that indicate unsafe or binary-looking text."""

    return any(_is_forbidden_control(character) for character in value)


def _normalize_text_whitespace(value: str) -> str:
    """Replace embedded line/tab controls and remove other unsafe controls.

    Valid printable Unicode is intentionally preserved.  LLDP-Runner operates in
    environments where legitimate location/description fields can contain
    non-ASCII characters, so sanitation must not be implemented as an ASCII-only
    filter.
    """

    output: list[str] = []
    for character in value:
        if character in _TEXT_WHITESPACE_CONTROLS:
            output.append(" ")
            continue
        if unicodedata.category(character) in {"Cc", "Cs"}:
            continue
        output.append(character)
    return "".join(output).strip()


def printable_hex(raw: bytes) -> str:
    """Return a stable, grep-safe printable representation of binary bytes."""

    return "hex:" + raw.hex(":")


def snmp_text(value: object | None) -> str | None:
    """Convert a value intended as SNMP text into safe printable Unicode.

    Rules are deliberately conservative:

    * trailing NUL padding on byte strings is removed before decoding;
    * valid UTF-8 text is preserved, with TAB/CR/LF normalized to spaces;
    * an embedded forbidden C0/C1 control or surrogate causes byte-backed values
      to be represented as ``hex:aa:bb:...`` instead of silently dropping bytes;
    * invalid UTF-8 byte strings are also represented as printable hexadecimal;
    * already-decoded Python strings containing forbidden controls are converted
      to hexadecimal from their UTF-8 representation where possible.

    The hexadecimal fallback is important for identifiers and malformed agent
    data: operators can still see exactly what was received without introducing
    NUL or terminal-control bytes into SQLite, JSON, CSV, or regex evidence.
    """

    if value is None:
        return None

    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        # A trailing NUL is common SNMP string padding and is not by itself a
        # reason to label an otherwise normal value as binary.
        trimmed = raw.rstrip(b"\x00")
        if not trimmed:
            return None
        try:
            decoded = trimmed.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return printable_hex(raw)
        if _contains_forbidden_controls(decoded):
            return printable_hex(raw)
        text = _normalize_text_whitespace(decoded)
        return text or None

    text = str(value).rstrip("\x00")
    if not text:
        return None
    # Most SNMP libraries preserve OCTET STRING values as bytes, but retaining
    # this check protects against a backend that has already decoded the value.
    if _contains_forbidden_controls(text):
        try:
            return printable_hex(text.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            text = _normalize_text_whitespace(text)
            return text or None
    text = _normalize_text_whitespace(text)
    return text or None


def _normalize_mac_text(value: str) -> str | None:
    """Normalize common textual MAC-address formats to colon-separated hex."""

    stripped = value.strip()
    if _MAC_COLON_OR_DASH.fullmatch(stripped):
        compact = re.sub(r"[:-]", "", stripped)
    elif _MAC_DOTTED.fullmatch(stripped):
        compact = stripped.replace(".", "")
    else:
        return None
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2)).lower()


def _lldp_mac_identifier(value: object | None) -> str | None:
    """Decode an LLDP macAddress identifier without interpreting bytes as text."""

    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) == 6:
            return raw.hex(":")
        # Some devices incorrectly return an ASCII MAC string even though the
        # subtype declares macAddress.  Accept that form before falling back.
        try:
            decoded = raw.rstrip(b"\x00").decode("ascii", errors="strict")
        except UnicodeDecodeError:
            return printable_hex(raw)
        normalized = _normalize_mac_text(decoded)
        return normalized or printable_hex(raw)
    text = snmp_text(value)
    if not text:
        return None
    return _normalize_mac_text(text) or text


def _lldp_network_identifier(value: object | None) -> str | None:
    """Decode an LLDP networkAddress identifier when its encoding is recognizable.

    IEEE LLDP network-address identifiers commonly carry one address-family octet
    followed by the address bytes.  Field implementations in the wild vary, so
    LLDP-Runner accepts both ``family + address`` and bare 4/16-byte addresses,
    then falls back to safe text/hex rather than guessing.
    """

    if value is None:
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        candidates: list[bytes] = []
        if len(raw) in {4, 16}:
            candidates.append(raw)
        elif len(raw) == 5 and raw[0] == 1:  # IPv4 family + address
            candidates.append(raw[1:])
        elif len(raw) == 17 and raw[0] == 2:  # IPv6 family + address
            candidates.append(raw[1:])
        for candidate in candidates:
            try:
                return str(ipaddress.ip_address(candidate))
            except ValueError:
                continue
        # A few agents expose textual IP addresses instead of the binary form.
        text = snmp_text(raw)
        if text and not text.startswith("hex:"):
            try:
                return str(ipaddress.ip_address(text.strip().strip("[]")))
            except ValueError:
                pass
        return text

    text = snmp_text(value)
    if not text:
        return None
    try:
        return str(ipaddress.ip_address(text.strip().strip("[]")))
    except ValueError:
        return text


def lldp_chassis_id(value: object | None, subtype_id: int | None) -> str | None:
    """Normalize an LLDP chassis ID according to its advertised subtype.

    ``mac_address`` (4) and ``network_address`` (5) are binary identifier types
    and therefore receive subtype-specific decoding.  Text-like or unknown
    subtypes use :func:`snmp_text`; binary-looking values remain visible as a
    ``hex:`` string rather than leaking control bytes into downstream data.
    """

    if subtype_id == 4:
        return _lldp_mac_identifier(value)
    if subtype_id == 5:
        return _lldp_network_identifier(value)
    return snmp_text(value)


def lldp_port_id(value: object | None, subtype_id: int | None) -> str | None:
    """Normalize an LLDP Port ID according to its advertised subtype.

    Port-ID subtype numbers differ from chassis-ID subtype numbers: macAddress is
    3 and networkAddress is 4. In particular, Windows and other endpoint LLDP
    agents commonly advertise a six-byte MAC address as Port ID; decoding it
    structurally avoids the generic ``hex:`` fallback that would otherwise hide
    the familiar MAC representation from operators.
    """

    if subtype_id == 3:
        return _lldp_mac_identifier(value)
    if subtype_id == 4:
        return _lldp_network_identifier(value)
    return snmp_text(value)


def safe_output_text(value: Any) -> str:
    """Return a final output-safe string for CSV/log-style text fields.

    This is a defense-in-depth layer, not a replacement for SNMP normalization.
    It removes C0/C1 controls and surrogates, normalizes embedded TAB/CR/LF to
    spaces, and converts raw byte values to a printable hexadecimal string.
    CSV record separators are added later by :mod:`csv`, so embedded newlines in
    device-supplied fields are never emitted into a cell.
    """

    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return printable_hex(bytes(value))
    return _normalize_text_whitespace(str(value))
