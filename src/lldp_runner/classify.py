"""Host classification and manufacturer/model inference."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import cast

from lldp_runner.config import AppConfig, _pattern_values
from lldp_runner.models import Candidate, HostCategory, SystemDetails

ENTERPRISE_MANUFACTURERS: dict[int, str] = {
    9: "Cisco",
    11: "HPE",
    318: "APC",
    534: "Eaton",
    2636: "Juniper",
    3375: "F5",
    6876: "VMware",
    14823: "Aruba",
    25461: "Palo Alto Networks",
    30065: "Arista",
}


@dataclass(slots=True)
class ClassificationDecision:
    category: HostCategory
    reasons: list[str]


@dataclass(slots=True)
class _CompiledEvidenceRule:
    category: HostCategory
    label: str
    name_regexes: list[re.Pattern[str]]
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    field_patterns: list[tuple[str, list[re.Pattern[str]]]]
    detail_patterns: list[tuple[str, list[re.Pattern[str]]]]


@dataclass(slots=True)
class _CompiledTagRule:
    tags: list[str]
    label: str
    category: HostCategory | None
    name_regexes: list[re.Pattern[str]]
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    field_patterns: list[tuple[str, list[re.Pattern[str]]]]
    detail_patterns: list[tuple[str, list[re.Pattern[str]]]]


def _evidence_text(value: object | None) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return " | ".join(str(item) for item in value)
    if isinstance(value, dict):
        return " | ".join(f"{key}={item}" for key, item in value.items())
    return str(value)


def _compile_pattern_value(value: str | list[str]) -> list[re.Pattern[str]]:
    return [re.compile(pattern) for pattern in _pattern_values(value)]


def _matching_regex(regexes: list[re.Pattern[str]], text: str) -> re.Pattern[str] | None:
    for regex in regexes:
        if regex.search(text) is not None:
            return regex
    return None


class Classifier:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.address_rules = sorted(
            [
                (ipaddress.ip_network(network, strict=False), rule.category)
                for rule in config.classification.address_rules
                for network in rule.network_values()
            ],
            key=lambda x: x[0].prefixlen,
            reverse=True,
        )
        self.name_rules = [
            ([re.compile(pattern) for pattern in rule.pattern_values()], rule.category)
            for rule in config.classification.name_rules
        ]
        self.evidence_rules: list[_CompiledEvidenceRule] = []
        for index, rule in enumerate(config.classification.evidence_rules, start=1):
            self.evidence_rules.append(
                _CompiledEvidenceRule(
                    category=cast(HostCategory, rule.category),
                    label=rule.label or f"#{index}",
                    name_regexes=[re.compile(pattern) for pattern in rule.name_pattern_values()],
                    networks=[
                        ipaddress.ip_network(network, strict=False)
                        for network in rule.network_values()
                    ],
                    field_patterns=[
                        (field_name, _compile_pattern_value(patterns))
                        for field_name, patterns in rule.field_patterns.items()
                    ],
                    detail_patterns=[
                        (detail_name, _compile_pattern_value(patterns))
                        for detail_name, patterns in rule.detail_patterns.items()
                    ],
                )
            )
        self.tag_rules: list[_CompiledTagRule] = []
        for index, rule in enumerate(config.tagging.rules, start=1):
            self.tag_rules.append(
                _CompiledTagRule(
                    tags=list(dict.fromkeys(tag.strip() for tag in rule.tags if tag.strip())),
                    label=rule.label or f"#{index}",
                    category=cast(HostCategory, rule.category) if rule.category else None,
                    name_regexes=[re.compile(pattern) for pattern in rule.name_pattern_values()],
                    networks=[
                        ipaddress.ip_network(network, strict=False)
                        for network in rule.network_values()
                    ],
                    field_patterns=[
                        (field_name, _compile_pattern_value(patterns))
                        for field_name, patterns in rule.field_patterns.items()
                    ],
                    detail_patterns=[
                        (detail_name, _compile_pattern_value(patterns))
                        for detail_name, patterns in rule.detail_patterns.items()
                    ],
                )
            )

        self.endpoint_patterns = [
            re.compile(x) for x in config.classification.managed_endpoint_patterns
        ]
        self.unmanaged_patterns = [re.compile(x) for x in config.classification.unmanaged_patterns]
        self.managed_manufacturers = {x.casefold() for x in config.classification.managed_manufacturers}

    def classify_candidate(self, candidate: Candidate) -> ClassificationDecision:
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for address in candidate.addresses:
            try:
                parsed_addresses.append(ipaddress.ip_address(address))
            except ValueError:
                continue
        for network, category in self.address_rules:
            if any(ip.version == network.version and ip in network for ip in parsed_addresses):
                return ClassificationDecision(
                    cast(HostCategory, category), [f"explicit most-specific address rule {network}"]
                )

        names = [*candidate.names]
        haystacks = [
            *names,
            candidate.remote_description or "",
            candidate.remote_platform or "",
            candidate.chassis_id or "",
        ]
        for regexes, category in self.name_rules:
            for regex in regexes:
                if any(regex.search(name) for name in names):
                    return ClassificationDecision(
                        cast(HostCategory, category), [f"explicit name rule {regex.pattern}"]
                    )

        for rule in self.evidence_rules:
            reasons = self._evidence_rule_match(rule, candidate, parsed_addresses)
            if reasons is not None:
                return ClassificationDecision(
                    rule.category,
                    [f"explicit evidence rule {rule.label}", *reasons],
                )

        combined = " | ".join(x for x in haystacks if x)
        for regex in self.endpoint_patterns:
            if regex.search(combined):
                return ClassificationDecision(
                    "managed_endpoint", [f"managed endpoint evidence matched {regex.pattern}"]
                )
        if any(cap in {"telephone", "wlanAccessPoint"} for cap in candidate.capabilities):
            return ClassificationDecision(
                "managed_endpoint", ["neighbor capability indicates phone or wireless access point"]
            )

        for regex in self.unmanaged_patterns:
            if regex.search(combined):
                return ClassificationDecision(
                    "unmanaged_device", [f"unmanaged evidence matched {regex.pattern}"]
                )
        if "stationOnly" in candidate.capabilities:
            return ClassificationDecision(
                "unmanaged_device", ["LLDP capability indicates station-only endpoint"]
            )

        manufacturer = infer_manufacturer(None, combined)
        network_cap = bool({"router", "bridge", "switch"} & set(candidate.capabilities))
        if manufacturer and manufacturer.casefold() in self.managed_manufacturers and network_cap:
            return ClassificationDecision(
                "managed_device",
                [f"managed manufacturer {manufacturer} with network-device capability"],
            )

        return ClassificationDecision("unknown_device", ["insufficient evidence to query safely"])

    @staticmethod
    def _evidence_rule_match(
        rule: _CompiledEvidenceRule,
        candidate: Candidate,
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    ) -> list[str] | None:
        reasons: list[str] = []
        if rule.name_regexes:
            matched_name_regex: re.Pattern[str] | None = None
            for regex in rule.name_regexes:
                if any(regex.search(name) for name in candidate.names):
                    matched_name_regex = regex
                    break
            if matched_name_regex is None:
                return None
            reasons.append(f"name matched {matched_name_regex.pattern}")

        if rule.networks:
            matched_network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
            for network in rule.networks:
                if any(
                    address.version == network.version and address in network
                    for address in parsed_addresses
                ):
                    matched_network = network
                    break
            if matched_network is None:
                return None
            reasons.append(f"address matched {matched_network}")

        for field_name, regexes in rule.field_patterns:
            if field_name == "protocol":
                value: object | None = list(
                    dict.fromkeys([*(candidate.protocols or []), candidate.protocol or ""])
                )
            else:
                value = getattr(candidate, field_name, None)
            text = _evidence_text(value)
            matched = _matching_regex(regexes, text) if text else None
            if matched is None:
                return None
            reasons.append(f"{field_name} matched {matched.pattern}")

        for detail_name, regexes in rule.detail_patterns:
            text = _evidence_text(candidate.details.get(detail_name))
            matched = _matching_regex(regexes, text) if text else None
            if matched is None:
                return None
            reasons.append(f"detail {detail_name} matched {matched.pattern}")

        return reasons

    def tags_for_candidate(self, candidate: Candidate) -> list[str]:
        """Return all matching operator tags in deterministic configuration order.

        Tag rules accumulate rather than using first-match-wins. Within one rule,
        alternatives in a pattern/CIDR list use OR semantics while separate
        condition types use AND semantics.
        """
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
        for address in candidate.addresses:
            try:
                parsed_addresses.append(ipaddress.ip_address(address))
            except ValueError:
                continue

        tags: list[str] = []
        for rule in self.tag_rules:
            if not self._tag_rule_matches(rule, candidate, parsed_addresses):
                continue
            for tag in rule.tags:
                if tag not in tags:
                    tags.append(tag)
        return tags

    @staticmethod
    def _tag_rule_matches(
        rule: _CompiledTagRule,
        candidate: Candidate,
        parsed_addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address],
    ) -> bool:
        if rule.category is not None and candidate.category != rule.category:
            return False
        if rule.name_regexes and not any(
            regex.search(name)
            for regex in rule.name_regexes
            for name in candidate.names
        ):
            return False
        if rule.networks and not any(
            address.version == network.version and address in network
            for network in rule.networks
            for address in parsed_addresses
        ):
            return False
        for field_name, regexes in rule.field_patterns:
            if field_name == "protocol":
                value: object | None = list(
                    dict.fromkeys([*(candidate.protocols or []), candidate.protocol or ""])
                )
            else:
                value = getattr(candidate, field_name, None)
            text = _evidence_text(value)
            if not text or _matching_regex(regexes, text) is None:
                return False
        for detail_name, regexes in rule.detail_patterns:
            text = _evidence_text(candidate.details.get(detail_name))
            if not text or _matching_regex(regexes, text) is None:
                return False
        return True


def infer_manufacturer(sys_object_id: str | None, description: str | None) -> str | None:
    if sys_object_id:
        parts = [x for x in sys_object_id.strip(".").split(".") if x.isdigit()]
        try:
            enterprise_pos = parts.index("4")
        except ValueError:
            enterprise_pos = -1
        # Standard enterprise OIDs begin 1.3.6.1.4.1.<enterprise>.
        if len(parts) >= 7 and parts[:6] == ["1", "3", "6", "1", "4", "1"]:
            try:
                return ENTERPRISE_MANUFACTURERS.get(int(parts[6]))
            except ValueError:
                pass
        elif enterprise_pos >= 0:
            pass
    text = (description or "").casefold()
    patterns = [
        ("cisco", "Cisco"),
        ("juniper", "Juniper"),
        ("junos", "Juniper"),
        ("arista", "Arista"),
        ("aruba", "Aruba"),
        ("hewlett packard", "HPE"),
        ("procurve", "HPE"),
        ("palo alto", "Palo Alto Networks"),
        ("pan-os", "Palo Alto Networks"),
        ("big-ip", "F5"),
        ("f5 networks", "F5"),
        ("vmware", "VMware"),
        ("gigamon", "Gigamon"),
        ("kemp", "Kemp"),
        ("western telematic", "WTI"),
    ]
    for needle, manufacturer in patterns:
        if needle in text:
            return manufacturer
    return None


def infer_model_version(system: SystemDetails) -> tuple[str | None, str | None]:
    text = system.sys_descr or ""
    model: str | None = None
    version: str | None = None
    model_patterns = [
        r"(?i)\b(C9\d{3}[A-Z0-9-]*)\b",
        r"(?i)\b(EX\d{3,4}[A-Z0-9-]*)\b",
        r"(?i)\b(QFX\d{3,4}[A-Z0-9-]*)\b",
        r"(?i)\b(7050[A-Z0-9-]*)\b",
        r"(?i)\b(PA-\d+[A-Z0-9-]*)\b",
    ]
    for pattern in model_patterns:
        match = re.search(pattern, text)
        if match:
            model = match.group(1)
            break
    version_patterns = [
        r"(?i)\bVersion\s+([^,;\s]+)",
        r"(?i)\bJUNOS\s+([^,;\s]+)",
        r"(?i)\bEOS[- ]?([^,;\s]+)",
    ]
    for pattern in version_patterns:
        match = re.search(pattern, text)
        if match:
            version = match.group(1)
            break
    return model, version


def classify_system_managed(system: SystemDetails, managed_manufacturers: Iterable[str]) -> bool:
    if not system.manufacturer:
        return False
    return system.manufacturer.casefold() in {x.casefold() for x in managed_manufacturers}
