"""CIDR scope, credential selection, query exceptions, and explain support."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass

from lldp_runner.config import AppConfig, CredentialProfile


@dataclass(slots=True)
class PolicyDecision:
    """Result of one discovery boundary or explicit query-policy decision."""

    allowed: bool
    reason: str
    matched_rule: str | None = None


@dataclass(slots=True)
class CredentialDecision:
    """Selected credential profile plus the rule explaining that selection."""

    profile: CredentialProfile
    reason: str
    matched_rule: str | None = None


class PolicyEngine:
    """Evaluate scope, query, and credential policy for resolved device targets."""

    def __init__(self, config: AppConfig) -> None:
        """Compile configured CIDRs and regex rules for repeated policy lookups.

        Args:
            config: Effective application configuration containing discovery
                boundaries, query-policy rules, and credential-selection rules.

        Returns:
            ``None``. The instance retains compiled/sorted rules for later calls.
        """

        self.config = config
        self.boundaries = [
            ipaddress.ip_network(x, strict=False) for x in config.discovery.boundaries
        ]

        # Address rules retain longest-prefix semantics across every CIDR in every
        # configured rule. Python's stable sort preserves configuration/list order
        # when two networks have the same prefix length.
        self.credential_address_rules = sorted(
            [
                (ipaddress.ip_network(network, strict=False), rule.profile)
                for rule in config.credential_rules.address
                for network in rule.network_values()
            ],
            key=lambda x: x[0].prefixlen,
            reverse=True,
        )
        # Name rules remain first-rule-wins. Any regex inside a rule may satisfy
        # that rule, which makes a group of equivalent patterns easy to maintain.
        self.credential_name_rules = [
            ([re.compile(pattern) for pattern in rule.pattern_values()], rule.profile)
            for rule in config.credential_rules.name
        ]
        self.query_address_rules = sorted(
            [
                (ipaddress.ip_network(network, strict=False), rule.action)
                for rule in config.query_policy.address_rules
                for network in rule.network_values()
            ],
            key=lambda x: x[0].prefixlen,
            reverse=True,
        )
        self.query_name_rules = [
            ([re.compile(pattern) for pattern in rule.pattern_values()], rule.action)
            for rule in config.query_policy.name_rules
        ]

    def in_boundary(self, address: str) -> PolicyDecision:
        """Determine whether one IP address belongs to a discovery boundary.

        Args:
            address: Candidate IPv4 or IPv6 address string.

        Returns:
            A :class:`PolicyDecision` identifying the matched boundary or why the
            address cannot be considered in scope.
        """

        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return PolicyDecision(False, "target is not an IP address")
        for network in self.boundaries:
            if ip.version == network.version and ip in network:
                return PolicyDecision(True, f"inside discovery boundary {network}", str(network))
        return PolicyDecision(False, "outside all discovery boundaries")

    @staticmethod
    def _matching_pattern(
        regexes: list[re.Pattern[str]], names: Iterable[str]
    ) -> re.Pattern[str] | None:
        """Return the first configured regex matching any supplied name.

        Args:
            regexes: Compiled patterns in configuration priority order.
            names: Candidate DNS/system names for the same device identity.

        Returns:
            The first matching compiled expression, or ``None`` when no rule
            matches any candidate name.
        """

        name_values = list(names)
        for regex in regexes:
            if any(regex.search(name) for name in name_values):
                return regex
        return None

    def query_policy(
        self,
        names: Iterable[str],
        address: str,
        *,
        enforce_boundary: bool = True,
    ) -> PolicyDecision:
        """Evaluate explicit query allow/deny policy for one address.

        Recursive discovery enforces ``discovery.boundaries`` before considering
        query-policy rules.  Single-device inspection is intentionally different:
        the operator explicitly named the target, so it calls this method with
        ``enforce_boundary=False`` while still honoring address/name deny rules.
        Keeping the behavior as an explicit parameter avoids duplicating policy
        matching logic or accidentally weakening recursive discovery.
        """

        if enforce_boundary:
            boundary = self.in_boundary(address)
            if not boundary.allowed:
                return boundary
        ip = ipaddress.ip_address(address)
        for network, action in self.query_address_rules:
            if network.version == ip.version and ip in network:
                return PolicyDecision(
                    action == "allow",
                    f"{action} by most-specific address rule {network}",
                    str(network),
                )
        name_values = list(names)
        for regexes, action in self.query_name_rules:
            matched = self._matching_pattern(regexes, name_values)
            if matched is not None:
                return PolicyDecision(
                    action == "allow",
                    f"{action} by first matching name rule {matched.pattern}",
                    matched.pattern,
                )
        action = self.config.query_policy.default_action
        return PolicyDecision(action == "allow", f"{action} by default query policy")

    def credential_profile(self, names: Iterable[str], address: str) -> CredentialDecision:
        """Select the credential profile for one resolved device candidate.

        Args:
            names: Candidate names used by ordered credential name rules.
            address: IPv4/IPv6 management address used by most-specific CIDR
                credential rules.

        Returns:
            The selected :class:`CredentialDecision`. Address rules take
            precedence over name rules, which take precedence over the configured
            default profile.
        """

        ip = ipaddress.ip_address(address)
        for network, profile_name in self.credential_address_rules:
            if network.version == ip.version and ip in network:
                return CredentialDecision(
                    self.config.credential_profiles[profile_name],
                    f"most-specific address match {network}",
                    str(network),
                )
        name_values = list(names)
        for regexes, profile_name in self.credential_name_rules:
            matched = self._matching_pattern(regexes, name_values)
            if matched is not None:
                return CredentialDecision(
                    self.config.credential_profiles[profile_name],
                    f"first matching name rule {matched.pattern}",
                    matched.pattern,
                )
        name = self.config.credential_rules.default_profile
        return CredentialDecision(
            self.config.credential_profiles[name], "default credential profile"
        )
