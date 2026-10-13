from __future__ import annotations

from lldp_runner.classify import Classifier
from lldp_runner.config import (
    AddressCredentialRule,
    ClassificationAddressRule,
    ClassificationEvidenceRule,
    ClassificationNameRule,
    NameCredentialRule,
    QueryAddressRule,
    QueryNameRule,
    TagRule,
)
from lldp_runner.models import Candidate
from lldp_runner.policy import PolicyEngine


def test_credential_address_rule_accepts_multiple_networks(config):
    config.credential_rules.address = [
        AddressCredentialRule(
            profile="specific",
            networks=["198.18.36.0/24", "198.51.100.0/24"],
        )
    ]
    policy = PolicyEngine(config)
    assert policy.credential_profile(["x"], "198.18.36.10").profile.name == "specific"
    assert policy.credential_profile(["x"], "198.51.100.10").profile.name == "specific"


def test_credential_address_lists_preserve_longest_prefix_semantics(config):
    config.credential_rules.address = [
        AddressCredentialRule(profile="default", networks=["198.18.0.0/15"]),
        AddressCredentialRule(profile="specific", networks=["198.18.36.0/24"]),
    ]
    decision = PolicyEngine(config).credential_profile(["x"], "198.18.36.44")
    assert decision.profile.name == "specific"
    assert "198.18.36.0/24" in decision.reason


def test_credential_name_rule_accepts_multiple_patterns_and_first_rule_wins(config):
    config.credential_rules.name = [
        NameCredentialRule(profile="specific", patterns=[r"^core-", r"^dist-"]),
        NameCredentialRule(profile="default", patterns=[r".*"]),
    ]
    decision = PolicyEngine(config).credential_profile(["dist-a.net.example.com"], "198.51.100.10")
    assert decision.profile.name == "specific"
    assert "^dist-" in decision.reason


def test_query_policy_address_and_name_rules_accept_lists(config):
    config.query_policy.address_rules = [
        QueryAddressRule(action="deny", networks=["198.18.200.0/24", "198.18.201.0/24"])
    ]
    config.query_policy.name_rules = [
        QueryNameRule(
            action="deny", patterns=[r"(?i)\.ops\.example\.com$", r"(?i)\.external\.example\.org$"]
        )
    ]
    policy = PolicyEngine(config)
    assert not policy.query_policy(["x"], "198.18.201.10").allowed
    assert not policy.query_policy(["ops-access-3850.ops.example.com"], "198.18.10.10").allowed
    assert not policy.query_policy(
        ["branch-router-01.external.example.org"], "198.18.10.10"
    ).allowed


def test_classification_address_and_name_rules_accept_lists(config):
    config.classification.address_rules = [
        ClassificationAddressRule(
            category="unmanaged_device",
            networks=["198.18.220.0/24", "198.18.221.0/24"],
        )
    ]
    config.classification.name_rules = [
        ClassificationNameRule(
            category="unmanaged_device",
            patterns=[r"(?i)\.ops\.example\.com$", r"(?i)\.branch\.example\.net$"],
        )
    ]
    classifier = Classifier(config)
    assert (
        classifier.classify_candidate(Candidate(addresses=["198.18.221.20"])).category
        == "unmanaged_device"
    )
    assert (
        classifier.classify_candidate(Candidate(names=["ops-access-3850.ops.example.com"])).category
        == "unmanaged_device"
    )
    assert (
        classifier.classify_candidate(
            Candidate(names=["branch-access-sw1.branch.example.net"])
        ).category
        == "unmanaged_device"
    )


def test_evidence_rule_uses_or_inside_lists_and_and_across_conditions(config):
    config.classification.managed_manufacturers = []
    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            label="hpe-access",
            category="managed_device",
            name_patterns=[r"(?i)-6300(?:\.|$)", r"(?i)-6200(?:\.|$)"],
            networks=["198.18.40.0/24", "198.18.41.0/24"],
            field_patterns={
                "remote_description": [r"(?i)^HPE\s+ANW\s+JL", r"(?i)^Aruba\s+JL"],
                "protocol": [r"\blldp\b", r"\bcdp\b"],
            },
        )
    ]
    classifier = Classifier(config)
    matched = Candidate(
        names=["hq-access-6200"],
        addresses=["198.18.41.10"],
        remote_description="HPE ANW JL725A",
        protocol="lldp",
        protocols=["lldp"],
    )
    wrong_network = Candidate(
        names=["hq-access-6200"],
        addresses=["198.18.42.10"],
        remote_description="HPE ANW JL725A",
        protocol="lldp",
        protocols=["lldp"],
    )
    assert classifier.classify_candidate(matched).category == "managed_device"
    assert classifier.classify_candidate(wrong_network).category == "unknown_device"


def test_tag_rule_accepts_multiple_name_network_and_field_patterns(config):
    config.tagging.rules = [
        TagRule(
            category="managed_endpoint",
            name_patterns=[r"(?i)^SEP", r"(?i)^VIPER-"],
            networks=["198.18.64.0/20", "198.18.80.0/20"],
            field_patterns={"remote_description": [r"(?i)Cisco.*Phone", r"(?i)General Dynamics"]},
            tags=["service:voice", "customer:shared"],
        )
    ]
    candidate = Candidate(
        names=["VIPER-12345"],
        addresses=["198.18.80.15"],
        category="managed_endpoint",
        remote_description="General Dynamics vIPer",
    )
    assert Classifier(config).tags_for_candidate(candidate) == ["service:voice", "customer:shared"]


def test_evidence_and_tag_detail_patterns_accept_lists(config):
    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            category="managed_device",
            detail_patterns={"lldp.remote_description": [r"(?i)^HPE\s+ANW", r"(?i)^Aruba\s+JL"]},
        )
    ]
    config.tagging.rules = [
        TagRule(
            detail_patterns={"lldp.remote_platform": [r"(?i)CX\s*6300", r"(?i)CX\s*6200"]},
            tags=["platform:aruba-cx"],
        )
    ]
    candidate = Candidate(
        details={
            "lldp.remote_description": "Aruba JL725A",
            "lldp.remote_platform": "CX 6200F",
        }
    )
    classifier = Classifier(config)
    assert classifier.classify_candidate(candidate).category == "managed_device"
    assert classifier.tags_for_candidate(candidate) == ["platform:aruba-cx"]
