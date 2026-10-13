from lldp_runner.classify import Classifier, infer_manufacturer
from lldp_runner.models import Candidate


def test_endpoint_classification(config):
    classifier = Classifier(config)
    candidate = Candidate(names=["SEP001122AABBCC"], capabilities=["telephone"])
    decision = classifier.classify_candidate(candidate)
    assert decision.category == "managed_endpoint"


def test_managed_network_device_classification(config):
    classifier = Classifier(config)
    candidate = Candidate(
        names=["dist-1"],
        remote_description="Cisco IOS XE Software",
        capabilities=["bridge", "router"],
    )
    decision = classifier.classify_candidate(candidate)
    assert decision.category == "managed_device"


def test_unknown_is_safe_default(config):
    classifier = Classifier(config)
    decision = classifier.classify_candidate(Candidate(names=["mystery-device"]))
    assert decision.category == "unknown_device"


def test_enterprise_oid_manufacturer():
    assert infer_manufacturer("1.3.6.1.4.1.9.1.1208", None) == "Cisco"


def test_classification_name_rule_order_is_rule_first(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import ClassificationNameRule
    from lldp_runner.models import Candidate

    config.classification.name_rules = [
        ClassificationNameRule(pattern="^managed-", category="managed_device"),
        ClassificationNameRule(pattern=".*", category="unmanaged_device"),
    ]
    classifier = Classifier(config)
    result = classifier.classify_candidate(
        Candidate(names=["aaa", "managed-switch.net.example.com"])
    )
    assert result.category == "managed_device"


def test_evidence_rule_combines_name_and_lldp_description(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import ClassificationEvidenceRule
    from lldp_runner.models import Candidate

    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            label="hpe-cx6300",
            category="managed_device",
            name_pattern=r"(?i)-6300(?:\.|$)",
            network="198.18.40.0/24",
            field_patterns={
                "remote_description": r"(?i)^HPE\s+ANW\s+JL",
                "protocol": r"\blldp\b",
            },
        )
    ]
    classifier = Classifier(config)
    result = classifier.classify_candidate(
        Candidate(
            names=["hq-spare-access-6300"],
            addresses=["198.18.40.10"],
            remote_description="HPE ANW JL660A  FL.10.16.1051",
            protocol="lldp",
            protocols=["lldp"],
            capabilities=["bridge"],
        )
    )
    assert result.category == "managed_device"
    assert result.reasons[0] == "explicit evidence rule hpe-cx6300"


def test_evidence_rule_requires_every_configured_condition(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import ClassificationEvidenceRule
    from lldp_runner.models import Candidate

    config.classification.managed_manufacturers = []
    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            category="managed_device",
            name_pattern=r"(?i)-6300(?:\.|$)",
            network="198.18.40.0/24",
            field_patterns={"remote_description": r"(?i)^HPE\s+ANW\s+JL"},
        )
    ]
    classifier = Classifier(config)
    result = classifier.classify_candidate(
        Candidate(
            names=["hq-spare-access-6300"],
            addresses=["198.18.41.10"],
            remote_description="HPE ANW JL660A FL.10.16.1051",
            capabilities=["bridge"],
        )
    )
    assert result.category == "unknown_device"


def test_evidence_rules_are_first_match_wins(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import ClassificationEvidenceRule
    from lldp_runner.models import Candidate

    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            label="specific-managed",
            category="managed_device",
            name_pattern=r"^edge-",
        ),
        ClassificationEvidenceRule(
            label="general-unmanaged",
            category="unmanaged_device",
            name_pattern=r".*",
        ),
    ]
    result = Classifier(config).classify_candidate(Candidate(names=["edge-01"]))
    assert result.category == "managed_device"
    assert "specific-managed" in result.reasons[0]


def test_evidence_rule_matches_protocol_specific_detail(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import ClassificationEvidenceRule
    from lldp_runner.models import Candidate

    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            category="managed_device",
            field_patterns={"protocol": r"\blldp\b"},
            detail_patterns={"lldp.remote_description": r"(?i)^HPE\s+ANW\s+JL"},
        )
    ]
    result = Classifier(config).classify_candidate(
        Candidate(
            names=["switch-01"],
            protocol="cdp",
            protocols=["cdp", "lldp"],
            details={"lldp.remote_description": "HPE ANW JL660A FL.10.16.1051"},
        )
    )
    assert result.category == "managed_device"


def test_tag_rules_accumulate_matching_tags_in_rule_order(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import TagRule
    from lldp_runner.models import Candidate

    config.tagging.rules = [
        TagRule(
            label="all-managed-phones",
            category="managed_endpoint",
            tags=["service:voice"],
        ),
        TagRule(
            label="tenant-a-phone",
            category="managed_endpoint",
            name_pattern=r"(?i)^SEP",
            field_patterns={"remote_description": r"(?i)customer\s+alpha"},
            tags=["tenant:a", "service:voice"],
        ),
    ]
    classifier = Classifier(config)
    candidate = Candidate(
        names=["SEP001122AABBCC"],
        category="managed_endpoint",
        remote_description="Cisco IP Phone - Customer Alpha",
    )
    assert classifier.tags_for_candidate(candidate) == ["service:voice", "tenant:a"]


def test_tag_rule_uses_and_semantics_for_category_network_and_evidence(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import TagRule
    from lldp_runner.models import Candidate

    config.tagging.rules = [
        TagRule(
            label="site-a-hpe",
            category="managed_device",
            network="198.18.40.0/24",
            field_patterns={"remote_description": r"(?i)^HPE\s+ANW\s+JL"},
            tags=["site:a", "platform:hpe-cx"],
        )
    ]
    classifier = Classifier(config)
    matched = Candidate(
        names=["hq-sw1-6300"],
        addresses=["198.18.40.20"],
        category="managed_device",
        remote_description="HPE ANW JL660A FL.10.16.1051",
    )
    wrong_network = Candidate(
        names=["hq-sw1-6300"],
        addresses=["198.18.41.20"],
        category="managed_device",
        remote_description="HPE ANW JL660A FL.10.16.1051",
    )
    assert classifier.tags_for_candidate(matched) == ["site:a", "platform:hpe-cx"]
    assert classifier.tags_for_candidate(wrong_network) == []



def test_evidence_rule_matches_chassis_id_subtype_text_and_numeric_id(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import ClassificationEvidenceRule
    from lldp_runner.models import Candidate

    config.classification.evidence_rules = [
        ClassificationEvidenceRule(
            label="windows-local-chassis",
            category="unmanaged_device",
            field_patterns={
                "chassis_id": r"(?i)^LABPC-P[0-9]+$",
                "chassis_id_subtype": r"^local$",
                "chassis_id_subtype_id": r"^7$",
            },
        )
    ]
    result = Classifier(config).classify_candidate(
        Candidate(
            chassis_id="LABPC-P123456",
            chassis_id_subtype="local",
            chassis_id_subtype_id=7,
        )
    )
    assert result.category == "unmanaged_device"
    assert "windows-local-chassis" in result.reasons[0]


def test_tag_rule_matches_protocol_specific_chassis_subtype_detail(config):
    from lldp_runner.classify import Classifier
    from lldp_runner.config import TagRule
    from lldp_runner.models import Candidate

    config.tagging.rules = [
        TagRule(
            detail_patterns={
                "lldp.chassis_id_subtype": r"^local$",
                "lldp.chassis_id_subtype_id": r"^7$",
            },
            tags=["identity:local-chassis"],
        )
    ]
    candidate = Candidate(
        details={
            "lldp.chassis_id_subtype": "local",
            "lldp.chassis_id_subtype_id": 7,
        }
    )
    assert Classifier(config).tags_for_candidate(candidate) == ["identity:local-chassis"]
