from __future__ import annotations

from lldp_runner.classify import Classifier
from lldp_runner.config import ClassificationNameRule
from lldp_runner.coordinator import Coordinator
from lldp_runner.identity import ResolvedIdentity
from lldp_runner.models import Candidate


def test_dns_enrichment_reclassifies_provisional_managed_neighbor(config, monkeypatch):
    config.classification.name_rules = [
        ClassificationNameRule(
            category="unmanaged_device",
            patterns=[r"(?i)\.ops\.example\.com$", r"(?i)\.external\.example\.org$"],
        )
    ]
    config.classification.managed_manufacturers = ["Cisco"]
    config.discovery.resolve_discovered_managed_names = True

    def fake_resolve(name: str, suffixes: list[str]) -> ResolvedIdentity:
        assert name == "ops-access-3850"
        return ResolvedIdentity(
            original=name,
            preferred_name="ops-access-3850.ops.example.com",
            names=["ops-access-3850.ops.example.com"],
            addresses=["198.18.44.20"],
        )

    monkeypatch.setattr("lldp_runner.coordinator.resolve_discovered_name", fake_resolve)

    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    candidate = Candidate(
        names=["ops-access-3850"],
        remote_description="Cisco IOS Software, Catalyst 3850",
        remote_platform="Cisco WS-C3850",
        capabilities=["bridge"],
        protocol="lldp",
        protocols=["lldp"],
    )

    # Before DNS enrichment the Cisco + bridge heuristic is enough to make the
    # device a provisional recursive target.
    assert coordinator.classifier.classify_candidate(candidate).category == "managed_device"

    coordinator._classify_and_enrich_neighbor(candidate, "ops-access-3850")

    assert "ops-access-3850.ops.example.com" in candidate.names
    assert candidate.category == "unmanaged_device"
    assert candidate.reason == [r"explicit name rule (?i)\.ops\.example\.com$"]


def test_dns_enrichment_preserves_only_direct_names_for_identity(config, monkeypatch):
    """Resolver aliases may affect classification but not global host correlation."""

    config.classification.managed_manufacturers = ["Cisco"]
    config.discovery.resolve_discovered_managed_names = True

    def fake_resolve(name: str, suffixes: list[str]) -> ResolvedIdentity:
        return ResolvedIdentity(
            original=name,
            preferred_name="shared-frontend.example.net",
            names=["shared-frontend.example.net"],
            addresses=["198.18.44.20"],
        )

    monkeypatch.setattr("lldp_runner.coordinator.resolve_discovered_name", fake_resolve)
    coordinator = Coordinator.__new__(Coordinator)
    coordinator.config = config
    coordinator.classifier = Classifier(config)
    candidate = Candidate(
        names=["edge-a"],
        identity_names=["edge-a"],
        identity_addresses=[],
        remote_description="Cisco IOS Software",
        remote_platform="Cisco C9300",
        capabilities=["bridge"],
        protocol="lldp",
        protocols=["lldp"],
    )

    coordinator._classify_and_enrich_neighbor(candidate, "edge-a")

    assert candidate.names == ["edge-a", "shared-frontend.example.net"]
    assert candidate.identity_names == ["edge-a"]
    assert candidate.addresses == ["198.18.44.20"]
    assert candidate.identity_addresses == []
