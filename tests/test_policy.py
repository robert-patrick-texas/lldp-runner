from lldp_runner.policy import PolicyEngine


def test_longest_prefix_credential_wins(config):
    policy = PolicyEngine(config)
    result = policy.credential_profile(["edge.net.example.com"], "198.18.36.42")
    assert result.profile.name == "specific"
    assert "198.18.36.0/24" in result.reason


def test_name_first_match_when_no_address_rule(config):
    policy = PolicyEngine(config)
    result = policy.credential_profile(["core-a.net.example.com"], "198.51.100.5")
    assert result.profile.name == "specific"
    assert "first matching name rule" in result.reason


def test_query_deny_and_boundary(config):
    policy = PolicyEngine(config)
    assert not policy.query_policy(["x"], "198.18.200.4").allowed
    assert not policy.in_boundary("203.0.113.1").allowed
    assert not policy.query_policy(["printer-5"], "198.18.10.1").allowed


def test_name_rule_order_is_rule_first_across_all_aliases(config):
    from lldp_runner.policy import PolicyEngine

    policy = PolicyEngine(config)
    # The first configured credential regex (^core-) must win even though the
    # first alias only matches the later catch-all rule.
    decision = policy.credential_profile(
        ["aaa.net.example.com", "core-switch.net.example.com"],
        "198.51.100.20",
    )
    assert decision.profile.name == "specific"
    assert "^core-" in decision.reason
