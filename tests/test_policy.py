"""Policy: categories, Do-Not-Inspect and URL rules."""

from pathlib import Path

import pytest

from swg.policy import Categories, Policy, PolicyError, UrlRule, domain_matches
from swg.settings import ConfigError, load_settings

ROOT = Path(__file__).resolve().parent.parent


def test_domain_matching_is_label_based():
    assert domain_matches("example.com", "example.com")
    assert domain_matches("www.example.com", "example.com")
    assert not domain_matches("badexample.com", "example.com")
    assert not domain_matches("example.com.evil.net", "example.com")


def test_most_specific_category_wins():
    cats = Categories({"search": ["google.com"], "webmail": ["mail.google.com"]})
    assert cats.lookup("www.google.com") == "search"
    assert cats.lookup("mail.google.com") == "webmail"
    assert cats.lookup("MAIL.Google.com.") == "webmail"
    assert cats.lookup("example.org") is None


def test_domain_in_two_categories_is_an_error():
    with pytest.raises(PolicyError, match="both"):
        Categories({"a": ["x.com"], "b": ["x.com"]})


def test_first_matching_rule_wins():
    policy = Policy(
        Categories({"social": ["social.test"]}),
        rules=[
            UrlRule("Allow work page", "allow", domains=["team.social.test"]),
            UrlRule("Block social", "block", categories=["social"]),
        ],
    )
    assert policy.decide("team.social.test").action == "allow"
    blocked = policy.decide("www.social.test")
    assert blocked.action == "block" and blocked.rule == "Block social"
    assert policy.decide("other.test").rule is None  # default action


def test_do_not_inspect_by_domain_and_category():
    policy = Policy(
        Categories({"finance": ["bank.test"]}), dni_domains=["pinned.test"], dni_categories=["finance"]
    )
    assert policy.decide("api.pinned.test").inspect is False
    decision = policy.decide("www.bank.test")
    assert decision.inspect is False and "finance" in decision.inspect_reason
    assert policy.decide("news.test").inspect is True


def test_unknown_category_in_a_rule_is_caught():
    with pytest.raises(PolicyError, match="unknown category"):
        Policy(Categories({"news": ["n.test"]}), rules=[UrlRule("typo", "block", categories=["nwes"])])


def test_typo_in_policy_yaml_is_caught(tmp_path):
    bad = tmp_path / "policy.yaml"
    bad.write_text("url_filtering:\n  rulez: []\n")
    with pytest.raises(PolicyError, match="rulez"):
        Policy.load(bad, None)


def test_shipped_policy_loads_and_behaves():
    policy = Policy.load(ROOT / "config/policy.yaml", ROOT / "config/categories.yaml")
    assert policy.decide("www.bet365.com").action == "block"
    assert policy.decide("www.paypal.com").inspect is False  # finance: not inspected
    assert policy.decide("signal.org").inspect is False  # pinned app
    assert policy.decide("github.com").action == "allow"
    assert policy.decide("github.com").category == "developer-tools"


def test_shipped_gateway_config_loads():
    settings = load_settings(ROOT / "config/gateway.yaml")
    assert settings.listen_port == 3128
    assert settings.inspect_tls is True
    assert settings.policy_file == Path("config/policy.yaml")


def test_typo_in_gateway_yaml_is_caught(tmp_path):
    bad = tmp_path / "gateway.yaml"
    bad.write_text("tls_inspection:\n  enable: true\n")
    with pytest.raises(ConfigError, match="enable"):
        load_settings(bad)
