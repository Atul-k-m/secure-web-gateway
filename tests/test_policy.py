"""Policy: categories, Do-Not-Inspect and URL rules."""

from pathlib import Path

import pytest

from swg import filetypes
from swg.directory import ANONYMOUS, Directory, DirectoryError, Identity
from swg.policy import Categories, DlpRule, FileTypeRule, Policy, PolicyError, UrlRule, domain_matches
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


# ---- phase 3: users, groups, file types, DLP ------------------------------------

ENG = Identity("asha", frozenset({"engineering"}))
FIN = Identity("meera", frozenset({"finance"}))
CON = Identity("dev", frozenset({"contractors"}))


def test_fields_combine_with_and_values_with_or():
    rule = UrlRule("r", "block", categories=["ai"], groups=["contractors", "interns"])
    cats = Categories({"ai": ["ai.test"]})
    policy = Policy(cats, rules=[rule])
    assert policy.decide("chat.ai.test", CON).action == "block"  # group AND category
    assert policy.decide("chat.ai.test", ENG).action == "allow"  # category only
    assert policy.decide("news.test", CON).action == "allow"  # group only
    assert policy.decide("chat.ai.test", Identity("x", frozenset({"interns"}))).action == "block"


def test_user_rule_and_anonymous():
    policy = Policy(rules=[UrlRule("only asha", "block", domains=["x.test"], users=["asha"])])
    assert policy.decide("x.test", ENG).action == "block"
    assert policy.decide("x.test", ANONYMOUS).action == "allow"


def test_file_type_rules_check_direction_and_both_labels():
    policy = Policy(
        file_rules=[
            FileTypeRule("exe down", "block", types=["windows-executable"]),
            FileTypeRule("zip up", "block", types=["zip"], direction="upload"),
        ]
    )
    exe = filetypes.detect("text/plain", b"MZ\x90\x00")
    labelled_exe = filetypes.detect("application/x-msdownload", b"")
    zip_file = filetypes.detect(None, b"PK\x03\x04")
    assert policy.check_file_type("h.test", ENG, exe, "download").action == "block"
    assert policy.check_file_type("h.test", ENG, labelled_exe, "download").action == "block"
    assert policy.check_file_type("h.test", ENG, exe, "upload").action == "allow"
    assert policy.check_file_type("h.test", ENG, zip_file, "upload").action == "block"
    assert policy.check_file_type("h.test", ENG, zip_file, "download").action == "allow"
    assert policy.has_file_rules("download") and policy.has_file_rules("upload")


def test_dlp_exception_above_the_general_rule():
    policy = Policy(
        dlp_rules=[
            DlpRule("finance to pay", "allow", groups=["finance"], domains=["pay.test"], detectors=["credit_card"]),
            DlpRule("cards", "block", detectors=["credit_card"]),
        ]
    )
    assert policy.check_dlp("api.pay.test", FIN, {"credit_card"}).action == "allow"
    assert policy.check_dlp("other.test", FIN, {"credit_card"}).action == "block"
    assert policy.check_dlp("api.pay.test", ENG, {"credit_card"}).action == "block"
    assert policy.check_dlp("api.pay.test", ENG, {"aadhaar"}).rule is None  # no rule for it
    assert policy.scans_uploads("anything.test", ENG)


@pytest.mark.parametrize(
    "yaml_text, message",
    [
        ("file_types:\n  rules:\n    - {name: x, action: block, types: [exe]}\n", "unknown file type"),
        ("file_types:\n  rules:\n    - {name: x, action: block, types: [zip], direction: sideways}\n", "direction"),
        ("dlp:\n  rules:\n    - {name: x, action: block, detectors: [ssn]}\n", "unknown detector"),
        ("dlp:\n  rules:\n    - {name: x, action: caution, detectors: [api_key]}\n", "action"),
        ("url_filtering:\n  rules:\n    - {name: x, action: warn}\n", "action"),
        ("url_filtering:\n  rules:\n    - {name: x, action: block, group: [a]}\n", "group"),
    ],
)
def test_policy_mistakes_are_reported(tmp_path, yaml_text, message):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml_text)
    with pytest.raises(PolicyError, match=message):
        Policy.load(path, None)


def test_directory_binds_ips_to_users():
    directory = Directory.load(ROOT / "config/directory.yaml")
    assert len(directory.users) == 5
    assert set().union(*directory.users.values()) == {"engineering", "finance", "contractors"}
    assert directory.identify("127.0.0.1").user == "asha"
    assert directory.identify("10.1.2.3") == ANONYMOUS
    with pytest.raises(DirectoryError, match="unknown user"):
        Directory({"a": []}, {"10.0.0.1": "nobody"})


def test_lint_flags_content_rules_on_uninspected_traffic():
    # The first shipped policy had exactly this: a DLP rule for razorpay.com
    # while razorpay.com was in the Do-Not-Inspect "finance" category.
    policy = Policy(
        Categories({"finance": ["razorpay.com"]}),
        dni_categories=["finance"],
        dlp_rules=[DlpRule("cards to razorpay", "allow", domains=["razorpay.com"], detectors=["credit_card"])],
        file_rules=[FileTypeRule("bank files", "block", categories=["finance"], types=["zip"])],
    )
    warnings = " | ".join(policy.lint())
    assert len(policy.lint()) == 2
    assert "razorpay.com is never inspected" in warnings
    assert "category finance is never inspected" in warnings


def test_shipped_policy_has_no_lint_warnings():
    assert Policy.load(ROOT / "config/policy.yaml", ROOT / "config/categories.yaml").lint() == []
