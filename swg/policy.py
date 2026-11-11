"""Policy: which traffic to inspect, and what to allow or block.

Two YAML files drive it:

* `config/categories.yaml` maps URL categories to domains (a small seed list).
* `config/policy.yaml` holds the SSL-inspection exemptions (Do-Not-Inspect)
  and the URL-filtering rules.

Domain matching works on whole labels: `example.com` matches `example.com`
and `www.example.com`, but not `badexample.com`.

Phase 2 matches on domain and category only. Phase 3 adds users and groups,
the caution action, file-type rules and DLP.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

ACTIONS = ("allow", "block")


class PolicyError(ValueError):
    """The YAML is wrong. The message says where."""


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _check_keys(where: str, data: dict, allowed: set[str]) -> None:
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}; expected {sorted(allowed)}")


def _domain_list(where: str, value) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}: expected a list of domain names")
    return [normalize_host(v) for v in value]


class Categories:
    """Looks up the category of a host, most specific domain first.

    With `google.com: search` and `mail.google.com: webmail`, the host
    `mail.google.com` is webmail and `www.google.com` is search.
    """

    def __init__(self, mapping: dict[str, list[str]] | None = None):
        self.names: set[str] = set()
        self._by_domain: dict[str, str] = {}
        for category, domains in (mapping or {}).items():
            self.names.add(category)
            for domain in _domain_list(f"category {category!r}", domains):
                if domain in self._by_domain:
                    raise PolicyError(
                        f"{domain} is in both {self._by_domain[domain]!r} and {category!r}"
                    )
                self._by_domain[domain] = category

    @classmethod
    def load(cls, path: Path | None) -> "Categories":
        if path is None:
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise PolicyError(f"{path}: expected 'category: [domains]' entries")
        return cls(data)

    def lookup(self, host: str) -> str | None:
        labels = normalize_host(host).split(".")
        for i in range(len(labels)):
            category = self._by_domain.get(".".join(labels[i:]))
            if category is not None:
                return category
        return None

    def __len__(self) -> int:
        return len(self._by_domain)


@dataclass
class UrlRule:
    name: str
    action: str
    domains: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)

    def matches(self, host: str, category: str | None) -> bool:
        if any(domain_matches(host, d) for d in self.domains):
            return True
        return category is not None and category in self.categories


@dataclass
class Decision:
    action: str  # "allow" or "block"
    category: str | None
    rule: str | None  # name of the rule that decided, None = default action
    inspect: bool  # False: Do-Not-Inspect, tunnel the TLS untouched
    inspect_reason: str | None = None  # which exemption applied


class Policy:
    def __init__(
        self,
        categories: Categories | None = None,
        rules: list[UrlRule] | None = None,
        default_action: str = "allow",
        dni_domains: list[str] | None = None,
        dni_categories: list[str] | None = None,
    ):
        self.categories = categories or Categories()
        self.rules = rules or []
        self.default_action = default_action
        self.dni_domains = dni_domains or []
        self.dni_categories = dni_categories or []
        self._validate()

    def _validate(self) -> None:
        if self.default_action not in ACTIONS:
            raise PolicyError(f"default_action must be one of {ACTIONS}")
        known = self.categories.names
        for where, names in [("do_not_inspect.categories", self.dni_categories)] + [
            (f"rule {r.name!r}", r.categories) for r in self.rules
        ]:
            for name in names:
                if name not in known:
                    raise PolicyError(f"{where}: unknown category {name!r}; known: {sorted(known)}")

    @classmethod
    def load(cls, policy_path: Path | None, categories_path: Path | None) -> "Policy":
        categories = Categories.load(categories_path)
        if policy_path is None:
            return cls(categories)
        data = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}
        _check_keys(str(policy_path), data, {"ssl_inspection", "url_filtering"})

        ssl_section = data.get("ssl_inspection") or {}
        _check_keys("ssl_inspection", ssl_section, {"do_not_inspect"})
        dni = ssl_section.get("do_not_inspect") or {}
        _check_keys("ssl_inspection.do_not_inspect", dni, {"domains", "categories"})

        url_section = data.get("url_filtering") or {}
        _check_keys("url_filtering", url_section, {"rules", "default_action"})
        rules = []
        for i, raw in enumerate(url_section.get("rules") or []):
            where = f"url_filtering.rules[{i}]"
            if not isinstance(raw, dict):
                raise PolicyError(f"{where}: expected a mapping")
            _check_keys(where, raw, {"name", "action", "domains", "categories"})
            if raw.get("action") not in ACTIONS:
                raise PolicyError(f"{where}: action must be one of {ACTIONS}")
            rules.append(
                UrlRule(
                    name=str(raw.get("name") or f"rule {i + 1}"),
                    action=raw["action"],
                    domains=_domain_list(where, raw.get("domains")),
                    categories=list(raw.get("categories") or []),
                )
            )

        return cls(
            categories=categories,
            rules=rules,
            default_action=url_section.get("default_action", "allow"),
            dni_domains=_domain_list("do_not_inspect.domains", dni.get("domains")),
            dni_categories=list(dni.get("categories") or []),
        )

    def decide(self, host: str) -> Decision:
        """First matching rule wins, like a firewall rule list."""
        host = normalize_host(host)
        category = self.categories.lookup(host)

        inspect, reason = True, None
        if any(domain_matches(host, d) for d in self.dni_domains):
            inspect, reason = False, "do_not_inspect domain"
        elif category is not None and category in self.dni_categories:
            inspect, reason = False, f"do_not_inspect category {category}"

        for rule in self.rules:
            if rule.matches(host, category):
                return Decision(rule.action, category, rule.name, inspect, reason)
        return Decision(self.default_action, category, None, inspect, reason)
