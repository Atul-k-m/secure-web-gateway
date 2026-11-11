"""The policy engine: what to inspect, and what to allow, warn about or block.

Three YAML files drive it:

* `config/categories.yaml` maps URL categories to domains (a small seed list).
* `config/policy.yaml` holds four rule lists, each checked top to bottom,
  first match wins:
    - `ssl_inspection.do_not_inspect`: traffic to tunnel untouched
    - `url_filtering.rules`: allow / caution / block a site
    - `file_types.rules`: allow / block a download or upload by file type
    - `dlp.rules`: allow / block an upload by what's in it
* `config/directory.yaml` (until phase 4) says which user is behind a client
  IP and which groups they're in.

Every rule can narrow who and where it applies to:

    users:      [asha, ravi]          any of these users
    groups:     [contractors]         a member of any of these groups
    domains:    [github.com]          the host or any subdomain of it
    categories: [file-sharing]        the host's category is one of these

A rule matches when *every* field it sets matches (AND), and a field matches
when *any* of its values does (OR). A rule that sets none of them matches
everything. Domain matching works on whole labels: `example.com` matches
`www.example.com`, never `badexample.com`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .directory import ANONYMOUS, Identity
from .dlp import DETECTORS
from .filetypes import KNOWN_TYPES, FileType

URL_ACTIONS = ("allow", "caution", "block")
CONTENT_ACTIONS = ("allow", "block")
DIRECTIONS = ("download", "upload", "both")


class PolicyError(ValueError):
    """The YAML is wrong. The message says where."""


def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _check_keys(where: str, data, allowed: set[str]) -> None:
    if not isinstance(data, dict):
        raise PolicyError(f"{where}: expected a mapping")
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown key(s) {sorted(unknown)}; expected {sorted(allowed)}")


def _str_list(where: str, value, lower: bool = True) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise PolicyError(f"{where}: expected a list of names")
    return [v.strip().lower() if lower else v for v in value]


def _domain_list(where: str, value) -> list[str]:
    return [normalize_host(v) for v in _str_list(where, value)]


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
                    raise PolicyError(f"{domain} is in both {self._by_domain[domain]!r} and {category!r}")
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


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------


@dataclass
class Rule:
    name: str
    action: str
    domains: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)

    def applies(self, host: str, category: str | None, identity: Identity) -> bool:
        if self.users and identity.user not in self.users:
            return False
        if self.groups and not identity.groups.intersection(self.groups):
            return False
        if self.domains and not any(domain_matches(host, d) for d in self.domains):
            return False
        if self.categories and category not in self.categories:
            return False
        return True


@dataclass
class UrlRule(Rule):
    pass


@dataclass
class FileTypeRule(Rule):
    types: list[str] = field(default_factory=list)
    direction: str = "download"

    def covers(self, file_type: FileType, direction: str) -> bool:
        return self.direction in (direction, "both") and bool(file_type.labels() & set(self.types))


@dataclass
class DlpRule(Rule):
    detectors: list[str] = field(default_factory=list)


@dataclass
class Decision:
    action: str  # "allow", "caution" or "block"
    category: str | None
    rule: str | None  # name of the rule that decided, None = default action
    inspect: bool  # False: Do-Not-Inspect, tunnel the TLS untouched
    inspect_reason: str | None = None  # which exemption applied


@dataclass
class ContentVerdict:
    """Outcome of a file-type or DLP check."""

    action: str  # "allow" or "block"
    rule: str | None


# --------------------------------------------------------------------------
# The policy
# --------------------------------------------------------------------------


class Policy:
    def __init__(
        self,
        categories: Categories | None = None,
        rules: list[UrlRule] | None = None,
        default_action: str = "allow",
        dni_domains: list[str] | None = None,
        dni_categories: list[str] | None = None,
        file_rules: list[FileTypeRule] | None = None,
        dlp_rules: list[DlpRule] | None = None,
        dlp_max_scan_bytes: int = 1024 * 1024,
        caution_minutes: float = 30,
    ):
        self.categories = categories or Categories()
        self.rules = rules or []
        self.default_action = default_action
        self.dni_domains = dni_domains or []
        self.dni_categories = dni_categories or []
        self.file_rules = file_rules or []
        self.dlp_rules = dlp_rules or []
        self.dlp_max_scan_bytes = dlp_max_scan_bytes
        self.caution_minutes = caution_minutes
        self._validate()

    def _validate(self) -> None:
        if self.default_action not in URL_ACTIONS:
            raise PolicyError(f"default_action must be one of {URL_ACTIONS}")
        known = self.categories.names
        everything = [("do_not_inspect", self.dni_categories)] + [
            (f"rule {r.name!r}", r.categories) for r in [*self.rules, *self.file_rules, *self.dlp_rules]
        ]
        for where, names in everything:
            for name in names:
                if name not in known:
                    raise PolicyError(f"{where}: unknown category {name!r}; known: {sorted(known)}")
        for rule in self.rules:
            if rule.action not in URL_ACTIONS:
                raise PolicyError(f"rule {rule.name!r}: action must be one of {URL_ACTIONS}")
        for rule in self.file_rules:
            if rule.action not in CONTENT_ACTIONS or rule.direction not in DIRECTIONS:
                raise PolicyError(f"rule {rule.name!r}: action {CONTENT_ACTIONS}, direction {DIRECTIONS}")
            for t in rule.types:
                if t not in KNOWN_TYPES:
                    raise PolicyError(f"rule {rule.name!r}: unknown file type {t!r}; known: {KNOWN_TYPES}")
            if not rule.types:
                raise PolicyError(f"rule {rule.name!r}: needs at least one file type")
        for rule in self.dlp_rules:
            if rule.action not in CONTENT_ACTIONS:
                raise PolicyError(f"rule {rule.name!r}: action must be one of {CONTENT_ACTIONS}")
            for d in rule.detectors:
                if d not in DETECTORS:
                    raise PolicyError(f"rule {rule.name!r}: unknown detector {d!r}; known: {list(DETECTORS)}")
            if not rule.detectors:
                raise PolicyError(f"rule {rule.name!r}: needs at least one detector")

    def lint(self) -> list[str]:
        """Rules that are valid but can never fire.

        File-type and DLP rules need decrypted traffic. A rule aimed at a
        domain or category on the Do-Not-Inspect list never sees an HTTPS
        request, so it silently does nothing. That's almost always a mistake,
        and an easy one to make: the first version of the shipped policy
        had a DLP rule for razorpay.com while razorpay.com sat in the
        Do-Not-Inspect "finance" category.
        """
        warnings = []
        for rule in [*self.file_rules, *self.dlp_rules]:
            for domain in rule.domains:
                decision = self.decide(domain)
                if not decision.inspect:
                    warnings.append(
                        f"rule {rule.name!r}: {domain} is never inspected ({decision.inspect_reason}), "
                        "so this rule can't see its HTTPS traffic"
                    )
            for category in rule.categories:
                if category in self.dni_categories:
                    warnings.append(
                        f"rule {rule.name!r}: category {category} is never inspected (do_not_inspect), "
                        "so this rule can't see its HTTPS traffic"
                    )
        return warnings

    # ---- loading ----------------------------------------------------------

    @classmethod
    def load(cls, policy_path: Path | None, categories_path: Path | None) -> "Policy":
        categories = Categories.load(categories_path)
        if policy_path is None:
            return cls(categories)
        data = yaml.safe_load(Path(policy_path).read_text(encoding="utf-8")) or {}
        _check_keys(str(policy_path), data, {"ssl_inspection", "url_filtering", "file_types", "dlp"})

        ssl_section = data.get("ssl_inspection") or {}
        _check_keys("ssl_inspection", ssl_section, {"do_not_inspect"})
        dni = ssl_section.get("do_not_inspect") or {}
        _check_keys("ssl_inspection.do_not_inspect", dni, {"domains", "categories"})

        url_section = data.get("url_filtering") or {}
        _check_keys("url_filtering", url_section, {"rules", "default_action", "caution_minutes"})
        file_section = data.get("file_types") or {}
        _check_keys("file_types", file_section, {"rules"})
        dlp_section = data.get("dlp") or {}
        _check_keys("dlp", dlp_section, {"rules", "max_scan_bytes"})

        return cls(
            categories=categories,
            rules=[cls._rule(UrlRule, "url_filtering", i, raw, {}) for i, raw in enumerate(url_section.get("rules") or [])],
            default_action=url_section.get("default_action", "allow"),
            dni_domains=_domain_list("do_not_inspect.domains", dni.get("domains")),
            dni_categories=_str_list("do_not_inspect.categories", dni.get("categories")),
            file_rules=[
                cls._rule(FileTypeRule, "file_types", i, raw, {"types": list, "direction": str})
                for i, raw in enumerate(file_section.get("rules") or [])
            ],
            dlp_rules=[
                cls._rule(DlpRule, "dlp", i, raw, {"detectors": list})
                for i, raw in enumerate(dlp_section.get("rules") or [])
            ],
            dlp_max_scan_bytes=int(dlp_section.get("max_scan_bytes", 1024 * 1024)),
            caution_minutes=float(url_section.get("caution_minutes", 30)),
        )

    @staticmethod
    def _rule(rule_class, section: str, index: int, raw, extra: dict):
        where = f"{section}.rules[{index}]"
        common = {"name", "action", "domains", "categories", "users", "groups"}
        _check_keys(where, raw, common | set(extra))
        kwargs = {
            "name": str(raw.get("name") or f"{section} rule {index + 1}"),
            "action": raw.get("action"),
            "domains": _domain_list(where, raw.get("domains")),
            "categories": _str_list(where, raw.get("categories")),
            "users": _str_list(where, raw.get("users")),
            "groups": _str_list(where, raw.get("groups")),
        }
        for key, kind in extra.items():
            if key in raw:
                kwargs[key] = _str_list(where, raw[key]) if kind is list else str(raw[key]).lower()
        return rule_class(**kwargs)

    # ---- decisions --------------------------------------------------------

    def decide(self, host: str, identity: Identity = ANONYMOUS) -> Decision:
        """Inspect or not, and allow / caution / block, for a host."""
        host = normalize_host(host)
        category = self.categories.lookup(host)

        inspect, reason = True, None
        if any(domain_matches(host, d) for d in self.dni_domains):
            inspect, reason = False, "do_not_inspect domain"
        elif category is not None and category in self.dni_categories:
            inspect, reason = False, f"do_not_inspect category {category}"

        for rule in self.rules:
            if rule.applies(host, category, identity):
                return Decision(rule.action, category, rule.name, inspect, reason)
        return Decision(self.default_action, category, None, inspect, reason)

    def has_file_rules(self, direction: str) -> bool:
        return any(r.direction in (direction, "both") for r in self.file_rules)

    def check_file_type(self, host: str, identity: Identity, file_type: FileType, direction: str) -> ContentVerdict:
        host = normalize_host(host)
        category = self.categories.lookup(host)
        for rule in self.file_rules:
            if rule.covers(file_type, direction) and rule.applies(host, category, identity):
                return ContentVerdict(rule.action, rule.name)
        return ContentVerdict("allow", None)

    def scans_uploads(self, host: str, identity: Identity) -> bool:
        """Should this request's body be read and checked before forwarding?"""
        host = normalize_host(host)
        category = self.categories.lookup(host)
        if any(r.applies(host, category, identity) for r in self.dlp_rules):
            return True
        return any(
            r.direction in ("upload", "both") and r.applies(host, category, identity) for r in self.file_rules
        )

    def check_dlp(self, host: str, identity: Identity, found: set[str]) -> ContentVerdict:
        host = normalize_host(host)
        category = self.categories.lookup(host)
        for rule in self.dlp_rules:
            if found.intersection(rule.detectors) and rule.applies(host, category, identity):
                return ContentVerdict(rule.action, rule.name)
        return ContentVerdict("allow", None)
