"""Who is making a request: a user name and the groups they belong to.

Policy rules can name users and groups, so the gateway must find out who is
behind each request. Phase 4 does this properly: proxy authentication (HTTP
407) checked against Active Directory over LDAP, with group lookup.

Until then, `config/directory.yaml` is a stand-in. It lists users and their
groups, and binds client IP addresses to users. Binding an identity to an IP
is a real technique: Zscaler calls it "IP surrogate", where a user who has
authenticated once is remembered by IP for a while. Here the binding is
simply configured.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


class DirectoryError(ValueError):
    pass


@dataclass(frozen=True)
class Identity:
    user: str | None = None
    groups: frozenset[str] = field(default_factory=frozenset)


ANONYMOUS = Identity()


class Directory:
    def __init__(self, users: dict[str, list[str]] | None = None, ip_bindings: dict[str, str] | None = None):
        self.users = {name.lower(): frozenset(g.lower() for g in groups) for name, groups in (users or {}).items()}
        self.ip_bindings = {ip: user.lower() for ip, user in (ip_bindings or {}).items()}
        for ip, user in self.ip_bindings.items():
            if user not in self.users:
                raise DirectoryError(f"ip_bindings: {ip} is bound to unknown user {user!r}")

    @classmethod
    def load(cls, path: Path | None) -> "Directory":
        if path is None:
            return cls()
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        unknown = set(data) - {"users", "ip_bindings"}
        if unknown:
            raise DirectoryError(f"{path}: unknown key(s) {sorted(unknown)}")
        users = {}
        for name, entry in (data.get("users") or {}).items():
            groups = (entry or {}).get("groups") or []
            if not isinstance(groups, list):
                raise DirectoryError(f"user {name!r}: groups must be a list")
            users[str(name)] = [str(g) for g in groups]
        bindings = {str(ip): str(user) for ip, user in (data.get("ip_bindings") or {}).items()}
        return cls(users, bindings)

    def lookup(self, user: str) -> Identity:
        user = user.lower()
        return Identity(user, self.users.get(user, frozenset()))

    def identify(self, client_ip: str) -> Identity:
        user = self.ip_bindings.get(client_ip)
        return self.lookup(user) if user else ANONYMOUS
