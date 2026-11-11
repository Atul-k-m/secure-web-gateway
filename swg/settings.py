"""Runtime settings for the gateway, loaded from config/gateway.yaml."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


class ConfigError(ValueError):
    pass


@dataclass
class Settings:
    listen_host: str = "127.0.0.1"
    listen_port: int = 3128  # the conventional explicit-proxy port (Squid's default)
    access_log: Path | None = Path("logs/access.log")
    log_to_stdout: bool = True
    connect_timeout: float = 10.0  # DNS + TCP (+ TLS) to the origin
    client_idle_timeout: float = 60.0  # keep-alive wait for the next request
    tunnel_idle_timeout: float = 300.0  # CONNECT tunnel with no bytes either way
    tls_handshake_timeout: float = 10.0
    via_name: str = "swg"  # appears in the Via header the gateway adds

    # TLS inspection (phase 2). Off unless the config file turns it on, so
    # nothing gets decrypted by accident.
    inspect_tls: bool = False
    ca_dir: Path = Path("ca")
    upstream_ca_file: Path | None = None  # extra CAs to trust for origins

    policy_file: Path | None = None
    categories_file: Path | None = None
    directory_file: Path | None = None  # users, groups, IP bindings (until phase 4)

    # How clients reach the gateway, e.g. http://10.0.0.5:3128. Goes into
    # the certificates' CRL links (and, in phase 6, the PAC file). Derived
    # from the listen address when not set.
    gateway_url: str | None = None

    def public_url(self) -> str:
        if self.gateway_url:
            return self.gateway_url.rstrip("/")
        host = "127.0.0.1" if self.listen_host in ("0.0.0.0", "::", "") else self.listen_host
        return f"http://{host}:{self.listen_port}"


def _path(value) -> Path | None:
    return Path(value) if value not in (None, "") else None


def _section(data: dict, name: str, allowed: set[str]) -> dict:
    section = data.get(name) or {}
    if not isinstance(section, dict):
        raise ConfigError(f"{name}: expected a mapping")
    unknown = set(section) - allowed
    if unknown:
        raise ConfigError(f"{name}: unknown key(s) {sorted(unknown)}")
    return section


def load_settings(path: Path | None) -> Settings:
    """Settings from a YAML file; anything the file leaves out keeps its default."""
    settings = Settings()
    if path is None:
        return settings
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    top = {
        "listen", "gateway_url", "access_log", "timeouts", "tls_inspection",
        "policy_file", "categories_file", "directory_file",
    }
    unknown = set(data) - top
    if unknown:
        raise ConfigError(f"{path}: unknown key(s) {sorted(unknown)}")

    listen = _section(data, "listen", {"host", "port"})
    settings.listen_host = listen.get("host", settings.listen_host)
    settings.listen_port = int(listen.get("port", settings.listen_port))
    if "access_log" in data:
        settings.access_log = _path(data["access_log"])

    timeouts = _section(data, "timeouts", {"connect", "client_idle", "tunnel_idle", "tls_handshake"})
    settings.connect_timeout = float(timeouts.get("connect", settings.connect_timeout))
    settings.client_idle_timeout = float(timeouts.get("client_idle", settings.client_idle_timeout))
    settings.tunnel_idle_timeout = float(timeouts.get("tunnel_idle", settings.tunnel_idle_timeout))
    settings.tls_handshake_timeout = float(timeouts.get("tls_handshake", settings.tls_handshake_timeout))

    tls = _section(data, "tls_inspection", {"enabled", "ca_dir", "upstream_ca_file"})
    settings.inspect_tls = bool(tls.get("enabled", settings.inspect_tls))
    settings.ca_dir = _path(tls.get("ca_dir")) or settings.ca_dir
    settings.upstream_ca_file = _path(tls.get("upstream_ca_file"))

    settings.gateway_url = data.get("gateway_url") or None
    settings.policy_file = _path(data.get("policy_file"))
    settings.categories_file = _path(data.get("categories_file"))
    settings.directory_file = _path(data.get("directory_file"))
    return settings
