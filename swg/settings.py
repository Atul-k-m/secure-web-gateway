"""Runtime settings for the gateway."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    listen_host: str = "127.0.0.1"
    listen_port: int = 3128  # the conventional explicit-proxy port (Squid's default)
    access_log: Path | None = Path("logs/access.log")
    log_to_stdout: bool = True
    connect_timeout: float = 10.0  # DNS + TCP connect to the origin
    client_idle_timeout: float = 60.0  # keep-alive wait for the next request
    tunnel_idle_timeout: float = 300.0  # CONNECT tunnel with no bytes either way
    via_name: str = "swg"  # appears in the Via header the gateway adds
