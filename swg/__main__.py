"""Command line.

    python -m swg                  run the gateway with config/gateway.yaml
    python -m swg --no-inspect     run it with TLS inspection off
    python -m swg ca               create the inspection CA (if needed) and show it
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .certs import CertificateAuthority
from .proxy import serve
from .settings import load_settings

DEFAULT_CONFIG = Path("config/gateway.yaml")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="swg", description="Run the secure web gateway.")
    parser.add_argument("command", nargs="?", choices=["run", "ca"], default="run",
                        help="run the gateway (default), or create/show the inspection CA")
    parser.add_argument("--config", type=Path, default=None,
                        help=f"settings file (default {DEFAULT_CONFIG} if it exists)")
    parser.add_argument("--host", help="address to listen on")
    parser.add_argument("--port", type=int, help="port to listen on")
    parser.add_argument("--access-log", type=Path, help="JSON-lines access log file")
    parser.add_argument("--no-inspect", action="store_true", help="turn TLS inspection off")
    parser.add_argument("--quiet", action="store_true", help="don't echo access-log lines to stdout")
    args = parser.parse_args(argv)

    config = args.config or (DEFAULT_CONFIG if DEFAULT_CONFIG.exists() else None)
    settings = load_settings(config)
    if args.host:
        settings.listen_host = args.host
    if args.port is not None:
        settings.listen_port = args.port
    if args.access_log:
        settings.access_log = args.access_log
    if args.no_inspect:
        settings.inspect_tls = False
    if args.quiet:
        settings.log_to_stdout = False

    if args.command == "ca":
        ca = CertificateAuthority.load_or_create(settings.ca_dir)
        print(f"root certificate : {ca.root_cert_path.resolve()}")
        print(f"subject          : {ca.root_cert.subject.rfc4514_string()}")
        print(f"valid until      : {ca.root_cert.not_valid_after_utc:%Y-%m-%d}")
        print(f"SHA-256          : {ca.fingerprint}")
        print("Install it as a trusted root: see docs/how-it-works.md, section 8.")
        return

    try:
        asyncio.run(serve(settings))
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
