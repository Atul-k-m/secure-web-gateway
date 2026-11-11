"""Command line: python -m swg [--host H] [--port P] [--access-log FILE]"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from .proxy import serve
from .settings import Settings


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="swg", description="Run the secure web gateway.")
    parser.add_argument("--host", default="127.0.0.1", help="address to listen on (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=3128, help="port to listen on (default 3128)")
    parser.add_argument("--access-log", default="logs/access.log", help="JSON-lines access log file")
    parser.add_argument("--quiet", action="store_true", help="don't echo access-log lines to stdout")
    args = parser.parse_args(argv)

    settings = Settings(
        listen_host=args.host,
        listen_port=args.port,
        access_log=Path(args.access_log),
        log_to_stdout=not args.quiet,
    )
    try:
        asyncio.run(serve(settings))
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
