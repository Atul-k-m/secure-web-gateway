"""One JSON line per request: the gateway's access log.

Each line is a complete JSON object, so the log works with `jq`, with
Python's `json` module, and with log shippers (Splunk, ELK) that expect
JSON lines. See docs/how-it-works.md for what each field means.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class LogEntry:
    time: str
    client_ip: str
    user: str | None = None  # filled in by proxy authentication (phase 4)
    method: str = ""
    host: str | None = None
    url: str | None = None
    status: int | None = None
    category: str | None = None  # filled in by the policy engine (phase 3)
    action: str = "allow"
    bytes_in: int = 0  # bytes the gateway read from the client
    bytes_out: int = 0  # bytes the gateway wrote to the client
    upstream_latency_ms: float | None = None
    duration_ms: float | None = None
    tls_version: str | None = None
    sni: str | None = None
    error: str | None = None

    @classmethod
    def begin(cls, client_ip: str, method: str = "") -> "LogEntry":
        entry = cls(time=utc_now_iso(), client_ip=client_ip, method=method)
        entry._started = time.perf_counter()
        return entry

    def finish(self) -> None:
        started = getattr(self, "_started", None)
        if started is not None:
            self.duration_ms = round((time.perf_counter() - started) * 1000, 2)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"))


class AccessLog:
    """Appends entries to a file and, optionally, echoes them to stdout."""

    def __init__(self, path: Path | None, echo: bool = False):
        self.path = path
        self.echo = echo
        self._lock = threading.Lock()
        self._file = None
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Line buffering: each entry reaches the file as soon as it's written.
            self._file = open(path, "a", encoding="utf-8", buffering=1)

    def write(self, entry: LogEntry) -> None:
        entry.finish()
        line = entry.to_json()
        with self._lock:
            if self._file is not None:
                self._file.write(line + "\n")
            if self.echo:
                print(line, file=sys.stdout, flush=True)

    def close(self) -> None:
        with self._lock:
            if self._file is not None:
                self._file.close()
                self._file = None
