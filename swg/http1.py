"""HTTP/1.1 parsing and body framing (RFC 9112).

The gateway speaks HTTP/1.1 to the client and to the origin. This module
turns bytes from a stream into request/response heads and body chunks, and
writes them back out.

Body framing is "hop-by-hop": the client and the origin can each frame a
body differently (Content-Length, chunked, or "read until the connection
closes"). The proxy decodes the body from one side and re-frames it for the
other side. Policy checks in later phases need the decoded bytes anyway.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import AsyncIterator, Iterable

MAX_HEAD_BYTES = 64 * 1024  # request line + all headers
MAX_HEADERS = 100
READ_CHUNK = 64 * 1024

# Headers that describe one TCP hop, not the end-to-end message. A proxy
# must not forward them (RFC 9110 section 7.6.1).
HOP_BY_HOP = {
    "connection",
    "proxy-connection",  # non-standard, but browsers still send it
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

REASONS = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    407: "Proxy Authentication Required",
    413: "Content Too Large",
    421: "Misdirected Request",
    431: "Request Header Fields Too Large",
    501: "Not Implemented",
    502: "Bad Gateway",
    504: "Gateway Timeout",
}


class HttpError(Exception):
    """A message the gateway cannot handle. `status` is the answer to send."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class Headers:
    """An ordered, case-insensitive header list.

    HTTP allows the same header name to appear more than once (for example
    Set-Cookie), so this is a list of pairs, not a dict.
    """

    def __init__(self, items: Iterable[tuple[str, str]] = ()):
        self._items: list[tuple[str, str]] = list(items)

    def get(self, name: str, default: str | None = None) -> str | None:
        name = name.lower()
        for key, value in self._items:
            if key.lower() == name:
                return value
        return default

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self._items if key.lower() == name]

    def tokens(self, name: str) -> set[str]:
        """Comma-separated tokens of a header, lower-cased.

        `Connection: keep-alive, Upgrade` -> {"keep-alive", "upgrade"}
        """
        found = set()
        for value in self.get_all(name):
            found.update(part.strip().lower() for part in value.split(",") if part.strip())
        return found

    def add(self, name: str, value: str) -> None:
        self._items.append((name, value))

    def set(self, name: str, value: str) -> None:
        self.remove(name)
        self._items.append((name, value))

    def remove(self, name: str) -> None:
        name = name.lower()
        self._items = [(k, v) for k, v in self._items if k.lower() != name]

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not None

    def items(self) -> list[tuple[str, str]]:
        return list(self._items)

    def copy(self) -> "Headers":
        return Headers(self._items)

    def encode(self) -> bytes:
        """Header block plus the blank line that ends the head."""
        lines = "".join(f"{key}: {value}\r\n" for key, value in self._items)
        return (lines + "\r\n").encode("latin-1")


@dataclass
class Request:
    method: str
    target: str  # absolute-form, authority-form (CONNECT) or origin-form
    version: str  # "HTTP/1.1" or "HTTP/1.0"
    headers: Headers


@dataclass
class Response:
    version: str
    status: int
    reason: str
    headers: Headers


@dataclass
class Framing:
    """How a message body is delimited on the wire."""

    kind: str  # "none", "length", "chunked" or "close"
    length: int = 0


async def _read_head_lines(reader) -> list[str] | None:
    """Read lines up to the blank line that ends a message head.

    Returns None if the peer closed the connection before sending anything,
    which is the normal end of a keep-alive connection.
    """
    lines: list[str] = []
    total = 0
    while True:
        try:
            line = await reader.readline()
        except ValueError:  # a single line longer than the stream limit
            raise HttpError(431, "header line too long")
        if not line:
            if not lines:
                return None
            raise HttpError(400, "connection closed in the middle of the headers")
        total += len(line)
        if total > MAX_HEAD_BYTES:
            raise HttpError(431, "request head too large")
        line = line.rstrip(b"\r\n")
        if not line:
            if not lines:
                continue  # RFC 9112 2.2: ignore empty lines before a request
            return lines
        lines.append(line.decode("latin-1"))


def _parse_header_lines(lines: list[str]) -> Headers:
    if len(lines) > MAX_HEADERS:
        raise HttpError(431, "too many headers")
    headers = Headers()
    for line in lines:
        if line[0] in " \t":
            # Obsolete line folding. Rejecting it is allowed (RFC 9112 5.2)
            # and closes off a class of request-smuggling tricks.
            raise HttpError(400, "folded header lines are not accepted")
        name, sep, value = line.partition(":")
        if not sep or not name or name != name.strip():
            # "Name : value" (space before the colon) is also a smuggling trick.
            raise HttpError(400, f"malformed header line: {line[:80]!r}")
        headers.add(name, value.strip())
    return headers


async def read_request(reader) -> Request | None:
    lines = await _read_head_lines(reader)
    if lines is None:
        return None
    parts = lines[0].split(" ")
    if len(parts) != 3:
        raise HttpError(400, f"malformed request line: {lines[0][:80]!r}")
    method, target, version = parts
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        raise HttpError(400, f"unsupported HTTP version: {version[:20]!r}")
    if not method.isalpha() or not method.isupper():
        raise HttpError(400, f"malformed method: {method[:20]!r}")
    return Request(method, target, version, _parse_header_lines(lines[1:]))


async def read_response(reader) -> Response:
    lines = await _read_head_lines(reader)
    if lines is None:
        raise HttpError(502, "origin closed the connection without a response")
    version, _, rest = lines[0].partition(" ")
    code, _, reason = rest.partition(" ")
    if not version.startswith("HTTP/1.") or not (code.isdigit() and len(code) == 3):
        raise HttpError(502, f"malformed status line from origin: {lines[0][:80]!r}")
    return Response(version, int(code), reason, _parse_header_lines(lines[1:]))


def _content_length(headers: Headers) -> int | None:
    values = headers.get_all("Content-Length")
    if not values:
        return None
    # "Content-Length: 5, 5" and repeated headers are legal only if they agree.
    numbers = {v.strip() for value in values for v in value.split(",")}
    if len(numbers) != 1:
        raise HttpError(400, "conflicting Content-Length values")
    number = numbers.pop()
    if not number.isdigit():
        raise HttpError(400, f"invalid Content-Length: {number[:20]!r}")
    return int(number)


def request_framing(headers: Headers) -> Framing:
    """RFC 9112 section 6.3, for requests."""
    if "Transfer-Encoding" in headers:
        if "Content-Length" in headers:
            # Two framings at once is the classic request-smuggling setup:
            # this proxy and the origin might pick different ones.
            raise HttpError(400, "both Transfer-Encoding and Content-Length")
        if headers.tokens("Transfer-Encoding") != {"chunked"}:
            raise HttpError(501, "only chunked transfer-coding is supported")
        return Framing("chunked")
    length = _content_length(headers)
    if length:
        return Framing("length", length)
    return Framing("none")


def response_framing(request_method: str, status: int, headers: Headers) -> Framing:
    """RFC 9112 section 6.3, for responses."""
    if request_method == "HEAD" or 100 <= status < 200 or status in (204, 304):
        return Framing("none")
    if "Transfer-Encoding" in headers:
        codings = [t.strip().lower() for t in headers.get("Transfer-Encoding", "").split(",")]
        if codings and codings[-1] == "chunked":
            return Framing("chunked")
        return Framing("close")
    length = _content_length(headers)
    if length is not None:
        return Framing("length", length) if length else Framing("none")
    return Framing("close")


async def iter_body(reader, framing: Framing) -> AsyncIterator[bytes]:
    """Yield the decoded body bytes, whatever the framing was."""
    if framing.kind == "length":
        remaining = framing.length
        while remaining:
            data = await reader.read(min(READ_CHUNK, remaining))
            if not data:
                raise asyncio.IncompleteReadError(b"", remaining)
            remaining -= len(data)
            yield data
    elif framing.kind == "chunked":
        while True:
            size_line = await reader.readline()
            if not size_line:
                raise asyncio.IncompleteReadError(b"", None)
            size_text = size_line.split(b";", 1)[0].strip()  # drop chunk extensions
            try:
                size = int(size_text, 16)
            except ValueError:
                raise HttpError(400, "malformed chunk size")
            if size == 0:
                # Skip any trailer fields up to the final blank line.
                while (await reader.readline()).strip():
                    pass
                return
            remaining = size
            while remaining:
                data = await reader.read(min(READ_CHUNK, remaining))
                if not data:
                    raise asyncio.IncompleteReadError(b"", remaining)
                remaining -= len(data)
                yield data
            await reader.readexactly(2)  # the CRLF after each chunk
    elif framing.kind == "close":
        while True:
            data = await reader.read(READ_CHUNK)
            if not data:
                return
            yield data


class BodyWriter:
    """Write a body either raw or with chunked framing."""

    def __init__(self, writer, chunked: bool):
        self._writer = writer
        self._chunked = chunked

    async def write(self, data: bytes) -> None:
        if not data:
            return
        if self._chunked:
            self._writer.write(b"%x\r\n" % len(data) + data + b"\r\n")
        else:
            self._writer.write(data)
        await self._writer.drain()

    async def finish(self) -> None:
        if self._chunked:
            self._writer.write(b"0\r\n\r\n")
            await self._writer.drain()


def strip_hop_by_hop(headers: Headers) -> Headers:
    """Copy of `headers` without hop-by-hop fields.

    That includes any header named in `Connection`, for example
    `Connection: close, X-Foo` makes X-Foo hop-by-hop too.
    """
    drop = HOP_BY_HOP | headers.tokens("Connection")
    return Headers((k, v) for k, v in headers.items() if k.lower() not in drop)


def wants_keep_alive(version: str, headers: Headers) -> bool:
    """HTTP/1.1 is persistent by default; HTTP/1.0 only if it asks."""
    tokens = headers.tokens("Connection") | headers.tokens("Proxy-Connection")
    if version == "HTTP/1.0":
        return "keep-alive" in tokens
    return "close" not in tokens


def simple_response(
    status: int,
    body: str | bytes,
    content_type: str = "text/html; charset=utf-8",
    extra_headers: Iterable[tuple[str, str]] = (),
    keep_alive: bool = False,
) -> bytes:
    """A complete response the gateway generates itself (errors, info pages)."""
    payload = body.encode("utf-8") if isinstance(body, str) else body
    headers = Headers(
        [
            ("Content-Type", content_type),
            ("Content-Length", str(len(payload))),
            ("Cache-Control", "no-store"),
            ("Connection", "keep-alive" if keep_alive else "close"),
            *extra_headers,
        ]
    )
    status_line = f"HTTP/1.1 {status} {REASONS.get(status, 'Error')}\r\n".encode("latin-1")
    return status_line + headers.encode() + payload
