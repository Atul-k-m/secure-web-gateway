"""The forward proxy: accept client connections and serve each request.

An explicit proxy receives two kinds of request:

1. Plain HTTP in absolute-form:   GET http://example.com/path HTTP/1.1
   The gateway opens TCP to example.com:80, sends the request in
   origin-form (GET /path HTTP/1.1) and relays the response back.

2. CONNECT example.com:443 HTTP/1.1
   The gateway opens TCP to example.com:443, answers
   "200 Connection established" and then copies bytes both ways. Those
   bytes are TLS, so the gateway only reads the two plaintext hello
   messages to log the SNI and the TLS version (see tlsparse.py).

docs/how-it-works.md walks through both on the wire.
"""

from __future__ import annotations

import asyncio
import sys
import time
import traceback
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from . import http1, pages, tlsparse
from .accesslog import AccessLog, LogEntry
from .http1 import HttpError, Request
from .settings import Settings

READ_CHUNK = 64 * 1024


def ms_since(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


# --------------------------------------------------------------------------
# Byte counting for the access log
# --------------------------------------------------------------------------


class MeteredReader:
    """Wraps an asyncio.StreamReader and counts every byte read through it."""

    def __init__(self, reader: asyncio.StreamReader):
        self._reader = reader
        self.count = 0

    async def readline(self) -> bytes:
        data = await self._reader.readline()
        self.count += len(data)
        return data

    async def read(self, n: int = -1) -> bytes:
        data = await self._reader.read(n)
        self.count += len(data)
        return data

    async def readexactly(self, n: int) -> bytes:
        try:
            data = await self._reader.readexactly(n)
        except asyncio.IncompleteReadError as exc:
            self.count += len(exc.partial)
            raise
        self.count += len(data)
        return data

    def at_eof(self) -> bool:
        return self._reader.at_eof()


class MeteredWriter:
    """Wraps an asyncio.StreamWriter and counts every byte written to it."""

    def __init__(self, writer: asyncio.StreamWriter):
        self._writer = writer
        self.count = 0

    def write(self, data: bytes) -> None:
        self.count += len(data)
        self._writer.write(data)

    async def drain(self) -> None:
        await self._writer.drain()

    def can_write_eof(self) -> bool:
        return self._writer.can_write_eof()

    def write_eof(self) -> None:
        self._writer.write_eof()

    def is_closing(self) -> bool:
        return self._writer.is_closing()

    def close(self) -> None:
        self._writer.close()

    async def wait_closed(self) -> None:
        await self._writer.wait_closed()

    def get_extra_info(self, name: str, default=None):
        return self._writer.get_extra_info(name, default)


# --------------------------------------------------------------------------
# Where a request is going
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int
    path: str  # origin-form: path plus query string

    @property
    def authority(self) -> str:
        """host[:port] as it belongs in a Host header."""
        host = f"[{self.host}]" if ":" in self.host else self.host
        default_port = 443 if self.scheme == "https" else 80
        return host if self.port == default_port else f"{host}:{self.port}"

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.authority}{self.path}"


def parse_absolute_uri(target: str) -> Target:
    """`http://example.com:8080/a?b=1` -> Target("http", "example.com", 8080, "/a?b=1")."""
    parts = urlsplit(target)
    if parts.scheme.lower() != "http":
        raise HttpError(400, f"only http:// URLs can be proxied directly, got {target[:60]!r}")
    try:
        port = parts.port or 80
    except ValueError:
        raise HttpError(400, "invalid port in URL")
    if not parts.hostname:
        raise HttpError(400, "URL has no host")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return Target("http", parts.hostname, port, path)  # the fragment is never sent


def parse_authority(target: str) -> tuple[str, int]:
    """CONNECT's target: `example.com:443` or `[2001:db8::1]:443`."""
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
    else:
        host, _, port_text = target.rpartition(":")
    if not host or not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise HttpError(400, f"CONNECT needs host:port, got {target[:60]!r}")
    return host.lower(), int(port_text)


async def open_tcp(host: str, port: int, timeout: float):
    """DNS lookup + TCP three-way handshake to the origin.

    A name can resolve to several addresses (IPv6 and IPv4). Happy Eyeballs
    (RFC 8305) starts the next address 250 ms after the previous one if it
    hasn't connected yet, so a dead IPv6 path doesn't stall the request.
    """
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, happy_eyeballs_delay=0.25, interleave=1), timeout
        )
    except asyncio.TimeoutError:
        raise HttpError(504, f"timed out connecting to {host}:{port}")
    except OSError as exc:
        raise HttpError(502, f"cannot connect to {host}:{port}: {exc}")


# --------------------------------------------------------------------------
# Connections
# --------------------------------------------------------------------------


@dataclass
class Upstream:
    host: str
    port: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    def close(self) -> None:
        self.writer.close()


class UpstreamPool:
    """Keeps at most one idle origin connection per client connection.

    A browser sends many requests over one proxy connection, often to the
    same host. Reusing the origin connection saves a TCP handshake per
    request.
    """

    def __init__(self) -> None:
        self._idle: Upstream | None = None

    async def acquire(self, host: str, port: int, timeout: float) -> tuple[Upstream, bool]:
        idle, self._idle = self._idle, None
        if idle is not None:
            if (idle.host, idle.port) == (host, port) and not idle.reader.at_eof():
                return idle, True
            idle.close()
        reader, writer = await open_tcp(host, port, timeout)
        return Upstream(host, port, reader, writer), False

    def release(self, upstream: Upstream, reusable: bool) -> None:
        if reusable and self._idle is None:
            self._idle = upstream
        else:
            upstream.close()

    def close(self) -> None:
        if self._idle is not None:
            self._idle.close()
            self._idle = None


@dataclass
class ClientConnection:
    reader: MeteredReader
    writer: MeteredWriter
    client_ip: str
    upstreams: UpstreamPool = field(default_factory=UpstreamPool)
    _in_mark: int = 0
    _out_mark: int = 0

    def mark(self) -> None:
        """Start counting bytes for the next request."""
        self._in_mark, self._out_mark = self.reader.count, self.writer.count

    def bytes_since_mark(self) -> tuple[int, int]:
        return self.reader.count - self._in_mark, self.writer.count - self._out_mark

    async def send(self, data: bytes) -> None:
        self.writer.write(data)
        await self.writer.drain()

    async def close(self) -> None:
        self.upstreams.close()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except OSError:
            pass


@dataclass
class Exchange:
    """One request/response pair on a client connection."""

    request: Request
    entry: LogEntry
    response_started: bool = False  # after this, errors can't become error pages


# --------------------------------------------------------------------------
# The gateway
# --------------------------------------------------------------------------


class Gateway:
    def __init__(self, settings: Settings, access_log: AccessLog | None = None):
        self.settings = settings
        self.log = access_log or AccessLog(settings.access_log, echo=settings.log_to_stdout)

    async def start(self) -> asyncio.Server:
        return await asyncio.start_server(
            self.handle_client, self.settings.listen_host, self.settings.listen_port
        )

    def _write_log(self, conn: ClientConnection, entry: LogEntry) -> None:
        entry.bytes_in, entry.bytes_out = conn.bytes_since_mark()
        self.log.write(entry)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one client TCP connection, which can carry many requests."""
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        conn = ClientConnection(MeteredReader(reader), MeteredWriter(writer), client_ip=peer[0])
        try:
            while True:
                conn.mark()
                try:
                    request = await asyncio.wait_for(
                        http1.read_request(conn.reader), self.settings.client_idle_timeout
                    )
                except asyncio.TimeoutError:
                    break  # idle keep-alive connection
                except HttpError as exc:
                    await self._reject(conn, LogEntry.begin(conn.client_ip), exc)
                    break
                if request is None:
                    break  # client closed the connection
                if request.method == "CONNECT":
                    await self._handle_connect(conn, request)
                    break  # the tunnel used up the connection
                if not await self._handle_http(conn, request):
                    break
        except (OSError, asyncio.IncompleteReadError):
            pass  # the client went away; nothing left to answer
        except Exception:
            traceback.print_exc(file=sys.stderr)
        finally:
            await conn.close()

    async def _reject(self, conn: ClientConnection, entry: LogEntry, exc: HttpError) -> None:
        """Answer with an error page, log it, and let the caller close."""
        entry.status, entry.error = exc.status, exc.message
        try:
            await conn.send(http1.simple_response(exc.status, pages.error_page(exc.status, exc.message)))
        finally:
            self._write_log(conn, entry)

    # ---- plain HTTP --------------------------------------------------------

    async def _handle_http(self, conn: ClientConnection, request: Request) -> bool:
        """Serve one HTTP request. Returns True to keep the connection open."""
        ex = Exchange(request, LogEntry.begin(conn.client_ip, request.method))
        keep_alive = False
        try:
            if request.target.startswith("/"):
                keep_alive = await self._serve_local(conn, ex)
            else:
                keep_alive = await self._forward(conn, ex)
        except HttpError as exc:
            ex.entry.error = exc.message
            if not ex.response_started:
                ex.entry.status = exc.status
                await conn.send(http1.simple_response(exc.status, pages.error_page(exc.status, exc.message)))
        except (OSError, asyncio.IncompleteReadError) as exc:
            ex.entry.error = f"connection lost: {exc.__class__.__name__}"
        finally:
            self._write_log(conn, ex.entry)
        return keep_alive

    async def _serve_local(self, conn: ClientConnection, ex: Exchange) -> bool:
        """A request in origin-form (GET / HTTP/1.1) is addressed to the
        gateway itself, not to be forwarded. Later phases serve the PAC
        file and block pages from here."""
        request = ex.request
        ex.entry.host = (request.headers.get("Host") or "").lower() or None
        ex.entry.url = request.target
        async for _ in http1.iter_body(conn.reader, http1.request_framing(request.headers)):
            pass  # read and discard any request body
        keep_alive = http1.wants_keep_alive(request.version, request.headers)
        if request.method == "GET" and request.target == "/":
            status, body = 200, pages.info_page()
        else:
            status, body = 404, pages.error_page(404, "no such page on the gateway")
        ex.entry.status = status
        ex.response_started = True
        await conn.send(http1.simple_response(status, body, keep_alive=keep_alive))
        return keep_alive

    async def _forward(self, conn: ClientConnection, ex: Exchange) -> bool:
        request, entry = ex.request, ex.entry
        target = parse_absolute_uri(request.target)
        entry.host, entry.url = target.host, target.url
        client_keep_alive = http1.wants_keep_alive(request.version, request.headers)
        body_framing = http1.request_framing(request.headers)

        if "100-continue" in request.headers.tokens("Expect"):
            # The client is waiting for permission to send a large body.
            # The gateway answers itself and forwards without the Expect.
            await conn.send(b"HTTP/1.1 100 Continue\r\n\r\n")

        # 1. Rewrite the request for the origin: origin-form target, no
        #    hop-by-hop headers, Host taken from the URL (RFC 9112 3.2.2),
        #    and a Via header that records the hop.
        headers = http1.strip_hop_by_hop(request.headers)
        headers.remove("Expect")
        headers.set("Host", target.authority)
        headers.add("Via", f"{request.version[5:]} {self.settings.via_name}")
        if body_framing.kind == "chunked":
            headers.set("Transfer-Encoding", "chunked")
        head = f"{request.method} {target.path} HTTP/1.1\r\n".encode("latin-1") + headers.encode()

        # 2. Send it and wait for the response head (time to first byte).
        started = time.perf_counter()
        upstream, response = await self._send_to_origin(conn, target, head, body_framing)
        entry.upstream_latency_ms = ms_since(started)
        entry.status = response.status

        # 3. Relay the response, re-framing the body for this client.
        try:
            framing = http1.response_framing(request.method, response.status, response.headers)
            out_headers = http1.strip_hop_by_hop(response.headers)
            out_headers.add("Via", f"{response.version[5:]} {self.settings.via_name}")
            keep_alive = client_keep_alive
            rechunk = False
            if framing.kind in ("chunked", "close"):
                if request.version == "HTTP/1.1":
                    rechunk = True  # lets this client connection stay open
                    out_headers.set("Transfer-Encoding", "chunked")
                else:
                    keep_alive = False  # HTTP/1.0 has no chunking: closing ends the body
            out_headers.set("Connection", "keep-alive" if keep_alive else "close")

            ex.response_started = True
            conn.writer.write(
                f"HTTP/1.1 {response.status} {response.reason}\r\n".encode("latin-1") + out_headers.encode()
            )
            body_out = http1.BodyWriter(conn.writer, chunked=rechunk)
            async for chunk in http1.iter_body(upstream.reader, framing):
                await body_out.write(chunk)
            await body_out.finish()
            await conn.writer.drain()
        except BaseException:
            upstream.close()
            raise

        reusable = framing.kind != "close" and http1.wants_keep_alive(response.version, response.headers)
        conn.upstreams.release(upstream, reusable)
        return keep_alive

    async def _send_to_origin(self, conn, target: Target, head: bytes, body_framing: http1.Framing):
        """Send the request head and body; return (upstream, response head).

        An idle origin connection can be closed by the origin at any time.
        If a reused connection fails and the request had no body, retry once
        on a fresh connection (the body, if any, was already consumed).
        """
        for attempt in (1, 2):
            upstream, reused = await conn.upstreams.acquire(
                target.host, target.port, self.settings.connect_timeout
            )
            try:
                upstream.writer.write(head)
                if body_framing.kind != "none":
                    body_out = http1.BodyWriter(upstream.writer, chunked=body_framing.kind == "chunked")
                    async for chunk in http1.iter_body(conn.reader, body_framing):
                        await body_out.write(chunk)
                    await body_out.finish()
                await upstream.writer.drain()
                response = await http1.read_response(upstream.reader)
                while 100 <= response.status < 200:
                    # Interim responses (100 Continue, 103 Early Hints) are
                    # dropped: the client already got its 100 from us.
                    response = await http1.read_response(upstream.reader)
                return upstream, response
            except (OSError, HttpError) as exc:
                upstream.close()
                if reused and body_framing.kind == "none" and attempt == 1:
                    continue
                if isinstance(exc, HttpError):
                    raise
                raise HttpError(502, f"origin connection failed: {exc}")
        raise AssertionError("unreachable")

    # ---- CONNECT tunnels ---------------------------------------------------

    async def _handle_connect(self, conn: ClientConnection, request: Request) -> None:
        entry = LogEntry.begin(conn.client_ip, "CONNECT")
        try:
            host, port = parse_authority(request.target)
        except HttpError as exc:
            await self._reject(conn, entry, exc)
            return
        entry.host = host
        entry.url = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

        started = time.perf_counter()
        try:
            up_reader, up_writer = await open_tcp(host, port, self.settings.connect_timeout)
        except HttpError as exc:
            await self._reject(conn, entry, exc)
            return
        entry.upstream_latency_ms = ms_since(started)  # DNS + TCP connect
        entry.status = 200

        def on_client_hello(record: bytes) -> None:
            info = tlsparse.parse_client_hello(record)
            if info is not None:
                entry.sni = info.sni

        def on_server_hello(record: bytes) -> None:
            info = tlsparse.parse_server_hello(record)
            if info is not None:
                entry.tls_version = info.version

        idle = self.settings.tunnel_idle_timeout
        try:
            await conn.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await asyncio.gather(
                relay(conn.reader, up_writer, idle, on_first_record=on_client_hello),
                relay(up_reader, conn.writer, idle, on_first_record=on_server_hello),
            )
        finally:
            up_writer.close()
            self._write_log(conn, entry)  # one line per tunnel, written when it closes


async def read_first_record(reader) -> bytes:
    """Read one whole TLS record, or whatever arrived if it isn't TLS."""
    try:
        header = await reader.readexactly(5)
    except asyncio.IncompleteReadError as exc:
        return exc.partial
    length = tlsparse.record_length(header)
    if length is None:
        return header  # not TLS, e.g. plain HTTP sent through the tunnel
    try:
        return header + await reader.readexactly(length)
    except asyncio.IncompleteReadError as exc:
        return header + exc.partial


async def relay(src, dst, idle_timeout: float, on_first_record=None) -> None:
    """Copy bytes from src to dst until src ends, then half-close dst.

    Half-close (TCP FIN in one direction) tells the other end "no more data
    from this side" while still letting its replies through.
    """
    try:
        if on_first_record is not None:
            first = await asyncio.wait_for(read_first_record(src), idle_timeout)
            if first:
                on_first_record(first)
                dst.write(first)
                await dst.drain()
        while True:
            data = await asyncio.wait_for(src.read(READ_CHUNK), idle_timeout)
            if not data:
                break
            dst.write(data)
            await dst.drain()
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        dst.close()  # reset or idle: close fully so the other direction ends too
        return
    try:
        if dst.can_write_eof():
            dst.write_eof()
    except OSError:
        pass


async def serve(settings: Settings) -> None:
    gateway = Gateway(settings)
    server = await gateway.start()
    for sock in server.sockets:
        host, port = sock.getsockname()[:2]
        print(f"secure-web-gateway listening on {host}:{port}", flush=True)
    async with server:
        await server.serve_forever()
