"""The forward proxy: accept client connections and serve each request.

An explicit proxy receives two kinds of request:

1. Plain HTTP in absolute-form:   GET http://example.com/path HTTP/1.1
   The gateway opens TCP to example.com:80, sends the request in
   origin-form (GET /path HTTP/1.1) and relays the response back.

2. CONNECT example.com:443 HTTP/1.1
   The gateway answers "200 Connection established", then either
   * tunnels the bytes untouched (inspection off, or the site is on the
     Do-Not-Inspect list). It reads only the plaintext TLS hellos for the
     log (tlsparse.py). Or it
   * inspects: it finishes the TLS handshake with the client itself, using a
     certificate minted for that host (certs.py), reads the HTTP requests
     inside, and sends each one to the origin over a *new* TLS connection
     that verifies the origin's real certificate.

docs/how-it-works.md walks through each of these on the wire.
"""

from __future__ import annotations

import asyncio
import ssl
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from . import http1, pages, tlsparse
from .accesslog import AccessLog, LogEntry
from .certs import CertificateAuthority, LeafCertCache
from .http1 import HttpError, Request
from .policy import Policy
from .settings import Settings

READ_CHUNK = 64 * 1024


def ms_since(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


class OriginCertificateError(HttpError):
    """The origin's certificate failed verification."""


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

    async def start_tls(self, context: ssl.SSLContext, handshake_timeout: float) -> None:
        """Turn this plain TCP connection into TLS, with the gateway as the
        server. Reads and writes after this are decrypted/encrypted."""
        await self._writer.start_tls(context, ssl_handshake_timeout=handshake_timeout)

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


@dataclass
class InspectedTunnel:
    """A CONNECT tunnel whose TLS the gateway terminated."""

    host: str  # from the CONNECT line
    port: int
    sni: str | None  # what the client put in its ClientHello
    tls_version: str  # negotiated between client and gateway


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
    return host.lower().rstrip("."), int(port_text)


def host_of(authority: str) -> str:
    """The host part of a Host header: `Example.com:443` -> `example.com`."""
    value = authority.strip().lower()
    if value.startswith("["):
        return value[1:].partition("]")[0]
    host, sep, port = value.rpartition(":")
    if sep and port.isdigit() and ":" not in host:
        value = host
    return value.rstrip(".")


def upstream_tls_context(extra_ca_file: Path | None) -> ssl.SSLContext:
    """How the gateway checks origin servers: the OS trust store, hostname
    checking, TLS 1.2 or newer. The client can't see the origin's
    certificate any more, so the gateway must reject a bad one for it."""
    ctx = ssl.create_default_context()
    if extra_ca_file is not None:
        ctx.load_verify_locations(cafile=str(extra_ca_file))
    ctx.set_alpn_protocols(["http/1.1"])
    # Match Python's own http.client, which enables this. It only adds one
    # extension to the ClientHello, but some bot filters fingerprint the
    # ClientHello: without it www.wikipedia.org answered 403 to requests
    # with a browser User-Agent (tested Nov 2026, see docs/kb).
    ctx.post_handshake_auth = True
    return ctx


async def open_upstream(host: str, port: int, timeout: float, tls: ssl.SSLContext | None = None):
    """DNS lookup + TCP three-way handshake (+ TLS handshake) to the origin.

    A name can resolve to several addresses (IPv6 and IPv4). Happy Eyeballs
    (RFC 8305) starts the next address 250 ms after the previous one if it
    hasn't connected yet, so a dead IPv6 path doesn't stall the request.
    """
    tls_args = {"ssl": tls, "server_hostname": host, "ssl_handshake_timeout": timeout} if tls else {}
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, happy_eyeballs_delay=0.25, interleave=1, **tls_args),
            timeout,
        )
    except asyncio.TimeoutError:
        raise HttpError(504, f"timed out connecting to {host}:{port}")
    except ssl.SSLCertVerificationError as exc:
        raise OriginCertificateError(502, f"{exc.verify_message} ({host}:{port})")
    except ssl.SSLError as exc:
        raise HttpError(502, f"TLS handshake with {host}:{port} failed: {exc.reason or exc}")
    except OSError as exc:
        raise HttpError(502, f"cannot connect to {host}:{port}: {exc}")


def describe_client_tls_failure(exc: BaseException) -> str:
    """Turn a failed client handshake into something a support engineer can act on."""
    reason = getattr(exc, "reason", None) or exc.__class__.__name__
    if any(alert in reason for alert in ("UNKNOWN_CA", "CERTIFICATE_UNKNOWN", "BAD_CERTIFICATE")):
        return (
            f"client rejected the gateway certificate ({reason}): the root CA is not "
            "installed on this client, or the app pins its certificate (add the domain "
            "to do_not_inspect)"
        )
    # Windows Schannel clients that don't trust the root abort in a way
    # OpenSSL reports as DECRYPTION_FAILED_OR_BAD_RECORD_MAC (seen with curl.exe).
    return (
        f"client TLS handshake failed ({reason}): check that this client trusts the "
        "gateway root CA"
    )


# --------------------------------------------------------------------------
# Connections
# --------------------------------------------------------------------------


@dataclass
class Upstream:
    key: tuple[str, str, int]  # (scheme, host, port)
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    def close(self) -> None:
        self.writer.close()


class UpstreamPool:
    """Keeps at most one idle origin connection per client connection.

    A browser sends many requests over one proxy connection, often to the
    same host. Reusing the origin connection saves a TCP handshake (and a TLS
    handshake, for inspected HTTPS) per request.
    """

    def __init__(self) -> None:
        self._idle: Upstream | None = None

    async def acquire(self, target: Target, timeout: float, tls: ssl.SSLContext | None):
        key = (target.scheme, target.host, target.port)
        idle, self._idle = self._idle, None
        if idle is not None:
            if idle.key == key and not idle.reader.at_eof():
                return idle, True
            idle.close()
        reader, writer = await open_upstream(target.host, target.port, timeout, tls)
        return Upstream(key, reader, writer), False

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
    requests: int = 0  # requests read on this connection so far
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
        except (OSError, ssl.SSLError):
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
    def __init__(
        self,
        settings: Settings,
        access_log: AccessLog | None = None,
        policy: Policy | None = None,
        ca: CertificateAuthority | None = None,
    ):
        self.settings = settings
        self.log = access_log or AccessLog(settings.access_log, echo=settings.log_to_stdout)
        self.policy = policy or Policy.load(settings.policy_file, settings.categories_file)
        self.certs: LeafCertCache | None = None
        if settings.inspect_tls:
            ca = ca or CertificateAuthority.load_or_create(settings.ca_dir, settings.public_url())
            self.certs = LeafCertCache(ca)
        self.upstream_tls = upstream_tls_context(settings.upstream_ca_file)

    async def start(self) -> asyncio.Server:
        return await asyncio.start_server(
            self.handle_client, self.settings.listen_host, self.settings.listen_port
        )

    def _new_entry(self, conn: ClientConnection, method: str, tunnel: InspectedTunnel | None = None) -> LogEntry:
        entry = LogEntry.begin(conn.client_ip, method)
        if tunnel is not None:
            entry.inspected = True
            entry.host, entry.sni, entry.tls_version = tunnel.host, tunnel.sni, tunnel.tls_version
        return entry

    def _write_log(self, conn: ClientConnection, entry: LogEntry) -> None:
        entry.bytes_in, entry.bytes_out = conn.bytes_since_mark()
        self.log.write(entry)

    async def _reject(self, conn: ClientConnection, entry: LogEntry, exc: HttpError, page: str | None = None) -> None:
        """Answer with an error (or block) page, log it, and let the caller close."""
        entry.status = exc.status
        if page is None:
            entry.error = exc.message
            page = pages.error_page(exc.status, exc.message, entry)
        try:
            await conn.send(http1.simple_response(exc.status, page))
        finally:
            self._write_log(conn, entry)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one client TCP connection, which can carry many requests."""
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        conn = ClientConnection(MeteredReader(reader), MeteredWriter(writer), client_ip=peer[0])
        try:
            await self._serve_requests(conn)
        except (OSError, asyncio.IncompleteReadError):
            pass  # the client went away; nothing left to answer
        except Exception:
            traceback.print_exc(file=sys.stderr)
        finally:
            await conn.close()

    async def _serve_requests(self, conn: ClientConnection, tunnel: InspectedTunnel | None = None) -> None:
        """Read and answer requests until the connection ends. `tunnel` is
        set when these requests arrive decrypted from an inspected CONNECT."""
        while True:
            conn.mark()
            try:
                request = await asyncio.wait_for(
                    http1.read_request(conn.reader), self.settings.client_idle_timeout
                )
            except asyncio.TimeoutError:
                return  # idle keep-alive connection
            except HttpError as exc:
                conn.requests += 1
                await self._reject(conn, self._new_entry(conn, "", tunnel), exc)
                return
            if request is None:
                return  # client closed the connection
            conn.requests += 1
            if request.method == "CONNECT" and tunnel is None:
                await self._handle_connect(conn, request)
                return  # the tunnel used up the connection
            if not await self._handle_http(conn, request, tunnel):
                return

    # ---- HTTP requests (plain, or decrypted from an inspected tunnel) -------

    async def _handle_http(self, conn: ClientConnection, request: Request, tunnel: InspectedTunnel | None) -> bool:
        """Serve one HTTP request. Returns True to keep the connection open."""
        ex = Exchange(request, self._new_entry(conn, request.method, tunnel))
        keep_alive = False
        try:
            if tunnel is None and request.target.startswith("/"):
                keep_alive = await self._serve_local(conn, ex)
            else:
                keep_alive = await self._forward(conn, ex, self._target(request, tunnel))
        except HttpError as exc:
            ex.entry.error = exc.message
            if not ex.response_started:
                ex.entry.status = exc.status
                if isinstance(exc, OriginCertificateError):
                    page = pages.origin_certificate_page(exc.message, ex.entry)
                else:
                    page = pages.error_page(exc.status, exc.message, ex.entry)
                await conn.send(http1.simple_response(exc.status, page))
        except (OSError, asyncio.IncompleteReadError) as exc:
            ex.entry.error = f"connection lost: {exc.__class__.__name__}"
        finally:
            self._write_log(conn, ex.entry)
        return keep_alive

    def _target(self, request: Request, tunnel: InspectedTunnel | None) -> Target:
        if tunnel is None:
            return parse_absolute_uri(request.target)
        # Inside an inspected tunnel the client talks as if to the origin:
        # origin-form, with a Host header.
        if not request.target.startswith("/"):
            raise HttpError(400, "requests inside an HTTPS tunnel must use a path")
        host_header = request.headers.get("Host")
        if host_header and host_of(host_header) != tunnel.host:
            # CONNECT to one site, Host header for another: domain fronting.
            raise HttpError(421, f"Host {host_header[:80]!r} does not match the tunnel to {tunnel.host}")
        return Target("https", tunnel.host, tunnel.port, request.target)

    async def _serve_local(self, conn: ClientConnection, ex: Exchange) -> bool:
        """A request in origin-form (GET / HTTP/1.1) is addressed to the
        gateway itself, not to be forwarded. Phase 6 serves the PAC file
        from here."""
        request = ex.request
        ex.entry.host = (request.headers.get("Host") or "").lower() or None
        ex.entry.url = request.target
        async for _ in http1.iter_body(conn.reader, http1.request_framing(request.headers)):
            pass  # read and discard any request body
        keep_alive = http1.wants_keep_alive(request.version, request.headers)
        path = request.target.split("?", 1)[0]
        content_type = "text/html; charset=utf-8"
        status, body = 404, pages.error_page(404, "no such page on the gateway")
        if request.method != "GET":
            status, body = 405, pages.error_page(405, "the gateway's own pages only answer GET")
        elif path == "/":
            status, body = 200, pages.info_page()
        elif self.certs is not None and path == "/ca.crt":
            # Lets a device download the root CA to install it.
            status, body = 200, self.certs.ca.root_cert_path.read_bytes()
            content_type = "application/x-x509-ca-cert"
        elif self.certs is not None and path in ("/crl/root.crl", "/crl/issuing.crl"):
            # Fetched by Windows (and other clients that check revocation)
            # from the URL inside each certificate.
            status, body = 200, self.certs.ca.crl(path.rsplit("/", 1)[1].removesuffix(".crl"))
            content_type = "application/pkix-crl"
        ex.entry.status = status
        ex.response_started = True
        await conn.send(http1.simple_response(status, body, content_type, keep_alive=keep_alive))
        return keep_alive

    async def _forward(self, conn: ClientConnection, ex: Exchange, target: Target) -> bool:
        request, entry = ex.request, ex.entry
        entry.host, entry.url = target.host, target.url

        decision = self.policy.decide(target.host)
        entry.category, entry.rule, entry.action = decision.category, decision.rule, decision.action
        if decision.action == "block":
            entry.status = 403
            ex.response_started = True
            # Connection: close, so any request body is never read.
            await conn.send(http1.simple_response(403, pages.block_page(entry)))
            return False

        client_keep_alive = http1.wants_keep_alive(request.version, request.headers)
        body_framing = http1.request_framing(request.headers)
        # An Upgrade (WebSocket) request is the one case where the
        # hop-by-hop Connection/Upgrade headers must reach the origin.
        upgrade = request.headers.get("Upgrade") if "upgrade" in request.headers.tokens("Connection") else None

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
        if upgrade:
            headers.set("Connection", "Upgrade")
            headers.set("Upgrade", upgrade)
        head = f"{request.method} {target.path} HTTP/1.1\r\n".encode("latin-1") + headers.encode()

        # 2. Send it and wait for the response head (time to first byte).
        started = time.perf_counter()
        upstream, response = await self._send_to_origin(conn, target, head, body_framing)
        entry.upstream_latency_ms = ms_since(started)
        entry.status = response.status

        if response.status == 101 and upgrade:
            return await self._switch_protocols(conn, ex, upstream, response)

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
        tls = self.upstream_tls if target.scheme == "https" else None
        for attempt in (1, 2):
            upstream, reused = await conn.upstreams.acquire(target, self.settings.connect_timeout, tls)
            try:
                upstream.writer.write(head)
                if body_framing.kind != "none":
                    body_out = http1.BodyWriter(upstream.writer, chunked=body_framing.kind == "chunked")
                    async for chunk in http1.iter_body(conn.reader, body_framing):
                        await body_out.write(chunk)
                    await body_out.finish()
                await upstream.writer.drain()
                response = await http1.read_response(upstream.reader)
                while 100 <= response.status < 200 and response.status != 101:
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

    async def _switch_protocols(self, conn, ex: Exchange, upstream: Upstream, response: http1.Response) -> bool:
        """101 Switching Protocols (WebSocket): both sides stop speaking
        HTTP, so from here on the gateway relays raw bytes, like a tunnel."""
        headers = http1.strip_hop_by_hop(response.headers)
        headers.set("Connection", "Upgrade")
        headers.set("Upgrade", response.headers.get("Upgrade", ""))
        ex.response_started = True
        await conn.send(b"HTTP/1.1 101 Switching Protocols\r\n" + headers.encode())
        idle = self.settings.tunnel_idle_timeout
        try:
            await asyncio.gather(
                relay(conn.reader, upstream.writer, idle), relay(upstream.reader, conn.writer, idle)
            )
        finally:
            upstream.close()
        return False

    # ---- CONNECT -------------------------------------------------------------

    async def _handle_connect(self, conn: ClientConnection, request: Request) -> None:
        entry = self._new_entry(conn, "CONNECT")
        try:
            host, port = parse_authority(request.target)
        except HttpError as exc:
            await self._reject(conn, entry, exc)
            return
        entry.host = host
        entry.url = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"

        decision = self.policy.decide(host)
        entry.category, entry.rule = decision.category, decision.rule
        if self.certs is not None and decision.inspect:
            await self._inspect(conn, entry, host, port)
            return

        if decision.action == "block":
            # The gateway won't decrypt this tunnel, so it can't show a page
            # inside it. Refusing the CONNECT is all it can do; the browser
            # shows its own generic error, not this block page.
            entry.action = "block"
            await self._reject(conn, entry, HttpError(403, "blocked"), page=pages.block_page(entry))
            return
        await self._tunnel(conn, entry, host, port)

    async def _inspect(self, conn: ClientConnection, entry: LogEntry, host: str, port: int) -> None:
        """Terminate the client's TLS with a certificate minted for `host`,
        then serve the HTTP requests inside it as if they were plain ones.

        Nothing is logged for the CONNECT itself when this works: each
        request inside the tunnel gets its own log line instead.
        """
        entry.inspected = True
        try:
            server_ctx = self.certs.context_for(host)
        except ValueError as exc:
            await self._reject(conn, entry, HttpError(400, str(exc)))
            return

        entry.status = 200
        await conn.send(b"HTTP/1.1 200 Connection established\r\n\r\n")
        try:
            await conn.writer.start_tls(server_ctx, self.settings.tls_handshake_timeout)
        except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
            # The commonest reason: the client doesn't trust our root CA,
            # or the app pins its certificate. Log it, so support can see it.
            entry.error = describe_client_tls_failure(exc)
            self._write_log(conn, entry)
            return

        ssl_object = conn.writer.get_extra_info("ssl_object")
        tunnel = InspectedTunnel(
            host=host,
            port=port,
            sni=getattr(ssl_object, "swg_sni", None),
            tls_version=ssl_object.version(),
        )
        before = conn.requests
        try:
            await self._serve_requests(conn, tunnel)
        except (OSError, asyncio.IncompleteReadError):
            pass  # client reset the connection; still worth logging below
        if conn.requests == before:
            # Many apps check certificate pins only *after* the handshake
            # and then hang up, so without this line they'd leave no trace.
            entry.sni, entry.tls_version = tunnel.sni, tunnel.tls_version
            entry.error = (
                "TLS handshake completed but the client sent no request: it may have "
                "rejected the certificate afterwards (certificate pinning, or a client that "
                "checks the chain itself), or it was an unused preconnect"
            )
            self._write_log(conn, entry)

    async def _tunnel(self, conn: ClientConnection, entry: LogEntry, host: str, port: int) -> None:
        """A blind tunnel: copy bytes both ways, read only the TLS hellos."""
        started = time.perf_counter()
        try:
            up_reader, up_writer = await open_upstream(host, port, self.settings.connect_timeout)
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
        else:
            # A TLS connection can't be half-closed (asyncio has no
            # write_eof for TLS), so end it fully. Buffered data is still
            # flushed, then a close_notify alert is sent.
            dst.close()
    except OSError:
        pass


async def serve(settings: Settings) -> None:
    gateway = Gateway(settings)
    server = await gateway.start()
    for sock in server.sockets:
        host, port = sock.getsockname()[:2]
        print(f"secure-web-gateway listening on {host}:{port}", flush=True)
    if gateway.certs is not None:
        ca = gateway.certs.ca
        print(f"TLS inspection ON. Clients must trust {ca.root_cert_path}", flush=True)
        print(f"  root CA SHA-256 {ca.fingerprint}", flush=True)
    else:
        print("TLS inspection OFF: HTTPS is tunnelled untouched", flush=True)
    print(
        f"policy: {len(gateway.policy.rules)} URL rules, "
        f"{len(gateway.policy.categories)} categorized domains",
        flush=True,
    )
    async with server:
        await server.serve_forever()
