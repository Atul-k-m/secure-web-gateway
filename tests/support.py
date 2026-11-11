"""Test helpers: a throwaway CA, a local origin server, and the gateway
running on a background thread so tests can use ordinary blocking clients."""

from __future__ import annotations

import asyncio
import datetime as dt
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from swg.accesslog import AccessLog
from swg.proxy import Gateway
from swg.settings import Settings

# --------------------------------------------------------------------------
# Certificates
# --------------------------------------------------------------------------


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def make_test_pki(directory: Path) -> tuple[Path, Path, Path]:
    """A CA and a leaf for localhost/127.0.0.1. Returns (ca, cert, key) paths."""
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("swg test origin CA"))
        .issuer_name(_name("swg test origin CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = directory / "ca.pem", directory / "leaf.pem", directory / "leaf.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf_cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca_path, cert_path, key_path


# --------------------------------------------------------------------------
# Origin server
# --------------------------------------------------------------------------


class OriginHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive and chunked work like a real server

    def log_message(self, format, *args):  # keep test output quiet
        pass

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip(), 16)
                if size == 0:
                    while self.rfile.readline().strip():
                        pass
                    return body
                body += self.rfile.read(size)
                self.rfile.read(2)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length)

    def _send(self, status: int, body: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/hello":
            self._send(200, b"hello from origin")
        elif self.path == "/headers":
            received = {k.lower(): v for k, v in self.headers.items()}
            received["_request_line"] = self.requestline
            self._send(200, json.dumps(received).encode(), "application/json")
        elif self.path == "/chunked":
            self.send_response(200)
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"one ", b"two ", b"three"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
            self.wfile.write(b"0\r\n\r\n")
        elif self.path == "/close-delimited":
            # No Content-Length, no chunking: the body ends when we close.
            self.send_response(200)
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"body ends at close")
            self.close_connection = True
        elif self.path == "/upgrade":
            # A minimal protocol switch, shaped like a WebSocket handshake:
            # answer 101, then echo the next bytes back in upper case.
            if self.headers.get("Upgrade", "").lower() != "echo":
                self._send(400, b"expected Upgrade: echo")
                return
            self.send_response(101)
            self.send_header("Connection", "Upgrade")
            self.send_header("Upgrade", "echo")
            self.end_headers()
            self.wfile.write(self.rfile.read1(65536).upper())
            self.close_connection = True
        elif self.path.startswith("/bytes/"):
            self._send(200, b"x" * int(self.path.rsplit("/", 1)[1]))
        else:
            self._send(404, b"not found")

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "1234")
        self.end_headers()

    def do_POST(self):
        if self.path == "/echo":
            self._send(200, self._read_body())
        else:
            self._read_body()
            self._send(404, b"not found")


class OriginServer:
    """A threaded HTTP (or HTTPS, if given a cert) server on 127.0.0.1."""

    def __init__(self, cert: Path | None = None, key: Path | None = None):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
        self.httpd.daemon_threads = True
        if cert is not None:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert, key)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


# --------------------------------------------------------------------------
# The gateway, on its own event loop thread
# --------------------------------------------------------------------------


class GatewayThread:
    def __init__(self, settings: Settings, policy=None, ca=None):
        self.settings = settings
        self.log = AccessLog(settings.access_log, echo=False)
        self.gateway = Gateway(settings, self.log, policy=policy, ca=ca)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self._ready = threading.Event()
        self.port = 0

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.server = self.loop.run_until_complete(self.gateway.start())
        self.port = self.server.sockets[0].getsockname()[1]
        self._ready.set()
        self.loop.run_forever()

    def __enter__(self):
        self.thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("gateway did not start")
        return self

    def __exit__(self, *exc):
        async def shutdown():
            self.server.close()
            tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        asyncio.run_coroutine_threadsafe(shutdown(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(10)
        self.loop.close()
        self.log.close()

    # ---- helpers for tests ----

    def connection(self, timeout: float = 10) -> http.client.HTTPConnection:
        return http.client.HTTPConnection("127.0.0.1", self.port, timeout=timeout)

    def raw_socket(self, timeout: float = 10) -> socket.socket:
        return socket.create_connection(("127.0.0.1", self.port), timeout=timeout)

    def log_entries(self, count: int = 1, timeout: float = 5.0) -> list[dict]:
        """Wait until the access log holds at least `count` lines."""
        deadline = time.monotonic() + timeout
        while True:
            path = self.settings.access_log
            lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
            if len(lines) >= count or time.monotonic() > deadline:
                return [json.loads(line) for line in lines]
            time.sleep(0.02)


def connect_tunnel(gateway: "GatewayThread", authority: str, timeout: float = 10) -> socket.socket:
    """Open a CONNECT tunnel through the gateway; return the raw socket."""
    sock = gateway.raw_socket(timeout)
    sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
    head = read_head(sock)
    if not head.startswith(b"HTTP/1.1 200"):
        sock.close()
        status_line = head.split(b"\r\n")[0].decode()
        raise OSError(f"tunnel refused: {status_line}")
    return sock


def read_head(sock) -> bytes:
    """Read a response head byte by byte, so nothing after it is consumed."""
    head = b""
    while b"\r\n\r\n" not in head:
        data = sock.recv(1)
        if not data:
            break
        head += data
    return head


def issuer_cn(cert: dict) -> str:
    """Issuer common name from ssl's getpeercert() dict."""
    for rdn in cert["issuer"]:
        for key, value in rdn:
            if key == "commonName":
                return value
    return ""


def recv_all(sock: socket.socket) -> bytes:
    chunks = []
    while True:
        data = sock.recv(65536)
        if not data:
            return b"".join(chunks)
        chunks.append(data)
