"""Read the two unencrypted TLS handshake messages: ClientHello and ServerHello.

A CONNECT tunnel carries encrypted bytes the proxy cannot read, but the
first record in each direction is plaintext:

* ClientHello (client -> server) carries the SNI, the host name the client
  wants, and the TLS versions it supports.
* ServerHello (server -> client) carries the version the server chose.

That is enough to log `sni` and `tls_version` without decrypting anything.
Layouts are from RFC 8446 (TLS 1.3) section 4.1 and RFC 6066 (SNI).

Record layout (5-byte header):
    content_type (1)  0x16 = handshake
    legacy_version (2)
    length (2)
    fragment (length bytes)
"""

from __future__ import annotations

from dataclasses import dataclass, field

HANDSHAKE = 0x16
CLIENT_HELLO = 0x01
SERVER_HELLO = 0x02
EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
MAX_RECORD = 16384 + 2048  # largest legal TLS record body

VERSION_NAMES = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}


def version_name(code: int) -> str:
    return VERSION_NAMES.get(code, f"0x{code:04x}")


def is_grease(code: int) -> bool:
    """GREASE values (RFC 8701) are fake entries like 0x0a0a that clients
    add so servers don't break on unknown values. They are not real versions."""
    return (code & 0x0F0F) == 0x0A0A and (code >> 8) == (code & 0xFF)


class _Cursor:
    """Bounds-checked reader over a byte string."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vector(self, length_bytes: int) -> "_Cursor":
        """A length-prefixed block, returned as its own cursor."""
        length = int.from_bytes(self.take(length_bytes), "big")
        return _Cursor(self.take(length))

    def done(self) -> bool:
        return self.pos >= len(self.data)


@dataclass
class ClientHelloInfo:
    sni: str | None
    offered_versions: list[str] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)


@dataclass
class ServerHelloInfo:
    version: str
    cipher_suite: int


def record_length(header: bytes) -> int | None:
    """Body length from a 5-byte record header, or None if it isn't a
    TLS handshake record."""
    if len(header) < 5 or header[0] != HANDSHAKE or header[1] != 0x03:
        return None
    length = int.from_bytes(header[3:5], "big")
    return length if length <= MAX_RECORD else None


def _handshake_body(record: bytes, expected_type: int) -> _Cursor:
    if record_length(record[:5]) is None:
        raise ValueError("not a TLS handshake record")
    fragment = _Cursor(record[5:])
    if fragment.u8() != expected_type:
        raise ValueError("unexpected handshake message")
    length = fragment.u24()
    # A ClientHello can be larger than one record (big post-quantum key
    # shares). Parse what arrived; the fields we need come early.
    available = len(fragment.data) - fragment.pos
    return _Cursor(fragment.take(min(length, available)))


def _extensions(body: _Cursor) -> dict[int, bytes]:
    found: dict[int, bytes] = {}
    if body.done():
        return found  # extensions are optional in TLS 1.2
    block = body.vector(2)
    while not block.done():
        ext_type = block.u16()
        found[ext_type] = block.vector(2).data
    return found


def parse_client_hello(record: bytes) -> ClientHelloInfo | None:
    try:
        return _parse_client_hello(record)
    except ValueError:
        return None


def _parse_client_hello(record: bytes) -> ClientHelloInfo:
    body = _handshake_body(record, CLIENT_HELLO)
    legacy_version = body.u16()
    body.take(32)  # random
    body.vector(1)  # legacy_session_id
    body.vector(2)  # cipher_suites
    body.vector(1)  # compression_methods
    extensions = _extensions(body)

    sni = None
    if EXT_SERVER_NAME in extensions:
        names = _Cursor(extensions[EXT_SERVER_NAME]).vector(2)
        while not names.done():
            name_type = names.u8()
            name = names.vector(2).data
            if name_type == 0:  # host_name
                sni = name.decode("ascii", "replace").lower()
                break

    if EXT_SUPPORTED_VERSIONS in extensions:
        versions = _Cursor(extensions[EXT_SUPPORTED_VERSIONS]).vector(1)
        offered = []
        while not versions.done():
            code = versions.u16()
            if not is_grease(code):
                offered.append(version_name(code))
    else:
        offered = [version_name(legacy_version)]

    alpn = []
    if EXT_ALPN in extensions:
        protocols = _Cursor(extensions[EXT_ALPN]).vector(2)
        while not protocols.done():
            alpn.append(protocols.vector(1).data.decode("ascii", "replace"))

    return ClientHelloInfo(sni=sni, offered_versions=offered, alpn=alpn)


def parse_server_hello(record: bytes) -> ServerHelloInfo | None:
    try:
        return _parse_server_hello(record)
    except ValueError:
        return None


def _parse_server_hello(record: bytes) -> ServerHelloInfo:
    body = _handshake_body(record, SERVER_HELLO)
    legacy_version = body.u16()
    body.take(32)  # random
    body.vector(1)  # legacy_session_id_echo
    cipher_suite = body.u16()
    body.u8()  # compression method
    extensions = _extensions(body)

    # TLS 1.3 pretends to be TLS 1.2 in legacy_version so old middleboxes
    # don't drop it. The real version is in the supported_versions extension.
    version = legacy_version
    selected = extensions.get(EXT_SUPPORTED_VERSIONS)
    if selected is not None and len(selected) == 2:
        version = int.from_bytes(selected, "big")
    return ServerHelloInfo(version=version_name(version), cipher_suite=cipher_suite)
