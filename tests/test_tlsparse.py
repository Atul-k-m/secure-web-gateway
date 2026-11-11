"""Phase 1: reading SNI and the TLS version from real handshake bytes.

Python's ssl module can run a handshake in memory (MemoryBIO), which gives
us a genuine ClientHello and ServerHello to parse without any network.
"""

import ssl

import pytest

from swg import tlsparse


def client_hello(server_hostname="www.example.com", max_version=None) -> bytes:
    ctx = ssl.create_default_context()
    if max_version:
        ctx.maximum_version = max_version
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = ctx.wrap_bio(incoming, outgoing, server_hostname=server_hostname)
    with pytest.raises(ssl.SSLWantReadError):
        client.do_handshake()
    return outgoing.read()


def server_hello(pki, max_version=None) -> bytes:
    _, cert, key = pki
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    if max_version:
        server_ctx.maximum_version = max_version
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_ctx.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(client_hello("localhost"))
    with pytest.raises(ssl.SSLWantReadError):
        server.do_handshake()
    return outgoing.read()


def test_client_hello_sni_and_versions():
    info = tlsparse.parse_client_hello(client_hello("WWW.Example.com"))
    assert info is not None
    assert info.sni == "www.example.com"  # host names are case-insensitive
    assert "TLSv1.3" in info.offered_versions and "TLSv1.2" in info.offered_versions


def test_client_hello_with_ip_has_no_sni():
    info = tlsparse.parse_client_hello(client_hello("192.0.2.10"))
    assert info is not None and info.sni is None


def test_client_hello_limited_to_tls12():
    info = tlsparse.parse_client_hello(client_hello(max_version=ssl.TLSVersion.TLSv1_2))
    assert "TLSv1.3" not in info.offered_versions


def test_server_hello_tls13_uses_supported_versions(pki):
    record = server_hello(pki)
    # TLS 1.3 puts 0x0303 (TLS 1.2) in legacy_version for middlebox
    # compatibility; only the extension says 1.3.
    assert record[9:11] == b"\x03\x03"
    info = tlsparse.parse_server_hello(record)
    assert info.version == "TLSv1.3"


def test_server_hello_tls12(pki):
    info = tlsparse.parse_server_hello(server_hello(pki, ssl.TLSVersion.TLSv1_2))
    assert info.version == "TLSv1.2"


@pytest.mark.parametrize(
    "data",
    [b"", b"GET / HTTP/1.1\r\n\r\n", b"\x16\x03\x01\x00\x05\x01\x00\x00", b"\x16\x03\x01\xff\xff"],
)
def test_garbage_is_not_a_hello(data):
    assert tlsparse.parse_client_hello(data) is None
    assert tlsparse.parse_server_hello(data) is None


def test_truncated_client_hello_does_not_crash():
    hello = client_hello()
    for cut in range(5, len(hello), 37):
        tlsparse.parse_client_hello(hello[:cut])  # must not raise


def test_grease_values_are_recognised():
    assert tlsparse.is_grease(0x0A0A) and tlsparse.is_grease(0xFAFA)
    assert not tlsparse.is_grease(0x0304)
