"""Phase 1: HTTPS through CONNECT tunnels, with SNI and TLS version logged."""

import http.client
import ssl

import pytest

from tests.support import recv_all


def https_via_gateway(gateway, tls_origin, context, host="localhost", path="/hello"):
    conn = http.client.HTTPSConnection("127.0.0.1", gateway.port, context=context, timeout=10)
    conn.set_tunnel(host, tls_origin.port)
    conn.request("GET", path)
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response, body


def test_https_through_connect_tunnel(gateway, tls_origin, client_tls):
    response, body = https_via_gateway(gateway, tls_origin, client_tls)
    assert response.status == 200
    assert body == b"hello from origin"
    # The tunnel is opaque: the gateway never sees the HTTP inside it,
    # so it can't add a Via header.
    assert response.getheader("Via") is None

    [entry] = gateway.log_entries(1)
    assert entry["method"] == "CONNECT"
    assert entry["host"] == "localhost"
    assert entry["url"] == f"localhost:{tls_origin.port}"
    assert entry["status"] == 200
    assert entry["sni"] == "localhost"
    assert entry["tls_version"] == "TLSv1.3"
    assert entry["bytes_in"] > 0 and entry["bytes_out"] > 0
    assert entry["upstream_latency_ms"] >= 0


def test_tls12_is_detected_from_server_hello(gateway, tls_origin, client_tls):
    client_tls.maximum_version = ssl.TLSVersion.TLSv1_2
    response, _ = https_via_gateway(gateway, tls_origin, client_tls)
    assert response.status == 200
    [entry] = gateway.log_entries(1)
    assert entry["tls_version"] == "TLSv1.2"
    assert entry["sni"] == "localhost"


def test_ip_literal_has_no_sni(gateway, tls_origin, client_tls):
    # RFC 6066: SNI carries host names only, never IP addresses.
    response, _ = https_via_gateway(gateway, tls_origin, client_tls, host="127.0.0.1")
    assert response.status == 200
    [entry] = gateway.log_entries(1)
    assert entry["sni"] is None
    assert entry["tls_version"] == "TLSv1.3"


def test_connect_to_closed_port_gets_502(gateway, client_tls):
    conn = http.client.HTTPSConnection("127.0.0.1", gateway.port, context=client_tls, timeout=20)
    conn.set_tunnel("127.0.0.1", 9)
    with pytest.raises(OSError, match="502"):
        conn.request("GET", "/")
    conn.close()
    [entry] = gateway.log_entries(1)
    assert entry["method"] == "CONNECT" and entry["status"] == 502


def test_connect_without_port_gets_400(gateway):
    with gateway.raw_socket() as sock:
        sock.sendall(b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
        assert recv_all(sock).startswith(b"HTTP/1.1 400")


def test_tunnel_carries_non_tls_bytes(gateway, origin):
    # CONNECT is a generic TCP tunnel; plain HTTP inside it works too,
    # there is just no TLS hello to read.
    with gateway.raw_socket() as sock:
        sock.sendall(f"CONNECT 127.0.0.1:{origin.port} HTTP/1.1\r\n\r\n".encode())
        assert sock.recv(4096).startswith(b"HTTP/1.1 200 Connection established")
        sock.sendall(b"GET /hello HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        response = recv_all(sock)
    assert response.endswith(b"hello from origin")
    [entry] = gateway.log_entries(1)
    assert entry["sni"] is None and entry["tls_version"] is None
