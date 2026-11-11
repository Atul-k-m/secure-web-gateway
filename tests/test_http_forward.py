"""Phase 1: plain HTTP through the explicit proxy (absolute-form requests)."""

import json

from tests.support import recv_all

LOG_FIELDS = [
    "time", "client_ip", "user", "method", "host", "url", "status", "category", "action",
    "bytes_in", "bytes_out", "upstream_latency_ms", "duration_ms", "tls_version", "sni", "error",
]


def test_get_is_forwarded_and_logged(gateway, origin):
    conn = gateway.connection()
    conn.request("GET", f"http://127.0.0.1:{origin.port}/hello")
    response = conn.getresponse()
    body = response.read()
    conn.close()

    assert response.status == 200
    assert body == b"hello from origin"
    assert response.getheader("Via") == "1.1 swg"

    [entry] = gateway.log_entries(1)
    assert list(entry) == LOG_FIELDS
    assert entry["client_ip"] == "127.0.0.1"
    assert entry["method"] == "GET"
    assert entry["host"] == "127.0.0.1"
    assert entry["url"] == f"http://127.0.0.1:{origin.port}/hello"
    assert entry["status"] == 200
    assert entry["action"] == "allow"
    assert entry["bytes_in"] > 0
    assert entry["bytes_out"] > len(body)  # headers + body
    assert entry["upstream_latency_ms"] >= 0
    assert entry["tls_version"] is None and entry["sni"] is None
    assert entry["time"].endswith("Z")


def test_request_is_rewritten_for_the_origin(gateway, origin):
    conn = gateway.connection()
    conn.request(
        "GET",
        f"http://127.0.0.1:{origin.port}/headers",
        headers={
            "Host": "spoofed.example",  # absolute-form must win over Host
            "Proxy-Connection": "keep-alive",
            "Connection": "keep-alive, X-Hop",
            "X-Hop": "named in Connection, so hop-by-hop",
            "X-End-To-End": "kept",
        },
    )
    seen = json.loads(conn.getresponse().read())
    conn.close()

    assert seen["_request_line"] == "GET /headers HTTP/1.1"  # origin-form
    assert seen["host"] == f"127.0.0.1:{origin.port}"
    assert seen["via"] == "1.1 swg"
    assert seen["x-end-to-end"] == "kept"
    for hop in ("proxy-connection", "connection", "x-hop"):
        assert hop not in seen


def test_post_with_content_length(gateway, origin):
    conn = gateway.connection()
    payload = b"field=value&n=42"
    conn.request("POST", f"http://127.0.0.1:{origin.port}/echo", body=payload)
    response = conn.getresponse()
    assert response.read() == payload
    conn.close()
    [entry] = gateway.log_entries(1)
    assert entry["bytes_in"] > len(payload)


def test_post_with_chunked_body(gateway, origin):
    conn = gateway.connection()
    parts = [b"alpha-", b"beta-", b"gamma"]
    conn.request("POST", f"http://127.0.0.1:{origin.port}/echo", body=iter(parts), encode_chunked=True)
    assert conn.getresponse().read() == b"".join(parts)
    conn.close()


def test_expect_100_continue_is_answered_by_gateway(gateway, origin):
    with gateway.raw_socket() as sock:
        sock.sendall(
            f"POST http://127.0.0.1:{origin.port}/echo HTTP/1.1\r\n"
            f"Host: 127.0.0.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\n"
            f"Connection: close\r\n\r\n".encode()
        )
        interim = sock.recv(4096)
        assert interim.startswith(b"HTTP/1.1 100 Continue")
        sock.sendall(b"hello")
        response = recv_all(sock)
    assert response.startswith(b"HTTP/1.1 200")
    assert response.endswith(b"hello")


def test_chunked_response_passes_through(gateway, origin):
    conn = gateway.connection()
    conn.request("GET", f"http://127.0.0.1:{origin.port}/chunked")
    response = conn.getresponse()
    assert response.getheader("Transfer-Encoding") == "chunked"
    assert response.read() == b"one two three"
    conn.close()


def test_close_delimited_response_is_rechunked_for_http11(gateway, origin):
    conn = gateway.connection()
    conn.request("GET", f"http://127.0.0.1:{origin.port}/close-delimited")
    response = conn.getresponse()
    # The origin ended the body by closing; the gateway re-frames it as
    # chunked so the client connection can stay open.
    assert response.getheader("Transfer-Encoding") == "chunked"
    assert response.read() == b"body ends at close"
    assert response.getheader("Connection") == "keep-alive"
    conn.close()


def test_http10_client_gets_close_delimited_body(gateway, origin):
    with gateway.raw_socket() as sock:
        sock.sendall(f"GET http://127.0.0.1:{origin.port}/chunked HTTP/1.0\r\n\r\n".encode())
        response = recv_all(sock)
    head, _, body = response.partition(b"\r\n\r\n")
    assert b"Transfer-Encoding" not in head  # HTTP/1.0 can't parse chunking
    assert b"Connection: close" in head
    assert body == b"one two three"


def test_head_response_has_no_body(gateway, origin):
    conn = gateway.connection()
    conn.request("HEAD", f"http://127.0.0.1:{origin.port}/anything")
    response = conn.getresponse()
    assert response.getheader("Content-Length") == "1234"
    assert response.read() == b""
    # The same connection still works, so no stray body bytes were sent.
    conn.request("GET", f"http://127.0.0.1:{origin.port}/hello")
    assert conn.getresponse().read() == b"hello from origin"
    conn.close()


def test_keep_alive_serves_many_requests_on_one_connection(gateway, origin):
    conn = gateway.connection()
    conn.request("GET", f"http://127.0.0.1:{origin.port}/hello")
    conn.getresponse().read()
    first_socket = conn.sock
    for _ in range(4):
        conn.request("GET", f"http://127.0.0.1:{origin.port}/bytes/2000")
        assert len(conn.getresponse().read()) == 2000
    assert conn.sock is first_socket  # no reconnect happened
    conn.close()
    entries = gateway.log_entries(5)
    assert len(entries) == 5
    assert all(e["status"] == 200 for e in entries)


def test_large_body_streams_through(gateway, origin):
    conn = gateway.connection()
    conn.request("GET", f"http://127.0.0.1:{origin.port}/bytes/3000000")
    assert len(conn.getresponse().read()) == 3_000_000
    conn.close()
    [entry] = gateway.log_entries(1)
    assert entry["bytes_out"] > 3_000_000


def test_unreachable_origin_gets_502(gateway):
    conn = gateway.connection(timeout=20)
    conn.request("GET", "http://127.0.0.1:9/")  # port 9 (discard) is closed
    response = conn.getresponse()
    assert response.status == 502
    assert b"cannot connect" in response.read()
    conn.close()
    [entry] = gateway.log_entries(1)
    assert entry["status"] == 502
    assert "cannot connect" in entry["error"]


def test_malformed_request_gets_400(gateway):
    with gateway.raw_socket() as sock:
        sock.sendall(b"THIS IS NOT HTTP\r\n\r\n")
        response = recv_all(sock)
    assert response.startswith(b"HTTP/1.1 400")
    [entry] = gateway.log_entries(1)
    assert entry["status"] == 400


def test_both_content_length_and_transfer_encoding_rejected(gateway, origin):
    with gateway.raw_socket() as sock:
        sock.sendall(
            f"POST http://127.0.0.1:{origin.port}/echo HTTP/1.1\r\n"
            "Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n".encode()
        )
        response = recv_all(sock)
    assert response.startswith(b"HTTP/1.1 400")


def test_https_url_without_connect_is_rejected(gateway):
    conn = gateway.connection()
    conn.request("GET", "https://example.com/")
    assert conn.getresponse().status == 400
    conn.close()


def test_error_page_escapes_client_input(gateway):
    conn = gateway.connection()
    conn.request("GET", "ftp://<script>alert(1)</script>/")
    body = conn.getresponse().read()
    assert b"<script>" not in body
    conn.close()


def test_request_addressed_to_gateway_gets_info_page(gateway):
    conn = gateway.connection()
    conn.request("GET", "/")
    response = conn.getresponse()
    assert response.status == 200
    assert b"secure-web-gateway is running" in response.read()
    conn.close()
