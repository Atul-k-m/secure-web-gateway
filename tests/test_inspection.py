"""Phase 2: TLS inspection, Do-Not-Inspect, block pages."""

import http.client
import json
import ssl

import pytest
from cryptography import x509

from swg.policy import Categories, Policy, UrlRule
from tests.support import connect_tunnel, issuer_cn, read_head, recv_all


def get_via(gw, context, host, port, path="/hello", headers=None):
    """HTTPS request through the gateway. Returns (response, body, peer cert)."""
    conn = http.client.HTTPSConnection("127.0.0.1", gw.port, context=context, timeout=10)
    conn.set_tunnel(host, port)
    conn.request("GET", path, headers=headers or {})
    peer = conn.sock.getpeercert()  # before the response: Connection: close drops the socket
    response = conn.getresponse()
    body = response.read()
    conn.close()
    return response, body, peer


# ---- inspection ---------------------------------------------------------------


def test_https_is_decrypted_and_re_encrypted(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    response, body, peer = get_via(gw, trusts_gateway, "localhost", tls_origin.port)

    assert response.status == 200 and body == b"hello from origin"
    # The client sees a certificate the gateway minted, not the origin's...
    assert issuer_cn(peer) == "SWG Inspection Issuing CA"
    assert ("DNS", "localhost") in peer["subjectAltName"]
    # ...and the gateway read the HTTP inside, so it could add its Via header.
    assert response.getheader("Via") == "1.1 swg"

    [entry] = gw.log_entries(1)
    assert entry["method"] == "GET"
    assert entry["url"] == f"https://localhost:{tls_origin.port}/hello"
    assert entry["inspected"] is True
    assert entry["sni"] == "localhost"
    assert entry["tls_version"] == "TLSv1.3"
    assert entry["status"] == 200
    assert entry["upstream_latency_ms"] > 0  # TCP + TLS to the origin + first byte


def test_origin_gets_a_normal_request(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    _, body, _ = get_via(gw, trusts_gateway, "localhost", tls_origin.port, "/headers")
    seen = json.loads(body)
    assert seen["_request_line"] == "GET /headers HTTP/1.1"
    assert seen["host"] == f"localhost:{tls_origin.port}"
    assert seen["via"] == "1.1 swg"


def test_many_requests_in_one_inspected_tunnel(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    conn = http.client.HTTPSConnection("127.0.0.1", gw.port, context=trusts_gateway, timeout=10)
    conn.set_tunnel("localhost", tls_origin.port)
    for size in (10, 2000, 300000):
        conn.request("GET", f"/bytes/{size}")
        assert len(conn.getresponse().read()) == size
    conn.close()
    entries = gw.log_entries(3)
    assert [e["status"] for e in entries] == [200, 200, 200]
    assert all(e["inspected"] for e in entries)


def test_leaf_certificate_is_minted_once_per_host(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    certs = gw.gateway.certs
    before = certs.minted
    for _ in range(3):
        response, _, _ = get_via(gw, trusts_gateway, "localhost", tls_origin.port)
        assert response.status == 200
    assert certs.minted - before <= 1  # cached after the first (or earlier) visit


def test_ip_address_gets_an_ip_certificate_and_no_sni(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    response, _, peer = get_via(gw, trusts_gateway, "127.0.0.1", tls_origin.port)
    assert response.status == 200
    assert ("IP Address", "127.0.0.1") in peer["subjectAltName"]
    [entry] = gw.log_entries(1)
    assert entry["sni"] is None and entry["inspected"] is True


def test_certificate_follows_sni_not_connect_host(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    sock = connect_tunnel(gw, f"127.0.0.1:{tls_origin.port}")
    # The CONNECT names 127.0.0.1, but the ClientHello asks for "localhost".
    with trusts_gateway.wrap_socket(sock, server_hostname="localhost") as tls:
        assert ("DNS", "localhost") in tls.getpeercert()["subjectAltName"]
        # A Host header that doesn't match the tunnel is refused (421): it
        # would let a client reach one site while policy checks another.
        tls.sendall(b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        assert recv_all(tls).startswith(b"HTTP/1.1 421")
    [entry] = gw.log_entries(1)
    assert entry["status"] == 421 and entry["sni"] == "localhost"


def test_client_without_the_root_ca_is_logged(start_gateway, tls_origin, client_tls):
    gw = start_gateway()
    # client_tls trusts the origin's CA but not the gateway's root.
    with pytest.raises(ssl.SSLCertVerificationError):
        get_via(gw, client_tls, "localhost", tls_origin.port)
    [entry] = gw.log_entries(1)
    assert entry["method"] == "CONNECT" and entry["inspected"] is True
    assert "client rejected the gateway certificate" in entry["error"]
    assert "UNKNOWN_CA" in entry["error"]


def test_tunnel_closed_without_a_request_is_logged(start_gateway, tls_origin, trusts_gateway):
    # What a pinning app looks like when it checks the pin after the
    # handshake: TLS succeeds, then it hangs up without sending anything.
    gw = start_gateway()
    sock = connect_tunnel(gw, f"localhost:{tls_origin.port}")
    with trusts_gateway.wrap_socket(sock, server_hostname="localhost"):
        pass
    [entry] = gw.log_entries(1)
    assert entry["method"] == "CONNECT" and entry["inspected"] is True
    assert "sent no request" in entry["error"]
    assert entry["sni"] == "localhost" and entry["tls_version"] == "TLSv1.3"


def test_gateway_serves_its_root_ca_and_crls(start_gateway, inspection_ca):
    gw = start_gateway()
    conn = gw.connection()
    conn.request("GET", "/ca.crt")
    response = conn.getresponse()
    assert response.getheader("Content-Type") == "application/x-x509-ca-cert"
    assert response.read() == inspection_ca.root_cert_path.read_bytes()
    conn.request("GET", "/crl/issuing.crl")
    response = conn.getresponse()
    assert response.getheader("Content-Type") == "application/pkix-crl"
    crl = x509.load_der_x509_crl(response.read())
    assert crl.is_signature_valid(inspection_ca.issuing_cert.public_key())
    conn.close()


def test_untrusted_origin_certificate_gets_an_error_page(start_gateway, tls_origin, trusts_gateway):
    # The gateway itself doesn't trust the test origin's CA here.
    gw = start_gateway(trust_origin_ca=False)
    response, body, _ = get_via(gw, trusts_gateway, "localhost", tls_origin.port)
    assert response.status == 502
    assert b"certificate could not be verified" in body
    [entry] = gw.log_entries(1)
    assert "unable to get local issuer certificate" in entry["error"]
    assert entry["txn_id"].encode() in body


# ---- Do-Not-Inspect -----------------------------------------------------------


def test_do_not_inspect_domain_is_tunnelled_untouched(start_gateway, tls_origin, client_tls):
    gw = start_gateway(Policy(dni_domains=["localhost"]))
    # A client that trusts only the origin's CA works: it sees the real cert.
    response, body, peer = get_via(gw, client_tls, "localhost", tls_origin.port)
    assert response.status == 200 and body == b"hello from origin"
    assert issuer_cn(peer) == "swg test origin CA"
    assert response.getheader("Via") is None  # the gateway never saw the HTTP
    [entry] = gw.log_entries(1)
    assert entry["method"] == "CONNECT"
    assert entry["inspected"] is False
    assert entry["tls_version"] == "TLSv1.3" and entry["sni"] == "localhost"


def test_do_not_inspect_category(start_gateway, tls_origin, client_tls):
    policy = Policy(Categories({"finance": ["localhost"]}), dni_categories=["finance"])
    gw = start_gateway(policy)
    response, _, peer = get_via(gw, client_tls, "localhost", tls_origin.port)
    assert response.status == 200
    assert issuer_cn(peer) == "swg test origin CA"
    [entry] = gw.log_entries(1)
    assert entry["category"] == "finance" and entry["inspected"] is False


def test_inspection_turned_off_tunnels_everything(start_gateway, tls_origin, client_tls):
    gw = start_gateway(inspect=False)
    response, _, peer = get_via(gw, client_tls, "localhost", tls_origin.port)
    assert response.status == 200 and issuer_cn(peer) == "swg test origin CA"


# ---- block pages --------------------------------------------------------------

BLOCKING = Policy(
    Categories({"gambling": ["casino.test"]}),
    rules=[
        UrlRule("Block gambling", "block", categories=["gambling"]),
        UrlRule("Block one domain", "block", domains=["blocked.test"]),
    ],
)


def test_http_block_page(start_gateway):
    gw = start_gateway(BLOCKING)
    conn = gw.connection()
    conn.request("GET", "http://www.casino.test/slots?x=1")
    response = conn.getresponse()
    body = response.read()
    conn.close()
    assert response.status == 403
    assert b"This site is blocked" in body and b"Block gambling" in body
    [entry] = gw.log_entries(1)
    assert entry["action"] == "block" and entry["rule"] == "Block gambling"
    assert entry["category"] == "gambling"
    assert entry["txn_id"].encode() in body  # the user can quote it in a ticket


def test_https_block_page_needs_inspection(start_gateway, trusts_gateway):
    gw = start_gateway(BLOCKING)
    # No origin exists for blocked.test: the gateway answers by itself,
    # over TLS with a certificate it minted, without any DNS lookup.
    response, body, peer = get_via(gw, trusts_gateway, "blocked.test", 443, "/login")
    assert response.status == 403
    assert b"https://blocked.test/login" in body
    assert issuer_cn(peer) == "SWG Inspection Issuing CA"
    [entry] = gw.log_entries(1)
    assert entry["action"] == "block" and entry["inspected"] is True
    assert entry["url"] == "https://blocked.test/login"


def test_blocked_and_not_inspected_refuses_the_connect(start_gateway):
    policy = Policy(rules=BLOCKING.rules, categories=BLOCKING.categories, dni_domains=["blocked.test"])
    gw = start_gateway(policy)
    with pytest.raises(OSError, match="403"):
        connect_tunnel(gw, "blocked.test:443")
    [entry] = gw.log_entries(1)
    assert entry["method"] == "CONNECT" and entry["action"] == "block" and entry["status"] == 403


def test_block_page_escapes_the_url(start_gateway):
    gw = start_gateway(BLOCKING)
    conn = gw.connection()
    conn.request("GET", "http://blocked.test/<script>alert(1)</script>")
    body = conn.getresponse().read()
    conn.close()
    assert b"<script>" not in body and b"&lt;script&gt;" in body


# ---- protocol upgrades (WebSocket) --------------------------------------------

UPGRADE = b"GET /upgrade HTTP/1.1\r\nHost: {host}\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n"


def test_upgrade_through_plain_proxy(gateway, origin):
    with gateway.raw_socket() as sock:
        request = UPGRADE.replace(b"GET /upgrade", f"GET http://127.0.0.1:{origin.port}/upgrade".encode())
        sock.sendall(request.replace(b"{host}", b"127.0.0.1"))
        assert read_head(sock).startswith(b"HTTP/1.1 101")
        sock.sendall(b"ping")
        assert recv_all(sock) == b"PING"


def test_upgrade_inside_inspected_tunnel(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway()
    sock = connect_tunnel(gw, f"localhost:{tls_origin.port}")
    with trusts_gateway.wrap_socket(sock, server_hostname="localhost") as tls:
        tls.sendall(UPGRADE.replace(b"{host}", f"localhost:{tls_origin.port}".encode()))
        assert read_head(tls).startswith(b"HTTP/1.1 101")
        tls.sendall(b"ping")
        assert recv_all(tls) == b"PING"
    [entry] = gw.log_entries(1)
    assert entry["status"] == 101 and entry["inspected"] is True
