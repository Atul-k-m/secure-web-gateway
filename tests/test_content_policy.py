"""Phase 3, end to end: caution pages, per-user/group rules, file-type
blocking and DLP, through a running gateway, over HTTP and inspected HTTPS."""

import html
import http.client
import re
import uuid
from urllib.parse import urlsplit

import pytest

from swg import dlp
from swg.directory import Directory
from swg.policy import Categories, DlpRule, FileTypeRule, Policy, UrlRule
from tests.support import RECEIVED_UPLOADS

USERS = {"asha": ["engineering"], "meera": ["finance"], "dev": ["contractors"]}


def as_user(name):
    """Every test client is 127.0.0.1; bind it to the user under test."""
    return Directory(USERS, {"127.0.0.1": name})


def fetch(gw, method, url, body=None, headers=None, context=None):
    parts = urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection("127.0.0.1", gw.port, context=context, timeout=10)
        conn.set_tunnel(parts.hostname, parts.port)
        target = parts.path + ("?" + parts.query if parts.query else "")
    else:
        conn = gw.connection()
        target = url
    conn.request(method, target, body=body, headers=headers or {})
    response = conn.getresponse()
    data = response.read()
    conn.close()
    return response, data


def upload_url(base):
    """A unique /echo URL, so the test can tell whether it reached the origin."""
    return f"{base}/echo?id={uuid.uuid4().hex}"


def reached_origin(url):
    parts = urlsplit(url)
    return f"{parts.path}?{parts.query}" in RECEIVED_UPLOADS


FORM = {"Content-Type": "application/x-www-form-urlencoded"}


# ---- caution ------------------------------------------------------------------

CAUTION = Policy(
    Categories({"social-media": ["127.0.0.1", "localhost"]}),
    rules=[UrlRule("Warn before social media", "caution", categories=["social-media"])],
)


def continue_link(page: bytes) -> str:
    return html.unescape(re.search(rb'href="([^"]+)"', page).group(1).decode())


def test_caution_warns_then_lets_the_user_continue(start_gateway, origin):
    gw = start_gateway(CAUTION, directory=as_user("asha"))
    url = f"http://127.0.0.1:{origin.port}/hello"

    response, page = fetch(gw, "GET", url)
    assert response.status == 403 and b"Are you sure you want to continue" in page

    response, _ = fetch(gw, "GET", continue_link(page))
    assert response.status == 302
    assert response.getheader("Location") == url  # the token is stripped again

    response, body = fetch(gw, "GET", url)
    assert response.status == 200 and body == b"hello from origin"

    actions = [e["action"] for e in gw.log_entries(3)]
    assert actions == ["caution", "caution-accepted", "caution-accepted"]
    assert all(e["rule"] == "Warn before social media" for e in gw.log_entries(3))


def test_caution_over_inspected_https(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway(CAUTION, directory=as_user("asha"))
    url = f"https://localhost:{tls_origin.port}/hello"
    response, page = fetch(gw, "GET", url, context=trusts_gateway)
    assert response.status == 403
    response, _ = fetch(gw, "GET", continue_link(page), context=trusts_gateway)
    assert response.status == 302
    response, body = fetch(gw, "GET", url, context=trusts_gateway)
    assert body == b"hello from origin"


def test_caution_acceptance_is_per_user(start_gateway, origin):
    gw = start_gateway(CAUTION, directory=as_user("asha"))
    url = f"http://127.0.0.1:{origin.port}/hello"
    _, page = fetch(gw, "GET", url)
    link = continue_link(page)
    assert fetch(gw, "GET", link)[0].status == 302  # asha accepted the warning

    # Same gateway (same signing secret); new connections now belong to dev.
    gw.gateway.directory = as_user("dev")
    assert fetch(gw, "GET", url)[0].status == 403  # asha's acceptance isn't dev's
    assert fetch(gw, "GET", link)[0].status == 403  # and asha's link doesn't work for dev


# ---- users and groups ---------------------------------------------------------

CONTRACTOR_RULE = Policy(
    Categories({"file-sharing": ["127.0.0.1"]}),
    rules=[UrlRule("Contractors may not use file sharing", "block", categories=["file-sharing"], groups=["contractors"])],
)


def test_group_rule_applies_only_to_its_group(start_gateway, origin):
    url = f"http://127.0.0.1:{origin.port}/hello"
    contractor = start_gateway(CONTRACTOR_RULE, directory=as_user("dev"))
    response, page = fetch(contractor, "GET", url)
    assert response.status == 403 and b"Contractors may not use file sharing" in page
    [entry] = contractor.log_entries(1)
    assert entry["user"] == "dev" and entry["action"] == "block"

    engineer = start_gateway(CONTRACTOR_RULE, directory=as_user("asha"))
    response, _ = fetch(engineer, "GET", url)
    assert response.status == 200
    [entry] = engineer.log_entries(1)
    assert entry["user"] == "asha" and entry["action"] == "allow"


def test_unbound_client_is_anonymous(start_gateway, origin):
    gw = start_gateway(CONTRACTOR_RULE, directory=Directory(USERS, {}))
    response, _ = fetch(gw, "GET", f"http://127.0.0.1:{origin.port}/hello")
    assert response.status == 200  # group rules can't match an unknown user
    [entry] = gw.log_entries(1)
    assert entry["user"] is None


# ---- file types ---------------------------------------------------------------

PROGRAMS = Policy(
    file_rules=[
        FileTypeRule("Engineering may download programs here", "allow", domains=["localhost"],
                     groups=["engineering"], types=["windows-executable"]),
        FileTypeRule("Block program downloads", "block", types=["windows-executable", "linux-executable"]),
    ]
)


@pytest.mark.parametrize(
    "query",
    [
        "kind=exe&ct=application/x-msdownload",  # honest label
        "kind=exe&ct=text/plain",  # disguised as text: caught by magic bytes
        "kind=exe&ct=application/octet-stream&gzip=1",  # compressed on the wire
        "kind=elf&ct=application/octet-stream",
    ],
)
def test_program_downloads_are_blocked(start_gateway, origin, query):
    gw = start_gateway(PROGRAMS, directory=as_user("dev"))
    response, page = fetch(gw, "GET", f"http://127.0.0.1:{origin.port}/file?{query}")
    assert response.status == 403
    assert b"This transfer was blocked" in page
    [entry] = gw.log_entries(1)
    assert entry["action"] == "block" and entry["rule"] == "Block program downloads"
    assert entry["file_type"] in ("windows-executable", "linux-executable")


def test_disguised_program_is_called_out(start_gateway, origin):
    gw = start_gateway(PROGRAMS, directory=as_user("dev"))
    _, page = fetch(gw, "GET", f"http://127.0.0.1:{origin.port}/file?kind=exe&ct=text/plain")
    assert b"a windows-executable file (sent as text/plain)" in page


def test_other_files_download_normally(start_gateway, origin):
    gw = start_gateway(PROGRAMS, directory=as_user("dev"))
    response, body = fetch(gw, "GET", f"http://127.0.0.1:{origin.port}/file?kind=pdf&ct=application/pdf")
    assert response.status == 200 and body.startswith(b"%PDF-")
    [entry] = gw.log_entries(1)
    assert entry["file_type"] == "pdf" and entry["action"] == "allow"


def test_exception_for_a_group_and_domain(start_gateway, tls_origin, trusts_gateway):
    url = f"https://localhost:{tls_origin.port}/file?kind=exe"
    engineer = start_gateway(PROGRAMS, directory=as_user("asha"))
    response, body = fetch(engineer, "GET", url, context=trusts_gateway)
    assert response.status == 200 and body.startswith(b"MZ")
    [entry] = engineer.log_entries(1)
    assert entry["rule"] == "Engineering may download programs here"  # the exception is logged
    contractor = start_gateway(PROGRAMS, directory=as_user("dev"))
    response, _ = fetch(contractor, "GET", url, context=trusts_gateway)
    assert response.status == 403  # blocked inside inspected HTTPS too


# ---- uploads: file types ------------------------------------------------------

NO_ARCHIVES = Policy(
    file_rules=[FileTypeRule("Contractors may not upload archives", "block", groups=["contractors"],
                             types=["zip"], direction="upload")]
)


def multipart_with_file(filename, data, content_type="application/octet-stream"):
    boundary = "swgtestboundary"
    body = (
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nquarterly files\r\n"
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"{filename}\"\r\n"
        f"Content-Type: {content_type}\r\n\r\n"
    ).encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, {"Content-Type": f"multipart/form-data; boundary={boundary}"}


def test_archive_upload_blocked_for_contractor_only(start_gateway, origin):
    body, headers = multipart_with_file("report.pdf", b"PK\x03\x04" + b"\x00" * 50)  # a zip named .pdf
    contractor = start_gateway(NO_ARCHIVES, directory=as_user("dev"))
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    response, page = fetch(contractor, "POST", url, body, headers)
    assert response.status == 403 and b"report.pdf" in page
    assert not reached_origin(url)

    engineer = start_gateway(NO_ARCHIVES, directory=as_user("asha"))
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    response, echoed = fetch(engineer, "POST", url, body, headers)
    assert response.status == 200 and echoed == body and reached_origin(url)


# ---- uploads: DLP -------------------------------------------------------------

DLP = Policy(
    dlp_rules=[
        DlpRule("Finance may send cards here", "allow", groups=["finance"], domains=["127.0.0.1"],
                detectors=["credit_card"]),
        DlpRule("Block card numbers", "block", detectors=["credit_card"]),
        DlpRule("Block secrets", "block", detectors=["api_key", "private_key", "aadhaar"]),
    ]
)


def test_card_number_upload_never_reaches_the_origin(start_gateway, origin):
    gw = start_gateway(DLP, directory=as_user("asha"))
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    response, page = fetch(gw, "POST", url, "name=A&card=4111+1111+1111+1111", FORM)
    assert response.status == 403
    assert b"visa ending 1111" in page and b"4111 1111 1111 1111" not in page
    assert not reached_origin(url)
    [entry] = gw.log_entries(1)
    assert entry["action"] == "block" and entry["rule"] == "Block card numbers"
    assert entry["dlp"]["matches"] == {"credit_card": 1}


def test_clean_upload_passes_and_is_logged(start_gateway, origin):
    gw = start_gateway(DLP, directory=as_user("asha"))
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    response, echoed = fetch(gw, "POST", url, "comment=all good", FORM)
    assert response.status == 200 and echoed == b"comment=all good" and reached_origin(url)
    [entry] = gw.log_entries(1)
    assert entry["dlp"] == {"scanned_bytes": 16, "truncated": False, "matches": {}}


def test_api_key_in_json_blocked_inside_https(start_gateway, tls_origin, trusts_gateway):
    gw = start_gateway(DLP, directory=as_user("asha"))
    url = upload_url(f"https://localhost:{tls_origin.port}")
    body = '{"config": {"aws_key": "AKIAIOSFODNN7EXAMPLE"}}'
    response, _ = fetch(gw, "POST", url, body, {"Content-Type": "application/json"}, trusts_gateway)
    assert response.status == 403 and not reached_origin(url)
    [entry] = gw.log_entries(1)
    assert entry["inspected"] is True and entry["dlp"]["matches"] == {"api_key": 1}


def test_aadhaar_in_chunked_upload_blocked(start_gateway, origin):
    gw = start_gateway(DLP, directory=as_user("asha"))
    number = "23456789012" + dlp.verhoeff_digit("23456789012")
    chunks = [b"applicant id: ", f"{number[:4]} {number[4:8]} ".encode(), number[8:].encode()]
    conn = gw.connection()
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    conn.request("POST", url, body=iter(chunks), encode_chunked=True)
    assert conn.getresponse().status == 403
    conn.close()
    assert not reached_origin(url)


def test_finance_exception(start_gateway, origin):
    finance = start_gateway(DLP, directory=as_user("meera"))
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    response, _ = fetch(finance, "POST", url, "card=4111111111111111", FORM)
    assert response.status == 200 and reached_origin(url)
    [entry] = finance.log_entries(1)
    assert entry["rule"] == "Finance may send cards here" and entry["dlp"]["matches"] == {"credit_card": 1}


def test_body_over_the_scan_limit_is_forwarded_intact(start_gateway, origin):
    policy = Policy(dlp_rules=DLP.dlp_rules, dlp_max_scan_bytes=1000)
    gw = start_gateway(policy, directory=as_user("asha"))
    body = b"a" * 3000 + b" 4111 1111 1111 1111 " + b"b" * 3000  # card beyond the limit
    url = upload_url(f"http://127.0.0.1:{origin.port}")
    response, echoed = fetch(gw, "POST", url, body, {"Content-Type": "text/plain"})
    assert response.status == 200 and echoed == body  # nothing lost or reordered
    [entry] = gw.log_entries(1)
    assert entry["dlp"]["truncated"] is True and entry["dlp"]["scanned_bytes"] == 1000
