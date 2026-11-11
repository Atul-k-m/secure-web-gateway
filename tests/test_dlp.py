"""Phase 3: DLP detectors. Synthetic data only: test card numbers published by
the card networks, Aadhaar-format numbers generated with a valid checksum,
and AWS's documented example key."""

import pytest

from swg import dlp

# Built with a valid Verhoeff check digit; not a real person's number.
AADHAAR = "23456789012" + dlp.verhoeff_digit("23456789012")


def detectors(text):
    return [f.detector for f in dlp.scan_text(text)]


def test_luhn():
    assert dlp.luhn_ok("4111111111111111")
    assert dlp.luhn_ok("79927398713")  # the textbook example
    assert not dlp.luhn_ok("4111111111111112")


def test_verhoeff():
    assert dlp.verhoeff_digit("236") == "3"  # the textbook example
    assert dlp.verhoeff_ok("2363") and not dlp.verhoeff_ok("2364")
    assert dlp.verhoeff_ok(AADHAAR)
    # Verhoeff catches a swap of two adjacent digits, which Luhn can miss.
    swapped = AADHAAR[:3] + AADHAAR[4] + AADHAAR[3] + AADHAAR[5:]
    assert not dlp.verhoeff_ok(swapped)


@pytest.mark.parametrize(
    "number, network",
    [
        ("4111 1111 1111 1111", "visa"),
        ("5555-5555-5555-4444", "mastercard"),
        ("378282246310005", "amex"),
        ("6011111111111117", "discover"),
        ("3530111333300000", "jcb"),
    ],
)
def test_card_numbers_are_found(number, network):
    [finding] = dlp.scan_text(f"pay with {number} please")
    assert finding.detector == "credit_card"
    assert finding.hint == f"{network} ending {number.replace(' ', '').replace('-', '')[-4:]}"


@pytest.mark.parametrize(
    "text",
    [
        "4111 1111 1111 1112",  # fails Luhn
        "1234567812345670",  # passes Luhn, but no card network starts with 12
        "call me on 9876543210",  # phone number
        "order 2026111214305512",  # timestamp-like id, Luhn fails
        "12344111111111111111999",  # a card hidden inside a longer number
        "IMEI 490154203237518",  # Luhn-valid, 15 digits, but not a card prefix
    ],
)
def test_card_false_positives_are_rejected(text):
    assert "credit_card" not in detectors(text)


def test_aadhaar_is_found_in_its_usual_formats():
    spaced = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
    dashed = spaced.replace(" ", "-")
    for text in (AADHAAR, spaced, dashed):
        assert detectors(f"ID: {text}") == ["aadhaar"]


def test_aadhaar_false_positives_are_rejected():
    bad_check = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
    starts_with_one = "1" + AADHAAR[1:]
    mixed = f"{AADHAAR[:4]} {AADHAAR[4:8]}-{AADHAAR[8:]}"  # inconsistent separators
    for text in (bad_check, starts_with_one, mixed, "phone 98765 43210 12"):
        assert "aadhaar" not in detectors(text)


@pytest.mark.parametrize(
    "secret, kind",
    [
        ("AKIAIOSFODNN7EXAMPLE", "aws-access-key"),
        ("ghp_" + "a1B2c3D4e5" * 3 + "a1B2c3", "github-token"),
        ("xoxb-123456789012-abcdefABCDEF", "slack-token"),
        ("sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc", "stripe-secret-key"),
        ("AIza" + "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY", "google-api-key"),
        ("sk-ant-api03-" + "x" * 40, "anthropic-api-key"),
    ],
)
def test_api_keys(secret, kind):
    findings = dlp.scan_text(f'{{"token": "{secret}"}}')
    assert [(f.detector, f.hint) for f in findings][:1] == [("api_key", kind)]


def test_private_key_header():
    assert detectors("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn...") == ["private_key"]
    assert detectors("-----BEGIN PUBLIC KEY-----") == []


def test_findings_never_contain_the_secret():
    for finding in dlp.scan_text("4111111111111111 AKIAIOSFODNN7EXAMPLE " + AADHAAR):
        assert "4111111111111111" not in finding.hint
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.hint
        assert AADHAAR not in finding.hint


def test_form_fields_are_url_decoded():
    body = b"name=x&card=4111%201111%201111%201111"
    parts = dlp.extract_parts(body, "application/x-www-form-urlencoded")
    assert [f.detector for f in dlp.scan_parts(parts)] == ["credit_card"]


def test_multipart_is_split_into_parts():
    body = (
        b"--XyZ\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n"
        b"--XyZ\r\nContent-Disposition: form-data; name=\"file\"; filename=\"keys.txt\"\r\n"
        b"Content-Type: text/plain\r\n\r\nAKIAIOSFODNN7EXAMPLE\r\n--XyZ--\r\n"
    )
    parts = dlp.extract_parts(body, "multipart/form-data; boundary=XyZ")
    assert [(p.name, p.filename) for p in parts] == [("note", None), ("file", "keys.txt")]
    assert parts[1].content_type == "text/plain"
    assert [f.detector for f in dlp.scan_parts(parts)] == ["api_key"]


def test_counts():
    findings = dlp.scan_text("4111111111111111 and 5555555555554444")
    assert dlp.counts(findings) == {"credit_card": 2}
