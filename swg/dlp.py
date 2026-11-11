"""Data Loss Prevention: find sensitive data in what users upload.

Detectors, each built to keep false positives low:

* `credit_card`: 13-19 digits (spaces or dashes allowed between them) that
  pass the **Luhn** checksum *and* start with a real card-network prefix
  (Visa 4, Mastercard 51-55/2221-2720, Amex 34/37, RuPay 60/65/81/82/508,
  Discover, JCB, Diners). Luhn alone accepts 1 random number in 10; the
  prefix check cuts that further.
* `aadhaar`: 12 digits, not starting with 0 or 1, often written
  `XXXX XXXX XXXX`, whose last digit is a valid **Verhoeff** checksum, the
  check digit scheme UIDAI uses for Aadhaar.
* `api_key`: well-known secret formats (AWS, GitHub, Slack, Stripe, Google,
  OpenAI, Anthropic). These have fixed prefixes, so they're rarely wrong.
* `private_key`: a PEM private-key header.

Findings never contain the secret itself, only a redacted hint (a card's
last four digits, a key's type), because a DLP log that stores what it
caught would itself be a leak.

What gets scanned: the decoded request body. Form fields are URL-decoded,
multipart uploads are split into their parts, and each part is scanned on
its own (`extract_parts`).
"""

from __future__ import annotations

import email.parser
import email.policy
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

from .filetypes import media_type

DETECTORS = ("credit_card", "aadhaar", "api_key", "private_key")

# A digit group must not continue past the match ("1234 5678 ..." inside a
# longer number), so both ends are guarded against digits and "digit + space".
_CARD = re.compile(r"(?<!\d)(?<!\d[ -])(?:\d[ -]?){12,18}\d(?![ -]?\d)")
_AADHAAR = re.compile(r"(?<!\d)(?<!\d[ -])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![ -]?\d)")

_API_KEYS = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("stripe-secret-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}")),
]
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----")


def luhn_ok(digits: str) -> bool:
    """Double every second digit from the right; the total must end in 0."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def card_network(digits: str) -> str | None:
    n = len(digits)
    two, three, four = int(digits[:2]), int(digits[:3]), int(digits[:4])
    if digits[0] == "4" and n in (13, 16, 19):
        return "visa"
    if (51 <= two <= 55 or 2221 <= four <= 2720) and n == 16:
        return "mastercard"
    if two in (34, 37) and n == 15:
        return "amex"
    if (four == 6011 or 644 <= three <= 649 or two == 65) and 16 <= n <= 19:
        return "discover"  # checked before RuPay, whose 60/65 ranges overlap
    if (two in (60, 81, 82) or three == 508) and n == 16:
        return "rupay"
    if 3528 <= four <= 3589 and 16 <= n <= 19:
        return "jcb"
    if (two in (36, 38, 39) or 300 <= three <= 305) and 14 <= n <= 19:
        return "diners"
    return None


# Verhoeff tables: multiplication in the dihedral group D5, and a
# position-dependent permutation. Unlike Luhn, Verhoeff catches every
# single-digit error and every swap of two adjacent digits.
_VD = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VP = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]
_VINV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def verhoeff_ok(digits: str) -> bool:
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VD[check][_VP[i % 8][int(ch)]]
    return check == 0


def verhoeff_digit(digits: str) -> str:
    """The check digit to append to `digits` (used to build test data)."""
    check = 0
    for i, ch in enumerate(reversed(digits)):
        check = _VD[check][_VP[(i + 1) % 8][int(ch)]]
    return str(_VINV[check])


@dataclass
class Finding:
    detector: str
    hint: str  # redacted: "visa ending 1111", "github-token"


@dataclass
class Part:
    """One thing to scan: a form field, an uploaded file, or a whole body."""

    name: str | None
    filename: str | None
    content_type: str | None
    data: bytes


def counts(findings: list[Finding]) -> dict[str, int]:
    """{"credit_card": 2, "api_key": 1}: what the access log records."""
    totals: dict[str, int] = {}
    for f in findings:
        totals[f.detector] = totals.get(f.detector, 0) + 1
    return totals


def scan_text(text: str) -> list[Finding]:
    findings = []
    for match in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        network = card_network(digits)
        if network and luhn_ok(digits):
            findings.append(Finding("credit_card", f"{network} ending {digits[-4:]}"))
    for match in _AADHAAR.finditer(text):
        digits = re.sub(r"[ -]", "", match.group())
        if verhoeff_ok(digits):
            findings.append(Finding("aadhaar", f"12-digit ID ending {digits[-4:]}"))
    for kind, pattern in _API_KEYS:
        for _ in pattern.finditer(text):
            findings.append(Finding("api_key", kind))
    for _ in _PRIVATE_KEY.finditer(text):
        findings.append(Finding("private_key", "PEM private key"))
    return findings


def extract_parts(body: bytes, content_type: str | None) -> list[Part]:
    """Split a request body into the pieces a person would call "the data"."""
    kind = media_type(content_type)
    if kind == "multipart/form-data":
        message = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
            b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body
        )
        if message.is_multipart():
            parts = []
            for part in message.iter_parts():
                payload = part.get_payload(decode=True) or b""
                parts.append(
                    Part(
                        name=part.get_param("name", header="content-disposition"),
                        filename=part.get_filename(),
                        content_type=part.get_content_type() if part.get("Content-Type") else None,
                        data=payload,
                    )
                )
            return parts
        # A truncated or malformed multipart body: fall through, scan it raw.
    if kind == "application/x-www-form-urlencoded":
        text = unquote_plus(body.decode("latin-1"))
        return [Part(None, None, kind, text.encode("utf-8", "replace"))]
    return [Part(None, None, kind, body)]


def scan_parts(parts: list[Part]) -> list[Finding]:
    findings = []
    for part in parts:
        findings.extend(scan_text(part.data.decode("utf-8", "replace")))
    return findings
