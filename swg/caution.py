"""The caution action: warn first, then let the user continue.

The first request to a site under a caution rule gets a warning page. Its
"Continue" link is the same URL plus a `swg-caution=<expiry>.<signature>`
parameter. When the gateway sees that parameter it checks the signature,
remembers "this user accepted the warning for this host" for a while
(30 minutes by default), and redirects to the URL without the parameter.

The signature is an HMAC over (who, host, expiry) with a secret that only
this gateway process knows, so a user can't forge a "continue" link for a
different site, for someone else, or one that never expires.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from urllib.parse import parse_qsl, urlencode

PARAM = "swg-caution"
LINK_LIFETIME = 10 * 60  # seconds the "Continue" link stays valid


class CautionTracker:
    def __init__(self, accept_minutes: float = 30):
        self.accept_seconds = accept_minutes * 60
        self._secret = secrets.token_bytes(32)
        self._accepted: dict[tuple[str, str], float] = {}  # (who, host) -> until

    def _sign(self, who: str, host: str, expires: int) -> str:
        message = f"{who}|{host}|{expires}".encode()
        return hmac.new(self._secret, message, hashlib.sha256).hexdigest()[:32]

    def token(self, who: str, host: str) -> str:
        expires = int(time.time()) + LINK_LIFETIME
        return f"{expires}.{self._sign(who, host, expires)}"

    def accept(self, who: str, host: str, token: str) -> bool:
        expires_text, _, signature = token.partition(".")
        if not expires_text.isdigit() or int(expires_text) < time.time():
            return False
        if not hmac.compare_digest(signature, self._sign(who, host, int(expires_text))):
            return False
        self._accepted[(who, host)] = time.monotonic() + self.accept_seconds
        return True

    def accepted(self, who: str, host: str) -> bool:
        until = self._accepted.get((who, host))
        if until is None:
            return False
        if until <= time.monotonic():
            del self._accepted[(who, host)]
            return False
        return True


def split_token(path: str) -> tuple[str, str | None]:
    """`/a?x=1&swg-caution=T` -> ("/a?x=1", "T")"""
    base, sep, query = path.partition("?")
    if not sep:
        return path, None
    pairs = parse_qsl(query, keep_blank_values=True)
    token = next((v for k, v in pairs if k == PARAM), None)
    if token is None:
        return path, None
    rest = [(k, v) for k, v in pairs if k != PARAM]
    return (base + ("?" + urlencode(rest) if rest else "")), token


def add_token(url: str, token: str) -> str:
    return url + ("&" if "?" in url else "?") + urlencode({PARAM: token})
