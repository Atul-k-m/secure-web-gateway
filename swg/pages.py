"""HTML pages the gateway generates itself: block pages, errors, info.

A block page is how users find out *why* a site didn't load, and the
transaction ID on it is what they quote in a support ticket. Support can
then find the exact log line with: grep <txn_id> logs/access.log
"""

from __future__ import annotations

import html

from .accesslog import LogEntry

_STYLE = """
:root{color-scheme:light dark;--bg:#f4f5f7;--card:#fff;--ink:#1d2330;--muted:#667085;--line:#e4e7ec;
--accent:#b42318;--code:#eef0f4}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#181b21;--ink:#e6e8ec;--muted:#98a2b3;
--line:#2a2f38;--accent:#f97066;--code:#232832}}
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:var(--bg);color:var(--ink)}
main{max-width:640px;margin:10vh auto;padding:32px;background:var(--card);border-radius:12px;
border:1px solid var(--line)}
@media (max-width:700px){main{margin:16px;padding:20px}}
h1{font-size:22px;margin:0 0 12px}p{line-height:1.5}
code{background:var(--code);padding:2px 6px;border-radius:4px;word-break:break-all}
.tag{display:inline-block;font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;
color:var(--accent);margin-bottom:8px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:20px 0 0;font-size:14px}
dt{color:var(--muted)}dd{margin:0;word-break:break-all}
.meta{color:var(--muted);font-size:13px;margin-top:24px}
"""


def _page(title: str, body_html: str) -> str:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main>{body_html}</main></body></html>"
    )


def _details(rows: list[tuple[str, str | None]]) -> str:
    # Everything shown comes from the request, so everything is escaped.
    # An unescaped block page would be an XSS hole on every blocked site.
    items = "".join(
        f"<dt>{html.escape(label)}</dt><dd>{html.escape(value)}</dd>" for label, value in rows if value
    )
    return f"<dl>{items}</dl>"


def block_page(entry: LogEntry) -> str:
    reason = f"the rule “{entry.rule}”" if entry.rule else "the default policy"
    return _page(
        "Blocked - secure-web-gateway",
        '<div class="tag">Blocked by policy</div>'
        "<h1>This site is blocked</h1>"
        f"<p>Your organisation's web policy blocks this page ({html.escape(reason)}). "
        "If you need it for work, contact support and quote the transaction ID below.</p>"
        + _details(
            [
                ("URL", entry.url),
                ("Category", entry.category or "uncategorized"),
                ("Rule", entry.rule or "default action"),
                ("User", entry.user),
                ("Client IP", entry.client_ip),
                ("Time (UTC)", entry.time),
                ("Transaction ID", entry.txn_id),
            ]
        ),
    )


def caution_page(entry: LogEntry, continue_url: str, minutes: float) -> str:
    return _page(
        "Caution - secure-web-gateway",
        '<div class="tag" style="color:#b54708">Caution</div>'
        "<h1>Are you sure you want to continue?</h1>"
        f"<p>Your organisation's web policy asks you to think twice before using sites in "
        f"the <strong>{html.escape(entry.category or 'uncategorized')}</strong> category. "
        "Activity on this site may be logged.</p>"
        f'<p><a href="{html.escape(continue_url, quote=True)}" '
        'style="display:inline-block;padding:10px 16px;border-radius:8px;background:#1d2330;'
        'color:#fff;text-decoration:none;font-weight:600">Continue to the site</a></p>'
        f"<p class=meta>Continuing allows this site for {minutes:g} minutes.</p>"
        + _details(
            [
                ("URL", entry.url),
                ("Rule", entry.rule),
                ("User", entry.user),
                ("Transaction ID", entry.txn_id),
            ]
        ),
    )


def content_block_page(entry: LogEntry, reason: str) -> str:
    """A block for what's *in* the request or response: file type or DLP."""
    return _page(
        "Blocked - secure-web-gateway",
        '<div class="tag">Blocked by policy</div>'
        "<h1>This transfer was blocked</h1>"
        f"<p>{html.escape(reason[0].upper() + reason[1:])}. Nothing was sent on to the site. "
        "If you need this for work, contact support and quote the transaction ID below.</p>"
        + _details(
            [
                ("URL", entry.url),
                ("Rule", entry.rule or "default action"),
                ("Detected type", entry.file_type),
                ("User", entry.user),
                ("Client IP", entry.client_ip),
                ("Time (UTC)", entry.time),
                ("Transaction ID", entry.txn_id),
            ]
        ),
    )


def error_page(status: int, message: str, entry: LogEntry | None = None) -> str:
    rows: list[tuple[str, str | None]] = [("Status", str(status)), ("Reason", message)]
    if entry is not None:
        rows += [("URL", entry.url), ("Time (UTC)", entry.time), ("Transaction ID", entry.txn_id)]
    return _page(
        f"{status} - secure-web-gateway",
        '<div class="tag">Gateway error</div>'
        "<h1>The gateway could not complete this request</h1>"
        + _details(rows)
        + '<p class="meta">secure-web-gateway</p>',
    )


def origin_certificate_page(message: str, entry: LogEntry) -> str:
    return _page(
        "Untrusted site certificate - secure-web-gateway",
        '<div class="tag">Certificate problem</div>'
        "<h1>This site's certificate could not be verified</h1>"
        "<p>The gateway checks every site's certificate for you, because your browser "
        "only ever sees the gateway's certificate. This one failed, so the page was not "
        "loaded. It may be misconfigured, expired, or someone may be impersonating it.</p>"
        + _details(
            [
                ("URL", entry.url),
                ("Problem", message),
                ("Time (UTC)", entry.time),
                ("Transaction ID", entry.txn_id),
            ]
        ),
    )


def info_page() -> str:
    return _page(
        "secure-web-gateway",
        "<h1>secure-web-gateway is running</h1>"
        "<p>This address is an explicit forward proxy. Point your browser or "
        "<code>curl -x</code> at it instead of opening it directly.</p>",
    )
