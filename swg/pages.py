"""HTML pages the gateway generates itself: errors and the info page."""

from __future__ import annotations

import html

_STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f4f5f7;color:#1d2330}
main{max-width:640px;margin:12vh auto;padding:32px;background:#fff;border-radius:12px;
box-shadow:0 1px 3px rgba(0,0,0,.12)}
h1{font-size:22px;margin:0 0 12px}p{line-height:1.5}code{background:#eef0f4;padding:2px 6px;border-radius:4px}
.meta{color:#667085;font-size:13px;margin-top:24px}
"""


def _page(title: str, body_html: str) -> str:
    return (
        "<!doctype html><html lang=en><head><meta charset=utf-8>"
        '<meta name=viewport content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title><style>{_STYLE}</style></head>"
        f"<body><main>{body_html}</main></body></html>"
    )


def error_page(status: int, message: str) -> str:
    # The message can contain client input (a host name, a header), so it
    # is always escaped. An unescaped error page is an XSS bug.
    return _page(
        f"{status} - secure-web-gateway",
        f"<h1>The gateway could not complete this request</h1>"
        f"<p><code>{status}</code> {html.escape(message)}</p>"
        f'<p class="meta">secure-web-gateway</p>',
    )


def info_page() -> str:
    return _page(
        "secure-web-gateway",
        "<h1>secure-web-gateway is running</h1>"
        "<p>This address is an explicit forward proxy. Point your browser or "
        "<code>curl -x</code> at it instead of opening it directly.</p>",
    )
