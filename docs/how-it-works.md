# How the gateway works

This document follows one request from the browser to the origin server and
explains every protocol step the gateway takes part in. Each section maps to
code in `swg/`, so you can read the explanation and the implementation side by
side.

Sections are written as each phase lands:

| Section | Phase | Status |
|---|---|---|
| [1. The big picture](#1-the-big-picture) | 1 | written |
| [2. TCP three-way handshake](#2-tcp-three-way-handshake) | 1 | written |
| [3. Explicit proxy, plain HTTP](#3-explicit-proxy-plain-http) | 1 | written |
| [4. HTTPS through CONNECT](#4-https-through-connect) | 1 | written |
| [5. TLS 1.2 and TLS 1.3 handshakes](#5-tls-12-and-tls-13-handshakes) | 1 | written |
| [6. SNI](#6-sni-server-name-indication) | 1 | written |
| [7. The access log](#7-the-access-log) | 1 | written |
| [8. Certificate chains and TLS inspection](#8-certificate-chains-and-tls-inspection) | 2 | written |
| [9. The policy engine: users, caution, file types, DLP](#9-the-policy-engine-users-caution-file-types-dlp) | 3 | written |
| [10. Proxy authentication: HTTP 407](#10-proxy-authentication-http-407) | 4 | to do |
| [11. LDAP bind](#11-ldap-bind) | 4 | to do |
| [12. SAML 2.0 single sign-on](#12-saml-20-single-sign-on) | 4 | to do |
| [13. DNS security](#13-dns-security) | 5 | to do |
| [14. PAC files](#14-pac-files) | 6 | to do |

## Capturing traffic for the screenshots

Spots marked **[Wireshark screenshot N]** say what to capture and what to
highlight. Save each image as `docs/img/wireshark-NN-<name>.png`, and replace
the marker with `![](img/wireshark-NN-<name>.png)`.

On Windows:

1. Install Wireshark (the installer lets you pick `D:\Program Files\Wireshark`).
   When the Npcap installer runs, tick **"Support loopback traffic"**.
2. Traffic between your browser or curl and the gateway goes over loopback
   (127.0.0.1). Capture it on **"Adapter for loopback traffic capture"**.
3. Traffic between the gateway and the internet goes over your real network
   card. Capture it on Wi-Fi or Ethernet.
4. Wireshark already treats port 3128 as HTTP (it's Squid's port), so it
   decodes the proxy conversation without extra settings.

---

## 1. The big picture

A Secure Web Gateway (SWG) is a proxy that sits between users and the
internet. Every web request goes through it, so it can log the request, check
it against policy, and block it if needed. Zscaler Internet Access is a
cloud-hosted SWG. This project is a small one you run yourself.

```
 browser / curl                gateway (swg)                    origin
 ┌──────────┐   TCP conn #1    ┌────────────┐   TCP conn #2    ┌──────────┐
 │ client   │ ───────────────► │ :3128      │ ───────────────► │ :80/:443 │
 │          │ ◄─────────────── │ log+policy │ ◄─────────────── │          │
 └──────────┘                  └────────────┘                  └──────────┘
```

The key fact: there are **two separate TCP connections**. The client never
talks to the origin directly. Everything below follows from that.

How traffic reaches a SWG:

* **Explicit proxy** (this project): the client is configured with the proxy
  address, by hand or with a PAC file (section 14). The client knows it is
  talking to a proxy and speaks proxy HTTP to it.
* **Transparent / tunnel forwarding**: the network sends traffic to the proxy
  without the client knowing, for example through a GRE or IPsec tunnel from
  the office router, or through an agent on the laptop (Zscaler Client
  Connector). The proxy then has to work out the destination from the packets
  themselves (SNI, Host header).

Code: `swg/proxy.py` is the gateway, `Gateway.handle_client` is where each
client connection starts.

## 2. TCP three-way handshake

Before any HTTP is sent, each TCP connection is opened with three packets:

```
client                                server
  │ ── SYN      seq=x ──────────────────► │   "I want to connect; my numbers start at x"
  │ ◄───────── SYN-ACK seq=y, ack=x+1 ─── │   "OK; mine start at y; I got your x"
  │ ── ACK      ack=y+1 ────────────────► │   "I got your y"
  │          (connection is open)         │
```

The SYN and SYN-ACK also agree on options: MSS (largest segment), window
scaling and SACK (selective acknowledgement).

With a proxy this happens **twice**: client → gateway on port 3128, then
gateway → origin on port 80 or 443. Each handshake costs one round trip on its
own path. That's why the access log records `upstream_latency_ms`, the time
spent on the gateway → origin side, separately from the total.

Closing a connection:

* **FIN** means "I have no more data to send". It closes one direction only.
  The other side can keep sending. This is a *half-close*, and the CONNECT
  relay uses it (section 4).
* **RST** aborts the connection immediately.

What failures look like, and how the gateway reports them:

| On the wire (gateway → origin) | Meaning | Gateway answers |
|---|---|---|
| SYN, then nothing | A firewall is dropping packets, or the host is down | `504 Gateway Timeout` after `connect_timeout` (10 s) |
| SYN, then RST | Nothing is listening on that port | `502 Bad Gateway` ("connection refused") |
| DNS lookup fails | The name doesn't exist | `502 Bad Gateway` ("getaddrinfo failed") |

On Windows a refused connection takes about 2 seconds to report, because
Windows retries the SYN a couple of times after an RST. Linux reports it at
once. The `502` tests in `tests/` take about 2 s each on Windows for this
reason.

A name can resolve to IPv6 and IPv4 addresses. If IPv6 is broken on a network,
trying it first stalls every request. `open_upstream` uses Happy Eyeballs (RFC 8305):
if the first address hasn't connected after 250 ms, it starts the next one in
parallel. (While building this, `localhost` resolved to `::1` first while the
test server listened only on IPv4. Each HTTPS test waited 2.3 s until Happy
Eyeballs fixed it.)

Code: `open_upstream` in `swg/proxy.py`.

> **[Wireshark screenshot 1: TCP handshake to the gateway]**
> Capture on: loopback. Filter: `tcp.port == 3128 && tcp.flags.syn == 1`.
> Run `curl.exe -x http://127.0.0.1:3128 http://example.com/`.
> Highlight the SYN and SYN-ACK packets, with the MSS and window scale options
> expanded.

> **[Wireshark screenshot 2: the second handshake, gateway to origin]**
> Capture on: Wi-Fi/Ethernet. Filter: `tcp.port == 80 && tcp.flags.syn == 1`.
> Same curl command. Shows that the gateway opens its own connection to the
> origin.

## 3. Explicit proxy, plain HTTP

### Absolute-form requests

A normal web server receives the path only (this is *origin-form*):

```http
GET /index.html HTTP/1.1
Host: example.com
```

A client talking to an explicit proxy sends the **whole URL** (this is
*absolute-form*, RFC 9112 section 3.2.2), because the proxy needs to know
where to go:

```http
GET http://example.com/index.html HTTP/1.1
Host: example.com
Proxy-Connection: keep-alive
```

The gateway then:

1. **Parses the URL** into scheme, host, port and path (`parse_absolute_uri`).
   Only `http://` is accepted. HTTPS must arrive as CONNECT (section 4).
2. **Opens TCP to the origin** (`example.com:80`), or reuses an idle connection
   to the same host (`UpstreamPool`).
3. **Rewrites the request** for the origin:
   * The request line goes back to origin-form: `GET /index.html HTTP/1.1`.
   * `Host` is taken from the URL. RFC 9112 says that when the request has an
     absolute URL, its host wins over any `Host` header. Otherwise a client
     could send `GET http://a.com/` with `Host: b.com` and get past a policy
     that checks one but not the other.
   * **Hop-by-hop headers are removed.** They describe one TCP hop, not the
     message: `Connection`, `Proxy-Connection`, `Keep-Alive`, `TE`, `Trailer`,
     `Transfer-Encoding`, `Upgrade`, `Proxy-Authorization`, plus any header
     named inside `Connection:`. `Proxy-Authorization` especially must never
     leak to the origin: it carries the user's proxy password.
   * A `Via: 1.1 swg` header is added, recording that a proxy handled the
     message.
4. **Relays the response** back, with the same hop-by-hop cleanup and its own
   `Via`.

### Body framing

HTTP/1.1 marks where a body ends in one of three ways (RFC 9112 section 6):

| Framing | Header | End of body |
|---|---|---|
| Length | `Content-Length: 1234` | after 1234 bytes |
| Chunked | `Transfer-Encoding: chunked` | after a zero-size chunk |
| Close | neither (responses only) | when the server closes the connection |

Framing is per hop, so the gateway **decodes the body from one side and
re-frames it for the other** (`iter_body` and `BodyWriter` in `swg/http1.py`).
Two cases where that matters:

* The origin ends a body by closing. The gateway re-sends it to an HTTP/1.1
  client as chunked, so the client connection can stay open.
* An HTTP/1.0 client can't read chunked bodies. It gets the raw body, and
  the gateway closes the connection to mark the end.

Later phases need the decoded body too: file-type checks and DLP (phase 3)
look at the bytes, not at the chunk framing.

### Keep-alive and `Expect: 100-continue`

HTTP/1.1 connections stay open by default. A browser sends many requests over
one proxy connection, so `handle_client` loops: read a request, serve it,
read the next. HTTP/1.0 keeps the connection open only if it sends
`Connection: keep-alive`.

Before uploading a large body, curl and other clients send
`Expect: 100-continue` and wait for `HTTP/1.1 100 Continue`. The gateway sends
that answer itself, then forwards the request without the `Expect` header.

### Request-smuggling defenses

If the gateway and the origin disagree on where a request ends, an attacker
can hide a second request inside the first one's body. The gateway refuses
the ambiguous cases with `400`:

* both `Content-Length` and `Transfer-Encoding` on one request
* `Content-Length` values that disagree
* folded header lines (a line that starts with a space)
* a space between a header name and its colon

### Errors the gateway generates

| Status | When |
|---|---|
| `400 Bad Request` | malformed request, `https://` URL without CONNECT, the smuggling cases above |
| `431 Request Header Fields Too Large` | head bigger than 64 KiB, or more than 100 headers |
| `501 Not Implemented` | a transfer-coding other than chunked |
| `502 Bad Gateway` | DNS failure, connection refused, origin closed without answering, garbage status line |
| `504 Gateway Timeout` | no TCP connection to the origin within 10 s |

For support work: a **502** means the gateway reached a verdict (refused, bad
DNS, broken response). A **504** means it waited and gave up, which usually
points at a firewall dropping packets or a route to nowhere.

Error pages HTML-escape everything they show, because the message can contain
client input such as a host name (`pages.error_page`). There is a test for it.

A request in origin-form (`GET / HTTP/1.1`) is addressed to the gateway
itself, not to be forwarded (`Gateway._serve_local`). The gateway serves:

| Path | What |
|---|---|
| `/` | info page |
| `/ca.crt` | the inspection root CA, for installing on a device (section 8.7) |
| `/crl/root.crl`, `/crl/issuing.crl` | certificate revocation lists (section 8.3) |
| `/proxy.pac` | the PAC file (phase 6) |

> **[Wireshark screenshot 3: absolute-form request to the proxy]**
> Capture on: loopback. Filter: `tcp.port == 3128 && http`.
> Run `curl.exe -x http://127.0.0.1:3128 http://example.com/`.
> Right-click the GET, then Follow → HTTP Stream. Highlight
> `GET http://example.com/ HTTP/1.1` and `Proxy-Connection`.

> **[Wireshark screenshot 4: the rewritten request to the origin]**
> Capture on: Wi-Fi/Ethernet. Filter: `http.host == "example.com"`.
> Highlight `GET / HTTP/1.1` (origin-form), the `Via: 1.1 swg` header, and
> that `Proxy-Connection` is gone.

## 4. HTTPS through CONNECT

For `https://` URLs the client asks the proxy for a **tunnel**:

```http
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
```

The target is in *authority-form*: host and port only, no path. The port is
required.

```
client                      gateway                         origin
  │ CONNECT example.com:443 ──► │                               │
  │                             │ ── TCP handshake ───────────► │
  │ ◄─ 200 Connection established                               │
  │ ══ TLS ClientHello ═══════► │ ══ (copied as-is) ══════════► │
  │ ◄═ TLS ServerHello ════════ │ ◄═ (copied as-is) ═══════════ │
  │ ◄═══════════ encrypted bytes, copied both ways ═══════════► │
```

After `200 Connection established` the gateway stops speaking HTTP. It copies
bytes in both directions (`relay` in `swg/proxy.py`) until one side finishes:

* When the client half-closes (FIN), the gateway half-closes towards the
  origin (`write_eof`) and keeps relaying the origin's remaining data back.
* On a reset, or no traffic for `tunnel_idle_timeout` (300 s), it closes both
  sides.

### What the gateway can and can't see in a tunnel

| Visible | Not visible |
|---|---|
| destination host and port (the CONNECT line) | URL path and query string |
| SNI and TLS version (section 6) | request and response headers, cookies |
| bytes each way, timing | request and response bodies |

The right-hand column is why SWGs do TLS inspection (section 8): you can't
apply URL policy, scan downloads or run DLP on bytes you can't read.

### One log line per tunnel

A browser sends many HTTPS requests through one tunnel, but the gateway sees
only the tunnel, so it writes **one log line when the tunnel closes**:

* `duration_ms` is how long the tunnel was open, not one request's time.
* `bytes_in` / `bytes_out` count every TLS byte that crossed it.
* `upstream_latency_ms` is the DNS + TCP connect time to the origin.

With TLS inspection (section 8) the gateway reads the requests inside the
tunnel, so inspected HTTPS gets one line per request, like plain HTTP. Only
tunnels left untouched (inspection off, or Do-Not-Inspect) still log one line
per tunnel.

CONNECT is a generic TCP tunnel. Anything can go through it, for example SSH
on port 22. Real SWGs therefore usually allow CONNECT to port 443 only. This
gateway allows any port for now; port restrictions belong to the policy
engine (phase 3).

> **[Wireshark screenshot 5: CONNECT, then TLS inside the tunnel]**
> Capture on: loopback. Filter: `tcp.port == 3128`.
> Run `curl.exe -x http://127.0.0.1:3128 https://example.com/`.
> Highlight the plaintext `CONNECT example.com:443`, the
> `200 Connection established`, and the TLS ClientHello right after, which
> Wireshark decodes inside the tunnel.

## 5. TLS 1.2 and TLS 1.3 handshakes

TLS sends everything in **records**. Each record starts with a 5-byte header:

| Byte(s) | Field | Values |
|---|---|---|
| 0 | content type | `0x16` handshake, `0x17` application data, `0x15` alert, `0x14` change_cipher_spec |
| 1–2 | legacy version | `0x0301`–`0x0303` |
| 3–4 | length | up to 16 KiB (+ overhead) |

`tlsparse.record_length` checks this header. `read_first_record` uses it to
read exactly one record.

### TLS 1.2 (RFC 5246), with ECDHE key exchange: two round trips

```
Client                                        Server
ClientHello                 -------->
                                         ServerHello
                                         Certificate        <- visible in plaintext
                                         ServerKeyExchange     (ECDHE public key, signed)
                            <--------    ServerHelloDone
ClientKeyExchange                                           <- client's ECDHE public key
ChangeCipherSpec
Finished                    -------->
                                         ChangeCipherSpec
                            <--------    Finished
Application Data            <------->    Application Data
```

### TLS 1.3 (RFC 8446): one round trip

```
Client                                        Server
ClientHello
  + key_share, supported_versions, server_name
                            -------->
                                         ServerHello
                                           + key_share, supported_versions
                                         {EncryptedExtensions}
                                         {Certificate}       <- encrypted
                                         {CertificateVerify}
                            <--------    {Finished}
{Finished}                  -------->
[Application Data]          <------->    [Application Data]

{ } = encrypted with handshake keys, [ ] = encrypted with application keys
```

What changed in 1.3, and why it matters to a SWG:

1. **One round trip instead of two.** The client guesses the key-exchange
   group and sends its `key_share` in the first message. If the server wants
   a different group, it answers with a HelloRetryRequest, which costs one
   extra round trip.
2. **Everything after ServerHello is encrypted, including the server's
   certificate.** In TLS 1.2 a passive firewall could read the certificate to
   identify the site. In 1.3 it can't. Only the SNI (section 6) is left in the
   clear.
3. **RSA key exchange is gone.** Every 1.3 handshake uses (EC)DHE, which gives
   forward secrecy: holding the server's private key does not let anyone
   decrypt recorded traffic. So a SWG can't decrypt TLS by passively watching
   it. It has to terminate TLS itself as a trusted man-in-the-middle, which is
   phase 2.
4. **It disguises itself as TLS 1.2.** Some middleboxes dropped anything that
   wasn't TLS 1.2, so a TLS 1.3 ServerHello says `0x0303` (TLS 1.2) in its
   version field and states the real version in the `supported_versions`
   extension. A TLS 1.3 server also sends a dummy ChangeCipherSpec record.
   `tlsparse.parse_server_hello` reads `supported_versions` for this reason,
   and `test_server_hello_tls13_uses_supported_versions` checks that the
   legacy field really says 1.2.

### How the gateway learns the version without decrypting

The gateway reads the first record from each side of the tunnel, then copies
everything after it unread:

* **ClientHello** gives the SNI and the versions the client *offers*.
* **ServerHello** gives the version the server *chose*. That is what the log
  records as `tls_version`.

If the handshake fails before a ServerHello arrives, `tls_version` stays
`null`. That's a useful clue in a ticket: the server rejected the
ClientHello, or something in between dropped it.

TLS alerts worth recognising in a capture (Wireshark shows them as
`Alert (Level: Fatal, Description: ...)`):

| Alert | Number | Usual meaning |
|---|---|---|
| handshake_failure | 40 | no cipher or version both sides support |
| bad_certificate | 42 | a certificate failed to parse or verify |
| unknown_ca | 48 | the chain doesn't end at a CA the peer trusts. This is what an app sends when it doesn't trust the SWG's inspection CA (phase 2). |
| protocol_version | 70 | the client offered only versions the server refuses |

> **[Wireshark screenshot 6: TLS 1.3 handshake]**
> Capture on: Wi-Fi/Ethernet. Filter: `tls.handshake.type == 1 || tls.handshake.type == 2`.
> Run `curl.exe -x http://127.0.0.1:3128 https://example.com/`.
> In the ServerHello, highlight `Version: TLS 1.2 (0x0303)` *and* the
> `supported_versions` extension saying `TLS 1.3 (0x0304)`.

> **[Wireshark screenshot 7: TLS 1.2 handshake, certificate in the clear]**
> Capture on: Wi-Fi/Ethernet. Filter: `tls.handshake`.
> Run `curl.exe --tls-max 1.2 -x http://127.0.0.1:3128 https://www.cloudflare.com/`.
> Highlight the plaintext Certificate message, which TLS 1.3 encrypts.

To decrypt your *own* browser's TLS in Wireshark, set the environment
variable `SSLKEYLOGFILE=D:\tls-keys.log` before starting Chrome or Firefox.
Then point Wireshark at that file: Preferences → Protocols → TLS →
(Pre)-Master-Secret log filename. Windows' built-in `curl.exe` uses Schannel,
which doesn't write this file.

## 6. SNI (Server Name Indication)

One IP address often hosts hundreds of HTTPS sites, each with its own
certificate. The server has to pick the certificate *before* any HTTP is
sent, so the client names the site it wants inside the ClientHello. That is
the `server_name` extension (RFC 6066), and it travels unencrypted.

How `tlsparse.parse_client_hello` walks the ClientHello to find it:

```
handshake type (1) = 0x01 ClientHello
length (3)
legacy_version (2)
random (32)
session_id        <1-byte length><bytes>
cipher_suites     <2-byte length><2 bytes each>
compression       <1-byte length><bytes>
extensions        <2-byte length>
  type (2) | length (2) | data
  ...
  0x0000 server_name:  list length (2) | name type (1) = 0 | name length (2) | "example.com"
  0x002b supported_versions:  length (1) | versions (2 each)
  0x0010 ALPN:  "h2", "http/1.1"
```

Every variable-length field is prefixed with its length. The parser reads the
length, skips the field, and checks bounds at every step (`_Cursor`), so a
truncated or malicious hello returns `None` instead of crashing. A test cuts a
real ClientHello at dozens of points to check this.

Details:

* **No SNI for IP addresses.** `https://192.0.2.10/` sends no SNI, because
  RFC 6066 allows host names only. Logs then show `sni: null`.
  (`test_ip_literal_has_no_sni`)
* **GREASE.** Chrome adds fake values like `0x0a0a` to version and extension
  lists, so that servers which choke on unknown values get caught early
  (RFC 8701). The parser skips them (`is_grease`).
* **CONNECT host vs SNI.** The log records both `host` (from CONNECT) and
  `sni`. They should match. If a client sends `CONNECT allowed.com:443` with
  SNI `blocked.com`, or the reverse, that is *domain fronting*: one name to
  get past the filter, another to reach the real service. A SWG can block the
  mismatch.
* **Encrypted Client Hello (ECH)** encrypts the real SNI, which blinds
  passive and transparent filters. An explicit proxy like this one still sees
  the host in the plaintext CONNECT line.

> **[Wireshark screenshot 8: the SNI in a ClientHello]**
> Capture on: loopback. Filter: `tls.handshake.extensions_server_name`.
> Expand Extension: server_name → Server Name Indication → `example.com`,
> and show the hex pane, where the name is readable as ASCII.

## 7. The access log

Every request writes one JSON object on one line to `logs/access.log`
(`swg/accesslog.py`). Two real lines, an inspected HTTPS request and a
Do-Not-Inspect tunnel:

```json
{"time":"2026-11-11T17:41:37.844Z","txn_id":"685773d842be","client_ip":"127.0.0.1","user":null,"method":"GET","host":"github.com","url":"https://github.com/","status":200,"category":"developer-tools","rule":null,"action":"allow","inspected":true,"bytes_in":73,"bytes_out":531752,"upstream_latency_ms":378.98,"duration_ms":609.6,"tls_version":"TLSv1.3","sni":"github.com","error":null}
{"time":"2026-11-11T17:42:00.325Z","txn_id":"4e3dd8153f5a","client_ip":"127.0.0.1","user":null,"method":"CONNECT","host":"www.paypal.com","url":"www.paypal.com:443","status":200,"category":"finance","rule":null,"action":"allow","inspected":false,"bytes_in":496,"bytes_out":5693,"upstream_latency_ms":113.62,"duration_ms":2196.21,"tls_version":"TLSv1.3","sni":"www.paypal.com","error":null}
```

| Field | Meaning |
|---|---|
| `time` | UTC time the request head was fully received |
| `txn_id` | random ID for this transaction, also printed on block and error pages. A user quotes it in a ticket; support runs `Select-String <txn_id> logs\access.log`. |
| `client_ip` | the client's address, as seen by the gateway |
| `user` | who made the request: from `config/directory.yaml`'s IP bindings for now, from proxy authentication in phase 4. `null` if unknown. |
| `method` | `GET`, `POST`, `CONNECT`, ... |
| `host` | destination host name (lower-cased) |
| `url` | full URL for HTTP and inspected HTTPS, `host:port` for an untouched tunnel |
| `status` | status the gateway sent to the client (the origin's, or the gateway's own 4xx/5xx) |
| `category` | URL category from `config/categories.yaml`, or `null` if uncategorized |
| `rule` | name of the policy rule that decided, `null` when the default action applied |
| `action` | `allow`, `block`, `caution` (warning page shown) or `caution-accepted` (the user clicked Continue) |
| `inspected` | `true` when the gateway decrypted this HTTPS request (section 8) |
| `file_type` | type of the download or upload, from magic bytes or Content-Type (section 9.4), when a file-type rule made the gateway look |
| `dlp` | for scanned uploads: `{"scanned_bytes": 34, "truncated": false, "matches": {"credit_card": 1}}`. Counts only, never the data. |
| `bytes_in` | bytes the gateway **read from the client** for this request: request line, headers and body. For an inspected request these are the decrypted HTTP bytes. For an untouched tunnel, every TLS byte the client sent. |
| `bytes_out` | bytes the gateway **wrote to the client**: status line, headers and body (decrypted, for inspected requests) |
| `upstream_latency_ms` | HTTP and inspected HTTPS: from starting the origin connection (or reusing one) to receiving the response head, i.e. connect (+ TLS handshake) plus time to first byte. Untouched tunnel: DNS + TCP connect only. |
| `duration_ms` | from request head received to log written. For tunnels, how long the tunnel was open. |
| `tls_version` | untouched tunnel: what the origin chose, from its ServerHello. Inspected: what the client and the gateway negotiated. `null` for plain HTTP. |
| `sni` | server name from the client's ClientHello. `null` for plain HTTP or IP-only HTTPS. |
| `error` | why a request failed (connect refused, timeout, bad origin certificate, client rejected our certificate, ...), else `null` |

Reading the log on Windows without extra tools:

```powershell
# all failed requests
Get-Content logs\access.log | ConvertFrom-Json | Where-Object status -ge 500

# slowest origins
Get-Content logs\access.log | ConvertFrom-Json |
  Sort-Object upstream_latency_ms -Descending | Select-Object -First 5 host, upstream_latency_ms

# TLS versions seen
Get-Content logs\access.log | ConvertFrom-Json | Group-Object tls_version | Select-Object Count, Name
```

With `jq` (Linux, macOS, Git Bash): `jq -c 'select(.status >= 500)' logs/access.log`.

---

## 8. Certificate chains and TLS inspection

### 8.1 Certificate chains

A certificate binds a public key to names. It holds a subject, a list of
names (the **subjectAltName**, SAN), validity dates, the **issuer**'s name,
and the issuer's signature over all of that. A client trusts a certificate if
it can build a **chain** from it up to a root it already trusts:

```
leaf          example.com                         sent by the server
  issued by   Cloudflare TLS Issuing ECC CA 3     sent by the server (intermediate)
  issued by   SSL.com TLS Transit ECC CA R2       sent by the server (intermediate)
  issued by   SSL.com TLS ECC Root CA 2022        already in the client's trust store (root)
```

That is example.com's real chain, from
`openssl s_client -connect example.com:443 -servername example.com`.

For each link, the client checks (RFC 5280, simplified):

1. **Signature:** each certificate is signed by the key of the one above it.
2. **Dates:** now is between `notBefore` and `notAfter`.
3. **CA rights:** every issuer has `BasicConstraints: CA:TRUE` and the
   `keyCertSign` key usage, and the chain isn't longer than its
   `pathLenConstraint` allows.
4. **Name:** the host name matches a SAN entry, a DNS name or an IP address.
   The subject CN is ignored by modern clients.
5. **Purpose:** the leaf's Extended Key Usage includes `serverAuth`.
6. **Revocation:** if the client checks it, no certificate in the chain is
   listed on its CA's CRL (or OCSP says "good"). See 8.3.

The root is never sent; it's a **trust anchor**, already in the client's
store. Common errors and what they mean:

| Error (OpenSSL wording) | Cause |
|---|---|
| `unable to get local issuer certificate` | the chain doesn't reach a trusted root: a missing intermediate, or an unknown root (e.g. the SWG's root isn't installed) |
| `self-signed certificate` | the server sent a root it made itself |
| `certificate has expired` | dates |
| `Hostname mismatch` | no SAN matches the name the client asked for |

The gateway shows all of these to users on its error page. The tests and
the live run above (expired, wrong.host and self-signed badssl.com) produced
exactly these messages.

Code: `tests/test_certs.py` validates minted chains with `cryptography`'s
RFC 5280 path builder, the same checks a browser does.

### 8.2 How inspection works

TLS was built so that nobody in the middle can read it. A SWG reads it
anyway, with the organisation's consent: the organisation installs the
SWG's root CA on its devices, and the SWG then acts as the server towards
the client and as the client towards the server. There are **two separate
TLS sessions**:

```
browser ═══ TLS #1 ═══════════════════► gateway ═══ TLS #2 ══════════════════► origin
        cert: example.com                        cert: the real example.com cert
        issued by SWG Inspection Issuing CA      verified by the gateway against
        (trusted because the root is installed)  the OS trust store
```

Step by step (`Gateway._handle_connect` → `_inspect`):

1. `CONNECT example.com:443` arrives. The policy decides: inspect, or leave
   it alone (Do-Not-Inspect, 8.4)?
2. The gateway answers `200 Connection established`.
3. The client sends its ClientHello. OpenSSL calls the gateway's **SNI
   callback** (`LeafCertCache._on_sni`) with the name from it. The gateway
   looks up a certificate for that name, or mints one, and switches the
   handshake to it. Minting takes **1.96 ms** (median of 300 hosts, p95
   3.64 ms, measured on this Windows laptop); a cache hit takes about 1 µs.
4. The gateway completes the handshake as the server. It offers only
   `http/1.1` in ALPN, so a browser that would use HTTP/2 falls back to 1.1.
5. The client sends HTTP inside TLS #1, and the gateway reads it like plain
   HTTP. The policy runs again for every request, and every request gets its
   own log line with `"inspected": true`.
6. For each request the gateway opens (or reuses) TLS #2 to the origin and
   **verifies the origin's certificate**. The client can no longer see that
   certificate, so the gateway has to reject a bad one on its behalf, with
   the "certificate could not be verified" page.

What the client sees, from
`openssl s_client -proxy 127.0.0.1:3128 -connect example.com:443 -CAfile ca/swg-root-ca.crt -showcerts`:

```
 0 s:CN = example.com
   i:CN = SWG Inspection Issuing CA, O = secure-web-gateway
 1 s:CN = SWG Inspection Issuing CA, O = secure-web-gateway
   i:CN = SWG Inspection Root CA, O = secure-web-gateway
Verify return code: 0 (ok)
```

The gateway's CA (`swg/certs.py`, files in `ca/`):

| | Root CA | Issuing CA | Leaf (minted) |
|---|---|---|---|
| Lifetime | 10 years | 5 years | 30 days, backdated 1 day for clients with slow clocks |
| BasicConstraints | CA, pathlen 1 | CA, pathlen 0 | not a CA |
| Key | EC P-256 | EC P-256 | EC P-256, **one key shared by all leaves** |
| CRL link | none (trust anchor) | `/crl/root.crl` | `/crl/issuing.crl` |
| Where | installed on clients | sent with every leaf | sent to the client |

Why an intermediate: the root key is needed only to create the intermediate,
so in a real deployment it can live offline. Why one shared leaf key:
generating a key pair is the slow part of minting; reusing one makes minting
a single signature. mitmproxy does the same. The price is that the leaf key
and the issuing CA key are as sensitive as the root: anyone who holds them
can impersonate **any** website to every client that trusts the root. That
is why commercial SWGs keep them in hardware security modules.

> **[Wireshark screenshot 9: the minted certificate]**
> Capture on: loopback. Filter: `tls.handshake.type == 11` (Certificate).
> Run `curl.exe --tls-max 1.2 --cacert ca\swg-root-ca.crt -x http://127.0.0.1:3128 https://example.com/`
> (TLS 1.2, so the Certificate message is not encrypted). Expand the
> certificate and highlight issuer `SWG Inspection Issuing CA`, the
> subjectAltName and the CRL Distribution Point.

> **[Wireshark screenshot 10: two TLS sessions for one request]**
> Capture on loopback *and* Wi-Fi together (Capture → Options, select both).
> Filter: `tls.handshake.type == 1`. Same curl command. Show two
> ClientHellos for example.com: one from curl to port 3128, one from the
> gateway to port 443. They are different handshakes with different random
> values.

To decrypt both sessions in Wireshark, start the gateway with
`$env:SSLKEYLOGFILE = "D:\swg-keys.log"; python -m swg`. The gateway writes
the session keys of both TLS legs to that file. Point Wireshark at it
(Preferences → Protocols → TLS → (Pre)-Master-Secret log filename). This is
for debugging only: the file decrypts everything.

> **[Wireshark screenshot 11: decrypted HTTP on both legs]**
> With the key log loaded, filter `http`. Show the same `GET /` once on the
> loopback leg (from curl) and once on the Wi-Fi leg (from the gateway, with
> `Via: 1.1 swg`).

### 8.3 Revocation, and a Windows surprise

A CA can **revoke** a certificate before it expires, for example if its key
leaked. Clients find out through a **CRL** (a signed list of revoked serial
numbers, at a URL named in the certificate's *CRL Distribution Points*
extension) or through **OCSP** (ask a responder about one certificate).

Browsers mostly rely on revocation lists their vendor pushes to them, and
let the connection through if an online check fails. Windows' TLS library
(Schannel) checks revocation whenever the app asks it to, and the built-in
`curl.exe` asks by default. The first version of the gateway minted
certificates without a CRL link, and this happened (real output):

```
> curl.exe --cacert ca\swg-root-ca.crt -x http://127.0.0.1:3128 https://example.com/
curl: (60) schannel: CertGetCertificateChain trust error CERT_TRUST_REVOCATION_STATUS_UNKNOWN
```

The chain was trusted, but Windows couldn't find out whether it was revoked,
and treats "unknown" as a failure. `--ssl-no-revoke` hides the problem; it
doesn't fix it. The fix is what enterprise CAs do: put a CRL Distribution
Point in every certificate below the root, and publish the CRLs. The gateway
serves them itself, at the URL in `gateway_url` (`config/gateway.yaml`):

* the issuing CA's certificate points to `/crl/root.crl`, signed by the root
* every leaf points to `/crl/issuing.crl`, signed by the issuing CA
* both are empty (nothing revoked), valid for 7 days, re-signed hourly

After the change the same command returns 200, and the access log shows
Windows fetching both lists by itself before the request:

```
GET  /crl/root.crl          200
GET  /crl/issuing.crl       200
GET  https://example.com/   200   inspected
```

If the gateway's address changes, the intermediate is re-issued with the new
CRL URL. The root stays the same, so clients don't need to reinstall anything
(`test_crl_links_point_back_at_the_gateway`).

> **[Wireshark screenshot 12: Windows fetching the CRL]**
> Capture on: loopback. Filter: `http.request.uri contains "crl"`.
> Run `certutil -urlcache crl delete` first so Windows hasn't cached the CRL,
> then the curl command above. Highlight the GET for `/crl/issuing.crl` and
> the `application/pkix-crl` response.

### 8.4 Do-Not-Inspect

Some traffic must not be decrypted:

* **Certificate pinning.** The app ships with the certificate or public-key
  hash it expects and refuses anything else, even a certificate from a
  trusted root. Banking apps, messengers (Signal, WhatsApp), and OS update
  and push services do this. Under inspection they simply stop working.
* **Privacy and law.** Many organisations choose not to read banking or
  health traffic.
* **Client certificates (mutual TLS).** The client proves its identity with
  its own certificate and key, which the gateway doesn't have, so TLS #2
  can't present it. Sites that need it must be exempted.

`config/policy.yaml` lists exemptions by domain and by category:

```yaml
ssl_inspection:
  do_not_inspect:
    domains: [signal.org, whatsapp.net, swcdn.apple.com]
    categories: [finance, health]
```

An exempt CONNECT becomes a blind tunnel (section 4), logged with
`"inspected": false`. The client gets the site's real certificate. With
PayPal (category `finance`), the client sees `DigiCert EV RSA CA G2`, not
the gateway's CA.

How a pinning failure shows up in the log, so you know to add an exemption:

| Log `error` | What happened |
|---|---|
| `client rejected the gateway certificate (TLSV1_ALERT_UNKNOWN_CA)` | the client aborted the handshake: its root store lacks our CA, or it pins |
| `client TLS handshake failed (DECRYPTION_FAILED_OR_BAD_RECORD_MAC)` | how a Windows Schannel client that doesn't trust the root looks from the gateway (seen with `curl.exe` before the CA was trusted) |
| `TLS handshake completed but the client sent no request` | the handshake worked, then the app hung up. Many pinning libraries check the pin only *after* the handshake. (An unused browser preconnect looks the same, so look for repeats.) |

> **[Wireshark screenshot 13: a Do-Not-Inspect tunnel keeps the real certificate]**
> Capture on: loopback. Filter: `tls.handshake.type == 11`.
> Run `curl.exe --tls-max 1.2 -x http://127.0.0.1:3128 https://www.paypal.com/`.
> Highlight issuer `DigiCert`, compared with screenshot 9.

### 8.5 Block pages for HTTP and HTTPS

| Traffic | What the gateway can do | What the user sees |
|---|---|---|
| HTTP | answer the request itself with `403` and a block page | the block page |
| HTTPS, inspected | finish TLS with a minted certificate, then answer every request with the block page. The origin is never contacted, not even DNS. | the block page, with a valid padlock |
| HTTPS, not inspected | refuse the CONNECT with `403` | the browser's own error (`ERR_TUNNEL_CONNECTION_FAILED` in Chrome). Browsers don't display a proxy's CONNECT error body. |

The last row is the reason SWGs inspect even sites they're going to block:
without decrypting, they can't explain anything to the user.

A block page shows the URL, category, rule, client IP, time and transaction
ID (`pages.block_page`). Everything on it is HTML-escaped, because the URL is
attacker-controlled; `test_block_page_escapes_the_url` checks it.

> **[Wireshark screenshot 14: HTTPS block page]**
> With `SSLKEYLOGFILE` set as in 8.2, open `https://www.bet365.com/` in a
> browser that trusts the root. Filter `http.response.code == 403`. Show that
> no packet went to bet365's servers: the only DNS or TCP traffic is to the
> gateway.

### 8.6 What inspection changes for the origin

The origin no longer talks to the browser. It talks to the gateway, and
that is visible:

* **Source IP**: the gateway's address.
* **HTTP/1.1** instead of HTTP/2, because of the ALPN restriction.
* **TLS fingerprint.** Bot-detection services fingerprint the ClientHello
  (cipher order, extensions; known as JA3/JA4). Under inspection they see
  the gateway's TLS library, not Chrome's. This broke a real site during
  testing. `www.wikipedia.org` answered `403 Please respect our robot
  policy` through the gateway, even with a browser User-Agent, but `200`
  directly. Varying one thing at a time narrowed it to a single ClientHello
  extension: with `post_handshake_auth` (which Python's own `http.client`
  enables) Wikipedia answered 200, without it 403, twice each. The gateway
  now enables it (`upstream_tls_context`). The lesson for tickets: "the site
  works off-network but not through the SWG", with no certificate error,
  can be bot management reacting to the proxy's fingerprint. The usual fix
  is a Do-Not-Inspect exemption.
* **Host must match the tunnel.** Inside a tunnel opened with
  `CONNECT a.com`, a request with `Host: b.com` gets `421 Misdirected
  Request`. Otherwise a client could get policy checked for one site and
  reach another (domain fronting).
* **WebSockets** (`Upgrade: websocket`, then `101 Switching Protocols`)
  pass through: after the 101 the gateway relays raw bytes both ways, as in
  a tunnel (`Gateway._switch_protocols`).

### 8.7 Installing the root CA

Every client that goes through the gateway with inspection on must trust
`ca/swg-root-ca.crt` (a PEM file). Print its location and fingerprint:

```powershell
python -m swg ca
# root certificate : D:\secure-web-gateway\ca\swg-root-ca.crt
# SHA-256          : 1E:4B:CF:76:...
```

Another device can download it from the running gateway:
`http://<gateway>:3128/ca.crt`. Before trusting it, compare the SHA-256
fingerprint with the one `python -m swg ca` printed. Installing a root CA
lets its owner read that device's HTTPS, so only install one you control.

**Windows** (Chrome, Edge, curl.exe and most apps use the Windows store):

```powershell
# current user, no admin rights needed (Windows asks you to confirm)
certutil -user -addstore Root ca\swg-root-ca.crt
# or the whole machine, from an elevated prompt
certutil -addstore -f Root ca\swg-root-ca.crt
# PowerShell equivalent
Import-Certificate -FilePath ca\swg-root-ca.crt -CertStoreLocation Cert:\CurrentUser\Root

# check, and remove
certutil -user -store Root "SWG Inspection Root CA"
certutil -user -delstore Root "SWG Inspection Root CA"
```

By hand: double-click the `.crt` → Install Certificate → place it in
"Trusted Root Certification Authorities". Companies push the root to every
laptop with Group Policy (Computer Configuration → Windows Settings →
Security Settings → Public Key Policies → Trusted Root Certification
Authorities) or Intune, which is how SWG vendors deploy theirs.

**macOS** (Safari, Chrome and most apps use the System keychain):

```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain swg-root-ca.crt
# check, and remove
security find-certificate -c "SWG Inspection Root CA" -Z /Library/Keychains/System.keychain
sudo security delete-certificate -c "SWG Inspection Root CA" /Library/Keychains/System.keychain
```

By hand: Keychain Access → System keychain → drag the file in →
double-click it → Trust → "When using this certificate: Always Trust".

**Linux** (curl, wget, Python's ssl and most CLI tools read the system bundle):

```bash
# Debian / Ubuntu: the file must end in .crt
sudo cp swg-root-ca.crt /usr/local/share/ca-certificates/swg-root-ca.crt
sudo update-ca-certificates
# remove: delete the file, then
sudo update-ca-certificates --fresh

# RHEL / Fedora / Rocky
sudo cp swg-root-ca.crt /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

**Apps with their own trust store.** These generate most "certificate not
trusted" tickets after a rollout, because installing the root in the OS
doesn't reach them:

| App | How to trust the root |
|---|---|
| Firefox | Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import. Or set `security.enterprise_roots.enabled` to `true` in `about:config` to use the OS store. |
| Python `requests` | uses the `certifi` bundle: set `REQUESTS_CA_BUNDLE=/path/to/bundle.pem`, a bundle that includes the root |
| Node.js | `NODE_EXTRA_CA_CERTS=/path/to/swg-root-ca.crt` |
| Java | `keytool -importcert -cacerts -storepass changeit -alias swg-root -file swg-root-ca.crt` |
| Git for Windows | `git config --global http.sslBackend schannel` (use the Windows store) |
| Docker containers | copy the root into the image and run `update-ca-certificates` in the Dockerfile |

> **[Wireshark screenshot 15: the client refusing an untrusted root]**
> Capture on: loopback. Filter: `tcp.port == 3128 && (tls.alert_message || tcp.flags.reset == 1 || tcp.flags.fin == 1)`.
> Run the curl command from 8.3 *without* `--cacert`, before installing the
> root, with `--tls-max 1.2` so alerts aren't encrypted. Show how the client
> ends the handshake (an alert, or a FIN/RST right after the server's
> Certificate). Then show the gateway's log line for the same attempt.

## 9. The policy engine: users, caution, file types, DLP

### 9.1 Where policy runs in a request

Every check happens at a point where the gateway can still say no. The
order (`Gateway._forward`, stages 1-6) matters:

```
request head ──► 1. URL policy (who + where) ──► block page / caution page / go on
                         │
request body ──► 2. upload check: file type + DLP ──► block page (body never forwarded)
                         │
                 3-4. forward to origin, read the response head
                         │
response body ─► 5. download check: first 512 bytes ──► block page (rest never sent)
                         │
                 6. relay the response to the client
```

Two things follow from that order:

* An upload is checked **before** it is forwarded. The body is buffered
  (up to `max_scan_bytes`), scanned, and only then sent on. A blocked upload
  never reaches the site. A test proves this: the test origin records every
  upload it receives, and blocked ones aren't there. In the live run the
  gateway blocked a card number bound for `postman-echo.com` in 0.9 ms with
  `upstream_latency_ms: null`: it never opened a connection.
* A download is checked on its **first bytes**, before the client gets the
  response head. The gateway reads 512 bytes, decides, and only then starts
  relaying. The 26.5 MB Python installer (`python-3.12.7-amd64.exe`,
  26,538,304 bytes) was blocked in 0.34 s, and the client received 1,911
  bytes, all of them the block page.

None of this can work on a tunnel the gateway doesn't decrypt. File-type and
DLP rules see inspected HTTPS and plain HTTP only. The lint check in 9.6
catches rules that silently can't fire for this reason.

### 9.2 Rules, users and groups

`config/policy.yaml` has three rule lists (`url_filtering`, `file_types`,
`dlp`). Each is checked top to bottom, and **the first matching rule
wins**, as in a firewall. So exceptions go above the rule they carve out of:

```yaml
- name: Engineering may use generative AI      # exception first
  groups: [engineering]
  categories: [generative-ai]
  action: allow
- name: Warn before generative AI              # general rule second
  categories: [generative-ai]
  action: caution
```

Any rule can be narrowed with `users`, `groups`, `domains` and `categories`.
A rule matches when **every field it sets** matches (AND), and a field
matches when **any of its values** does (OR). So
`groups: [contractors], categories: [file-sharing]` means "a contractor AND a
file-sharing site", while `categories: [gambling, security-test]` means
"either category". A rule that sets no fields matches everything.

Who the user is comes from `config/directory.yaml` until phase 4. It's a
stand-in for Active Directory with the same 5 users in 3 groups (engineering:
asha, ravi; finance: meera, kiran; contractors: dev), plus `ip_bindings` that
say which user is behind which client IP. Zscaler calls the same idea an "IP
surrogate": once a user has authenticated, requests from their IP are tied to
them for a while. A client whose IP isn't bound is anonymous, so rules with
`users` or `groups` never match it.

With the shipped policy (`python -m swg check-policy` prints every case):

| | chatgpt.com | dropbox.com | reddit.com | bet365.com |
|---|---|---|---|---|
| asha (engineering) | allow | allow | caution | block |
| meera (finance) | caution | allow | caution | block |
| dev (contractors) | caution | **block** | caution | block |
| anonymous | caution | allow | caution | block |

### 9.3 The caution action

Caution means "warn, then let them through". It's meant for categories that
aren't forbidden but deserve a second thought (social media, generative AI).

1. The first request gets a warning page (`403`). Its **Continue** link is the
   same URL plus `?swg-caution=<expiry>.<signature>`.
2. The signature is an HMAC-SHA256 over *(user, host, expiry)*, keyed with a
   random secret that only this gateway process knows (`swg/caution.py`). A
   user can't forge a link for another site, another user, or a later
   expiry, and a link expires after 10 minutes.
3. When the gateway sees a valid token, it remembers *(user, host)* as
   accepted for `caution_minutes` (30), and answers `302` to the URL without
   the parameter. The origin never sees the token.
4. Requests during those 30 minutes are allowed and logged as
   `caution-accepted`, so the log shows who clicked through.

Live, against `https://www.reddit.com/`:

```
GET https://www.reddit.com/   403  asha  caution            rule=Warn before social media
GET https://www.reddit.com/   302  asha  caution-accepted   (the Continue link)
GET https://www.reddit.com/   200  asha  caution-accepted
```

Why 403 and not 200 for the warning page: a script or API client that hits
a caution page should see a failure, not an HTML page it might parse as the
real answer. Browsers show the page either way.

A caution rule on a Do-Not-Inspect site can't show a page, because there's
no decrypted HTTP to answer. The tunnel is allowed.

> **[Wireshark screenshot 16: the caution redirect]**
> With `SSLKEYLOGFILE` set (8.2), open `https://www.reddit.com/` in a
> browser that trusts the root, and click Continue. Filter
> `http.request.uri contains "swg-caution" || http.response.code == 302`.
> Show the request carrying the token and the gateway's 302. Then show, on
> the Wi-Fi side, that the request reaching reddit has no `swg-caution`
> parameter.

### 9.4 File types: Content-Type and magic bytes

A file's type can be read two ways (`swg/filetypes.py`):

* **Content-Type**, the header: what the sender *says* it is.
* **Magic bytes**, the first few bytes: what it *is*. Formats start with a
  fixed signature.

| Signature (hex) | ASCII | Type |
|---|---|---|
| `4D 5A` | `MZ` | Windows program (.exe, .dll), named after Mark Zbikowski |
| `7F 45 4C 46` | `.ELF` | Linux program |
| `CF FA ED FE` | | macOS program (Mach-O, 64-bit) |
| `D0 CF 11 E0 A1 B1 1A E1` | | OLE2 compound file: .msi, legacy .doc/.xls |
| `50 4B 03 04` | `PK..` | ZIP, and everything that is secretly a ZIP: .docx, .xlsx, .jar, .apk |
| `52 61 72 21 1A 07` | `Rar!..` | RAR |
| `25 50 44 46 2D` | `%PDF-` | PDF |
| `23 21` | `#!` | script with an interpreter line |

The gateway blocks if **either** answer matches a blocked type, and the
bytes win when they disagree. Malware is routinely served as `text/plain` or
`application/octet-stream`, so a filter that trusts the header is easy to get
past. The block page says so: "downloading a windows-executable file (sent
as text/plain) is not allowed".

**Content-Encoding vs Content-Type.** If the server gzip-compresses the
response (`Content-Encoding: gzip`), the first bytes on the wire are gzip's
(`1F 8B`), not the file's. The gateway decompresses the first chunk before
sniffing; a test serves a gzip-encoded .exe to check this. Brotli (`br`)
isn't in Python's standard library, so for brotli-encoded responses only the
Content-Type is checked. That's a known gap, written down rather than hidden.

Uploads are checked the same way, per part: a browser upload is
`multipart/form-data`, a body made of several parts (form fields and files),
each with its own headers. The gateway splits it (`dlp.extract_parts`, using
Python's `email` parser, since multipart is a MIME format) and checks every
file in it. A ZIP renamed to `report.pdf` is still a ZIP.

> **[Wireshark screenshot 17: an executable disguised as text]**
> Decrypted capture (8.2). Fetch an .exe from a server that labels it
> `text/plain` (the test origin does: `/file?kind=exe&ct=text/plain`).
> Highlight `Content-Type: text/plain` in the origin's response and the
> `4D 5A` ("MZ") at the start of its body in the hex pane, then the
> gateway's 403 to the client.

### 9.5 DLP: finding sensitive data in uploads

`swg/dlp.py` scans upload bodies for four kinds of data. The hard part of
DLP isn't finding numbers, it's *not* flagging every long number. Each
detector adds a validity check that random digits rarely pass:

| Detector | Pattern | Validity check |
|---|---|---|
| `credit_card` | 13-19 digits, optional spaces or dashes | **Luhn** checksum *and* a real card-network prefix (Visa 4…, Mastercard 51-55/2221-2720, Amex 34/37, Discover, JCB, RuPay, Diners) |
| `aadhaar` | 12 digits, first digit 2-9, optionally `XXXX XXXX XXXX` with consistent separators | **Verhoeff** checksum, the check-digit scheme UIDAI uses for Aadhaar |
| `api_key` | AWS `AKIA…`, GitHub `ghp_…`, Slack `xoxb-…`, Stripe `sk_live_…`, Google `AIza…`, OpenAI, Anthropic | fixed prefixes and lengths are already specific |
| `private_key` | `-----BEGIN … PRIVATE KEY-----` | |

**Luhn** (cards): from the right, double every second digit (subtract 9 if
that gives more than 9), add everything up; the total must end in 0. For
`4111 1111 1111 1111` the total is 30, so it passes. Change one digit and it
fails. Luhn catches every single-digit typo, but a random number still
passes 1 time in 10, which is why the prefix check is also needed. An IMEI
(phone serial) also uses Luhn; the test suite checks that a Luhn-valid IMEI
isn't reported as a card.

**Verhoeff** (Aadhaar): a check digit built on the dihedral group D5 instead
of addition. It catches every single-digit error *and* every swap of two
adjacent digits, which Luhn misses for 09↔90. The test vector from the
literature: the check digit of `236` is `3`, so `2363` is valid.

Edge cases the detectors handle, each with a test:

* a card number inside a longer digit run (an order ID) isn't reported:
  both ends are guarded against more digits;
* a 10-digit phone number, a Luhn-failing 16-digit number, and an Aadhaar
  with a wrong check digit aren't reported;
* form fields are URL-decoded first (`4111+1111+…` is how a browser sends a
  card typed with spaces), and multipart bodies are split into parts;
* bodies bigger than `max_scan_bytes` (1 MiB) have their first 1 MiB
  scanned and the rest forwarded unscanned, and the log records
  `"truncated": true`. A size limit is a real limitation of every inline DLP.
  It's logged, so it isn't a silent hole.

**What the log keeps.** Only counts and redacted hints: `"matches":
{"credit_card": 1}` in the log, "visa ending 1111" on the block page. A DLP
system that stores what it caught is itself a database of card numbers.

> **[Wireshark screenshot 18: a blocked upload never leaves]**
> Capture loopback and Wi-Fi together, with the key log from 8.2. Run
> `curl.exe --cacert ca\swg-root-ca.crt -x http://127.0.0.1:3128 -d "card=4111 1111 1111 1111" https://postman-echo.com/post`.
> Show the POST arriving on loopback, the gateway's 403, and *no* new
> connection to postman-echo.com on the Wi-Fi side.

### 9.6 Testing the policy itself

`tests/policy_cases.yaml` lists what the shipped policy must decide: 38
cases covering users, groups, caution, Do-Not-Inspect, downloads, uploads and
DLP. Run it any time the policy changes:

```
python -m swg check-policy
...
PASS  Finance may send cards to the payment processor  [allow; Finance may send card numbers to the payment processor]
38/38 cases passed (100.0%)
```

On its first run the suite **failed two cases** and found a real bug in the
policy. `razorpay.com` was in the `finance` category, which is
Do-Not-Inspect, so the rule "Finance may send card numbers to the payment
processor" could never fire. Worse, card numbers from *anyone* went to
Razorpay unscanned. The fix was to move payment processors into their own,
inspected `payments` category. Because the mistake is easy to make,
`Policy.lint()` now warns about it at startup and in `check-policy`:

```
WARNING rule 'cards to razorpay': razorpay.com is never inspected (do_not_inspect category finance), so this rule can't see its HTTPS traffic
```

Mistakes in the YAML itself (an unknown key, action, category, file type or
detector) stop the gateway at startup with a message that names the rule.

## 10. Proxy authentication: HTTP 407

*Written in phase 4.*

## 11. LDAP bind

*Written in phase 4.*

## 12. SAML 2.0 single sign-on

*Written in phase 4.*

## 13. DNS security

*Written in phase 5.*

## 14. PAC files

*Written in phase 6.*
