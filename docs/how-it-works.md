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
| [8. Certificate chains and TLS inspection](#8-certificate-chains-and-tls-inspection) | 2 | to do |
| [9. Proxy authentication: HTTP 407](#9-proxy-authentication-http-407) | 4 | to do |
| [10. LDAP bind](#10-ldap-bind) | 4 | to do |
| [11. SAML 2.0 single sign-on](#11-saml-20-single-sign-on) | 4 | to do |
| [12. DNS security](#12-dns-security) | 5 | to do |
| [13. PAC files](#13-pac-files) | 6 | to do |

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
  address, by hand or with a PAC file (section 13). The client knows it is
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
trying it first stalls every request. `open_tcp` uses Happy Eyeballs (RFC 8305):
if the first address hasn't connected after 250 ms, it starts the next one in
parallel. (While building this, `localhost` resolved to `::1` first while the
test server listened only on IPv4. Each HTTPS test waited 2.3 s until Happy
Eyeballs fixed it.)

Code: `open_tcp` in `swg/proxy.py`.

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
itself, not to be forwarded. The gateway answers with an info page. Phase 6
serves the PAC file from the same place (`Gateway._serve_local`).

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

The right-hand column is why SWGs do TLS inspection (phase 2): you can't apply
URL policy, scan downloads or run DLP on bytes you can't read.

### One log line per tunnel

A browser sends many HTTPS requests through one tunnel, but the gateway sees
only the tunnel, so it writes **one log line when the tunnel closes**:

* `duration_ms` is how long the tunnel was open, not one request's time.
* `bytes_in` / `bytes_out` count every TLS byte that crossed it.
* `upstream_latency_ms` is the DNS + TCP connect time to the origin.

After TLS inspection (phase 2), inspected traffic gets one line per HTTPS
request again.

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
(`swg/accesslog.py`). Example, from a real run:

```json
{"time":"2026-11-11T14:24:40.267Z","client_ip":"127.0.0.1","user":null,"method":"CONNECT","host":"example.com","url":"example.com:443","status":200,"category":null,"action":"allow","bytes_in":590,"bytes_out":5801,"upstream_latency_ms":5.93,"duration_ms":193.29,"tls_version":"TLSv1.3","sni":"example.com","error":null}
```

| Field | Meaning |
|---|---|
| `time` | UTC time the request head was fully received |
| `client_ip` | the client's address, as seen by the gateway |
| `user` | authenticated user, from phase 4. `null` until then. |
| `method` | `GET`, `POST`, `CONNECT`, ... |
| `host` | destination host name (lower-cased) |
| `url` | full URL for HTTP, `host:port` for CONNECT tunnels |
| `status` | status the gateway sent to the client (the origin's, or the gateway's own 4xx/5xx) |
| `category` | URL category, from phase 3. `null` until then. |
| `action` | `allow` for now. Phase 3 adds `block` and `caution`. |
| `bytes_in` | bytes the gateway **read from the client** for this request: request line, headers and body as sent on the wire. For a tunnel, every byte the client sent. |
| `bytes_out` | bytes the gateway **wrote to the client**: status line, headers and body |
| `upstream_latency_ms` | HTTP: from starting the origin connection (or reusing one) to receiving the response head, i.e. connect time plus time to first byte. CONNECT: DNS + TCP connect only. |
| `duration_ms` | from request head received to log written. For tunnels, how long the tunnel was open. |
| `tls_version` | version the server chose, from the ServerHello. `null` for plain HTTP. |
| `sni` | server name from the ClientHello. `null` for plain HTTP or IP-only HTTPS. |
| `error` | why a request failed (connect refused, timeout, ...), else `null` |

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

*Written in phase 2.*

## 9. Proxy authentication: HTTP 407

*Written in phase 4.*

## 10. LDAP bind

*Written in phase 4.*

## 11. SAML 2.0 single sign-on

*Written in phase 4.*

## 12. DNS security

*Written in phase 5.*

## 13. PAC files

*Written in phase 6.*
