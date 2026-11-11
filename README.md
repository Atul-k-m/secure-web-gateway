# secure-web-gateway

A small Secure Web Gateway written in Python asyncio: a scaled-down version
of what cloud security proxies such as Zscaler Internet Access do. It is an
explicit forward proxy that logs every request and decrypts HTTPS with its own
CA (except for sites on a Do-Not-Inspect list). It applies a YAML policy per
user and group: allow, caution or block sites; block downloads and uploads by
real file type; and stop uploads that contain card numbers, Aadhaar numbers
or API keys. Next come proxy authentication against Active Directory, DNS
security and PAC-file traffic forwarding.

[`docs/how-it-works.md`](docs/how-it-works.md) explains every protocol step
the gateway takes part in: TCP, HTTP proxying, CONNECT, TLS 1.2/1.3, SNI,
certificate chains, TLS inspection, revocation and the policy engine so far.

## Status

| Phase | What | Status |
|---|---|---|
| 1 | Explicit forward proxy: HTTP (absolute-form) + HTTPS via CONNECT, JSON access log | done |
| 2 | TLS inspection: own root + issuing CA, per-host leaf certs from SNI (cached), origin cert verification, Do-Not-Inspect by domain/category, block pages for HTTP and HTTPS, CRLs | done |
| 3 | YAML policy engine: categories, allow/caution/block per user and group, file types by Content-Type and magic bytes, DLP on uploads (Luhn-checked cards, Verhoeff-checked Aadhaar, API keys), policy test suite + lint | done |
| 4 | Proxy auth (407) against Samba AD / LDAP, SAML SSO admin page via Keycloak | waiting for Docker |
| 5 | DNS forwarder with DoH upstream and sinkholing | next |
| 6 | PAC file serving | |
| 7 | docker-compose lab, full test suite, GitHub Actions | waiting for Docker |
| 8 | Benchmarks: throughput and added latency, inspection on vs off | |
| 9 | Troubleshooting KB articles | |

## Quick start (Windows, PowerShell)

Requires Python 3.11 or newer.

```powershell
cd D:\secure-web-gateway
py -3.11 -m venv .venv            # or py -3.12
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

python -m swg ca                  # create the inspection CA; prints its path and SHA-256
python -m swg                     # listens on 127.0.0.1:3128, TLS inspection on
```

In a second terminal:

```powershell
# plain HTTP
curl.exe -x http://127.0.0.1:3128 http://example.com/

# HTTPS, decrypted by the gateway: tell curl to trust the gateway's root
curl.exe --cacert ca\swg-root-ca.crt -x http://127.0.0.1:3128 https://example.com/

# a blocked site: gets the block page (403), over HTTPS
curl.exe --cacert ca\swg-root-ca.crt -x http://127.0.0.1:3128 https://www.bet365.com/

# a Do-Not-Inspect site (finance): tunnelled untouched, real certificate, no --cacert needed
curl.exe -x http://127.0.0.1:3128 https://www.paypal.com/

# a broken origin certificate: the gateway refuses it for you (502 page)
curl.exe --cacert ca\swg-root-ca.crt -x http://127.0.0.1:3128 https://expired.badssl.com/

# inspection off: every HTTPS site is a blind tunnel, as in phase 1
python -m swg --no-inspect
```

Policy (phase 3). `config/directory.yaml` binds 127.0.0.1 to the user
`asha` (engineering); change it to `dev` to see a contractor's policy.

```powershell
$P = "--cacert", "ca\swg-root-ca.crt", "-x", "http://127.0.0.1:3128"

# caution: a warning page (403) with a Continue link; Continue allows the site for 30 minutes
curl.exe @P https://www.reddit.com/

# a program download from anywhere but GitHub: blocked on its first bytes
curl.exe @P -o NUL -w "%{http_code}\n" https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe

# DLP: a card number in an upload is blocked before it leaves; a clean upload goes through
curl.exe @P -d "card=4111 1111 1111 1111" https://postman-echo.com/post
curl.exe @P -d "comment=hello" https://postman-echo.com/post

# check the policy against its test suite (tests/policy_cases.yaml)
python -m swg check-policy
```

Each request prints one JSON line and appends it to `logs/access.log`:

```json
{"time":"2026-11-11T17:41:37.844Z","txn_id":"685773d842be","client_ip":"127.0.0.1","user":null,"method":"GET","host":"github.com","url":"https://github.com/","status":200,"category":"developer-tools","rule":null,"action":"allow","inspected":true,"bytes_in":73,"bytes_out":531752,"upstream_latency_ms":378.98,"duration_ms":609.6,"tls_version":"TLSv1.3","sni":"github.com","error":null}
```

### Using it from a browser

1. Trust the root CA. For Firefox only (it has its own store): Settings →
   Privacy & Security → Certificates → View Certificates → Authorities →
   Import `ca\swg-root-ca.crt`, and tick "trust this CA to identify
   websites". For Chrome/Edge (Windows store):
   `certutil -user -addstore Root ca\swg-root-ca.crt`. Section 8.7 of
   [how-it-works](docs/how-it-works.md#87-installing-the-root-ca) covers
   Windows, macOS, Linux, and apps with their own stores (Java, Node,
   Python requests).
2. Point the browser at the proxy. Firefox: Settings → Network Settings →
   Manual proxy configuration → HTTP Proxy `127.0.0.1`, Port `3128`, tick
   "Also use this proxy for HTTPS".
3. Browse, and watch `logs/access.log`. Try `https://www.bet365.com/` for a
   block page.

To undo: `certutil -user -delstore Root "SWG Inspection Root CA"`.

## Configuration

| File | What |
|---|---|
| `config/gateway.yaml` | listen address, timeouts, log file, TLS inspection on/off, CA folder, `gateway_url` |
| `config/policy.yaml` | Do-Not-Inspect list, then URL, file-type and DLP rules. In each list the first match wins. Rules can name users, groups, domains and categories. |
| `config/categories.yaml` | URL categories: a small curated seed list of 70 domains in 15 categories |
| `config/directory.yaml` | 5 users in 3 groups, and which client IP is which user (a stand-in for Active Directory until phase 4) |

Typos in these files are reported by name at startup (an unknown key,
action, category, file type or detector is an error, not ignored). Rules
that are valid but can never fire, such as a DLP rule for a Do-Not-Inspect
site, are printed as warnings. Command-line flags override
`gateway.yaml`: `--host`, `--port`, `--access-log`, `--no-inspect`,
`--quiet`, `--config`.

`ca/` holds the root and issuing CA keys. It is in `.gitignore`. Anyone with
those keys can impersonate any website to a client that trusts the root.

## Tests

```powershell
python -m pytest        # 187 tests, under a minute
```

The tests start a local origin (HTTP and HTTPS with a throwaway CA) and the
gateway on random ports, and drive them with real sockets and TLS clients.

- **Phase 1:** forwarding, header rewriting, body framing, keep-alive,
  errors, request-smuggling rejections, CONNECT tunnels and the hello parser.
- **Phase 2:** decryption and re-encryption, the minted chain validated by
  RFC 5280 path building, the certificate cache, SNI-driven certificates,
  421 on Host/tunnel mismatch, Do-Not-Inspect by domain and category, HTTP
  and HTTPS block pages, untrusted-origin pages, clients that reject the
  gateway's root, CRL links and signatures, WebSocket-style upgrades, and
  config validation.
- **Phase 3:** rule semantics (AND across fields, OR within one, first
  match wins), the caution flow end to end (warning, signed Continue link,
  302, per-user acceptance, forged and expired links). Also: programs
  blocked by magic bytes even when labelled `text/plain` or gzip-encoded,
  group and domain exceptions, archive uploads inside multipart, and DLP with
  textbook Luhn/Verhoeff vectors and false-positive cases (phone numbers,
  IMEI, numbers inside longer numbers). Blocked uploads are proven never to
  reach the origin, and over-limit bodies are forwarded intact. Plus the
  38-case policy suite against the shipped config.

## Layout

```
swg/
  proxy.py       the gateway: connection loop, HTTP forwarding, CONNECT, inspection
  certs.py       inspection CA: root, issuing CA, leaf minting and caching, CRLs
  policy.py      the policy engine: categories, Do-Not-Inspect, URL/file-type/DLP rules, lint
  directory.py   users and groups (stand-in for AD until phase 4)
  caution.py     caution pages: signed Continue links, per-user acceptance
  filetypes.py   file type from Content-Type and magic bytes
  dlp.py         card / Aadhaar / API-key / private-key detectors, multipart parsing
  policytest.py  runs tests/policy_cases.yaml (python -m swg check-policy)
  http1.py       HTTP/1.1 parsing, body framing, hop-by-hop headers
  tlsparse.py    reads SNI and TLS version from ClientHello / ServerHello
  accesslog.py   JSON-lines access log
  pages.py       block, error and certificate-error pages
  settings.py    loads config/gateway.yaml
config/          gateway.yaml, policy.yaml, categories.yaml, directory.yaml
tests/           pytest suite; policy_cases.yaml is the policy test suite
docs/
  how-it-works.md   protocol walkthrough with Wireshark capture points
```

## Results

Measured numbers go here in phase 8: throughput and added latency (p50/p95)
with inspection on and off, and the policy test-suite pass rate. Nothing is
listed until it has been measured.

## License

MIT, see [LICENSE](LICENSE).
