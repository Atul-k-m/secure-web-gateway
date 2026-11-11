# secure-web-gateway

A small Secure Web Gateway written in Python asyncio: a scaled-down version
of what cloud security proxies such as Zscaler Internet Access do. It is an
explicit forward proxy that logs every request, decrypts HTTPS with its own
CA (except for sites on a Do-Not-Inspect list), checks a URL policy and shows
block pages. It is growing phase by phase into DLP, proxy authentication
against Active Directory, DNS security and PAC-file traffic forwarding.

[`docs/how-it-works.md`](docs/how-it-works.md) explains every protocol step
the gateway takes part in: TCP, HTTP proxying, CONNECT, TLS 1.2/1.3, SNI,
certificate chains, TLS inspection and revocation so far.

## Status

| Phase | What | Status |
|---|---|---|
| 1 | Explicit forward proxy: HTTP (absolute-form) + HTTPS via CONNECT, JSON access log | done |
| 2 | TLS inspection: own root + issuing CA, per-host leaf certs from SNI (cached), origin cert verification, Do-Not-Inspect by domain/category, block pages for HTTP and HTTPS, CRLs | done |
| 3 | YAML policy: users & groups, allow/block/caution, file types, DLP | next |
| 4 | Proxy auth (407) against Samba AD / LDAP, SAML SSO admin page via Keycloak | waiting for Docker |
| 5 | DNS forwarder with DoH upstream and sinkholing | |
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
| `config/policy.yaml` | Do-Not-Inspect domains and categories, URL rules (first match wins) |
| `config/categories.yaml` | URL categories: a small curated seed list of domains |

Typos in these files are reported by name at startup (an unknown key or
category is an error, not ignored). Command-line flags override
`gateway.yaml`: `--host`, `--port`, `--access-log`, `--no-inspect`,
`--quiet`, `--config`.

`ca/` holds the root and issuing CA keys. It is in `.gitignore`. Anyone with
those keys can impersonate any website to a client that trusts the root.

## Tests

```powershell
python -m pytest        # 72 tests, about 25 s
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

## Layout

```
swg/
  proxy.py       the gateway: connection loop, HTTP forwarding, CONNECT, inspection
  certs.py       inspection CA: root, issuing CA, leaf minting and caching, CRLs
  policy.py      categories, Do-Not-Inspect, URL rules
  http1.py       HTTP/1.1 parsing, body framing, hop-by-hop headers
  tlsparse.py    reads SNI and TLS version from ClientHello / ServerHello
  accesslog.py   JSON-lines access log
  pages.py       block, error and certificate-error pages
  settings.py    loads config/gateway.yaml
config/          gateway.yaml, policy.yaml, categories.yaml
tests/           pytest suite
docs/
  how-it-works.md   protocol walkthrough with Wireshark capture points
```

## Results

Measured numbers go here in phase 8: throughput and added latency (p50/p95)
with inspection on and off, and the policy test-suite pass rate. Nothing is
listed until it has been measured.

## License

MIT, see [LICENSE](LICENSE).
