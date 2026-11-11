# secure-web-gateway

A small Secure Web Gateway written in Python asyncio: a scaled-down version
of what cloud security proxies such as Zscaler Internet Access do. It is an
explicit forward proxy that logs every request, and it grows phase by phase
into TLS inspection, URL and DLP policy, proxy authentication against Active
Directory, DNS security and PAC-file traffic forwarding.

[`docs/how-it-works.md`](docs/how-it-works.md) explains every protocol step
the gateway takes part in: TCP, HTTP proxying, CONNECT, TLS 1.2/1.3 and SNI so
far.

## Status

| Phase | What | Status |
|---|---|---|
| 1 | Explicit forward proxy: HTTP (absolute-form) + HTTPS via CONNECT, JSON access log | done |
| 2 | TLS inspection: own root CA, per-host leaf certs from SNI, Do-Not-Inspect list, block pages | next |
| 3 | YAML policy: URL categories, allow/block/caution, users & groups, file types, DLP | |
| 4 | Proxy auth (407) against Samba AD / LDAP, SAML SSO admin page via Keycloak | |
| 5 | DNS forwarder with DoH upstream and sinkholing | |
| 6 | PAC file serving | |
| 7 | docker-compose lab, full test suite, GitHub Actions | |
| 8 | Benchmarks: throughput and added latency, inspection on vs off | |
| 9 | Troubleshooting KB articles | |

## Quick start (Windows, PowerShell)

Requires Python 3.11 or newer. Phase 1 uses the standard library only.

```powershell
cd D:\secure-web-gateway
py -3.11 -m venv .venv            # or py -3.12
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"           # pytest + cryptography, for the tests

python -m swg                     # listens on 127.0.0.1:3128
```

In a second terminal:

```powershell
curl.exe -x http://127.0.0.1:3128 http://example.com/     # plain HTTP, absolute-form
curl.exe -x http://127.0.0.1:3128 https://example.com/    # HTTPS through a CONNECT tunnel
curl.exe -v -x http://127.0.0.1:3128 https://example.com/ # -v shows the CONNECT exchange
```

Each request prints one JSON log line and appends it to `logs/access.log`:

```json
{"time":"2026-11-11T14:24:40.267Z","client_ip":"127.0.0.1","user":null,"method":"CONNECT","host":"example.com","url":"example.com:443","status":200,"category":null,"action":"allow","bytes_in":590,"bytes_out":5801,"upstream_latency_ms":5.93,"duration_ms":193.29,"tls_version":"TLSv1.3","sni":"example.com","error":null}
```

Options: `python -m swg --host 0.0.0.0 --port 8080 --access-log D:\swg.log --quiet`.

### Using it from a browser

Firefox has its own proxy settings, so it can use the gateway without
touching the rest of Windows: Settings → Network Settings → Manual proxy
configuration → HTTP Proxy `127.0.0.1`, Port `3128`, and tick "Also use this
proxy for HTTPS". Browse, then watch `logs/access.log`.

Chrome and Edge use the Windows proxy (Settings → Network & internet →
Proxy). Turn it off when the gateway isn't running, or every site will fail.

## Tests

```powershell
python -m pytest
```

The tests start a local origin server (HTTP and HTTPS with a throwaway CA)
and the gateway on random ports, and drive them with real sockets. Phase 1
covers absolute-form forwarding, header rewriting, Content-Length and chunked
bodies, `Expect: 100-continue`, HTTP/1.0 clients, keep-alive, 502/400 errors,
request-smuggling rejections, error-page escaping, CONNECT tunnels with TLS
1.3, TLS 1.2 and no-SNI handshakes, and the ClientHello/ServerHello parser
against real handshake bytes.

## Layout

```
swg/
  proxy.py       the gateway: connection loop, HTTP forwarding, CONNECT tunnels
  http1.py       HTTP/1.1 parsing, body framing, hop-by-hop headers
  tlsparse.py    reads SNI and TLS version from ClientHello / ServerHello
  accesslog.py   JSON-lines access log
  pages.py       error and info pages
  settings.py    timeouts, ports, paths
tests/           pytest suite (see above)
docs/
  how-it-works.md   protocol walkthrough with Wireshark capture points
```

## Results

Measured numbers go here in phase 8: throughput and added latency (p50/p95)
with inspection on and off, and the policy test-suite pass rate. Nothing is
listed until it has been measured.

## License

MIT, see [LICENSE](LICENSE).
