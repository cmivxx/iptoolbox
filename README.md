# IP & DNS Toolbox

A self-hosted network diagnostics toolbox — public-IP reflection, DNS lookups,
mail-auth validation (SPF/DKIM/DMARC), MX analysis, RDAP whois, and a subnet
calculator. Single-container Flask app served behind a Cloudflare tunnel.

**Live:** [ip.pftx.us](https://ip.pftx.us) · also serves [pftx.us](https://pftx.us)

```bash
# The one-liner this was built for:
curl https://ip.pftx.us/plain
```

---

## Features

| Tool | What it does |
|---|---|
| **Public IP** | Your real public IP as JSON or raw text (for scripts) |
| **DNS Lookup** | A/AAAA/CNAME/MX/TXT/NS/SOA/CAA/SRV against Cloudflare, Google, or Quad9 |
| **DNS Propagation** | Runs the same query against all three resolvers and diffs the answers |
| **Reverse DNS** | PTR lookup for an IPv4/IPv6 address |
| **SPF Check** | Parses the SPF record and validates it against RFC 7208 (10-lookup limit, qualifiers, deprecated mechanisms) |
| **DMARC Check** | Parses the `_dmarc` policy record and flags weak/missing settings |
| **DKIM Check** | Looks up a DKIM public key by selector |
| **MX Analyzer** | MX records by priority, each resolved to its A/AAAA addresses, with misconfig flags |
| **WHOIS (RDAP)** | Registration data for a domain or IP via the modern RDAP protocol |
| **Subnet Calculator** | CIDR math — network, broadcast, netmask, wildcard, usable host range |

A single-page web UI at the root exposes every tool; each is also a JSON API.

---

## API

All endpoints return a JSON envelope: `{"success": true, ...}` or
`{"success": false, "error": "..."}`. The two IP endpoints also have raw-text
variants for shell use.

### Public IP

```bash
curl https://ip.pftx.us/plain
# 203.0.113.42

curl https://ip.pftx.us/api/ip
# {"success":true,"ip":"203.0.113.42","version":4,"country":"US"}
```

| Method | Path | Notes |
|---|---|---|
| GET | `/api/ip`, `/ip` | JSON: `ip`, `version`, `country` |
| GET | `/api/ip/plain`, `/plain` | Raw text, trailing newline — ideal for scripts |

> Behind Cloudflare the client IP is read from the `CF-Connecting-IP` header
> (the socket peer is the Cloudflare edge, not the visitor).

### DNS

```bash
curl "https://ip.pftx.us/api/dns?name=example.com&type=MX&resolver=google"
curl "https://ip.pftx.us/api/dns/propagation?name=example.com&type=A"
curl "https://ip.pftx.us/api/dns/reverse?ip=8.8.8.8"
```

| Method | Path | Params |
|---|---|---|
| GET | `/api/dns` | `name` (required), `type` (default `A`), `resolver` (`cloudflare`\|`google`\|`quad9`) |
| GET | `/api/dns/propagation` | `name` (required), `type` (default `A`) |
| GET | `/api/dns/reverse` | `ip` (required) |

### Mail authentication

```bash
curl "https://ip.pftx.us/api/mail/spf?domain=example.com"
curl "https://ip.pftx.us/api/mail/dmarc?domain=example.com"
curl "https://ip.pftx.us/api/mail/dkim?domain=example.com&selector=google"
curl "https://ip.pftx.us/api/mail/mx?domain=example.com"
```

| Method | Path | Params |
|---|---|---|
| GET | `/api/mail/spf` | `domain` |
| GET | `/api/mail/dmarc` | `domain` |
| GET | `/api/mail/dkim` | `domain`, `selector` |
| GET | `/api/mail/mx` | `domain` |

### WHOIS & subnet

```bash
curl "https://ip.pftx.us/api/whois?query=example.com"
curl "https://ip.pftx.us/api/whois?query=8.8.8.8"
curl "https://ip.pftx.us/api/subnet?cidr=10.0.0.0/22"
```

| Method | Path | Params |
|---|---|---|
| GET | `/api/whois` | `query` (domain or IP) |
| GET | `/api/subnet` | `cidr` (e.g. `192.168.1.0/24`) |
| GET | `/healthz` | Health check (`ok`) |

---

## Design & security

**Read-only by design.** No tool accepts a user-supplied outbound destination —
DNS queries go only to a fixed allowlist of public resolvers, and RDAP goes to
`rdap.org`. That means there is **no SSRF surface**, which is why the app can run
safely on a LAN-resident host with no egress firewall.

Other guardrails:

- **Whitelist input validation** — hostnames, IPs, selectors, and resolver
  names are validated/rejected, never trusted.
- **Rate limiting** — 120 requests/min per client IP (keyed on
  `CF-Connecting-IP`).
- **Security headers** — CSP, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy` set on every response.
- **Hard timeouts** on all DNS and RDAP operations.
- **Non-root container** (`appuser`, uid 1001).

> Anything that would connect to a *user-provided* host/IP/resolver (custom-
> resolver lookups, TLS inspection, traceroute) is intentionally **out of
> scope** for this Tier-1 build — adding it requires private-range validation
> and a network egress firewall. See the architecture decision record.

### Known limitations

- **RDAP coverage** — some ccTLDs (e.g. `.us`) have no RDAP server and return
  `found: false`. Legacy port-43 whois would cover them but isn't implemented.

---

## Stack

Flask · Gunicorn · [dnspython](https://www.dnspython.org/) · requests ·
Flask-Limiter · Python 3.12

```
iptools.py            # blueprint: routes, helpers, validation
app.py                # app factory + rate limiter
gunicorn_config.py    # production WSGI config
templates/index.html  # single-page UI
tests/                # pytest suite (23 tests)
Dockerfile
docker-compose.yml
```

---

## Development

```bash
pip install -r requirements.txt
python3 -m pytest          # run the test suite
python3 app.py             # dev server on http://localhost:5050
```

## Deploy

Runs as a single container; the host port is mapped in `docker-compose.yml`
(8087 → 8000) and published through the Cloudflare tunnel.

```bash
git pull
docker compose up -d --build
```

> `docker compose restart` does **not** rebuild after code changes — use
> `up -d --build`.

---

## License

Personal homelab project. Use at your own risk.
