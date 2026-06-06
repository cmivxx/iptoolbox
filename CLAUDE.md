# ip.pftx.us — IP & DNS Toolbox

Network/IP diagnostic toolbox at https://ip.pftx.us (also serves https://pftx.us).
Single-container Flask app behind the Cloudflare tunnel on **artemis (10.0.0.4)**.

**Stack:** Flask + dnspython + requests + Flask-Limiter + Gunicorn.
**Tests:** pytest, run `python3 -m pytest`.
**Tier:** 1 only (read-only). See vault [[ADR-0001 - IP & DNS Toolbox]].

---

## Design rule that defines this app

**No tool takes a user-supplied outbound destination.** DNS queries go to a
fixed allowlist of public resolvers (`PUBLIC_RESOLVERS`); RDAP goes to
rdap.org. There is therefore no SSRF surface into the LAN, which is why this
runs safely on a LAN-resident host with no egress firewall. **Do not add a
feature that connects to a user-provided host/IP/resolver without moving to
Tier 2 and adding the private-range validation + egress firewall** described in
the ADR.

## Routes

All on the `ip_bp` blueprint in `iptools.py`.

| Path | Purpose |
|---|---|
| `GET /` | Toolbox UI |
| `GET /api/ip`, `/ip` | Client IP + metadata (JSON) |
| `GET /api/ip/plain`, `/plain` | Client IP, raw text (scripts) |
| `GET /api/dns` | DNS records (`name`, `type`, `resolver`) |
| `GET /api/dns/propagation` | Same query across all resolvers |
| `GET /api/dns/reverse` | PTR (`ip`) |
| `GET /api/mail/spf` | SPF + RFC 7208 checks (`domain`) |
| `GET /api/mail/dmarc` | DMARC parse (`domain`) |
| `GET /api/mail/dkim` | DKIM by selector (`domain`, `selector`) |
| `GET /api/mail/mx` | MX analyzer (`domain`) |
| `GET /api/whois` | RDAP (`query` = domain or IP) |
| `GET /api/subnet` | CIDR calculator (`cidr`) — pure compute |
| `GET /healthz` | Health check |

## Conventions (mirrors qrcode.chrisrmiller.com)

- **Whitelist validation:** `_safe_hostname`, `_safe_ip`, `_safe_selector`,
  `_resolver_ip`. New params follow the same reject-don't-trust pattern.
- **Client IP via `CF-Connecting-IP`** — the socket peer is the Cloudflare
  edge, not the user. `_client_ip()` handles this; rate limiting keys on it.
- **Security headers** set globally in `ip_bp.after_request`.
- **Rate limit:** 120/min per client IP (Flask-Limiter, in-memory).
- **JSON envelope:** `{"success": true, ...}` or `{"success": false, "error": ...}`.

## Deploy

Repo lives at the deploy path on artemis (like qrcodegen on opscore). To deploy:
```bash
cd /opt/docker/ip.pftx.us
git pull
docker compose up -d --build
```
Container port 8000 → host **8087**. Published with:
```bash
/opt/docker/scripts/cf-route add ip.pftx.us http://localhost:8087
/opt/docker/scripts/cf-route add pftx.us    http://localhost:8087
```

## Gotchas

- `docker compose restart` does NOT rebuild. Use `up -d --build` after code
  changes (or `--force-recreate` for env changes).
- Cloudflare can cache responses — if the public URL looks stale but the
  container is right (`curl localhost:8087/...`), suspect edge cache.
- Source of truth: GitHub `cmivxx/iptoolbox` → checked out at
  `/opt/docker/ip.pftx.us/` on artemis. Branch `master`.
