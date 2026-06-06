"""IP & DNS Toolbox — Tier 1 blueprint.

All tools are read-only: client-IP reflection, DNS lookups against a fixed
allowlist of public resolvers, mail-auth (SPF/DKIM/DMARC) parsing, MX analysis,
RDAP, and pure-compute subnet math. No tool takes a user-supplied outbound
destination, so there is no SSRF surface into the LAN.
"""
import datetime
import ipaddress
import json
import os
import re

import dns.resolver
import dns.reversename
import requests
from flask import Blueprint, jsonify, render_template, request

ip_bp = Blueprint("ip_bp", __name__)

# ── Config ───────────────────────────────────────────────────────────────────

PUBLIC_RESOLVERS = {
    "cloudflare": "1.1.1.1",
    "google": "8.8.8.8",
    "quad9": "9.9.9.9",
}
DEFAULT_RESOLVER = "cloudflare"

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV"]

DNS_TIMEOUT = 3.0
DNS_LIFETIME = 5.0
RDAP_TIMEOUT = 8.0
MAX_NAME_LEN = 253

SUGGESTIONS_PATH = os.environ.get("SUGGESTIONS_PATH", "/app/data/suggestions.jsonl")
MAX_SUGGEST_DESC = 1000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

# ── Validation helpers (whitelist-based) ─────────────────────────────────────


def _safe_hostname(value):
    """Return a normalized hostname or None if invalid."""
    if not value:
        return None
    v = value.strip().rstrip(".").lower()
    if not v or len(v) > MAX_NAME_LEN:
        return None
    try:
        v.encode("idna")
    except (UnicodeError, ValueError):
        return None
    if not _HOSTNAME_RE.match(v):
        return None
    return v


def _safe_ip(value):
    """Return an ipaddress object or None."""
    if not value:
        return None
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        return None


def _safe_selector(value):
    if not value:
        return None
    v = value.strip().lower()
    if re.fullmatch(r"[A-Za-z0-9_-]{1,63}", v):
        return v
    return None


def _resolver_ip(name):
    """Map a resolver name from the fixed allowlist to its IP (default fallback)."""
    return PUBLIC_RESOLVERS.get((name or "").strip().lower(), PUBLIC_RESOLVERS[DEFAULT_RESOLVER])


# ── DNS core ─────────────────────────────────────────────────────────────────


def _make_resolver(server_ip):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [server_ip]
    r.timeout = DNS_TIMEOUT
    r.lifetime = DNS_LIFETIME
    return r


def _query(name, rtype, server_ip):
    """Run a single DNS query. Returns (records, status)."""
    r = _make_resolver(server_ip)
    try:
        ans = r.resolve(name, rtype, raise_on_no_answer=False)
        if ans.rrset is None:
            return [], "no_answer"
        records = sorted(rr.to_text() for rr in ans.rrset)
        return records, "ok"
    except dns.resolver.NXDOMAIN:
        return [], "nxdomain"
    except dns.resolver.NoNameservers:
        return [], "servfail"
    except (dns.resolver.NoAnswer,):
        return [], "no_answer"
    except (dns.exception.Timeout,):
        return [], "timeout"
    except dns.exception.DNSException:
        return [], "error"


# ── Client IP ────────────────────────────────────────────────────────────────


def _client_ip():
    """Real client IP. Behind the Cloudflare tunnel this is CF-Connecting-IP;
    the socket peer would be the CF edge, not the user."""
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf.strip()
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or ""


# ── JSON helpers ─────────────────────────────────────────────────────────────


def _ok(**data):
    return jsonify({"success": True, **data})


def _err(message, code=400):
    return jsonify({"success": False, "error": message}), code


# ── Routes: client IP ────────────────────────────────────────────────────────


@ip_bp.route("/api/ip")
def api_ip():
    ip = _client_ip()
    obj = _safe_ip(ip)
    return _ok(
        ip=ip,
        version=(obj.version if obj else None),
        country=request.headers.get("CF-IPCountry"),
    )


@ip_bp.route("/api/ip/plain")
@ip_bp.route("/plain")
def api_ip_plain():
    return _client_ip() + "\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


@ip_bp.route("/ip")
def api_ip_short():
    return api_ip()


# ── Routes: DNS ──────────────────────────────────────────────────────────────


@ip_bp.route("/api/dns")
def api_dns():
    name = _safe_hostname(request.args.get("name"))
    if not name:
        return _err("Invalid or missing 'name'")
    rtype = (request.args.get("type") or "A").upper()
    if rtype not in RECORD_TYPES:
        return _err(f"Unsupported record type. Allowed: {', '.join(RECORD_TYPES)}")
    server_ip = _resolver_ip(request.args.get("resolver"))
    records, status = _query(name, rtype, server_ip)
    return _ok(name=name, type=rtype, resolver=server_ip, status=status, records=records)


@ip_bp.route("/api/dns/propagation")
def api_dns_propagation():
    name = _safe_hostname(request.args.get("name"))
    if not name:
        return _err("Invalid or missing 'name'")
    rtype = (request.args.get("type") or "A").upper()
    if rtype not in RECORD_TYPES:
        return _err(f"Unsupported record type. Allowed: {', '.join(RECORD_TYPES)}")
    results = {}
    for label, server_ip in PUBLIC_RESOLVERS.items():
        records, status = _query(name, rtype, server_ip)
        results[label] = {"resolver": server_ip, "status": status, "records": records}
    consistent = len({tuple(v["records"]) for v in results.values()}) == 1
    return _ok(name=name, type=rtype, consistent=consistent, results=results)


@ip_bp.route("/api/dns/reverse")
def api_dns_reverse():
    obj = _safe_ip(request.args.get("ip"))
    if not obj:
        return _err("Invalid or missing 'ip'")
    rev = dns.reversename.from_address(str(obj))
    records, status = _query(str(rev), "PTR", PUBLIC_RESOLVERS[DEFAULT_RESOLVER])
    return _ok(ip=str(obj), status=status, records=records)


# ── Routes: mail auth ────────────────────────────────────────────────────────


def _txt_records(name, server_ip):
    records, status = _query(name, "TXT", server_ip)
    # strip surrounding quotes dnspython adds, join split strings
    cleaned = []
    for r in records:
        parts = re.findall(r'"([^"]*)"', r)
        cleaned.append("".join(parts) if parts else r)
    return cleaned, status


@ip_bp.route("/api/mail/spf")
def api_spf():
    domain = _safe_hostname(request.args.get("domain"))
    if not domain:
        return _err("Invalid or missing 'domain'")
    server_ip = PUBLIC_RESOLVERS[DEFAULT_RESOLVER]
    txts, status = _txt_records(domain, server_ip)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    issues = []
    if not spf:
        return _ok(domain=domain, found=False, issues=["No SPF record found"])
    if len(spf) > 1:
        issues.append("Multiple SPF records found (RFC 7208 violation)")
    record = spf[0]
    # count DNS-querying mechanisms toward the 10-lookup limit
    lookup_mechs = re.findall(r"\b(include|a|mx|ptr|exists|redirect)\b[:=]?", record.lower())
    lookups = len(lookup_mechs)
    if lookups > 10:
        issues.append(f"{lookups} DNS-lookup mechanisms exceeds RFC 7208 limit of 10")
    if "ptr" in record.lower():
        issues.append("Uses deprecated 'ptr' mechanism")
    all_match = re.search(r"([~\-+?])all\b", record.lower())
    qualifier = all_match.group(1) if all_match else None
    if qualifier == "+":
        issues.append("'+all' allows any sender — effectively no protection")
    if not all_match:
        issues.append("No 'all' mechanism — record is incomplete")
    return _ok(
        domain=domain,
        found=True,
        record=record,
        dns_lookups=lookups,
        all_qualifier=qualifier,
        issues=issues,
    )


@ip_bp.route("/api/mail/dmarc")
def api_dmarc():
    domain = _safe_hostname(request.args.get("domain"))
    if not domain:
        return _err("Invalid or missing 'domain'")
    server_ip = PUBLIC_RESOLVERS[DEFAULT_RESOLVER]
    txts, status = _txt_records("_dmarc." + domain, server_ip)
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        return _ok(domain=domain, found=False, issues=["No DMARC record found"])
    record = dmarc[0]
    tags = {}
    for pair in record.split(";"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    issues = []
    policy = tags.get("p")
    if policy is None:
        issues.append("Missing required 'p' policy tag")
    elif policy == "none":
        issues.append("Policy is 'none' — monitoring only, no enforcement")
    if "rua" not in tags:
        issues.append("No 'rua' aggregate report address set")
    return _ok(domain=domain, found=True, record=record, tags=tags, policy=policy, issues=issues)


@ip_bp.route("/api/mail/dkim")
def api_dkim():
    domain = _safe_hostname(request.args.get("domain"))
    selector = _safe_selector(request.args.get("selector"))
    if not domain:
        return _err("Invalid or missing 'domain'")
    if not selector:
        return _err("Invalid or missing 'selector' (e.g. 'google', 'default', 'selector1')")
    server_ip = PUBLIC_RESOLVERS[DEFAULT_RESOLVER]
    name = f"{selector}._domainkey.{domain}"
    txts, status = _txt_records(name, server_ip)
    dkim = [t for t in txts if "p=" in t.lower()]
    if not dkim:
        return _ok(domain=domain, selector=selector, found=False,
                   issues=[f"No DKIM record at {name}"])
    record = dkim[0]
    has_key = bool(re.search(r"\bp=([A-Za-z0-9+/=]+)", record))
    issues = [] if has_key else ["Record present but public key (p=) is empty — key revoked"]
    return _ok(domain=domain, selector=selector, found=True, record=record,
               has_key=has_key, issues=issues)


@ip_bp.route("/api/mail/mx")
def api_mx():
    domain = _safe_hostname(request.args.get("domain"))
    if not domain:
        return _err("Invalid or missing 'domain'")
    server_ip = PUBLIC_RESOLVERS[DEFAULT_RESOLVER]
    records, status = _query(domain, "MX", server_ip)
    if not records:
        return _ok(domain=domain, found=False, status=status, hosts=[],
                   issues=["No MX records found"])
    hosts = []
    issues = []
    for r in records:
        parts = r.split()
        if len(parts) != 2:
            continue
        pref, host = int(parts[0]), parts[1].rstrip(".")
        if host == "" or pref == 0 and host == ".":
            issues.append("Null MX (RFC 7505) — domain does not accept mail")
        a, _ = _query(host, "A", server_ip)
        aaaa, _ = _query(host, "AAAA", server_ip)
        if not a and not aaaa:
            issues.append(f"MX host {host} does not resolve to an address")
        hosts.append({"preference": pref, "host": host, "a": a, "aaaa": aaaa})
    hosts.sort(key=lambda h: h["preference"])
    return _ok(domain=domain, found=True, hosts=hosts, issues=issues)


# ── Routes: RDAP (modern whois) ──────────────────────────────────────────────


@ip_bp.route("/api/whois")
def api_whois():
    q = (request.args.get("query") or "").strip()
    ip = _safe_ip(q)
    host = None if ip else _safe_hostname(q)
    if not ip and not host:
        return _err("Provide a valid domain or IP in 'query'")
    url = f"https://rdap.org/{'ip' if ip else 'domain'}/{ip or host}"
    try:
        resp = requests.get(url, timeout=RDAP_TIMEOUT,
                            headers={"Accept": "application/rdap+json"})
    except requests.RequestException:
        return _err("RDAP lookup failed (upstream timeout or error)", 502)
    if resp.status_code == 404:
        return _ok(query=q, found=False)
    if resp.status_code != 200:
        return _err(f"RDAP returned status {resp.status_code}", 502)
    data = resp.json()
    summary = {
        "handle": data.get("handle"),
        "name": data.get("name"),
        "status": data.get("status"),
        "events": {e.get("eventAction"): e.get("eventDate")
                   for e in data.get("events", [])},
        "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
    }
    return _ok(query=q, found=True, type=("ip" if ip else "domain"), summary=summary)


# ── Routes: subnet calculator (pure compute) ─────────────────────────────────


@ip_bp.route("/api/subnet")
def api_subnet():
    cidr = (request.args.get("cidr") or "").strip()
    if not cidr:
        return _err("Missing 'cidr' (e.g. 192.168.1.0/24)")
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError as e:
        return _err(f"Invalid CIDR: {e}")
    hosts = net.num_addresses
    data = {
        "cidr": str(net),
        "version": net.version,
        "network_address": str(net.network_address),
        "netmask": str(net.netmask),
        "prefix_length": net.prefixlen,
        "num_addresses": hosts,
        "is_private": net.is_private,
    }
    if net.version == 4:
        data["broadcast_address"] = str(net.broadcast_address)
        data["wildcard"] = str(net.hostmask)
        if hosts > 2:
            h = list(net.hosts())
            data["first_host"] = str(h[0])
            data["last_host"] = str(h[-1])
            data["usable_hosts"] = hosts - 2
        else:
            data["usable_hosts"] = hosts
    return _ok(**data)


# ── Routes: tool suggestions ─────────────────────────────────────────────────


@ip_bp.route("/api/suggest", methods=["POST"])
def api_suggest():
    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip()
    desc = (data.get("description") or "").strip()
    if not email or len(email) > 254 or not _EMAIL_RE.match(email):
        return _err("Please provide a valid email address")
    if not desc:
        return _err("Please describe the tool you'd like to see")
    if len(desc) > MAX_SUGGEST_DESC:
        return _err(f"Description too long (max {MAX_SUGGEST_DESC} characters)")
    record = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ip": _client_ip(),
        "email": email,
        "description": desc,
    }
    # Log it (flows to central Loki via Fluent Bit) ...
    print("tool_suggestion " + json.dumps(record), flush=True)
    # ... and persist to the mounted data volume.
    try:
        os.makedirs(os.path.dirname(SUGGESTIONS_PATH), exist_ok=True)
        with open(SUGGESTIONS_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass  # already logged above; don't fail the request on storage error
    return _ok(message="Thanks! Your suggestion was received.")


# ── UI + health ──────────────────────────────────────────────────────────────


@ip_bp.route("/")
def index():
    return render_template("index.html")


@ip_bp.route("/healthz")
def healthz():
    return "ok\n", 200, {"Content-Type": "text/plain; charset=utf-8"}


# ── Security headers ─────────────────────────────────────────────────────────


@ip_bp.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
    )
    return resp
