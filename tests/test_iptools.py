import pytest

from app import create_app
import iptools


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


# ── validation helpers ───────────────────────────────────────────────────────


@pytest.mark.parametrize("good", ["example.com", "sub.example.co.uk", "a.io", "xn--bcher-kva.com"])
def test_safe_hostname_accepts(good):
    assert iptools._safe_hostname(good) is not None


@pytest.mark.parametrize("bad", ["", None, "-bad.com", "bad-.com", "no_underscore.com",
                                 "a" * 64 + ".com", "has space.com", "http://x.com"])
def test_safe_hostname_rejects(bad):
    assert iptools._safe_hostname(bad) is None


def test_safe_ip():
    assert str(iptools._safe_ip("8.8.8.8")) == "8.8.8.8"
    assert iptools._safe_ip("999.1.1.1") is None
    assert iptools._safe_ip("not-an-ip") is None


def test_resolver_allowlist():
    assert iptools._resolver_ip("google") == "8.8.8.8"
    assert iptools._resolver_ip("bogus") == "1.1.1.1"  # falls back to default
    assert iptools._resolver_ip(None) == "1.1.1.1"


def test_safe_selector():
    assert iptools._safe_selector("google") == "google"
    assert iptools._safe_selector("selector1") == "selector1"
    assert iptools._safe_selector("bad selector") is None
    assert iptools._safe_selector("") is None


# ── routes that need no network ──────────────────────────────────────────────


def test_ip_plain(client):
    r = client.get("/plain", headers={"CF-Connecting-IP": "203.0.113.5"})
    assert r.status_code == 200
    assert r.data.decode().strip() == "203.0.113.5"
    assert r.mimetype == "text/plain"


def test_ip_json_uses_cf_header(client):
    r = client.get("/api/ip", headers={"CF-Connecting-IP": "203.0.113.7", "CF-IPCountry": "US"})
    j = r.get_json()
    assert j["success"] and j["ip"] == "203.0.113.7"
    assert j["version"] == 4 and j["country"] == "US"


def test_subnet_ipv4(client):
    j = client.get("/api/subnet?cidr=192.168.1.0/24").get_json()
    assert j["success"]
    assert j["network_address"] == "192.168.1.0"
    assert j["broadcast_address"] == "192.168.1.255"
    assert j["usable_hosts"] == 254
    assert j["netmask"] == "255.255.255.0"


def test_subnet_invalid(client):
    j = client.get("/api/subnet?cidr=not-a-cidr").get_json()
    assert j["success"] is False


def test_dns_rejects_bad_name(client):
    assert client.get("/api/dns?name=bad name").get_json()["success"] is False


def test_dns_rejects_bad_type(client):
    assert client.get("/api/dns?name=example.com&type=BOGUS").get_json()["success"] is False


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in r.headers


def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200 and r.data.decode().strip() == "ok"


# ── suggestion form ──────────────────────────────────────────────────────────


def test_suggest_valid(client, tmp_path, monkeypatch):
    path = tmp_path / "suggestions.jsonl"
    monkeypatch.setattr(iptools, "SUGGESTIONS_PATH", str(path))
    r = client.post("/api/suggest", json={"email": "a@b.com", "description": "A WHOIS history tool"})
    j = r.get_json()
    assert j["success"] is True
    assert path.read_text().strip()  # a record was written
    assert "A WHOIS history tool" in path.read_text()


def test_suggest_bad_email(client):
    j = client.post("/api/suggest", json={"email": "not-an-email", "description": "x"}).get_json()
    assert j["success"] is False


def test_suggest_missing_description(client):
    j = client.post("/api/suggest", json={"email": "a@b.com", "description": ""}).get_json()
    assert j["success"] is False


def test_suggest_description_too_long(client):
    j = client.post("/api/suggest", json={"email": "a@b.com", "description": "x" * 1001}).get_json()
    assert j["success"] is False


def test_notify_discord_skipped_when_unset(monkeypatch):
    monkeypatch.setattr(iptools, "DISCORD_WEBHOOK_URL", None)
    assert iptools._notify_discord({"email": "a@b.com", "ip": "1.2.3.4",
                                    "description": "x", "ts": "now"}) == "skipped"


def test_notify_discord_posts_when_set(monkeypatch):
    calls = {}

    class FakeResp:
        status_code = 204

    def fake_post(url, json=None, timeout=None):
        calls["url"] = url
        calls["json"] = json
        return FakeResp()

    monkeypatch.setattr(iptools, "DISCORD_WEBHOOK_URL", "https://discord.test/hook")
    monkeypatch.setattr(iptools.requests, "post", fake_post)
    status = iptools._notify_discord({"email": "a@b.com", "ip": "1.2.3.4",
                                      "description": "want X", "ts": "now"})
    assert status == "204"
    assert calls["url"] == "https://discord.test/hook"
    assert calls["json"]["embeds"][0]["fields"][0]["value"] == "a@b.com"
