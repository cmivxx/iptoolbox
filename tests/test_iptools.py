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
