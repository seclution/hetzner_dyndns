from hetzner_dyndns.backend import app as backend_app
import json


class DummyResp:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.ok = status_code == 200
        self.text = json.dumps(json_data)

    def json(self):
        return self._json


import pytest


@pytest.fixture(autouse=True)
def reset_request_cache(monkeypatch):
    monkeypatch.setattr(backend_app, "REQUEST_CACHE", {})
    monkeypatch.setattr(backend_app, "REQUEST_CACHE_TTL", 3600)

def test_update_requires_api_key(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )
    client = backend_app.app.test_client()
    resp = client.post("/update", json={"fqdn": "host.example.com"})
    assert resp.status_code == 401


def test_update_creates_record(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        assert url.endswith("/records")
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "created", "ip": "1.2.3.4"}


def test_update_request_exception(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    called = {}
    monkeypatch.setattr(
        backend_app,
        "send_ntfy",
        lambda *a, **k: called.setdefault("ntfy", True),
    )
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(*args, **kwargs):
        raise backend_app.requests.RequestException("boom")

    monkeypatch.setattr(backend_app.requests, "get", mock_get)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert called.get("ntfy") is True


def test_update_updates_record(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp(
                {"records": [{"id": "r1", "name": "host", "type": "A"}]}
            )
        raise AssertionError("unexpected GET " + url)

    def mock_put(url, headers=None, json=None, **kwargs):
        assert url.endswith("/records/r1")
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "put", mock_put)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "updated", "ip": "1.2.3.4"}


def test_update_api_failure(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    called = {}
    monkeypatch.setattr(
        backend_app,
        "send_ntfy",
        lambda *a, **k: called.setdefault("ntfy", True),
    )
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        assert url.endswith("/records")
        return DummyResp({"error": "fail"}, status_code=500)

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 500
    data = resp.get_json()
    assert data.get("error") == "API failure"
    assert "fail" in data.get("detail")
    assert called.get("ntfy") is True


def test_invalid_ip(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )
    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "bad-ip"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 400


def test_ipv6_record(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        assert json["type"] == "AAAA"
        assert json["value"] == "2001:db8::1"
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "2001:db8::1", "type": "AAAA"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200


def test_ip_version_mismatch(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )
    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "2001:db8::1"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 400


def test_disallowed_domain(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "ALLOWED_ZONES", ["example.com"])
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.other.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 403


def test_update_multi_level_zone(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp(
                {
                    "zones": [
                        {"id": "z1", "name": "example.com"},
                        {"id": "z2", "name": "example.co.uk"},
                    ]
                }
            )
        elif url.startswith(
            "https://dns.hetzner.com/api/v1/records?zone_id=z2"
        ):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        assert json["zone_id"] == "z2"
        assert json["name"] == "host"
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.co.uk", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "created", "ip": "1.2.3.4"}


def test_root_domain_rejected(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        raise AssertionError("unexpected GET " + url)

    monkeypatch.setattr(backend_app.requests, "get", mock_get)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 400


def test_basic_auth(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "BASIC_AUTH_USERNAME", "u")
    monkeypatch.setattr(backend_app, "BASIC_AUTH_PASSWORD", "p")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    import base64

    cred = base64.b64encode(b"u:p").decode()
    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"Authorization": f"Basic {cred}"},
    )
    assert resp.status_code == 200


def test_nic_update(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "BASIC_AUTH_USERNAME", "u")
    monkeypatch.setattr(backend_app, "BASIC_AUTH_PASSWORD", "p")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    import base64

    cred = base64.b64encode(b"u:p").decode()
    client = backend_app.app.test_client()
    resp = client.get(
        "/nic/update?hostname=host.example.com&myip=1.2.3.4",
        headers={"Authorization": f"Basic {cred}"},
    )
    assert resp.status_code == 200
    assert resp.data.decode().startswith("good ")


def test_nic_update_query_auth(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "BASIC_AUTH_USERNAME", "u")
    monkeypatch.setattr(backend_app, "BASIC_AUTH_PASSWORD", "p")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    def mock_post(url, headers=None, json=None, **kwargs):
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.get(
        "/nic/update?hostname=host.example.com&myip=1.2.3.4&user=u&pass=p",
    )
    assert resp.status_code == 200
    assert resp.data.decode().startswith("good ")


def test_record_ttl_from_env(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(
        backend_app, "ZONE_CACHE", {"zones": None, "expires": 0}
    )
    monkeypatch.setattr(backend_app, "RECORD_TTL", 1234)

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    captured = {}

    def mock_post(url, headers=None, json=None, **kwargs):
        captured["ttl"] = json.get("ttl")
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200
    assert captured["ttl"] == 1234


def test_request_cache_skips_duplicate(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEY", "test")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)
    monkeypatch.setattr(backend_app, "ZONE_CACHE", {"zones": None, "expires": 0})

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": []})
        raise AssertionError("unexpected GET " + url)

    call_count = {"post": 0}

    def mock_post(url, headers=None, json=None, **kwargs):
        call_count["post"] += 1
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "post", mock_post)

    client = backend_app.app.test_client()
    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "created"

    resp = client.post(
        "/update",
        json={"fqdn": "host.example.com", "ip": "1.2.3.4"},
        headers={"X-Pre-Shared-Key": "test"},
    )
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "unchanged"
    assert call_count["post"] == 1
