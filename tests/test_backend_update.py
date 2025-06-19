import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend import app as backend_app
import json

class DummyResp:
    def __init__(self, json_data, status_code=200):
        self._json = json_data
        self.status_code = status_code
        self.ok = status_code == 200
        self.text = json.dumps(json_data)
    def json(self):
        return self._json


def test_update_creates_record(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)

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
    resp = client.post("/update", json={"fqdn": "host.example.com", "ip": "1.2.3.4"})
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "created", "ip": "1.2.3.4"}


def test_update_request_exception(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    called = {}
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: called.setdefault('ntfy', True))

    def mock_get(*args, **kwargs):
        raise backend_app.requests.RequestException("boom")

    monkeypatch.setattr(backend_app.requests, "get", mock_get)

    client = backend_app.app.test_client()
    resp = client.post("/update", json={"fqdn": "host.example.com"})
    assert resp.status_code == 500
    data = resp.get_json()
    assert "error" in data
    assert called.get('ntfy') is True


def test_update_updates_record(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: None)

    def mock_get(url, headers=None, **kwargs):
        if url.endswith("/zones"):
            return DummyResp({"zones": [{"id": "z1", "name": "example.com"}]})
        elif url.startswith("https://dns.hetzner.com/api/v1/records"):
            return DummyResp({"records": [{"id": "r1", "name": "host", "type": "A"}]})
        raise AssertionError("unexpected GET " + url)

    def mock_put(url, headers=None, json=None, **kwargs):
        assert url.endswith("/records/r1")
        return DummyResp({"record": {"id": "r1"}})

    monkeypatch.setattr(backend_app.requests, "get", mock_get)
    monkeypatch.setattr(backend_app.requests, "put", mock_put)

    client = backend_app.app.test_client()
    resp = client.post("/update", json={"fqdn": "host.example.com", "ip": "1.2.3.4"})
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "updated", "ip": "1.2.3.4"}


def test_update_api_failure(monkeypatch):
    monkeypatch.setattr(backend_app, "HETZNER_TOKEN", "token")
    called = {}
    monkeypatch.setattr(backend_app, "send_ntfy", lambda *a, **k: called.setdefault('ntfy', True))

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
    resp = client.post("/update", json={"fqdn": "host.example.com", "ip": "1.2.3.4"})
    assert resp.status_code == 500
    data = resp.get_json()
    assert data.get("error") == "API failure"
    assert "fail" in data.get("detail")
    assert called.get('ntfy') is True
