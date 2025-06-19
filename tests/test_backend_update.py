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
