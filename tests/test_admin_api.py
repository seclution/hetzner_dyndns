from hetzner_dyndns.backend import app as backend_app


def setup_admin(monkeypatch):
    monkeypatch.setattr(backend_app, "API_TOKEN", "admintoken")
    monkeypatch.setattr(backend_app, "REGISTERED_FQDNS", [])
    monkeypatch.setattr(backend_app, "PRE_SHARED_KEYS", {})
    monkeypatch.setattr(backend_app, "_write_pre_shared_keys", lambda keys: None)


def test_register_returns_token(monkeypatch):
    setup_admin(monkeypatch)
    client = backend_app.app.test_client()
    resp = client.post(
        "/register",
        json={"fqdn": "host.example.com"},
        headers={"X-Api-Token": "admintoken"},
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert data["fqdn"] == "host.example.com"
    assert backend_app.PRE_SHARED_KEYS["host.example.com"] == data["token"]


def test_get_token(monkeypatch):
    setup_admin(monkeypatch)
    backend_app.PRE_SHARED_KEYS["host.example.com"] = "secret"
    backend_app.REGISTERED_FQDNS.append("host.example.com")
    client = backend_app.app.test_client()
    resp = client.get(
        "/token/host.example.com",
        headers={"X-Api-Token": "admintoken"},
    )
    assert resp.status_code == 200
    assert resp.get_json() == {"fqdn": "host.example.com", "token": "secret"}


def test_reset_token(monkeypatch):
    setup_admin(monkeypatch)
    backend_app.PRE_SHARED_KEYS["host.example.com"] = "old"
    backend_app.REGISTERED_FQDNS.append("host.example.com")
    tokens = {}

    def capture(keys):
        tokens.update(keys)

    monkeypatch.setattr(backend_app, "_write_pre_shared_keys", capture)
    client = backend_app.app.test_client()
    resp = client.post(
        "/reset/host.example.com",
        headers={"X-Api-Token": "admintoken"},
    )
    assert resp.status_code == 200
    new_token = resp.get_json()["token"]
    assert new_token != "old"
    assert tokens["host.example.com"] == new_token
