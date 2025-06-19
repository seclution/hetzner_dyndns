import os
import sys

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
from backend import app as backend_app


def test_send_ntfy_with_auth(monkeypatch):
    called = {}

    def mock_post(url, headers=None, data=None, auth=None, timeout=None):
        called["auth"] = auth
        return type("R", (), {})()

    monkeypatch.setattr(backend_app.requests, "post", mock_post)
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "NTFY_USERNAME", "user")
    monkeypatch.setattr(backend_app, "NTFY_PASSWORD", "pass")

    backend_app.send_ntfy("t", "m")
    assert called["auth"] == ("user", "pass")


def test_send_ntfy_without_auth(monkeypatch):
    called = {}

    def mock_post(url, headers=None, data=None, auth=None, timeout=None):
        called["auth"] = auth
        return type("R", (), {})()

    monkeypatch.setattr(backend_app.requests, "post", mock_post)
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "NTFY_USERNAME", None)
    monkeypatch.setattr(backend_app, "NTFY_PASSWORD", None)

    backend_app.send_ntfy("t", "m")
    assert called["auth"] is None
