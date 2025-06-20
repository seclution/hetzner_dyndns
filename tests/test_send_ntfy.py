from hetzner_dyndns.backend import app as backend_app


def test_send_ntfy_with_auth(monkeypatch):
    called = {}

    class DummyResp:
        status_code = 200
        ok = True
        text = ""

    def mock_post(url, headers=None, data=None, auth=None, timeout=None):
        called["auth"] = auth
        return DummyResp()

    monkeypatch.setattr(backend_app.requests, "post", mock_post)
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "NTFY_USERNAME", "user")
    monkeypatch.setattr(backend_app, "NTFY_PASSWORD", "pass")
    monkeypatch.setattr(backend_app, "DEBUG_LOGGING", True)

    backend_app.send_ntfy("t", "m")
    assert called["auth"] == ("user", "pass")


def test_send_ntfy_without_auth(monkeypatch):
    called = {}

    class DummyResp:
        status_code = 200
        ok = True
        text = ""

    def mock_post(url, headers=None, data=None, auth=None, timeout=None):
        called["auth"] = auth
        return DummyResp()

    monkeypatch.setattr(backend_app.requests, "post", mock_post)
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "NTFY_USERNAME", None)
    monkeypatch.setattr(backend_app, "NTFY_PASSWORD", None)
    monkeypatch.setattr(backend_app, "DEBUG_LOGGING", True)

    backend_app.send_ntfy("t", "m")
    assert called["auth"] is None


def test_send_ntfy_logs_error(monkeypatch):
    class DummyResp:
        status_code = 500
        ok = False
        text = "fail"

    monkeypatch.setattr(backend_app.requests, "post", lambda *a, **k: DummyResp())
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "DEBUG_LOGGING", True)

    logs = []
    monkeypatch.setattr(backend_app.app.logger, "error", lambda msg, *a: logs.append(msg % a))

    backend_app.send_ntfy("t", "m", is_error=True)
    assert "500" in logs[0]


def test_send_ntfy_logs_warning(monkeypatch):
    class DummyResp:
        status_code = 500
        ok = False
        text = "fail"

    monkeypatch.setattr(backend_app.requests, "post", lambda *a, **k: DummyResp())
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "DEBUG_LOGGING", True)

    logs = []
    monkeypatch.setattr(backend_app.app.logger, "warning", lambda msg, *a: logs.append(msg % a))

    backend_app.send_ntfy("t", "m")
    assert "500" in logs[0]


def test_send_ntfy_priority(monkeypatch):
    called = {}

    class DummyResp:
        status_code = 200
        ok = True
        text = ""

    def mock_post(url, headers=None, data=None, auth=None, timeout=None):
        called["headers"] = headers
        return DummyResp()

    monkeypatch.setattr(backend_app.requests, "post", mock_post)
    monkeypatch.setattr(backend_app, "NTFY_URL", "http://ntfy")
    monkeypatch.setattr(backend_app, "NTFY_TOPIC", None)
    monkeypatch.setattr(backend_app, "DEBUG_LOGGING", True)

    backend_app.send_ntfy("t", "m", priority=4)
    assert called["headers"]["Priority"] == "4"
