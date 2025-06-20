import sys
from hetzner_dyndns.client import update_dns
import pytest
import requests


def test_get_verify_option_ca_bundle(monkeypatch):
    monkeypatch.setenv("CA_BUNDLE", "/tmp/bundle.pem")
    monkeypatch.setenv("VERIFY_SSL", "1")
    assert update_dns.get_verify_option() == "/tmp/bundle.pem"


def test_get_verify_option_disable_verify(monkeypatch):
    monkeypatch.delenv("CA_BUNDLE", raising=False)
    monkeypatch.setenv("VERIFY_SSL", "0")
    assert update_dns.get_verify_option() is False


def test_get_verify_option_certifi(monkeypatch):
    monkeypatch.delenv("CA_BUNDLE", raising=False)
    monkeypatch.delenv("VERIFY_SSL", raising=False)

    class DummyCert:
        @staticmethod
        def where():
            return "certifi/path"

    monkeypatch.setattr(update_dns, "certifi", DummyCert)
    assert update_dns.get_verify_option() == "certifi/path"


def test_get_verify_option_default(monkeypatch):
    monkeypatch.delenv("CA_BUNDLE", raising=False)
    monkeypatch.delenv("VERIFY_SSL", raising=False)
    monkeypatch.setattr(update_dns, "certifi", None, raising=False)
    assert update_dns.get_verify_option() is True


def test_invalid_interval_defaults_to_sixty(monkeypatch, capsys):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("INTERVAL", "bad")
    monkeypatch.setenv("PRE_SHARED_KEY", "k")
    monkeypatch.delenv("IP", raising=False)

    called = {}

    class DummyResp:
        status_code = 200
        text = ""

    def mock_post(url, json=None, verify=None, headers=None, timeout=None):
        called["url"] = url
        return DummyResp()

    monkeypatch.setattr(update_dns.requests, "post", mock_post)
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    def fake_sleep(i):
        raise StopIteration()

    monkeypatch.setattr(update_dns.time, "sleep", fake_sleep)

    with pytest.raises(StopIteration):
        update_dns.main()
    assert called["url"] == "http://b/update"
    assert "Invalid INTERVAL" in capsys.readouterr().out


def test_negative_interval_treated_as_zero(monkeypatch, capsys):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("INTERVAL", "-5")
    monkeypatch.setenv("PRE_SHARED_KEY", "k")
    monkeypatch.delenv("IP", raising=False)

    called = {}

    class DummyResp:
        status_code = 200
        text = ""

    def mock_post(url, json=None, verify=None, headers=None, timeout=None):
        called["url"] = url
        return DummyResp()

    monkeypatch.setattr(update_dns.requests, "post", mock_post)
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)
    monkeypatch.setattr(update_dns.time, "sleep", lambda i: called.setdefault("sleep", True))

    update_dns.main()
    assert called["url"] == "http://b/update"
    assert "sleep" not in called


def test_update_dns_request_exception(monkeypatch, capsys):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("PRE_SHARED_KEY", "k")
    monkeypatch.setenv("INTERVAL", "0")
    monkeypatch.delenv("IP", raising=False)

    def mock_post(*args, **kwargs):
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr(update_dns.requests, "post", mock_post)
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    with pytest.raises(SystemExit) as exc:
        update_dns.main()
    assert exc.value.code == 1
    assert "boom" in capsys.readouterr().out


def test_update_dns_non_2xx(monkeypatch, capsys):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("PRE_SHARED_KEY", "k")
    monkeypatch.setenv("INTERVAL", "0")
    monkeypatch.delenv("IP", raising=False)

    class DummyResp:
        def __init__(self):
            self.status_code = 500
            self.text = "fail"

    monkeypatch.setattr(
        update_dns.requests, "post", lambda *a, **k: DummyResp()
    )
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    with pytest.raises(SystemExit) as exc:
        update_dns.main()
    assert exc.value.code == 1
    out = capsys.readouterr().out
    assert "500" in out
    assert "fail" in out


def test_missing_api_key(monkeypatch, capsys):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.delenv("PRE_SHARED_KEY", raising=False)
    monkeypatch.delenv("IP", raising=False)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    with pytest.raises(SystemExit) as exc:
        update_dns.main()
    assert exc.value.code == 1
    assert "PRE_SHARED_KEY not set" in capsys.readouterr().out


def test_update_dns_loops_on_failure(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("PRE_SHARED_KEY", "k")
    monkeypatch.setenv("INTERVAL", "10")
    monkeypatch.delenv("IP", raising=False)

    def mock_post(*args, **kwargs):
        raise requests.exceptions.RequestException("boom")

    monkeypatch.setattr(update_dns.requests, "post", mock_post)
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)

    def fake_sleep(i):
        raise StopIteration()

    monkeypatch.setattr(update_dns.time, "sleep", fake_sleep)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    with pytest.raises(StopIteration):
        update_dns.main()


def test_update_dns_single_run_failure_exits(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("PRE_SHARED_KEY", "k")
    monkeypatch.setenv("INTERVAL", "0")
    monkeypatch.delenv("IP", raising=False)

    class DummyResp:
        status_code = 500
        text = "fail"

    monkeypatch.setattr(update_dns.requests, "post", lambda *a, **k: DummyResp())
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    with pytest.raises(SystemExit) as exc:
        update_dns.main()
    assert exc.value.code == 1
