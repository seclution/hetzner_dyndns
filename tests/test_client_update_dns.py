import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from client import update_dns


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


def test_invalid_interval_defaults_to_zero(monkeypatch, capsys):
    monkeypatch.setenv("BACKEND_URL", "http://b")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("INTERVAL", "bad")
    monkeypatch.delenv("IP", raising=False)

    called = {}

    def mock_post(url, json=None, verify=None, timeout=None):
        called["url"] = url
        return type("R", (), {})()

    monkeypatch.setattr(update_dns.requests, "post", mock_post)
    monkeypatch.setattr(update_dns, "get_verify_option", lambda: True)
    monkeypatch.setattr(sys, "argv", ["update_dns.py"], raising=False)

    update_dns.main()
    assert called["url"] == "http://b/update"
    assert "Invalid INTERVAL" in capsys.readouterr().out
