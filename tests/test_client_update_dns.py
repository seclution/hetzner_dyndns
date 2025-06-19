import os, sys; sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from client import update_dns
import pytest


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


def test_main_request_exception(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "http://backend")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("INTERVAL", "0")

    def mock_post(*args, **kwargs):
        raise update_dns.requests.exceptions.RequestException("boom")

    monkeypatch.setattr(update_dns.requests, "post", mock_post)

    with pytest.raises(SystemExit) as excinfo:
        update_dns.main()
    assert excinfo.value.code != 0


def test_main_non_2xx(monkeypatch):
    monkeypatch.setenv("BACKEND_URL", "http://backend")
    monkeypatch.setenv("FQDN", "host.example.com")
    monkeypatch.setenv("INTERVAL", "0")

    class DummyResp:
        status_code = 500
        text = "err"

    monkeypatch.setattr(update_dns.requests, "post", lambda *a, **k: DummyResp())

    with pytest.raises(SystemExit) as excinfo:
        update_dns.main()
    assert excinfo.value.code != 0
