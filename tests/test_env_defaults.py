import importlib
import sys


def test_invalid_int_env_does_not_crash(monkeypatch):
    monkeypatch.setenv("LOG_MAX_BYTES", "bad")
    mod = importlib.reload(sys.modules["hetzner_dyndns.backend.app"])
    assert mod.LOG_MAX_BYTES == 1 * 1024 * 1024
    monkeypatch.delenv("LOG_MAX_BYTES", raising=False)
    importlib.reload(sys.modules["hetzner_dyndns.backend.app"])
