from core.config import load_config


def test_timeout_env(monkeypatch):
    monkeypatch.setenv("PEN_DEFAULT_TIMEOUT", "12")
    cfg = load_config()
    assert cfg.default_timeout_seconds == 12


def test_production_active_default_false(monkeypatch):
    monkeypatch.delenv("PEN_ALLOW_PRODUCTION_ACTIVE", raising=False)
    cfg = load_config()
    assert cfg.allow_production_active is False
