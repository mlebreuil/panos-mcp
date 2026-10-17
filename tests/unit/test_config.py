from __future__ import annotations

import pytest
from pydantic import ValidationError

from panos_mcp.config import Settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    for name in list(os.environ):
        if name.startswith("PANOS_MCP_"):
            monkeypatch.delenv(name)


def test_host_required_unless_offline() -> None:
    with pytest.raises(ValidationError, match="PANOS_MCP_HOST"):
        Settings()
    assert Settings(samples_scenario="baseline").offline


def test_credentials_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PANOS_MCP_HOST", "panorama.example.com")
    with pytest.raises(ValidationError, match="API_KEY"):
        Settings()
    monkeypatch.setenv("PANOS_MCP_USERNAME", "admin")
    monkeypatch.setenv("PANOS_MCP_PASSWORD", "pw")
    assert Settings().username == "admin"


def test_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PANOS_MCP_HOST", "panorama.example.com")
    monkeypatch.setenv("PANOS_MCP_API_KEY", "k")
    s = Settings()
    assert s.verify_tls is True
    assert (s.timeout, s.query_timeout, s.log_limit_max) == (30, 60, 1000)
    assert (s.cache_ttl, s.max_concurrency) == (30, 4)
    assert s.tls_warning() is None


def test_tls_disabled_warns(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PANOS_MCP_HOST", "panorama.example.com")
    monkeypatch.setenv("PANOS_MCP_API_KEY", "k")
    monkeypatch.setenv("PANOS_MCP_VERIFY_TLS", "false")
    assert "DISABLED" in (Settings().tls_warning() or "")


def test_secrets_never_rendered(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PANOS_MCP_HOST", "panorama.example.com")
    monkeypatch.setenv("PANOS_MCP_API_KEY", "TESTKEY-DO-NOT-LEAK")
    monkeypatch.setenv("PANOS_MCP_PASSWORD", "PW-DO-NOT-LEAK")
    s = Settings()
    for rendered in (repr(s), str(s), str(s.model_dump()), s.model_dump_json()):
        assert "TESTKEY-DO-NOT-LEAK" not in rendered
        assert "PW-DO-NOT-LEAK" not in rendered
    assert set(s.secrets()) == {"TESTKEY-DO-NOT-LEAK", "PW-DO-NOT-LEAK"}
