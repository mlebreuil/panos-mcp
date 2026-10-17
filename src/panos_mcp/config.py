"""Server settings from environment variables (contracts/configuration.md)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

TLS_WARNING = (
    "TLS certificate verification is DISABLED (PANOS_MCP_VERIFY_TLS=false). "
    "Responses could come from an impersonated Panorama."
)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PANOS_MCP_", extra="ignore")

    host: str | None = None
    api_key: SecretStr | None = None
    username: str | None = None
    password: SecretStr | None = None
    verify_tls: bool = True
    ca_bundle: Path | None = None
    timeout: float = Field(default=30, gt=0)
    query_timeout: float = Field(default=60, gt=0)
    log_limit_max: int = Field(default=1000, ge=1)
    cache_ttl: float = Field(default=30, ge=0)
    max_concurrency: int = Field(default=4, ge=1, le=32)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    samples_scenario: str | None = None
    samples_dir: Path | None = None

    @model_validator(mode="after")
    def _check_connection(self) -> Settings:
        if self.samples_scenario:
            return self
        if not self.host:
            raise ValueError(
                "PANOS_MCP_HOST is required "
                "(or set PANOS_MCP_SAMPLES_SCENARIO for offline demo mode)"
            )
        has_key = self.api_key is not None and self.api_key.get_secret_value() != ""
        has_userpass = bool(self.username) and self.password is not None
        if not has_key and not has_userpass:
            raise ValueError(
                "Set PANOS_MCP_API_KEY, or both PANOS_MCP_USERNAME and PANOS_MCP_PASSWORD"
            )
        return self

    @property
    def offline(self) -> bool:
        return bool(self.samples_scenario)

    def secrets(self) -> list[str]:
        """Secret values that must never appear in output or logs."""
        values = []
        for secret in (self.api_key, self.password):
            if secret is not None and secret.get_secret_value():
                values.append(secret.get_secret_value())
        return values

    def tls_warning(self) -> str | None:
        return None if self.verify_tls else TLS_WARNING


def load_settings() -> Settings:
    """Load settings; on invalid config print a plain-language message and exit 2."""
    env_file = os.environ.get("PANOS_MCP_ENV_FILE")
    try:
        if env_file:
            return Settings(_env_file=env_file)  # type: ignore[call-arg]
        return Settings()
    except ValidationError as exc:
        print("panos-mcp: invalid configuration:", file=sys.stderr)
        for err in exc.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "settings"
            name = f"PANOS_MCP_{loc.upper()}" if loc != "settings" else "settings"
            msg = str(err["msg"]).removeprefix("Value error, ")
            print(f"  - {name}: {msg}", file=sys.stderr)
        raise SystemExit(2) from None
