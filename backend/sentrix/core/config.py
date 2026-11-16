"""Application configuration.

All settings are read from environment variables (or a local ``.env`` file).
Every setting has a safe default so the platform starts without any secrets.
Credentials (LLM API keys, SOAR webhook tokens) are optional and are never
returned by any API endpoint - only their *presence* is reported.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Application ---------------------------------------------------
    app_env: Literal["development", "production", "test"] = "development"
    log_level: str = "INFO"
    host: str = "127.0.0.1"
    port: int = 8000
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Database ------------------------------------------------------
    database_url: str = f"sqlite:///{(BACKEND_DIR / 'sentrix.db').as_posix()}"

    # --- API security --------------------------------------------------
    # When set, every mutating request (POST/PUT/PATCH/DELETE) must carry
    # the header ``X-API-Key: <value>``. Leave empty for local development.
    api_key: SecretStr | None = None

    # --- LLM (optional) ------------------------------------------------
    llm_provider: Literal["none", "openai", "anthropic"] = "none"
    openai_api_key: SecretStr | None = None
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com/v1"
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-sonnet-5-5"
    anthropic_base_url: str = "https://api.anthropic.com"
    llm_timeout_seconds: float = 30.0
    llm_max_tokens: int = 900

    # --- Response execution (optional) ---------------------------------
    # Approved response actions are *dispatched* to this webhook (e.g. a
    # SOAR / ticketing integration). If unset, approved actions are recorded
    # as manual tasks for an analyst to carry out. Nothing is executed
    # automatically against infrastructure by SENTRIX AI itself.
    soar_webhook_url: str | None = None
    soar_webhook_token: SecretStr | None = None

    # --- Detection tuning ----------------------------------------------
    correlation_window_minutes: int = Field(default=60, ge=1, le=1440)
    anomaly_min_baseline_events: int = Field(default=20, ge=5)
    twin_simulation_runs: int = Field(default=300, ge=50, le=5000)

    # --- Council weights (relative; normalised at runtime) -------------
    council_weight_oracle: float = 1.3
    council_weight_behavior: float = 1.0
    council_weight_sentinel: float = 1.1
    council_weight_graph: float = 1.0
    council_weight_twin: float = 1.2
    council_weight_risk: float = 1.0
    council_weight_business: float = 0.9
    council_weight_intel: float = 0.8

    @field_validator("llm_provider", mode="before")
    @classmethod
    def _lower(cls, v: str) -> str:
        return (v or "none").strip().lower()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def council_weights(self) -> dict[str, float]:
        return {
            "Oracle": self.council_weight_oracle,
            "Behavior": self.council_weight_behavior,
            "Sentinel": self.council_weight_sentinel,
            "GraphAI": self.council_weight_graph,
            "DigitalTwin": self.council_weight_twin,
            "Risk": self.council_weight_risk,
            "Business": self.council_weight_business,
            "Intel": self.council_weight_intel,
        }

    @property
    def llm_configured(self) -> bool:
        if self.llm_provider == "openai":
            return bool(self.openai_api_key and self.openai_api_key.get_secret_value())
        if self.llm_provider == "anthropic":
            return bool(self.anthropic_api_key and self.anthropic_api_key.get_secret_value())
        return False


@lru_cache
def get_settings() -> Settings:
    return Settings()
