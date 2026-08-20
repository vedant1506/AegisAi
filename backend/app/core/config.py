"""
AegisAI — Application Configuration
=====================================
Uses pydantic-settings to load and validate all environment
variables. Import `settings` wherever config values are needed.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App metadata ──────────────────────────────────────────
    app_version: str = "0.1.0"

    # ── Network ───────────────────────────────────────────────
    backend_port: int = 8000
    cors_origins: str = "http://localhost:3000"

    # ── Infrastructure ────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    database_url: str = (
        "postgresql+asyncpg://aegis:changeme@localhost:5432/aegisai"
    )

    # ── AI / LLM ─────────────────────────────────────────────
    ollama_api_base: str = "http://localhost:11434"
    openai_api_key: str = ""
    openai_api_base: str = "https://api.openai.com/v1"

    # ── Security ─────────────────────────────────────────────
    secret_key: str = "change-me-to-a-random-256-bit-secret"


# Singleton instance used throughout the application
settings = Settings()
