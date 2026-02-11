"""Sentinel configuration management using Pydantic Settings."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # === Application ===
    app_name: str = "Sentinel"
    app_env: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # === LLM Providers ===
    anthropic_api_key: SecretStr = Field(..., description="Anthropic API key for Claude")
    cerebras_api_key: SecretStr = Field(..., description="Cerebras API key")
    openai_api_key: SecretStr | None = Field(None, description="OpenAI API key for embeddings")

    # === Neo4j ===
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: SecretStr = Field(default="sentinel_password")

    # === Temporal ===
    temporal_host: str = "localhost:7233"
    temporal_namespace: str = "default"
    temporal_task_queue: str = "sentinel-tasks"

    # === PostgreSQL (Vector Store) ===
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_user: str = "sentinel"
    postgres_password: SecretStr = Field(default="sentinel_password")
    postgres_db: str = "sentinel"

    @property
    def postgres_dsn(self) -> str:
        """PostgreSQL connection string."""
        return f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password.get_secret_value()}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    # === OWASP ZAP ===
    zap_api_url: str = "http://localhost:8090"
    zap_proxy_url: str = "http://localhost:8080"

    # === Target Configuration ===
    default_target_url: str = "http://localhost:3000"  # Juice Shop

    # === Engagement Scope ===
    max_requests_per_second: int = 10
    max_scan_duration_minutes: int = 120
    require_explicit_authorization: bool = True


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
