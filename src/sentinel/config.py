"""Configuration management using Pydantic settings."""

from typing import Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Cerebras API
    cerebras_api_key: str = Field(..., description="Cerebras API key")
    cerebras_base_url: str = Field(
        default="https://api.cerebras.ai/v1",
        description="Cerebras API base URL",
    )

    # Model selection
    primary_model: str = Field(
        default="zai-glm-4.7",
        description="Primary model for agents (GLM-4.7)",
    )
    fallback_model: str = Field(
        default="gpt-oss-120b",
        description="Fallback model for high-volume tasks",
    )
    router_model: str = Field(
        default="llama3.1-8b",
        description="Fast model for routing/classification",
    )

    # Generation settings
    default_temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=2.0,
        description="Default sampling temperature",
    )
    default_max_tokens: int = Field(
        default=4096,
        ge=1,
        le=200000,
        description="Default max tokens in response",
    )
    tool_call_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Timeout for tool execution in seconds",
    )
    max_tool_iterations: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Max iterations in tool loop",
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    log_format: Literal["json", "console"] = Field(
        default="json",
        description="Log output format",
    )

    @field_validator("primary_model", "fallback_model", "router_model")
    @classmethod
    def validate_model_not_deprecated(cls, v: str) -> str:
        """Ensure deprecated models are not used."""
        if v == "llama-3.3-70b":
            raise ValueError(
                "llama-3.3-70b is deprecated as of Feb 16 2026. "
                "Use llama3.1-8b, gpt-oss-120b, or zai-glm-4.7 instead."
            )
        return v

    @field_validator("cerebras_api_key")
    @classmethod
    def validate_api_key_format(cls, v: str) -> str:
        """Validate API key has correct prefix."""
        if not v.startswith("csk-"):
            raise ValueError("Cerebras API key must start with 'csk-'")
        return v


def get_settings() -> Settings:
    """Get settings instance. Use this instead of module-level instantiation
    to avoid crashing on import when .env is missing (e.g. in tests)."""
    return Settings()
