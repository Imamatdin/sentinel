"""Tests for configuration management."""

import os
import pytest
from pydantic import ValidationError

from sentinel.config import Settings


def test_settings_defaults():
    """Test default settings values with valid API key."""
    settings = Settings(cerebras_api_key="csk-test-key-123")

    assert settings.cerebras_base_url == "https://api.cerebras.ai/v1"
    assert settings.primary_model == "zai-glm-4.7"
    assert settings.fallback_model == "gpt-oss-120b"
    assert settings.router_model == "llama3.1-8b"
    assert settings.default_temperature == 0.7
    assert settings.default_max_tokens == 4096
    assert settings.tool_call_timeout == 30
    assert settings.max_tool_iterations == 10
    assert settings.log_level == "INFO"
    assert settings.log_format == "json"


def test_api_key_validation():
    """API key must start with 'csk-'."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(cerebras_api_key="invalid-key")
    assert "must start with 'csk-'" in str(exc_info.value)


def test_deprecated_model_validation():
    """llama-3.3-70b must be rejected as deprecated."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(cerebras_api_key="csk-test", primary_model="llama-3.3-70b")
    assert "deprecated" in str(exc_info.value).lower()


def test_temperature_bounds():
    """Temperature must be between 0.0 and 2.0."""
    # Valid
    s = Settings(cerebras_api_key="csk-test", default_temperature=0.0)
    assert s.default_temperature == 0.0

    s = Settings(cerebras_api_key="csk-test", default_temperature=2.0)
    assert s.default_temperature == 2.0

    # Invalid
    with pytest.raises(ValidationError):
        Settings(cerebras_api_key="csk-test", default_temperature=-0.1)

    with pytest.raises(ValidationError):
        Settings(cerebras_api_key="csk-test", default_temperature=3.0)


def test_settings_from_env(monkeypatch):
    """Settings should load from environment variables."""
    monkeypatch.setenv("CEREBRAS_API_KEY", "csk-from-env-123")
    monkeypatch.setenv("PRIMARY_MODEL", "gpt-oss-120b")
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")

    settings = Settings()
    assert settings.cerebras_api_key == "csk-from-env-123"
    assert settings.primary_model == "gpt-oss-120b"
    assert settings.log_level == "DEBUG"
