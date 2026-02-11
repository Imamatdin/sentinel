"""Custom exceptions for Sentinel."""

from typing import Any


class SentinelError(Exception):
    """Base exception for all Sentinel errors."""

    def __init__(self, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigurationError(SentinelError):
    """Configuration-related errors."""
    pass


class AuthorizationError(SentinelError):
    """Target not authorized for testing."""
    pass


class GraphError(SentinelError):
    """Knowledge graph operation errors."""
    pass


class OrchestrationError(SentinelError):
    """Workflow orchestration errors."""
    pass


class ToolExecutionError(SentinelError):
    """Security tool execution errors."""

    def __init__(self, tool_name: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(f"[{tool_name}] {message}", details)
        self.tool_name = tool_name


class ExploitError(SentinelError):
    """Exploitation-related errors."""
    pass


class ValidationError(SentinelError):
    """PoC validation errors."""
    pass
