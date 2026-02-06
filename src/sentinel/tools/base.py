"""Base infrastructure for tool implementations."""

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ToolOutput:
    """Standardized tool output returned to the LLM.

    This is different from sentinel.core.client.ToolResult which is
    the wrapper used internally by CerebrasClient. ToolOutput is what
    tool functions return before conversion.
    """

    tool_name: str
    success: bool
    data: dict[str, Any]
    raw_output: str = ""
    error: str | None = None
    duration_ms: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_llm_string(self, max_chars: int = 8000) -> str:
        """Format for LLM consumption. Truncates intelligently."""
        if not self.success:
            return f"Error running {self.tool_name}: {self.error}"
        result_str = json.dumps(self.data, indent=2, default=str)
        if len(result_str) > max_chars:
            result_str = (
                result_str[: max_chars - 100]
                + f"\n\n... [truncated, {len(result_str)} total chars]"
            )
        return result_str

    def __str__(self) -> str:
        return self.to_llm_string()


async def run_subprocess(
    cmd: list[str],
    timeout: int = 120,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[str, str, int]:
    """Run a subprocess with timeout. Returns (stdout, stderr, returncode).

    Raises TimeoutError if the command exceeds the timeout.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=env,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
        return (
            stdout_bytes.decode("utf-8", errors="replace"),
            stderr_bytes.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")


def timed(func):
    """Decorator that adds duration_ms to ToolOutput results."""

    async def wrapper(*args, **kwargs) -> ToolOutput:
        start = time.monotonic()
        try:
            result = await func(*args, **kwargs)
            result.duration_ms = int((time.monotonic() - start) * 1000)
            return result
        except Exception as e:
            duration = int((time.monotonic() - start) * 1000)
            logger.error(
                "tool_exception",
                tool=func.__name__,
                error=str(e),
                error_type=type(e).__name__,
            )
            return ToolOutput(
                tool_name=func.__name__,
                success=False,
                data={},
                error=f"{type(e).__name__}: {str(e)}",
                duration_ms=duration,
            )

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    # Preserve tool schema if decorated with @tool_schema
    if hasattr(func, "__tool_schema__"):
        wrapper.__tool_schema__ = func.__tool_schema__
    return wrapper
