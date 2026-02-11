"""Tool schema system for OpenAI-compatible function calling."""

from typing import Any, Callable, Optional
from dataclasses import dataclass, field

from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class ToolParameter:
    """Tool parameter definition."""

    def __init__(
        self,
        name: str,
        type: str,
        description: str,
        required: bool = True,
        enum: Optional[list[str]] = None,
        default: Any = None,
    ):
        self.name = name
        self.type = type
        self.description = description
        self.required = required
        self.enum = enum
        self.default = default


@dataclass
class Tool:
    """Tool definition with OpenAI-compatible schema.

    Each tool has a name, description, parameters, and an optional handler function.
    The to_openai_schema() method produces the exact JSON structure expected by
    the OpenAI chat completions API (and Cerebras, which is compatible).
    """

    name: str
    description: str
    parameters: list[ToolParameter] = field(default_factory=list)
    handler: Optional[Callable] = None

    def to_openai_schema(self) -> dict[str, Any]:
        """Convert to OpenAI function calling schema with strict mode."""
        properties: dict[str, Any] = {}
        required: list[str] = []

        for param in self.parameters:
            param_schema: dict[str, Any] = {
                "type": param.type,
                "description": param.description,
            }

            if param.enum:
                param_schema["enum"] = param.enum

            if param.default is not None:
                param_schema["default"] = param.default

            properties[param.name] = param_schema

            if param.required:
                required.append(param.name)

        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": properties,
                    "required": required,
                },
                
            },
        }


class ToolRegistry:
    """Registry for managing available tools."""

    def __init__(self) -> None:
        self.tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a tool. Warns on duplicate names."""
        if tool.name in self.tools:
            logger.warning("tool_already_registered", tool_name=tool.name)
            return
        self.tools[tool.name] = tool
        logger.debug(
            "tool_registered",
            tool_name=tool.name,
            parameter_count=len(tool.parameters),
        )

    def get(self, name: str) -> Optional[Tool]:
        """Get tool by name."""
        return self.tools.get(name)

    def get_schemas(self, tool_names: Optional[list[str]] = None) -> list[dict[str, Any]]:
        """Get OpenAI schemas for specified tools (or all if None)."""
        if tool_names:
            tools = [self.tools[n] for n in tool_names if n in self.tools]
        else:
            tools = list(self.tools.values())
        return [t.to_openai_schema() for t in tools]

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self.tools.keys())


def tool_schema(
    name: str,
    description: str,
    parameters: Optional[list[ToolParameter]] = None,
) -> Callable:
    """Decorator to attach a Tool schema to a function.

    Usage:
        @tool_schema(
            name="http_request",
            description="Make HTTP request",
            parameters=[ToolParameter("url", "string", "Target URL")]
        )
        async def http_request(url: str) -> dict:
            ...

    The decorated function gets a __tool_schema__ attribute containing the Tool object.
    This is used by ToolRegistry and ToolExecutor for automatic registration.
    """

    def decorator(func: Callable) -> Callable:
        tool = Tool(
            name=name,
            description=description,
            parameters=parameters or [],
            handler=func,
        )
        func.__tool_schema__ = tool  # type: ignore[attr-defined]
        return func

    return decorator
