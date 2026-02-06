"""Tests for tool schema system."""

import pytest

from sentinel.core.tools import Tool, ToolParameter, ToolRegistry, tool_schema


def test_tool_parameter_creation():
    """ToolParameter stores name, type, description, required, enum, default."""
    param = ToolParameter(
        name="url",
        type="string",
        description="Target URL",
        required=True,
    )
    assert param.name == "url"
    assert param.type == "string"
    assert param.required is True
    assert param.enum is None


def test_tool_to_openai_schema():
    """Tool.to_openai_schema() produces valid OpenAI function calling format."""
    tool = Tool(
        name="http_request",
        description="Make HTTP request",
        parameters=[
            ToolParameter("url", "string", "Target URL", required=True),
            ToolParameter(
                "method", "string", "HTTP method",
                required=False, enum=["GET", "POST", "PUT"],
            ),
        ],
    )

    schema = tool.to_openai_schema()

    assert schema["type"] == "function"
    assert schema["function"]["name"] == "http_request"
    assert schema["function"]["description"] == "Make HTTP request"
    assert schema["function"]["strict"] is True

    props = schema["function"]["parameters"]["properties"]
    assert "url" in props
    assert "method" in props
    assert props["method"]["enum"] == ["GET", "POST", "PUT"]

    required = schema["function"]["parameters"]["required"]
    assert "url" in required
    assert "method" not in required  # required=False


def test_tool_registry_register_and_get():
    """ToolRegistry stores and retrieves tools."""
    registry = ToolRegistry()
    tool = Tool(name="test_tool", description="A test tool")

    registry.register(tool)

    assert registry.get("test_tool") is tool
    assert registry.get("nonexistent") is None
    assert "test_tool" in registry.list_tools()
    assert len(registry.get_schemas()) == 1


def test_tool_registry_duplicate_warning():
    """Registering the same tool name twice should not overwrite."""
    registry = ToolRegistry()
    tool1 = Tool(name="dupe", description="First")
    tool2 = Tool(name="dupe", description="Second")

    registry.register(tool1)
    registry.register(tool2)

    assert registry.get("dupe").description == "First"
    assert len(registry.list_tools()) == 1


def test_tool_registry_get_schemas_subset():
    """get_schemas() with tool_names filters to requested tools."""
    registry = ToolRegistry()
    registry.register(Tool(name="a", description="A"))
    registry.register(Tool(name="b", description="B"))
    registry.register(Tool(name="c", description="C"))

    schemas = registry.get_schemas(tool_names=["a", "c"])
    names = [s["function"]["name"] for s in schemas]
    assert names == ["a", "c"]


def test_tool_schema_decorator():
    """@tool_schema attaches a Tool object to the decorated function."""

    @tool_schema(
        name="example_tool",
        description="Example tool for testing",
        parameters=[
            ToolParameter("arg1", "string", "First argument"),
            ToolParameter("arg2", "string", "Second argument", required=False),
        ],
    )
    async def example_tool(arg1: str, arg2: str = "default") -> str:
        return f"Result: {arg1}, {arg2}"

    assert hasattr(example_tool, "__tool_schema__")
    tool = example_tool.__tool_schema__
    assert tool.name == "example_tool"
    assert tool.handler is example_tool
    assert len(tool.parameters) == 2

    schema = tool.to_openai_schema()
    assert schema["function"]["name"] == "example_tool"
    assert "arg1" in schema["function"]["parameters"]["required"]
