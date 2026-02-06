"""Tool executor and registry for SENTINEL.

This module provides the ToolExecutor class that bridges the tool implementations
to CerebrasClient.tool_loop(). It satisfies the interface:
    async execute_tool(name: str, arguments: dict) -> Any
"""

from typing import Any, Callable, Awaitable

import structlog

from sentinel.core.tools import Tool, ToolParameter, ToolRegistry
from sentinel.tools.base import ToolOutput
from sentinel.tools.http_tool import http_request, close_session
from sentinel.tools.scanner_tool import port_scan, path_scan
from sentinel.tools.injection_tool import sql_injection_test
from sentinel.tools.xss_tool import xss_test
from sentinel.tools.auth_tool import login_attempt, idor_test
from sentinel.tools.api_tool import api_discover
from sentinel.tools.juice_shop import check_challenges
from sentinel.tools.blue.monitor import NetworkMonitor
from sentinel.tools.blue.waf import WAFEngine
from sentinel.tools.blue.responder import Responder
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class ToolExecutor:
    """Executes tools by name. Used by CerebrasClient.tool_loop().

    Implements the interface: async execute_tool(name, arguments) -> Any

    The return value is converted to string by the client and truncated
    to 8000 chars. ToolOutput.__str__() handles formatting.
    """

    def __init__(self):
        self._executors: dict[str, Callable[..., Awaitable[ToolOutput]]] = {}

    def register(self, name: str, handler: Callable[..., Awaitable[ToolOutput]]) -> None:
        """Register a tool handler by name."""
        self._executors[name] = handler

    async def execute_tool(self, name: str, arguments: dict[str, Any]) -> ToolOutput:
        """Execute a tool by name with given arguments.

        This is the method called by CerebrasClient.tool_loop().
        """
        handler = self._executors.get(name)
        if handler is None:
            logger.error("unknown_tool", tool_name=name)
            return ToolOutput(
                tool_name=name,
                success=False,
                data={},
                error=f"Unknown tool: {name}. Available tools: {list(self._executors.keys())}",
            )

        try:
            result = await handler(**arguments)
            return result
        except TypeError as e:
            logger.error(
                "tool_argument_error",
                tool_name=name,
                error=str(e),
                arguments=list(arguments.keys()),
            )
            return ToolOutput(
                tool_name=name,
                success=False,
                data={},
                error=f"Invalid arguments for {name}: {e}",
            )


def create_red_team_executor() -> tuple[ToolExecutor, ToolRegistry]:
    """Create tool executor and registry for the red team.

    Returns (executor, registry) where:
    - executor: ToolExecutor for use with CerebrasClient.tool_loop()
    - registry: ToolRegistry for generating OpenAI tool schemas
    """
    executor = ToolExecutor()
    registry = ToolRegistry()

    # Register all red team tools
    red_tools = [
        http_request,
        port_scan,
        path_scan,
        sql_injection_test,
        xss_test,
        login_attempt,
        idor_test,
        api_discover,
        check_challenges,
    ]

    for tool_func in red_tools:
        if hasattr(tool_func, "__tool_schema__"):
            tool: Tool = tool_func.__tool_schema__
            registry.register(tool)
            executor.register(tool.name, tool_func)
        else:
            logger.warning(
                "tool_missing_schema",
                tool=getattr(tool_func, "__name__", str(tool_func)),
            )

    logger.info(
        "red_team_executor_created",
        tool_count=len(registry.list_tools()),
        tools=registry.list_tools(),
    )
    return executor, registry


def create_blue_team_executor(
    monitor: NetworkMonitor | None = None,
    waf: WAFEngine | None = None,
    responder: Responder | None = None,
) -> tuple[ToolExecutor, ToolRegistry]:
    """Create tool executor and registry for the blue team.

    Blue team tools are bound to shared state objects (monitor, WAF, responder)
    so they operate on the same data the red team is generating.

    Returns (executor, registry).
    """
    monitor = monitor or NetworkMonitor()
    waf = waf or WAFEngine()
    responder = responder or Responder()

    executor = ToolExecutor()
    registry = ToolRegistry()

    # Blue team tools are methods on the shared objects
    blue_tools: list[tuple[str, Any, Callable]] = [
        # (name, object_with_schema, bound_method)
        ("get_network_logs", monitor.get_logs, monitor.get_logs),
        ("analyze_attack_pattern", monitor.analyze_pattern, monitor.analyze_pattern),
        ("deploy_waf_rule", waf.deploy_rule, waf.deploy_rule),
        ("get_waf_status", waf.get_status, waf.get_status),
        ("log_defense_action", responder.log_action, responder.log_action),
    ]

    for name, schema_source, handler in blue_tools:
        if hasattr(schema_source, "__tool_schema__"):
            tool: Tool = schema_source.__tool_schema__
            registry.register(tool)
            executor.register(tool.name, handler)
        else:
            logger.warning("blue_tool_missing_schema", tool=name)

    logger.info(
        "blue_team_executor_created",
        tool_count=len(registry.list_tools()),
        tools=registry.list_tools(),
    )
    return executor, registry
