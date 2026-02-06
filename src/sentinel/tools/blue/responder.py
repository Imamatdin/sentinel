"""Automated response actions for blue team."""

import time
from typing import Any

import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class Responder:
    """Executes defense responses for the blue team.

    Tracks all defense actions taken and their outcomes.
    """

    def __init__(self):
        self._actions: list[dict[str, Any]] = []

    @tool_schema(
        name="log_defense_action",
        description=(
            "Record a defense action taken by the blue team. "
            "This creates an audit trail of all defensive responses. "
            "Use after deploying a WAF rule, analyzing an attack, or taking any defensive action."
        ),
        parameters=[
            ToolParameter("action_type", "string", "Type of action taken (e.g. 'waf_rule_deployed', 'attack_analyzed', 'alert_raised')"),
            ToolParameter("description", "string", "Human-readable description of what was done and why"),
            ToolParameter("target", "string", "What was the action targeting (e.g. endpoint path, attack type)"),
            ToolParameter(
                "severity",
                "string",
                "Severity of the threat being responded to",
                required=False,
                enum=["critical", "high", "medium", "low", "info"],
            ),
        ],
    )
    @timed
    async def log_action(
        self,
        action_type: str,
        description: str,
        target: str,
        severity: str = "medium",
    ) -> ToolOutput:
        """Log a defense action."""
        action = {
            "id": f"def_{len(self._actions) + 1}_{int(time.time())}",
            "timestamp": time.time(),
            "action_type": action_type,
            "description": description,
            "target": target,
            "severity": severity,
        }
        self._actions.append(action)

        logger.info(
            "defense_action",
            action_type=action_type,
            target=target,
            severity=severity,
        )

        return ToolOutput(
            tool_name="log_defense_action",
            success=True,
            data={
                "action_logged": action,
                "total_actions": len(self._actions),
            },
        )

    def get_all_actions(self) -> list[dict[str, Any]]:
        """Get all defense actions taken."""
        return list(self._actions)
