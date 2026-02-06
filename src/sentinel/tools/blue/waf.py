"""Web Application Firewall rule engine for blue team."""

import re
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class WAFRule:
    """A WAF rule that matches and blocks requests."""
    id: str
    name: str
    rule_type: str  # pattern, rate_limit, ip_block
    pattern: str
    target: str  # path, query, body, headers, all
    action: str  # block, log, rate_limit
    created_at: float = field(default_factory=time.time)
    triggered_count: int = 0
    active: bool = True


class WAFEngine:
    """Pattern-based WAF for blue team defense.

    The blue team agent can deploy rules in real-time to block
    attack patterns it detects.
    """

    def __init__(self):
        self._rules: dict[str, WAFRule] = {}
        self._blocked_ips: set[str] = set()
        self._block_log: list[dict[str, Any]] = []

    def check_request(self, path: str, query: str, body: str, headers: dict[str, str], source_ip: str) -> tuple[bool, str | None]:
        """Check if a request should be blocked. Returns (allowed, blocking_rule_name)."""
        # IP block check
        if source_ip in self._blocked_ips:
            return False, "ip_blocked"

        # Check all active rules
        full_input = f"{path} {query} {body}"
        for rule in self._rules.values():
            if not rule.active:
                continue

            target_text = ""
            if rule.target == "path":
                target_text = path
            elif rule.target == "query":
                target_text = query
            elif rule.target == "body":
                target_text = body
            elif rule.target == "headers":
                target_text = str(headers)
            else:  # "all"
                target_text = full_input

            try:
                if re.search(rule.pattern, target_text, re.IGNORECASE):
                    rule.triggered_count += 1
                    if rule.action == "block":
                        self._block_log.append({
                            "timestamp": time.time(),
                            "rule": rule.name,
                            "path": path,
                            "source_ip": source_ip,
                        })
                        return False, rule.name
            except re.error:
                pass  # Skip invalid regex

        return True, None

    @tool_schema(
        name="deploy_waf_rule",
        description=(
            "Deploy a new WAF (Web Application Firewall) rule to block malicious requests. "
            "Rules match patterns in requests and can block, log, or rate-limit matching traffic. "
            "Use this to defend against attack patterns detected by the monitor."
        ),
        parameters=[
            ToolParameter("rule_name", "string", "Descriptive name for the rule (e.g. 'block_sqli_search')"),
            ToolParameter("pattern", "string", "Regex pattern to match (e.g. 'union\\s+select|or\\s+1\\s*=\\s*1')"),
            ToolParameter(
                "target",
                "string",
                "What part of the request to match against",
                required=False,
                enum=["path", "query", "body", "headers", "all"],
            ),
            ToolParameter(
                "action",
                "string",
                "Action to take on match",
                required=False,
                enum=["block", "log"],
            ),
        ],
    )
    @timed
    async def deploy_rule(
        self,
        rule_name: str,
        pattern: str,
        target: str = "all",
        action: str = "block",
    ) -> ToolOutput:
        """Deploy a new WAF rule."""
        # Validate regex
        try:
            re.compile(pattern)
        except re.error as e:
            return ToolOutput(
                tool_name="deploy_waf_rule",
                success=False,
                data={},
                error=f"Invalid regex pattern: {e}",
            )

        rule_id = f"waf_{len(self._rules) + 1}_{int(time.time())}"
        rule = WAFRule(
            id=rule_id,
            name=rule_name,
            rule_type="pattern",
            pattern=pattern,
            target=target,
            action=action,
        )
        self._rules[rule_id] = rule

        logger.info(
            "waf_rule_deployed",
            rule_name=rule_name,
            pattern=pattern,
            target=target,
            action=action,
        )

        return ToolOutput(
            tool_name="deploy_waf_rule",
            success=True,
            data={
                "rule_id": rule_id,
                "rule_name": rule_name,
                "pattern": pattern,
                "target": target,
                "action": action,
                "total_active_rules": len(
                    [r for r in self._rules.values() if r.active]
                ),
            },
        )

    @tool_schema(
        name="get_waf_status",
        description=(
            "Get the current status of the WAF: active rules, block statistics, "
            "and recent blocked requests. Use to monitor defense effectiveness."
        ),
        parameters=[],
    )
    @timed
    async def get_status(self) -> ToolOutput:
        """Get WAF status and statistics."""
        rules_data = [
            {
                "id": r.id,
                "name": r.name,
                "pattern": r.pattern,
                "target": r.target,
                "action": r.action,
                "triggered_count": r.triggered_count,
                "active": r.active,
            }
            for r in self._rules.values()
        ]

        return ToolOutput(
            tool_name="get_waf_status",
            success=True,
            data={
                "active_rules": len([r for r in self._rules.values() if r.active]),
                "total_rules": len(self._rules),
                "blocked_ips": list(self._blocked_ips),
                "rules": rules_data,
                "recent_blocks": self._block_log[-20:],
                "total_blocks": len(self._block_log),
            },
        )
