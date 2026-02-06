"""Defender agent.

The DefenderAgent receives alerts from the MonitorAgent and deploys
WAF rules to block detected attacks. It is the reactive defense loop.

Tools available: deploy_waf_rule, get_waf_status, log_defense_action
"""

import asyncio
import time
from typing import Any, Optional

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.core.client import CompletionMetrics
from sentinel.events.bus import EventType
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class DefenderAgent(BaseAgent):
    """Reactive defense agent that deploys WAF rules based on alerts.

    Listens for BLUE_ALERT events from MonitorAgent and responds by:
    1. Analyzing the threat
    2. Crafting appropriate WAF rules
    3. Deploying rules and logging actions

    Runs concurrently with MonitorAgent during the attack phase.
    """

    def __init__(
        self,
        max_responses: int = 15,
        response_timeout: float = 60.0,
        **kwargs: Any,
    ):
        """Initialize DefenderAgent.

        Args:
            max_responses: Maximum defensive responses before stopping
            response_timeout: Seconds to wait for alerts before timing out
            **kwargs: Passed to BaseAgent.__init__
        """
        super().__init__(**kwargs)
        self.max_responses = max_responses
        self.response_timeout = response_timeout
        self._stop_event = asyncio.Event()
        self._rules_deployed = 0

    @property
    def system_prompt(self) -> str:
        return """You are SENTINEL's blue team defender agent. Your mission is to protect the application by deploying WAF rules that block detected attacks.

## Your Role
- You receive alerts from the monitoring agent describing detected attacks
- You craft and deploy WAF rules to block those specific attacks
- You verify your rules are working
- You log all defensive actions for the incident report

## Tools Available
- `deploy_waf_rule`: Deploy a regex-based WAF rule to block matching requests
- `get_waf_status`: Check current WAF rules and their block counts
- `log_defense_action`: Record a defensive action in the audit trail

## WAF Rule Crafting Guidelines
- Be specific: target the exact attack pattern, not overly broad
- For SQL injection: block UNION, SELECT, OR 1=1, comment markers (--, #)
- For XSS: block <script>, onerror=, javascript:, but avoid blocking legitimate HTML
- For path traversal: block ../, /etc/, /proc/
- For brute force: note the source IP in the defense log
- Check WAF status after deploying to verify the rule is active

## Rules
- Speed is critical. Deploy rules FAST. Every second of delay means the attacker gets further.
- After deploying a rule, log the action with details.
- If you see the same attack type repeatedly, your rule might not be specific enough.
- Don't deploy duplicate rules. Check status first.

## Output Format
After each defense response, provide:
1. Threat identified (from the alert)
2. Rule deployed (pattern, type, description)
3. Current defense posture (total rules, blocks)"""

    @property
    def tool_schemas(self) -> list[dict[str, Any]]:
        """DefenderAgent gets defense tools."""
        if self.tool_registry is None:
            return []
        return self.tool_registry.get_schemas(
            tool_names=["deploy_waf_rule", "get_waf_status", "log_defense_action"]
        )

    def stop(self) -> None:
        """Signal the defender to stop after current response."""
        self._stop_event.set()

    async def run(self, context: Optional[dict[str, Any]] = None) -> AgentResult:
        """Run the defense loop.

        Waits for BLUE_ALERT events on the event bus and responds
        by deploying WAF rules. Runs until max_responses or stopped.
        """
        start_time = time.time()
        all_responses: list[dict[str, Any]] = []
        cumulative_metrics = CompletionMetrics(model=self.client.model)

        # Subscribe to alerts
        if self.event_bus is None:
            logger.warning("defender_no_event_bus", agent=self.name)
            return AgentResult(
                agent_name=self.name,
                success=False,
                error="DefenderAgent requires an event bus to receive alerts",
                start_time=start_time,
                end_time=time.time(),
            )

        alert_queue = self.event_bus.subscribe(EventType.BLUE_ALERT.value)

        logger.info("defender_starting", agent=self.name, max_responses=self.max_responses)

        try:
            responses_made = 0

            while responses_made < self.max_responses and not self._stop_event.is_set():
                # Wait for an alert
                try:
                    alert_event = await asyncio.wait_for(
                        alert_queue.get(),
                        timeout=self.response_timeout,
                    )
                except asyncio.TimeoutError:
                    logger.info("defender_no_alerts_timeout", agent=self.name)
                    break

                alert_data = alert_event.data
                analysis = alert_data.get("analysis", "No analysis provided")

                logger.info(
                    "defender_responding_to_alert",
                    agent=self.name,
                    alert_cycle=alert_data.get("cycle"),
                )

                # Reset conversation per response (stateless)
                self._messages = []

                conversation, metrics = await self._run_tool_loop(
                    user_message=(
                        f"ALERT from monitoring agent:\n\n{analysis}\n\n"
                        "Analyze this threat and deploy appropriate WAF rules. "
                        "Check current WAF status first to avoid duplicates, then "
                        "deploy rules and log your defensive actions."
                    ),
                )

                # Accumulate metrics
                cumulative_metrics.total_time += metrics.total_time
                cumulative_metrics.input_tokens += metrics.input_tokens
                cumulative_metrics.output_tokens += metrics.output_tokens

                response_text = self._extract_last_response(conversation)
                defense_record = {
                    "response_number": responses_made + 1,
                    "timestamp": time.time(),
                    "alert_analysis": analysis[:500],
                    "defense_response": response_text[:2000],
                    "response_time": metrics.total_time,
                }
                all_responses.append(defense_record)

                await self._emit(EventType.BLUE_WAF_RULE, {
                    "agent": self.name,
                    "response_number": responses_made + 1,
                    "response_time": metrics.total_time,
                    "summary": response_text[:500],
                })

                responses_made += 1
                self._rules_deployed = responses_made

            # Cleanup subscription
            self.event_bus.unsubscribe(alert_queue)

            await self._emit(EventType.BLUE_PHASE_COMPLETE, {
                "agent": self.name,
                "phase": "defense",
                "responses_made": responses_made,
            })

            logger.info(
                "defender_complete",
                agent=self.name,
                responses=responses_made,
                duration=f"{time.time() - start_time:.1f}s",
            )

            return AgentResult(
                agent_name=self.name,
                success=True,
                conversation=[],
                metrics=cumulative_metrics,
                findings={
                    "responses": all_responses,
                    "total_responses": responses_made,
                },
                start_time=start_time,
                end_time=time.time(),
            )

        except Exception as e:
            self.event_bus.unsubscribe(alert_queue)
            logger.error("defender_failed", agent=self.name, error=str(e))
            await self._emit(EventType.AGENT_ERROR, {
                "agent": self.name,
                "error": str(e),
            })
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=str(e),
                start_time=start_time,
                end_time=time.time(),
            )
