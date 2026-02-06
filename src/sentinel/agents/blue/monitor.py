"""Monitor agent.

The MonitorAgent watches network traffic and red team events, analyzing
patterns and raising alerts. It runs continuously during the attack phase
and feeds alerts to the DefenderAgent.

Tools available: get_network_logs, analyze_attack_pattern
"""

import asyncio
import time
from typing import Any, Optional

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.core.client import CompletionMetrics
from sentinel.events.bus import EventType
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class MonitorAgent(BaseAgent):
    """Network monitoring and threat detection agent.

    Runs in a loop during the attack phase:
    1. Watches for red team events (tool calls/results) on the event bus
    2. Periodically checks network logs
    3. Analyzes attack patterns
    4. Emits BLUE_ALERT events when threats are detected
    """

    def __init__(
        self,
        poll_interval: float = 3.0,
        max_cycles: int = 20,
        **kwargs: Any,
    ):
        """Initialize MonitorAgent.

        Args:
            poll_interval: Seconds between monitoring cycles
            max_cycles: Maximum monitoring cycles before stopping
            **kwargs: Passed to BaseAgent.__init__
        """
        super().__init__(**kwargs)
        self.poll_interval = poll_interval
        self.max_cycles = max_cycles
        self._stop_event = asyncio.Event()
        self._alerts_raised = 0

    @property
    def system_prompt(self) -> str:
        return """You are SENTINEL's blue team monitoring agent. Your mission is to detect and analyze attacks on the protected application in real-time.

## Your Role
- You are a Security Operations Center (SOC) analyst
- You monitor network traffic and system logs for signs of attack
- You raise alerts when you detect suspicious activity
- You classify attack types and assess severity

## Tools Available
- `get_network_logs`: View recent HTTP requests with flagged suspicious ones
- `analyze_attack_pattern`: Get statistical analysis of attack patterns

## Detection Priorities
1. SQL injection attempts (UNION, error-based, blind)
2. XSS payloads in parameters
3. Authentication bruteforce
4. Path traversal and directory enumeration
5. API abuse and IDOR attempts

## Rules
- Check logs frequently. Attacks happen fast.
- When you detect an attack, describe it precisely: type, source, target endpoint, payload used.
- Assess severity: Critical (data exfiltration), High (auth bypass), Medium (info disclosure), Low (recon)
- Your alerts feed directly to the defender agent. Be specific so they can write targeted WAF rules.

## Output Format
After each analysis, provide:
1. Active threats detected (type, endpoint, severity)
2. Attack progression (what stage is the attacker in?)
3. Recommended defensive actions"""

    @property
    def tool_schemas(self) -> list[dict[str, Any]]:
        """MonitorAgent only gets monitoring tools."""
        if self.tool_registry is None:
            return []
        return self.tool_registry.get_schemas(
            tool_names=["get_network_logs", "analyze_attack_pattern"]
        )

    def stop(self) -> None:
        """Signal the monitor to stop after current cycle."""
        self._stop_event.set()

    async def run(self, context: Optional[dict[str, Any]] = None) -> AgentResult:
        """Run the monitoring loop.

        Executes multiple cycles of log checking and analysis.
        Each cycle is one tool_loop call asking the LLM to analyze current traffic.
        Stops when max_cycles is reached or stop() is called.
        """
        start_time = time.time()
        all_alerts: list[dict[str, Any]] = []
        cumulative_metrics = None
        cycle = 0

        logger.info("monitor_starting", agent=self.name, max_cycles=self.max_cycles)

        try:
            for cycle in range(self.max_cycles):
                if self._stop_event.is_set():
                    logger.info("monitor_stopped_by_signal", agent=self.name, cycle=cycle)
                    break

                logger.debug("monitor_cycle", agent=self.name, cycle=cycle + 1)

                # Build context with any red team events we've seen
                cycle_context = dict(context) if context else {}
                cycle_context["cycle"] = cycle + 1
                cycle_context["previous_alerts"] = all_alerts[-5:]  # Last 5 alerts

                # Reset conversation for each cycle (stateless analysis)
                self._messages = []

                conversation, metrics = await self._run_tool_loop(
                    user_message=(
                        f"Monitoring cycle {cycle + 1}. Check network logs for suspicious "
                        "activity. Analyze any attack patterns. Report what you find."
                    ),
                    context=cycle_context if cycle_context else None,
                )

                # Accumulate metrics
                if cumulative_metrics is None:
                    cumulative_metrics = metrics
                else:
                    cumulative_metrics.total_time += metrics.total_time
                    cumulative_metrics.input_tokens += metrics.input_tokens
                    cumulative_metrics.output_tokens += metrics.output_tokens

                # Extract alert from response
                response_text = self._extract_last_response(conversation)
                if response_text:
                    alert = {
                        "cycle": cycle + 1,
                        "timestamp": time.time(),
                        "analysis": response_text[:2000],
                    }
                    all_alerts.append(alert)

                    # Emit alert for defender
                    await self._emit(EventType.BLUE_ALERT, {
                        "agent": self.name,
                        "cycle": cycle + 1,
                        "analysis": response_text[:2000],
                    })

                    self._alerts_raised += 1

                # Wait before next cycle
                try:
                    await asyncio.wait_for(
                        self._stop_event.wait(),
                        timeout=self.poll_interval,
                    )
                    # If we get here, stop was signaled
                    break
                except asyncio.TimeoutError:
                    pass  # Normal: timeout means continue to next cycle

            cycles_completed = min(cycle + 1, self.max_cycles)

            await self._emit(EventType.BLUE_PHASE_COMPLETE, {
                "agent": self.name,
                "phase": "monitoring",
                "cycles_completed": cycles_completed,
                "alerts_raised": self._alerts_raised,
            })

            logger.info(
                "monitor_complete",
                agent=self.name,
                cycles=cycles_completed,
                alerts=self._alerts_raised,
                duration=f"{time.time() - start_time:.1f}s",
            )

            return AgentResult(
                agent_name=self.name,
                success=True,
                conversation=[],  # Don't carry per-cycle conversations
                metrics=cumulative_metrics if cumulative_metrics else CompletionMetrics(model=self.client.model),
                findings={
                    "alerts": all_alerts,
                    "cycles_completed": cycles_completed,
                    "alerts_raised": self._alerts_raised,
                },
                start_time=start_time,
                end_time=time.time(),
            )

        except Exception as e:
            logger.error("monitor_failed", agent=self.name, error=str(e))
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
