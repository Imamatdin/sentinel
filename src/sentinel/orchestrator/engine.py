"""Engagement orchestrator.

The EngagementOrchestrator manages the full red vs. blue engagement lifecycle:
1. Setup: Create agents, event bus, shared state
2. Recon phase: Red team maps the target (blue team monitors passively)
3. Attack phase: Red team exploits (blue team detects and defends concurrently)
4. Report phase: Both teams generate reports
5. Teardown: Collect results, compute stats

This is the top-level entry point for running SENTINEL.
"""

import asyncio
import time
from typing import Any, Optional
from dataclasses import dataclass, field

from sentinel.config import Settings, get_settings
from sentinel.core.client import CerebrasClient, CompletionMetrics
from sentinel.events.bus import EventBus, Event, EventType
from sentinel.tools import create_red_team_executor, create_blue_team_executor
from sentinel.tools.blue.monitor import NetworkMonitor
from sentinel.tools.blue.waf import WAFEngine
from sentinel.tools.blue.responder import Responder
from sentinel.agents.base import AgentResult
from sentinel.agents.red.recon import ReconAgent
from sentinel.agents.red.exploit import ExploitAgent
from sentinel.agents.red.report import ReportAgent
from sentinel.agents.blue.monitor import MonitorAgent
from sentinel.agents.blue.defender import DefenderAgent
from sentinel.agents.blue.forensics import ForensicsAgent
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class EngagementResult:
    """Complete results from an engagement.

    Attributes:
        success: Whether the engagement completed without fatal errors
        target_url: The target that was tested
        duration: Total wall-clock time in seconds
        phases: Results from each phase
        agent_results: Results from each agent
        event_count: Total events published
        speed_stats: Performance metrics for the demo
        red_report: Generated pentest report (if available)
        blue_report: Generated incident response report (if available)
    """

    success: bool
    target_url: str
    duration: float = 0.0
    phases: dict[str, dict[str, Any]] = field(default_factory=dict)
    agent_results: dict[str, AgentResult] = field(default_factory=dict)
    event_count: int = 0
    speed_stats: dict[str, Any] = field(default_factory=dict)
    red_report: str = ""
    blue_report: str = ""

    def summary(self) -> str:
        """Generate a human-readable summary of the engagement."""
        lines = [
            "=" * 60,
            "SENTINEL ENGAGEMENT SUMMARY",
            "=" * 60,
            f"Target: {self.target_url}",
            f"Duration: {self.duration:.1f}s",
            f"Events: {self.event_count}",
            f"Success: {self.success}",
            "",
        ]

        # Agent summaries
        lines.append("AGENT RESULTS:")
        for name, result in self.agent_results.items():
            status = "OK" if result.success else f"FAILED: {result.error}"
            lines.append(
                f"  {name}: {status} "
                f"({result.duration:.1f}s, {result.tool_calls_made} tool calls, "
                f"{result.metrics.output_tokens} tokens)"
            )

        # Speed stats
        if self.speed_stats:
            lines.append("")
            lines.append("SPEED STATS:")
            for key, value in self.speed_stats.items():
                lines.append(f"  {key}: {value}")

        lines.append("=" * 60)
        return "\n".join(lines)


class EngagementOrchestrator:
    """Manages the full engagement lifecycle.

    Usage:
        orchestrator = EngagementOrchestrator(target_url="http://localhost:3000")
        result = await orchestrator.run()
        print(result.summary())
    """

    def __init__(
        self,
        target_url: str = "http://localhost:3000",
        settings: Optional[Settings] = None,
        event_bus: Optional[EventBus] = None,
        monitor_poll_interval: float = 3.0,
        monitor_max_cycles: int = 10,
        defender_max_responses: int = 10,
        exploit_max_iterations: int = 15,
        skip_recon: bool = False,
        skip_reports: bool = False,
    ):
        """Initialize the orchestrator.

        Args:
            target_url: Target application URL
            settings: Optional Settings (defaults to get_settings())
            event_bus: Optional EventBus (created if not provided)
            monitor_poll_interval: Seconds between monitor cycles
            monitor_max_cycles: Max monitor cycles during attack phase
            defender_max_responses: Max defensive responses
            exploit_max_iterations: Max tool loop iterations for exploit agent
            skip_recon: Skip recon phase (for testing exploit directly)
            skip_reports: Skip report generation (faster runs)
        """
        self.target_url = target_url
        self.settings = settings or get_settings()
        self.event_bus = event_bus or EventBus()
        self.monitor_poll_interval = monitor_poll_interval
        self.monitor_max_cycles = monitor_max_cycles
        self.defender_max_responses = defender_max_responses
        self.exploit_max_iterations = exploit_max_iterations
        self.skip_recon = skip_recon
        self.skip_reports = skip_reports

        # Shared blue team state
        self.network_monitor = NetworkMonitor()
        self.waf_engine = WAFEngine()
        self.responder = Responder()

        # Tool executors
        self.red_executor, self.red_registry = create_red_team_executor()
        self.blue_executor, self.blue_registry = create_blue_team_executor(
            monitor=self.network_monitor,
            waf=self.waf_engine,
            responder=self.responder,
        )

        logger.info(
            "orchestrator_initialized",
            target=target_url,
            red_tools=self.red_registry.list_tools(),
            blue_tools=self.blue_registry.list_tools(),
        )

    def _create_client(self, model: Optional[str] = None) -> CerebrasClient:
        """Create a CerebrasClient, optionally overriding the model."""
        return CerebrasClient(
            api_key=self.settings.cerebras_api_key,
            base_url=self.settings.cerebras_base_url,
            model=model or self.settings.primary_model,
            temperature=self.settings.default_temperature,
            max_tokens=self.settings.default_max_tokens,
            tool_call_timeout=self.settings.tool_call_timeout,
            max_tool_iterations=self.settings.max_tool_iterations,
        )

    async def run(self) -> EngagementResult:
        """Execute the full engagement.

        Phases:
        1. Recon (red only, blue monitors passively)
        2. Attack + Defense (concurrent red exploit + blue monitor/defend)
        3. Reports (both teams generate reports)
        """
        start_time = time.time()
        result = EngagementResult(success=True, target_url=self.target_url)

        await self.event_bus.publish(Event(
            type=EventType.ENGAGEMENT_START.value,
            data={"target": self.target_url},
            source="orchestrator",
        ))

        logger.info("engagement_starting", target=self.target_url)

        try:
            # -- Phase 1: Reconnaissance --
            recon_result = None
            if not self.skip_recon:
                await self._emit_phase_transition("recon")
                recon_result = await self._run_recon_phase()
                result.agent_results["recon"] = recon_result
                result.phases["recon"] = {
                    "duration": recon_result.duration,
                    "success": recon_result.success,
                    "tool_calls": recon_result.tool_calls_made,
                }

            # -- Phase 2: Attack + Defense (concurrent) --
            await self._emit_phase_transition("attack")
            exploit_result, monitor_result, defender_result = await self._run_attack_phase(
                recon_findings=recon_result.findings if recon_result else None,
            )
            result.agent_results["exploit"] = exploit_result
            result.agent_results["monitor"] = monitor_result
            result.agent_results["defender"] = defender_result
            result.phases["attack"] = {
                "duration": max(
                    exploit_result.duration,
                    monitor_result.duration,
                    defender_result.duration,
                ),
                "exploit_success": exploit_result.success,
                "monitor_cycles": monitor_result.findings.get("cycles_completed", 0),
                "defender_responses": defender_result.findings.get("total_responses", 0),
            }

            # -- Phase 3: Reports --
            if not self.skip_reports:
                await self._emit_phase_transition("report")
                red_report_result, blue_report_result = await self._run_report_phase(
                    recon_findings=recon_result.findings if recon_result else {},
                    exploit_findings=exploit_result.findings,
                    monitor_findings=monitor_result.findings,
                    defender_findings=defender_result.findings,
                )
                result.agent_results["red_report"] = red_report_result
                result.agent_results["blue_report"] = blue_report_result
                result.red_report = red_report_result.findings.get("report", "")
                result.blue_report = blue_report_result.findings.get("report", "")

        except Exception as e:
            logger.error("engagement_failed", error=str(e))
            result.success = False

        # Compute stats
        result.duration = time.time() - start_time
        result.event_count = self.event_bus.event_count
        result.speed_stats = self._compute_speed_stats(result)

        await self.event_bus.publish(Event(
            type=EventType.ENGAGEMENT_END.value,
            data={
                "duration": result.duration,
                "event_count": result.event_count,
                "success": result.success,
            },
            source="orchestrator",
        ))

        logger.info(
            "engagement_complete",
            duration=f"{result.duration:.1f}s",
            events=result.event_count,
            success=result.success,
        )

        return result

    async def _run_recon_phase(self) -> AgentResult:
        """Run the reconnaissance phase."""
        client = self._create_client()

        recon_agent = ReconAgent(
            target_url=self.target_url,
            name="recon_agent",
            client=client,
            event_bus=self.event_bus,
            tool_executor=self.red_executor,
            tool_registry=self.red_registry,
        )

        return await recon_agent.run()

    async def _run_attack_phase(
        self,
        recon_findings: Optional[dict[str, Any]] = None,
    ) -> tuple[AgentResult, AgentResult, AgentResult]:
        """Run the attack phase with concurrent red and blue agents.

        Red team: ExploitAgent attacks based on recon findings
        Blue team: MonitorAgent detects, DefenderAgent responds

        All three run concurrently via asyncio.gather().
        """
        # Create separate clients for each agent (independent rate limiting)
        exploit_client = self._create_client()
        monitor_client = self._create_client()
        defender_client = self._create_client()

        exploit_agent = ExploitAgent(
            target_url=self.target_url,
            name="exploit_agent",
            client=exploit_client,
            event_bus=self.event_bus,
            tool_executor=self.red_executor,
            tool_registry=self.red_registry,
            max_iterations=self.exploit_max_iterations,
        )

        monitor_agent = MonitorAgent(
            poll_interval=self.monitor_poll_interval,
            max_cycles=self.monitor_max_cycles,
            name="monitor_agent",
            client=monitor_client,
            event_bus=self.event_bus,
            tool_executor=self.blue_executor,
            tool_registry=self.blue_registry,
        )

        defender_agent = DefenderAgent(
            max_responses=self.defender_max_responses,
            name="defender_agent",
            client=defender_client,
            event_bus=self.event_bus,
            tool_executor=self.blue_executor,
            tool_registry=self.blue_registry,
        )

        context = {}
        if recon_findings:
            context["recon_findings"] = recon_findings

        async def run_exploit() -> AgentResult:
            result = await exploit_agent.run(context=context if context else None)
            # Signal blue team to stop after red team finishes
            monitor_agent.stop()
            defender_agent.stop()
            return result

        # Run all three concurrently
        exploit_result, monitor_result, defender_result = await asyncio.gather(
            run_exploit(),
            monitor_agent.run(),
            defender_agent.run(),
        )

        return exploit_result, monitor_result, defender_result

    async def _run_report_phase(
        self,
        recon_findings: dict[str, Any],
        exploit_findings: dict[str, Any],
        monitor_findings: dict[str, Any],
        defender_findings: dict[str, Any],
    ) -> tuple[AgentResult, AgentResult]:
        """Run report generation for both teams concurrently."""
        red_report_client = self._create_client()
        blue_report_client = self._create_client()

        red_report_agent = ReportAgent(
            name="red_report_agent",
            client=red_report_client,
            event_bus=self.event_bus,
        )

        blue_report_agent = ForensicsAgent(
            name="blue_forensics_agent",
            client=blue_report_client,
            event_bus=self.event_bus,
        )

        # Get event history for reports
        all_events = self.event_bus.get_history(limit=500)
        event_timeline = [
            {
                "id": e.event_id,
                "type": e.type,
                "source": e.source,
                "timestamp": e.timestamp,
                "data": {k: str(v)[:200] for k, v in e.data.items()},
            }
            for e in all_events
        ]

        red_context = {
            "recon_findings": recon_findings,
            "exploit_findings": exploit_findings,
            "event_timeline": event_timeline,
        }

        blue_context = {
            "monitor_findings": monitor_findings,
            "defender_findings": defender_findings,
            "event_timeline": event_timeline,
        }

        red_report_result, blue_report_result = await asyncio.gather(
            red_report_agent.run(context=red_context),
            blue_report_agent.run(context=blue_context),
        )

        return red_report_result, blue_report_result

    async def _emit_phase_transition(self, phase: str) -> None:
        """Emit a phase transition event."""
        await self.event_bus.publish(Event(
            type=EventType.PHASE_TRANSITION.value,
            data={"phase": phase},
            source="orchestrator",
        ))

    def _compute_speed_stats(self, result: EngagementResult) -> dict[str, Any]:
        """Compute speed-related statistics for the demo narrative."""
        stats: dict[str, Any] = {}

        total_tokens = 0
        total_llm_time = 0.0
        total_tool_calls = 0

        for name, agent_result in result.agent_results.items():
            total_tokens += agent_result.metrics.input_tokens + agent_result.metrics.output_tokens
            total_llm_time += agent_result.metrics.total_time
            total_tool_calls += agent_result.tool_calls_made

        stats["total_tokens"] = total_tokens
        stats["total_llm_time_seconds"] = round(total_llm_time, 2)
        stats["total_tool_calls"] = total_tool_calls
        stats["avg_tokens_per_second"] = (
            round(total_tokens / total_llm_time) if total_llm_time > 0 else 0
        )
        stats["engagement_wall_clock_seconds"] = round(result.duration, 2)

        # Attack-to-defense latency (if we have both exploit and defender data)
        exploit = result.agent_results.get("exploit")
        defender = result.agent_results.get("defender")
        if exploit and defender and exploit.success and defender.success:
            exploit_start = exploit.start_time
            defender_responses = defender.findings.get("responses", [])
            if defender_responses:
                first_defense = defender_responses[0].get("timestamp", 0)
                if first_defense > 0 and exploit_start > 0:
                    latency = first_defense - exploit_start
                    stats["attack_to_first_defense_seconds"] = round(latency, 2)

        return stats
