"""Forensics agent.

The ForensicsAgent has NO tools. It receives all engagement events and
generates an incident response report. This is the final blue team deliverable.
"""

import time
from typing import Any, Optional

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class ForensicsAgent(BaseAgent):
    """Incident response report generator. No tools, pure LLM synthesis."""

    @property
    def system_prompt(self) -> str:
        return """You are SENTINEL's forensics analyst. Your job is to create an incident response report based on all events from the engagement.

## Report Structure
1. **Incident Summary**: What happened, when, and the outcome
2. **Attack Timeline**: Chronological sequence of attacker actions
3. **Techniques Used**: MITRE ATT&CK mapping if applicable
4. **Defense Timeline**: When threats were detected and how they were mitigated
5. **Defense Effectiveness**:
   - Time from attack to detection (detection latency)
   - Time from detection to mitigation (response latency)
   - Attacks blocked vs. attacks that succeeded
6. **Gaps Identified**: What the blue team missed or was slow to respond to
7. **Recommendations**: How to improve detection and response
8. **Speed Analysis**: How inference speed impacted defense effectiveness

## Rules
- Be data-driven. Use timestamps and specific events.
- The speed narrative is critical: faster inference = faster defense = more attacks blocked
- Compare what was caught vs. what was missed
- Write for a CISO audience"""

    async def run(self, context: Optional[dict[str, Any]] = None) -> AgentResult:
        """Generate the incident response report."""
        start_time = time.time()

        logger.info("forensics_report_starting", agent=self.name)

        try:
            conversation, metrics = await self._run_tool_loop(
                user_message=(
                    "Generate a comprehensive incident response report based on "
                    "the engagement data provided below. Focus on attack timelines, "
                    "defense effectiveness, and the role of inference speed."
                ),
                context=context,
            )

            report = self._extract_last_response(conversation)

            return AgentResult(
                agent_name=self.name,
                success=True,
                conversation=conversation,
                metrics=metrics,
                findings={"report": report},
                start_time=start_time,
                end_time=time.time(),
            )

        except Exception as e:
            logger.error("forensics_report_failed", agent=self.name, error=str(e))
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=str(e),
                start_time=start_time,
                end_time=time.time(),
            )
