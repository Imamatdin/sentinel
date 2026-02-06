"""Red team report agent.

The ReportAgent has NO tools. It receives all red team findings and events,
then generates a structured penetration test report. This is the final
red team deliverable.
"""

import time
from typing import Any, Optional

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class ReportAgent(BaseAgent):
    """Pentest report generator. No tools, pure LLM synthesis."""

    @property
    def system_prompt(self) -> str:
        return """You are SENTINEL's penetration test report writer. Your job is to synthesize all reconnaissance and exploitation findings into a professional, structured report.

## Report Structure
1. **Executive Summary**: 2-3 sentence overview of the engagement
2. **Scope**: Target URL, engagement duration, tools used
3. **Findings Summary**: Table of vulnerabilities (severity, type, endpoint)
4. **Detailed Findings**: For each vulnerability:
   - Description
   - Affected endpoint
   - Proof of concept (exact payload/request)
   - Impact assessment
   - Remediation recommendation
5. **Attack Timeline**: Chronological list of actions taken
6. **Juice Shop Scorecard**: Challenges solved during the engagement
7. **Recommendations**: Prioritized list of security improvements

## Rules
- Be precise. Include exact URLs, payloads, and responses.
- Severity ratings: Critical, High, Medium, Low, Informational
- Write for a technical audience (security team or developers)
- If the blue team blocked any attacks, note that as a positive finding"""

    async def run(self, context: Optional[dict[str, Any]] = None) -> AgentResult:
        """Generate the penetration test report."""
        start_time = time.time()

        logger.info("report_generation_starting", agent=self.name)

        try:
            user_message = (
                "Generate a professional penetration test report based on "
                "the reconnaissance and exploitation findings provided below. "
                "Include all details: endpoints, payloads, responses, and severity ratings."
            )

            conversation, metrics = await self._run_tool_loop(
                user_message=user_message,
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
            logger.error("report_generation_failed", agent=self.name, error=str(e))
            return AgentResult(
                agent_name=self.name,
                success=False,
                error=str(e),
                start_time=start_time,
                end_time=time.time(),
            )
