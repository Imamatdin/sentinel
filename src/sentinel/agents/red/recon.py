"""Reconnaissance agent.

The ReconAgent is the first agent to run in an engagement. Its job is to
map the target: open ports, accessible paths, API endpoints, and technology
fingerprinting. It does NOT attempt exploitation.

Tools available: http_request, port_scan, path_scan, api_discover, check_challenges
"""

import time
from typing import Any, Optional

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.events.bus import EventType
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class ReconAgent(BaseAgent):
    """Reconnaissance agent for target mapping.

    Discovers attack surface: open ports, web paths, API endpoints,
    technology stack. Output feeds into ExploitAgent.
    """

    def __init__(self, target_url: str, **kwargs: Any):
        """Initialize ReconAgent.

        Args:
            target_url: Base URL of the target (e.g. "http://localhost:3000")
            **kwargs: Passed to BaseAgent.__init__
        """
        super().__init__(**kwargs)
        self.target_url = target_url

    @property
    def system_prompt(self) -> str:
        return f"""You are SENTINEL's reconnaissance agent. Your mission is to thoroughly map the attack surface of the target application.

## Target
- URL: {self.target_url}
- Type: Web application (OWASP Juice Shop)

## Objectives
1. Scan for open ports on the target host
2. Discover accessible web paths and directories
3. Enumerate API endpoints
4. Identify the technology stack and frameworks
5. Check the Juice Shop challenge scoreboard for baseline

## Rules
- Do NOT attempt any exploitation. Recon only.
- Be systematic: start with port scan, then path discovery, then API enumeration.
- Record everything you find. Your output feeds directly into the exploit agent.
- Be efficient with tool calls. Combine information across results.

## Output Format
After reconnaissance is complete, provide a structured summary:
1. Open ports and services
2. Discovered web paths (with status codes and interesting responses)
3. API endpoints found
4. Technology fingerprints
5. Potential attack vectors identified (but NOT attempted)
6. Juice Shop challenge status"""

    @property
    def tool_schemas(self) -> list[dict[str, Any]]:
        """ReconAgent only gets recon tools, not exploit tools."""
        if self.tool_registry is None:
            return []
        recon_tools = ["http_request", "port_scan", "path_scan", "api_discover", "check_challenges"]
        return self.tool_registry.get_schemas(tool_names=recon_tools)

    async def run(self, context: Optional[dict[str, Any]] = None) -> AgentResult:
        """Execute reconnaissance against the target."""
        start_time = time.time()

        logger.info("recon_starting", target=self.target_url, agent=self.name)

        try:
            conversation, metrics = await self._run_tool_loop(
                user_message=(
                    f"Perform comprehensive reconnaissance on {self.target_url}. "
                    "Start with a port scan, then discover web paths and API endpoints. "
                    "Document everything you find for the exploit agent."
                ),
            )

            # Extract findings from the final response
            final_response = self._extract_last_response(conversation)

            findings = {
                "target_url": self.target_url,
                "summary": final_response,
                "tool_calls_made": sum(
                    len(m.tool_calls) for m in conversation if m.tool_calls
                ),
            }

            # Emit findings event
            await self._emit(EventType.RED_FINDING, {
                "agent": self.name,
                "phase": "recon",
                "findings": findings,
            })

            await self._emit(EventType.RED_PHASE_COMPLETE, {
                "agent": self.name,
                "phase": "recon",
            })

            logger.info(
                "recon_complete",
                agent=self.name,
                tool_calls=findings["tool_calls_made"],
                duration=f"{time.time() - start_time:.1f}s",
            )

            return AgentResult(
                agent_name=self.name,
                success=True,
                conversation=conversation,
                metrics=metrics,
                findings=findings,
                start_time=start_time,
                end_time=time.time(),
            )

        except Exception as e:
            logger.error("recon_failed", agent=self.name, error=str(e))
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
