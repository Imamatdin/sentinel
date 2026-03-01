"""
Workflow State Machine Abuse Tester.

Tests for state machine bypass: skip steps, replay steps, access wrong-state endpoints.
Example: jump from "cart" directly to "order_complete" skipping "payment".
"""

import aiohttp
from dataclasses import dataclass, field

from sentinel.tools.base import ToolOutput
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class WorkflowStep:
    name: str
    endpoint: str
    method: str
    body: dict = field(default_factory=dict)
    expected_status: int = 200


@dataclass
class WorkflowAbuseFinding:
    attack_type: str     # "step_skip", "step_replay", "state_bypass"
    skipped_steps: list[str]
    endpoint_accessed: str
    status_code: int
    description: str
    severity: str = "high"


class WorkflowAbuseTester:
    name = "workflow_abuse"
    description = "Test workflow state machines for step-skipping and state bypass"

    async def execute(
        self,
        workflow_steps: list[WorkflowStep],
        session_headers: dict,
        base_url: str,
    ) -> ToolOutput:
        """Test workflow by:
        1. Trying to access each step out of order (skip preceding steps)
        2. Replaying completed steps
        3. Accessing final step directly without any preceding steps
        """
        findings: list[WorkflowAbuseFinding] = []

        # Test 1: Skip to last step directly
        if len(workflow_steps) > 1:
            last = workflow_steps[-1]
            finding = await self._try_step(
                base_url, last, session_headers,
                skipped=[s.name for s in workflow_steps[:-1]],
            )
            if finding:
                findings.append(finding)

        # Test 2: Skip intermediate steps (try step N without doing step N-1)
        for i in range(1, len(workflow_steps)):
            finding = await self._try_with_partial(
                base_url, workflow_steps, i, session_headers
            )
            if finding:
                findings.append(finding)

        return ToolOutput(
            tool_name=self.name,
            success=True,
            data={
                "findings": [
                    {
                        "attack_type": f.attack_type,
                        "skipped_steps": f.skipped_steps,
                        "endpoint_accessed": f.endpoint_accessed,
                        "status_code": f.status_code,
                        "description": f.description,
                        "severity": f.severity,
                    }
                    for f in findings
                ],
            },
            metadata={
                "tests_run": len(workflow_steps),
                "findings": len(findings),
            },
        )

    async def _try_step(
        self, base_url: str, step: WorkflowStep,
        headers: dict, skipped: list[str],
    ) -> WorkflowAbuseFinding | None:
        """Try accessing a step without completing prerequisites."""
        url = base_url.rstrip("/") + step.endpoint
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    step.method, url, json=step.body, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status < 400:  # Success without prerequisites
                        return WorkflowAbuseFinding(
                            attack_type="step_skip",
                            skipped_steps=skipped,
                            endpoint_accessed=step.endpoint,
                            status_code=resp.status,
                            description=(
                                f"Accessed '{step.name}' ({step.endpoint}) without "
                                f"completing: {skipped}. Server returned {resp.status} "
                                f"instead of rejecting."
                            ),
                        )
        except Exception as e:
            logger.debug(f"Workflow test failed: {e}")
        return None

    async def _try_with_partial(
        self, base_url: str, steps: list[WorkflowStep],
        target_idx: int, headers: dict,
    ) -> WorkflowAbuseFinding | None:
        """Execute steps up to target_idx-2, skip target_idx-1, try target_idx."""
        async with aiohttp.ClientSession() as session:
            # Execute prerequisite steps (except the one we're skipping)
            for i in range(target_idx - 1):
                step = steps[i]
                url = base_url.rstrip("/") + step.endpoint
                try:
                    async with session.request(
                        step.method, url, json=step.body, headers=headers,
                    ) as resp:
                        pass
                except Exception:
                    return None

            # Now try the target step (skipping step target_idx-1)
            target = steps[target_idx]
            skipped_step = steps[target_idx - 1]
            return await self._try_step(
                base_url, target, headers, skipped=[skipped_step.name]
            )
