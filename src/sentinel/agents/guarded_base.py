"""Base agent class with tool-guarded LLM execution.

Implements the core safety pattern:
1. LLM proposes actions via structured output
2. Policy engine validates against allowlist
3. Verification layer checks for hallucinations
4. Only validated actions execute

This extends the original BaseAgent pattern with policy enforcement
and hallucination prevention layers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import json

from pydantic import BaseModel

from sentinel.core import get_logger, get_settings
from sentinel.agents.llm_client import (
    BaseLLMClient,
    LLMMessage,
    LLMResponse,
    get_llm_client,
    LLMProvider,
)
from sentinel.agents.policy import (
    PolicyEngine,
    EngagementPolicy,
    ActionRequest,
    ActionDecision,
    ActionType,
)
from sentinel.agents.schemas import AgentThought, ActionProposal, AgentResponse
from sentinel.agents.verification import FindingVerifier, VerificationResult

logger = get_logger(__name__)


@dataclass
class AgentContext:
    """Context for agent execution."""
    engagement_id: str
    target_url: str
    policy: EngagementPolicy

    # State
    current_phase: str = "initialization"
    iteration: int = 0
    max_iterations: int = 50

    # History
    actions_taken: list[ActionDecision] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    # Tokens/cost tracking
    total_input_tokens: int = 0
    total_output_tokens: int = 0


@dataclass
class GuardedAgentResult:
    """Result from a guarded agent execution."""
    success: bool
    context: AgentContext
    output: Any
    duration_seconds: float
    iterations: int
    verification_summary: dict[str, Any] = field(default_factory=dict)


class GuardedBaseAgent(ABC):
    """Base class for Sentinel agents with tool-guarded execution.

    Unlike the original BaseAgent (which uses CerebrasClient directly),
    this class wraps all LLM interactions with:
    - Policy enforcement (scope, risk level, rate limiting)
    - Structured output validation (Pydantic schemas)
    - Hallucination verification checks
    """

    def __init__(
        self,
        name: str,
        llm_client: BaseLLMClient | None = None,
        provider: LLMProvider = LLMProvider.ANTHROPIC,
    ):
        self.name = name
        self.llm = llm_client or get_llm_client(provider)
        self.verifier = FindingVerifier()
        self.logger = get_logger(f"agent.{name}")

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """System prompt for this agent."""
        pass

    @property
    def allowed_actions(self) -> list[ActionType]:
        """Actions this agent is allowed to request."""
        return [ActionType.UPDATE_GRAPH, ActionType.CREATE_FINDING]

    async def run(
        self,
        context: AgentContext,
        initial_input: str,
    ) -> GuardedAgentResult:
        """Run the agent with tool-guarded execution."""
        start_time = datetime.utcnow()
        policy_engine = PolicyEngine(context.policy)

        messages = [LLMMessage(role="user", content=initial_input)]

        self.logger.info(
            "Agent starting",
            agent=self.name,
            engagement=context.engagement_id,
            target=context.target_url,
        )

        try:
            while context.iteration < context.max_iterations:
                context.iteration += 1

                # Step 1: Get LLM response with structured output
                response = await self._get_structured_response(
                    messages=messages,
                    context=context,
                )

                # Step 2: Validate proposed actions against policy
                approved_actions: list[tuple[ActionProposal, ActionDecision]] = []
                for proposal in response.proposed_actions:
                    decision = await self._validate_action(
                        proposal=proposal,
                        policy_engine=policy_engine,
                        context=context,
                    )
                    context.actions_taken.append(decision)

                    if decision.approved:
                        approved_actions.append((proposal, decision))
                    else:
                        self.logger.warning(
                            "Action rejected",
                            action=proposal.action_type,
                            reason=decision.reason,
                        )

                # Step 3: Execute approved actions
                results = []
                for proposal, decision in approved_actions:
                    if decision.requires_human_approval:
                        self.logger.info(
                            "Action requires human approval",
                            action=proposal.action_type,
                        )
                        # In production, this would signal to Temporal workflow
                        continue

                    result = await self._execute_action(proposal, context)
                    results.append(result)

                # Step 4: Verify any findings
                for finding in response.findings:
                    verification = await self.verifier.verify_hypothesis(finding)
                    if all(v.passed for v in verification):
                        context.findings.append(finding.model_dump())
                    else:
                        self.logger.warning(
                            "Finding failed verification",
                            finding=finding.hypothesis,
                            failures=[v.details for v in verification if not v.passed],
                        )

                # Step 5: Check if we should continue
                if response.needs_human_input:
                    self.logger.info(
                        "Agent needs human input",
                        reason=response.human_input_reason,
                    )
                    break

                if not response.proposed_actions:
                    self.logger.info("No more actions proposed, stopping")
                    break

                # Step 6: Feed results back for next iteration
                result_summary = self._summarize_results(results, context)
                messages.append(LLMMessage(
                    role="assistant",
                    content=json.dumps(response.model_dump(), default=str),
                ))
                messages.append(LLMMessage(
                    role="user",
                    content=f"Results from executed actions:\n{result_summary}\n\nContinue analysis.",
                ))

        except Exception as e:
            self.logger.error("Agent execution failed", error=str(e))
            context.errors.append(str(e))
            duration = (datetime.utcnow() - start_time).total_seconds()
            return GuardedAgentResult(
                success=False,
                context=context,
                output={"error": str(e)},
                duration_seconds=duration,
                iterations=context.iteration,
                verification_summary=self.verifier.get_summary(),
            )

        duration = (datetime.utcnow() - start_time).total_seconds()

        self.logger.info(
            "Agent completed",
            agent=self.name,
            iterations=context.iteration,
            findings=len(context.findings),
            duration=duration,
        )

        return GuardedAgentResult(
            success=True,
            context=context,
            output=await self._compile_output(context),
            duration_seconds=duration,
            iterations=context.iteration,
            verification_summary=self.verifier.get_summary(),
        )

    async def _get_structured_response(
        self,
        messages: list[LLMMessage],
        context: AgentContext,
    ) -> AgentResponse:
        """Get a structured response from the LLM."""
        enhanced_system = f"""{self.system_prompt}

## Current Context
- Engagement: {context.engagement_id}
- Target: {context.target_url}
- Phase: {context.current_phase}
- Iteration: {context.iteration}/{context.max_iterations}
- Findings so far: {len(context.findings)}

## IMPORTANT RULES
1. You MUST respond with structured JSON matching the AgentResponse schema
2. Every finding MUST have concrete evidence - no speculation
3. Every action MUST have justification
4. Set confidence appropriately - start LOW and upgrade with evidence
5. If uncertain, set needs_human_input=true
"""

        response = await self.llm.complete_structured(
            messages=messages,
            output_schema=AgentResponse,
            system=enhanced_system,
        )

        # Track token usage
        # (structured response wraps complete() which returns LLMResponse)
        return response

    async def _validate_action(
        self,
        proposal: ActionProposal,
        policy_engine: PolicyEngine,
        context: AgentContext,
    ) -> ActionDecision:
        """Validate a proposed action against policy."""
        try:
            action_type = ActionType(proposal.action_type)
        except ValueError:
            return ActionDecision(
                request=ActionRequest(
                    action_type=ActionType.SHELL_COMMAND,  # Default for unknown
                    parameters=proposal.parameters,
                    justification=proposal.justification,
                    target=proposal.target,
                ),
                approved=False,
                reason=f"Unknown action type: {proposal.action_type}",
            )

        # Check if agent is allowed to request this action
        if action_type not in self.allowed_actions:
            request = ActionRequest(
                action_type=action_type,
                parameters=proposal.parameters,
                justification=proposal.justification,
                target=proposal.target,
            )
            return ActionDecision(
                request=request,
                approved=False,
                reason=f"Agent '{self.name}' not authorized for action '{action_type.value}'",
            )

        request = ActionRequest(
            action_type=action_type,
            parameters=proposal.parameters,
            justification=proposal.justification,
            target=proposal.target,
        )

        return policy_engine.evaluate(request)

    @abstractmethod
    async def _execute_action(
        self,
        proposal: ActionProposal,
        context: AgentContext,
    ) -> dict[str, Any]:
        """Execute an approved action. Subclasses implement tool-specific logic."""
        pass

    async def _compile_output(self, context: AgentContext) -> dict[str, Any]:
        """Compile final output from agent execution."""
        return {
            "findings": context.findings,
            "actions_taken": len(context.actions_taken),
            "actions_approved": sum(1 for a in context.actions_taken if a.approved),
            "actions_rejected": sum(1 for a in context.actions_taken if not a.approved),
            "errors": context.errors,
            "verification": self.verifier.get_summary(),
        }

    def _summarize_results(
        self,
        results: list[dict[str, Any]],
        context: AgentContext,
    ) -> str:
        """Summarize action results for feeding back to LLM."""
        if not results:
            return "No actions were executed this iteration."

        summary_parts = []
        for i, result in enumerate(results, 1):
            summary_parts.append(f"Action {i}: {json.dumps(result, default=str)[:2000]}")

        return "\n".join(summary_parts)
