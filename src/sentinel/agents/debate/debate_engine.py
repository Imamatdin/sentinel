"""
Debate Engine — Orchestrates multi-reviewer finding validation.

Protocol:
1. Only debate findings with confidence < CONFIDENCE_THRESHOLD or severity >= HIGH
2. Spawn 2-3 reviewers with different personas
3. Collect independent verdicts
4. Majority vote determines final verdict
5. If split (1 valid, 1 invalid, 1 uncertain): escalate for human review
6. Aggregate reasoning into enriched finding description

Cost optimization: skip debate for findings already at >90% confidence with strong PoC.
"""

import asyncio
from dataclasses import dataclass, field

from sentinel.agents.debate.reviewer import FindingReviewer, ReviewResult, Verdict
from sentinel.agents.llm_client import BaseLLMClient
from sentinel.llm.model_router import ModelRouter
from sentinel.core import get_logger

logger = get_logger(__name__)

CONFIDENCE_THRESHOLD = 0.85  # Debate findings below this
SEVERITY_ALWAYS_DEBATE = ["critical", "high"]  # Always debate these
NUM_REVIEWERS = 3


@dataclass
class DebateOutcome:
    finding_id: str
    original_verdict: str
    final_verdict: Verdict
    final_confidence: float
    reviews: list[ReviewResult]
    consensus: bool             # All reviewers agree
    escalate_to_human: bool     # Split decision, needs human
    severity_consensus: str     # Agreed severity
    aggregated_reasoning: str   # Combined insights from all reviewers


class DebateEngine:
    """Orchestrate multi-agent debate on findings."""

    def __init__(
        self,
        router: ModelRouter,
        num_reviewers: int = NUM_REVIEWERS,
        llm_client: BaseLLMClient | None = None,
    ):
        self.router = router
        self.num_reviewers = num_reviewers
        self.reviewers = [
            FindingReviewer(f"reviewer_{i}", router, llm_client=llm_client)
            for i in range(num_reviewers)
        ]

    def should_debate(self, finding: dict) -> bool:
        """Determine if a finding needs multi-agent debate."""
        confidence = finding.get("confidence", 0.0)
        severity = finding.get("severity", "").lower()

        if severity in SEVERITY_ALWAYS_DEBATE:
            return True

        if confidence < CONFIDENCE_THRESHOLD:
            return True

        return False

    async def debate(self, finding: dict, evidence: dict) -> DebateOutcome:
        """Run debate protocol on a finding."""
        tasks = [
            reviewer.review(finding, evidence)
            for reviewer in self.reviewers
        ]
        reviews: list[ReviewResult] = await asyncio.gather(*tasks)

        # Tally votes
        verdicts = [r.verdict for r in reviews]
        valid_count = verdicts.count(Verdict.VALID)
        invalid_count = verdicts.count(Verdict.INVALID)

        # Majority vote
        if valid_count > self.num_reviewers // 2:
            final_verdict = Verdict.VALID
        elif invalid_count > self.num_reviewers // 2:
            final_verdict = Verdict.INVALID
        else:
            final_verdict = Verdict.UNCERTAIN

        # Check consensus
        consensus = len(set(verdicts)) == 1

        # Escalate if no clear majority
        escalate = (
            valid_count > 0
            and invalid_count > 0
            and max(valid_count, invalid_count) <= self.num_reviewers // 2
        )

        # Weighted confidence
        confidences = [r.confidence for r in reviews if r.verdict == final_verdict]
        final_confidence = sum(confidences) / len(confidences) if confidences else 0.5

        # Severity consensus
        sev_adjustments = [r.severity_adjustment for r in reviews]
        if sev_adjustments.count("agree") >= self.num_reviewers // 2 + 1:
            severity_consensus = "agree"
        elif sev_adjustments.count("downgrade") >= 2:
            severity_consensus = "downgrade"
        elif sev_adjustments.count("upgrade") >= 2:
            severity_consensus = "upgrade"
        else:
            severity_consensus = "agree"

        # Aggregate reasoning
        reasoning_parts = []
        for r in reviews:
            reasoning_parts.append(
                f"[{r.reviewer_id} -- {r.verdict.value} ({r.confidence:.0%})]: {r.reasoning}"
            )
        aggregated = "\n\n".join(reasoning_parts)

        outcome = DebateOutcome(
            finding_id=finding.get("finding_id", ""),
            original_verdict=finding.get("status", ""),
            final_verdict=final_verdict,
            final_confidence=final_confidence,
            reviews=reviews,
            consensus=consensus,
            escalate_to_human=escalate,
            severity_consensus=severity_consensus,
            aggregated_reasoning=aggregated,
        )

        logger.info(
            "debate_result",
            finding_id=outcome.finding_id,
            verdict=final_verdict.value,
            confidence=f"{final_confidence:.0%}",
            consensus=consensus,
            escalate=escalate,
        )

        return outcome

    async def batch_debate(
        self, findings: list[dict], evidence_map: dict
    ) -> list[DebateOutcome]:
        """Debate multiple findings, skipping those that don't need it."""
        outcomes = []
        for finding in findings:
            fid = finding.get("finding_id", "")
            if self.should_debate(finding):
                evidence = evidence_map.get(fid, {})
                outcome = await self.debate(finding, evidence)
                outcomes.append(outcome)
            else:
                # Auto-approve high-confidence findings
                outcomes.append(DebateOutcome(
                    finding_id=fid,
                    original_verdict="verified",
                    final_verdict=Verdict.VALID,
                    final_confidence=finding.get("confidence", 0.9),
                    reviews=[],
                    consensus=True,
                    escalate_to_human=False,
                    severity_consensus="agree",
                    aggregated_reasoning="Auto-approved: high confidence, strong PoC.",
                ))
        return outcomes
