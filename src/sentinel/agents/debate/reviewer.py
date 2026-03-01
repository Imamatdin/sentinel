"""
Finding Reviewer Agent — Independently evaluates whether a finding is valid.

Each reviewer gets:
- The finding details (category, target, description)
- The PoC evidence (HTTP traces, screenshots)
- The original hypothesis and reasoning

Each reviewer outputs:
- VALID / INVALID / UNCERTAIN verdict
- Confidence score (0.0-1.0)
- Reasoning (why valid or why FP)
- Suggested severity adjustment (if any)
"""

import json
from dataclasses import dataclass
from enum import Enum

from sentinel.agents.llm_client import BaseLLMClient, LLMMessage, get_llm_client, LLMProvider
from sentinel.llm.model_router import ModelRouter, TaskType
from sentinel.core import get_logger

logger = get_logger(__name__)


class Verdict(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    UNCERTAIN = "uncertain"


@dataclass
class ReviewResult:
    reviewer_id: str
    verdict: Verdict
    confidence: float       # 0.0-1.0
    reasoning: str
    severity_adjustment: str  # "agree", "upgrade", "downgrade"
    evidence_quality: str    # "strong", "moderate", "weak"


PERSONAS = {
    "skeptic": (
        "You are a skeptical security reviewer. You look for reasons a finding "
        "might be a false positive. You check: Is the PoC truly exploitable in "
        "production? Could the behavior be benign? Is the severity inflated?"
    ),
    "validator": (
        "You are a thorough security validator. You verify the evidence chain: "
        "Is the HTTP trace complete? Does the response actually prove data leakage "
        "or unauthorized access? Could this be a testing artifact?"
    ),
    "impact": (
        "You are a business impact assessor. You evaluate: What's the real-world "
        "impact? Is sensitive data actually exposed or just test data? "
        "What's the attack complexity in a real environment?"
    ),
}


class FindingReviewer:
    """Independent reviewer agent that evaluates a finding."""

    def __init__(
        self,
        reviewer_id: str,
        router: ModelRouter,
        persona: str = "",
        llm_client: BaseLLMClient | None = None,
    ):
        self.reviewer_id = reviewer_id
        self.router = router
        self.persona = persona or self._default_persona()
        if llm_client is not None:
            self.llm = llm_client
        else:
            model_config = router.route(TaskType.VERIFY_FINDING)
            provider = LLMProvider(model_config.provider)
            self.llm = get_llm_client(provider, model_config.model_id)

    def _default_persona(self) -> str:
        keys = list(PERSONAS.keys())
        idx = hash(self.reviewer_id) % len(keys)
        return PERSONAS[keys[idx]]

    async def review(self, finding: dict, evidence: dict) -> ReviewResult:
        """Review a finding and produce a verdict."""
        prompt = f"""{self.persona}

FINDING TO REVIEW:
Category: {finding.get('category')}
Severity: {finding.get('severity')}
Target: {finding.get('target_url')}
Description: {finding.get('description')}

EVIDENCE PROVIDED:
PoC Script: {str(evidence.get('poc_script', 'N/A'))[:500]}
HTTP Traces: {str(evidence.get('http_traces', 'N/A'))[:1000]}
Response Snippets: {str(evidence.get('response_snippets', 'N/A'))[:500]}

Evaluate this finding. Respond in EXACTLY this JSON format:
{{
  "verdict": "valid" | "invalid" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "Your detailed reasoning...",
  "severity_adjustment": "agree" | "upgrade" | "downgrade",
  "evidence_quality": "strong" | "moderate" | "weak"
}}"""

        try:
            response = await self.llm.complete(
                messages=[LLMMessage(role="user", content=prompt)],
                system="You are a security finding reviewer. Respond only with valid JSON.",
                max_tokens=1024,
                temperature=0.1,
            )
            return self._parse_review(response.content)
        except Exception as e:
            logger.error(f"Reviewer {self.reviewer_id} failed: {e}")
            return ReviewResult(
                reviewer_id=self.reviewer_id,
                verdict=Verdict.UNCERTAIN,
                confidence=0.0,
                reasoning=f"Review failed: {e}",
                severity_adjustment="agree",
                evidence_quality="weak",
            )

    def _parse_review(self, response: str) -> ReviewResult:
        """Parse LLM response into ReviewResult."""
        try:
            text = response.strip()
            if "```" in text:
                text = text.split("```")[1].strip().lstrip("json\n")
            data = json.loads(text)
            return ReviewResult(
                reviewer_id=self.reviewer_id,
                verdict=Verdict(data.get("verdict", "uncertain")),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", ""),
                severity_adjustment=data.get("severity_adjustment", "agree"),
                evidence_quality=data.get("evidence_quality", "moderate"),
            )
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning(f"Failed to parse review response: {e}")
            return ReviewResult(
                reviewer_id=self.reviewer_id,
                verdict=Verdict.UNCERTAIN,
                confidence=0.3,
                reasoning=f"Parse error. Raw response: {response[:200]}",
                severity_adjustment="agree",
                evidence_quality="weak",
            )
