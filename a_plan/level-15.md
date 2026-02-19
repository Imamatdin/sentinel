# LEVEL 15: Multi-Agent Debate & False Positive Reduction

## Context
Even with PoC verification, some findings are noise (environmental artifacts, non-exploitable conditions, severity inflation). This level adds a debate protocol where 2-3 independent reviewer agents challenge each finding. Research shows 2-3 reviewers are sufficient (diminishing returns beyond), and debate only on low-confidence or high-impact findings saves cost.

Research: Block 3 (Debate architecture, Reflexion, LATS). Shannon uses multi-stage self-validation. XBOW uses headless browser validators + custom checkers.

**Enhances:** L14 (Auto-Patch). Debate protocol also reviews generated patches.

## Why
False positives destroy trust. A single FP in an executive report kills credibility. Debate architecture is the cheapest way to push precision from ~85% to ~95%+ without sacrificing recall. Also: each reviewer generates different reasoning traces → richer evidence for the final report.

---

## Files to Create

### `src/sentinel/agents/debate/__init__.py`
```python
"""Multi-agent debate and review system for finding verification."""
```

### `src/sentinel/agents/debate/reviewer.py`
```python
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
from dataclasses import dataclass
from enum import Enum
from sentinel.logging import get_logger
from sentinel.llm.model_router import ModelRouter, TaskType

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


class FindingReviewer:
    """Independent reviewer agent that evaluates a finding."""
    
    def __init__(self, reviewer_id: str, router: ModelRouter, persona: str = ""):
        self.reviewer_id = reviewer_id
        self.router = router
        self.persona = persona or self._default_persona()
    
    def _default_persona(self) -> str:
        personas = {
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
        # Cycle through personas based on reviewer_id
        keys = list(personas.keys())
        idx = hash(self.reviewer_id) % len(keys)
        return personas[keys[idx]]
    
    async def review(self, finding: dict, evidence: dict) -> ReviewResult:
        """
        Review a finding and produce a verdict.
        
        Args:
            finding: {category, severity, description, target_url, hypothesis_id}
            evidence: {poc_script, http_traces, response_snippets, screenshots}
        """
        model = self.router.route(TaskType.VERIFY_FINDING)
        
        prompt = f"""{self.persona}

FINDING TO REVIEW:
Category: {finding.get('category')}
Severity: {finding.get('severity')}
Target: {finding.get('target_url')}
Description: {finding.get('description')}

EVIDENCE PROVIDED:
PoC Script: {evidence.get('poc_script', 'N/A')[:500]}
HTTP Traces: {evidence.get('http_traces', 'N/A')[:1000]}
Response Snippets: {evidence.get('response_snippets', 'N/A')[:500]}

Evaluate this finding. Respond in EXACTLY this JSON format:
{{
  "verdict": "valid" | "invalid" | "uncertain",
  "confidence": 0.0-1.0,
  "reasoning": "Your detailed reasoning...",
  "severity_adjustment": "agree" | "upgrade" | "downgrade",
  "evidence_quality": "strong" | "moderate" | "weak"
}}"""
        
        try:
            from sentinel.llm.client import complete
            response = await complete(prompt, model=model.model_id, provider=model.provider)
            return self._parse_review(response)
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
        import json
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
```

### `src/sentinel/agents/debate/debate_engine.py`
```python
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
from sentinel.llm.model_router import ModelRouter
from sentinel.logging import get_logger

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
    
    def __init__(self, router: ModelRouter, num_reviewers: int = NUM_REVIEWERS):
        self.router = router
        self.num_reviewers = num_reviewers
        self.reviewers = [
            FindingReviewer(f"reviewer_{i}", router)
            for i in range(num_reviewers)
        ]
    
    def should_debate(self, finding: dict) -> bool:
        """Determine if a finding needs multi-agent debate."""
        confidence = finding.get("confidence", 0.0)
        severity = finding.get("severity", "").lower()
        
        # Always debate high/critical severity findings
        if severity in SEVERITY_ALWAYS_DEBATE:
            return True
        
        # Debate low-confidence findings
        if confidence < CONFIDENCE_THRESHOLD:
            return True
        
        return False
    
    async def debate(self, finding: dict, evidence: dict) -> DebateOutcome:
        """
        Run debate protocol on a finding.
        
        Returns DebateOutcome with final verdict and aggregated reasoning.
        """
        # Run all reviewers in parallel
        tasks = [
            reviewer.review(finding, evidence)
            for reviewer in self.reviewers
        ]
        reviews = await asyncio.gather(*tasks)
        
        # Tally votes
        verdicts = [r.verdict for r in reviews]
        valid_count = verdicts.count(Verdict.VALID)
        invalid_count = verdicts.count(Verdict.INVALID)
        uncertain_count = verdicts.count(Verdict.UNCERTAIN)
        
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
        escalate = (valid_count > 0 and invalid_count > 0 and
                    max(valid_count, invalid_count) <= self.num_reviewers // 2)
        
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
                f"[{r.reviewer_id} — {r.verdict.value} ({r.confidence:.0%})]: {r.reasoning}"
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
            f"Debate result for {outcome.finding_id}: "
            f"{final_verdict.value} ({final_confidence:.0%}), "
            f"consensus={consensus}, escalate={escalate}"
        )
        
        return outcome
    
    async def batch_debate(self, findings: list[dict], evidence_map: dict) -> list[DebateOutcome]:
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
```

---

## Tests

### `tests/agents/debate/test_reviewer.py`
```python
import pytest
from sentinel.agents.debate.reviewer import FindingReviewer, Verdict, ReviewResult
from sentinel.llm.model_router import ModelRouter

class TestFindingReviewer:
    def setup_method(self):
        self.reviewer = FindingReviewer("test_0", ModelRouter())
    
    def test_parse_valid_json(self):
        response = '{"verdict": "valid", "confidence": 0.9, "reasoning": "PoC works", "severity_adjustment": "agree", "evidence_quality": "strong"}'
        result = self.reviewer._parse_review(response)
        assert result.verdict == Verdict.VALID
        assert result.confidence == 0.9
    
    def test_parse_markdown_wrapped(self):
        response = '```json\n{"verdict": "invalid", "confidence": 0.8, "reasoning": "FP", "severity_adjustment": "downgrade", "evidence_quality": "weak"}\n```'
        result = self.reviewer._parse_review(response)
        assert result.verdict == Verdict.INVALID
    
    def test_parse_garbage_returns_uncertain(self):
        result = self.reviewer._parse_review("this is not json")
        assert result.verdict == Verdict.UNCERTAIN
    
    def test_default_personas_cycle(self):
        r0 = FindingReviewer("r_0", ModelRouter())
        r1 = FindingReviewer("r_1", ModelRouter())
        # Different IDs should (likely) get different personas
        # Not guaranteed due to hash, but verifies no crash
        assert len(r0.persona) > 0
        assert len(r1.persona) > 0
```

### `tests/agents/debate/test_debate_engine.py`
```python
import pytest
from sentinel.agents.debate.debate_engine import DebateEngine, DebateOutcome, CONFIDENCE_THRESHOLD
from sentinel.agents.debate.reviewer import Verdict
from sentinel.llm.model_router import ModelRouter

class TestDebateEngine:
    def setup_method(self):
        self.engine = DebateEngine(ModelRouter(), num_reviewers=3)
    
    def test_should_debate_low_confidence(self):
        finding = {"confidence": 0.5, "severity": "medium"}
        assert self.engine.should_debate(finding) is True
    
    def test_should_debate_high_severity(self):
        finding = {"confidence": 0.95, "severity": "critical"}
        assert self.engine.should_debate(finding) is True
    
    def test_should_not_debate_confident_low_sev(self):
        finding = {"confidence": 0.95, "severity": "low"}
        assert self.engine.should_debate(finding) is False
    
    def test_auto_approve_in_batch(self):
        findings = [{"finding_id": "f1", "confidence": 0.95, "severity": "low"}]
        import asyncio
        outcomes = asyncio.get_event_loop().run_until_complete(
            self.engine.batch_debate(findings, {})
        )
        assert outcomes[0].final_verdict == Verdict.VALID
        assert outcomes[0].consensus is True
        assert len(outcomes[0].reviews) == 0  # Skipped debate
```

---

## Acceptance Criteria
- [ ] FindingReviewer generates independent verdicts with reasoning
- [ ] Three reviewer personas (skeptic, validator, impact) provide diverse perspectives
- [ ] DebateEngine majority-vote produces VALID/INVALID/UNCERTAIN
- [ ] Split decisions get `escalate_to_human=True`
- [ ] High-confidence + low-severity findings skip debate (cost optimization)
- [ ] Aggregated reasoning combines all reviewer insights
- [ ] All tests pass