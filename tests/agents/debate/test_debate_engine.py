"""Tests for DebateEngine."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.agents.debate.debate_engine import (
    DebateEngine,
    DebateOutcome,
    CONFIDENCE_THRESHOLD,
)
from sentinel.agents.debate.reviewer import Verdict, ReviewResult
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

    @pytest.mark.asyncio
    async def test_auto_approve_in_batch(self):
        findings = [{"finding_id": "f1", "confidence": 0.95, "severity": "low"}]
        outcomes = await self.engine.batch_debate(findings, {})
        assert outcomes[0].final_verdict == Verdict.VALID
        assert outcomes[0].consensus is True
        assert len(outcomes[0].reviews) == 0

    @pytest.mark.asyncio
    async def test_debate_majority_valid(self):
        """When majority of reviewers say VALID, outcome is VALID."""
        mock_reviews = [
            ReviewResult("r_0", Verdict.VALID, 0.9, "Looks real", "agree", "strong"),
            ReviewResult("r_1", Verdict.VALID, 0.85, "Confirmed", "agree", "strong"),
            ReviewResult("r_2", Verdict.INVALID, 0.6, "Might be FP", "downgrade", "weak"),
        ]
        for i, reviewer in enumerate(self.engine.reviewers):
            reviewer.review = AsyncMock(return_value=mock_reviews[i])

        finding = {"finding_id": "f1", "severity": "high", "confidence": 0.7}
        outcome = await self.engine.debate(finding, {})
        assert outcome.final_verdict == Verdict.VALID
        assert outcome.consensus is False

    @pytest.mark.asyncio
    async def test_debate_majority_invalid(self):
        """When majority say INVALID, outcome is INVALID."""
        mock_reviews = [
            ReviewResult("r_0", Verdict.INVALID, 0.9, "FP", "downgrade", "weak"),
            ReviewResult("r_1", Verdict.INVALID, 0.85, "Not real", "downgrade", "weak"),
            ReviewResult("r_2", Verdict.VALID, 0.6, "Could be real", "agree", "moderate"),
        ]
        for i, reviewer in enumerate(self.engine.reviewers):
            reviewer.review = AsyncMock(return_value=mock_reviews[i])

        finding = {"finding_id": "f2", "severity": "high", "confidence": 0.5}
        outcome = await self.engine.debate(finding, {})
        assert outcome.final_verdict == Verdict.INVALID

    @pytest.mark.asyncio
    async def test_debate_escalation_on_split(self):
        """Split decision triggers escalation to human."""
        mock_reviews = [
            ReviewResult("r_0", Verdict.VALID, 0.7, "Real", "agree", "moderate"),
            ReviewResult("r_1", Verdict.INVALID, 0.7, "FP", "downgrade", "weak"),
            ReviewResult("r_2", Verdict.UNCERTAIN, 0.5, "Unclear", "agree", "weak"),
        ]
        for i, reviewer in enumerate(self.engine.reviewers):
            reviewer.review = AsyncMock(return_value=mock_reviews[i])

        finding = {"finding_id": "f3", "severity": "critical", "confidence": 0.5}
        outcome = await self.engine.debate(finding, {})
        assert outcome.escalate_to_human is True
