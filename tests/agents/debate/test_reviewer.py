"""Tests for FindingReviewer."""

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
        assert len(r0.persona) > 0
        assert len(r1.persona) > 0
