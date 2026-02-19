"""Tests for HypothesisEngine."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.agents.hypothesis_engine import (
    HypothesisEngine,
    VulnHypothesis,
    HypothesisCategory,
    HypothesisConfidence
)


class TestHypothesisEngine:
    """Test HypothesisEngine functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_graph = AsyncMock()
        self.mock_llm = AsyncMock()
        self.engine = HypothesisEngine(self.mock_graph, self.mock_llm)

    def test_hypothesis_engine_initialization(self):
        """Test HypothesisEngine initializes with rules."""
        assert self.engine.graph == self.mock_graph
        assert self.engine.llm == self.mock_llm
        assert len(self.engine._rules) > 0

    def test_load_hypothesis_rules(self):
        """Test rules are loaded correctly."""
        rules = self.engine._load_hypothesis_rules()

        # Check we have rules for common patterns
        assert any("login" in rule["pattern"].get("path_contains", []) for rule in rules)
        assert any("upload" in rule["pattern"].get("path_contains", []) for rule in rules)
        assert any("api" in rule["pattern"].get("path_contains", []) for rule in rules)

    def test_apply_rules_login_endpoint(self):
        """Test rule matching for login endpoint."""
        endpoint = {
            "url": "http://test.com/login",
            "path": "/login",
            "params": ["username", "password"],
            "content_type": "application/json"
        }

        hypotheses = self.engine._apply_rules(endpoint)

        # Should generate AUTH_BYPASS and INJECTION hypotheses for login
        assert len(hypotheses) > 0
        categories = [h.category for h in hypotheses]
        assert HypothesisCategory.AUTH_BYPASS in categories
        assert HypothesisCategory.INJECTION in categories

    def test_apply_rules_upload_endpoint(self):
        """Test rule matching for upload endpoint."""
        endpoint = {
            "url": "http://test.com/upload",
            "path": "/upload",
            "params": ["file"],
            "content_type": "multipart/form-data"
        }

        hypotheses = self.engine._apply_rules(endpoint)

        # Should generate FILE_UPLOAD hypothesis
        assert len(hypotheses) > 0
        assert any(h.category == HypothesisCategory.FILE_UPLOAD for h in hypotheses)

    def test_apply_rules_api_with_id_param(self):
        """Test rule matching for API with ID parameter."""
        endpoint = {
            "url": "http://test.com/api/users/123",
            "path": "/api/users/123",
            "params": ["user_id"],
            "content_type": "application/json"
        }

        hypotheses = self.engine._apply_rules(endpoint)

        # Should generate IDOR hypothesis for ID parameter
        assert len(hypotheses) > 0
        assert any(h.category == HypothesisCategory.IDOR for h in hypotheses)

    def test_deduplicate_hypotheses(self):
        """Test deduplication removes exact duplicates."""
        h1 = VulnHypothesis(
            id="1",
            category=HypothesisCategory.INJECTION,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://test.com/login",
            target_param="username",
            description="Test",
            rationale="Test",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="HIGH",
            priority_score=0.0
        )
        h2 = VulnHypothesis(
            id="2",
            category=HypothesisCategory.INJECTION,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://test.com/login",
            target_param="username",  # Same category, URL, param = duplicate
            description="Different description",
            rationale="Different",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="HIGH",
            priority_score=0.0
        )
        h3 = VulnHypothesis(
            id="3",
            category=HypothesisCategory.XSS,
            confidence=HypothesisConfidence.MEDIUM,
            target_url="http://test.com/search",
            target_param="q",
            description="Test",
            rationale="Test",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="MEDIUM",
            priority_score=0.0
        )

        deduped = self.engine._deduplicate([h1, h2, h3])

        # Should keep only 2: first INJECTION and the XSS
        assert len(deduped) == 2
        assert deduped[0].id == "1"  # First INJECTION kept
        assert deduped[1].id == "3"  # XSS kept

    def test_rank_hypotheses_auth_bypass_highest(self):
        """Test ranking puts AUTH_BYPASS at top."""
        h1 = VulnHypothesis(
            id="1",
            category=HypothesisCategory.XSS,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://test.com",
            target_param=None,
            description="Test",
            rationale="Test",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="MEDIUM",
            priority_score=0.0
        )
        h2 = VulnHypothesis(
            id="2",
            category=HypothesisCategory.AUTH_BYPASS,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://test.com",
            target_param=None,
            description="Test",
            rationale="Test",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="HIGH",
            priority_score=0.0
        )

        ranked = self.engine._rank([h1, h2])

        # AUTH_BYPASS should be first (higher impact weight)
        assert ranked[0].category == HypothesisCategory.AUTH_BYPASS
        assert ranked[1].category == HypothesisCategory.XSS
        # Check scores were calculated
        assert ranked[0].priority_score > ranked[1].priority_score

    def test_rank_confidence_affects_priority(self):
        """Test that confidence affects priority scoring."""
        h_high = VulnHypothesis(
            id="1",
            category=HypothesisCategory.INJECTION,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://test.com",
            target_param=None,
            description="Test",
            rationale="Test",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="HIGH",
            priority_score=0.0
        )
        h_low = VulnHypothesis(
            id="2",
            category=HypothesisCategory.INJECTION,
            confidence=HypothesisConfidence.LOW,
            target_url="http://test.com",
            target_param=None,
            description="Test",
            rationale="Test",
            test_plan=[],
            required_tools=[],
            expected_evidence="",
            risk_level="HIGH",
            priority_score=0.0
        )

        ranked = self.engine._rank([h_low, h_high])

        # HIGH confidence should rank higher
        assert ranked[0].confidence == HypothesisConfidence.HIGH
        assert ranked[0].priority_score > ranked[1].priority_score

    @pytest.mark.asyncio
    async def test_generate_hypotheses_queries_graph(self):
        """Test generate_hypotheses queries the knowledge graph."""
        self.mock_graph.query = AsyncMock(return_value=[])

        await self.engine.generate_hypotheses("engagement-123")

        # Should query for endpoints and services
        assert self.mock_graph.query.call_count >= 2

    @pytest.mark.asyncio
    async def test_generate_hypotheses_returns_ranked_list(self):
        """Test generate_hypotheses returns ranked list."""
        # Mock graph to return sample endpoints
        self.mock_graph.query = AsyncMock(side_effect=[
            [{"e": {"url": "http://test.com/login", "path": "/login", "params": []}}],  # endpoints
            []  # services
        ])

        hypotheses = await self.engine.generate_hypotheses("engagement-123")

        # Should return list of hypotheses
        assert isinstance(hypotheses, list)
        # Should have generated some hypotheses from /login endpoint
        if len(hypotheses) > 1:
            # Check they're sorted by priority (descending)
            assert hypotheses[0].priority_score >= hypotheses[1].priority_score
