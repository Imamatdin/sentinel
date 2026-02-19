"""Tests for GuardedVulnAgent."""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.agents.vuln_agent import GuardedVulnAgent
from sentinel.agents.hypothesis_engine import (
    VulnHypothesis,
    HypothesisCategory,
    HypothesisConfidence
)
from sentinel.tools.base import ToolOutput


class TestGuardedVulnAgent:
    """Test GuardedVulnAgent functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_graph = AsyncMock()
        self.mock_llm = AsyncMock()
        self.mock_policy = AsyncMock()
        self.mock_policy.evaluate = AsyncMock(return_value=True)  # Allow all by default

        # Mock NucleiTool and ZAPTool to avoid settings validation
        with patch('sentinel.agents.vuln_agent.NucleiTool') as mock_nuclei, \
             patch('sentinel.agents.vuln_agent.ZAPTool') as mock_zap:
            self.agent = GuardedVulnAgent(
                graph_client=self.mock_graph,
                llm_client=self.mock_llm,
                policy_engine=self.mock_policy
            )
            # Store mock instances for test access
            self.agent.nuclei = MagicMock()
            self.agent.zap = MagicMock()

    def test_vuln_agent_initialization(self):
        """Test GuardedVulnAgent initializes correctly."""
        assert self.agent.agent_name == "vuln_analyst"
        assert self.agent.graph == self.mock_graph
        assert self.agent.hypothesis_engine is not None
        assert self.agent.nuclei is not None
        assert self.agent.zap is not None

    def test_category_to_tools_mapping_complete(self):
        """Test all hypothesis categories have tool mappings."""
        # Verify every category has tools defined
        for category in HypothesisCategory:
            tools = self.agent.CATEGORY_TO_TOOLS.get(category)
            assert tools is not None, f"No tools mapped for {category}"
            assert len(tools) > 0, f"Empty tool list for {category}"

    @pytest.mark.asyncio
    async def test_test_hypothesis_checks_policy(self):
        """Test that test_hypothesis checks policy before execution."""
        hypothesis = VulnHypothesis(
            id="test-1",
            category=HypothesisCategory.INJECTION,
            confidence=HypothesisConfidence.HIGH,
            target_url="http://test.com/login",
            target_param="username",
            description="SQL injection hypothesis",
            rationale="Unvalidated input",
            test_plan=["test"],
            required_tools=["sqli_tool"],
            expected_evidence="SQL error",
            risk_level="HIGH",
            priority_score=0.9
        )

        # Mock policy to deny
        self.mock_policy.evaluate = AsyncMock(return_value=False)

        # Mock LLM response
        self.mock_llm.complete = AsyncMock(return_value='{"confirmed": false, "confidence": "low", "evidence": "", "severity": "low", "remediation": ""}')

        result = await self.agent.test_hypothesis(hypothesis, "http://test.com")

        # Should call policy engine
        assert self.mock_policy.evaluate.called
        # Should return unverified result
        assert result["verified"] is False

    @pytest.mark.asyncio
    async def test_test_hypothesis_executes_tools(self):
        """Test that test_hypothesis executes appropriate tools."""
        hypothesis = VulnHypothesis(
            id="test-1",
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
            priority_score=0.9
        )

        # Mock policy to allow
        self.mock_policy.evaluate = AsyncMock(return_value=True)

        # Mock nuclei tool
        self.agent.nuclei.execute = AsyncMock(return_value=ToolOutput(
            success=True,
            data={"findings": []},
            tool_name="nuclei_scan"
        ))

        # Mock LLM response
        self.mock_llm.complete = AsyncMock(return_value='{"confirmed": true, "confidence": "high", "evidence": "SQL error detected", "severity": "high", "remediation": "Use parameterized queries"}')

        result = await self.agent.test_hypothesis(hypothesis, "http://test.com")

        # Should execute nuclei (INJECTION maps to nuclei_scan)
        assert self.agent.nuclei.execute.called
        # Should call LLM for verification
        assert self.mock_llm.complete.called

    @pytest.mark.asyncio
    async def test_execute_tool_nuclei_for_injection(self):
        """Test _execute_tool selects Nuclei for INJECTION category."""
        hypothesis = VulnHypothesis(
            id="test-1",
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
            priority_score=0.9
        )

        self.agent.nuclei.execute = AsyncMock(return_value=ToolOutput(
            success=True,
            data={"findings": []},
            tool_name="nuclei_scan"
        ))

        result = await self.agent._execute_tool("nuclei_scan", hypothesis, "http://test.com")

        # Should call nuclei with sqli tags
        self.agent.nuclei.execute.assert_called_once()
        call_kwargs = self.agent.nuclei.execute.call_args[1]
        assert "tags" in call_kwargs
        assert "sqli" in call_kwargs["tags"] or "nosqli" in call_kwargs["tags"]

    @pytest.mark.asyncio
    async def test_execute_tool_zap_for_auth_bypass(self):
        """Test _execute_tool selects ZAP for AUTH_BYPASS category."""
        hypothesis = VulnHypothesis(
            id="test-1",
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
            priority_score=0.9
        )

        self.agent.zap.active_scan = AsyncMock(return_value=ToolOutput(
            success=True,
            data={"alerts": []},
            tool_name="zap_scan"
        ))

        result = await self.agent._execute_tool("zap_scan", hypothesis, "http://test.com")

        # Should call ZAP active scan
        self.agent.zap.active_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_record_finding_writes_to_graph(self):
        """Test _record_finding writes to Neo4j."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "injection",
            "target_url": "http://test.com/login",
            "severity": "high",
            "confidence": "high",
            "evidence": "SQL error detected",
            "remediation": "Use parameterized queries",
            "mitre_technique": "T1190"
        }

        self.mock_graph.query = AsyncMock()

        await self.agent._record_finding("engagement-123", finding)

        # Should call graph.query to create Finding node
        self.mock_graph.query.assert_called_once()
        call_args = self.mock_graph.query.call_args[0]
        assert "Finding" in call_args[0]  # Query contains Finding node creation
        assert "HAS_VULNERABILITY" in call_args[0]  # Query creates relationship

    def test_format_results(self):
        """Test _format_results formats tool outputs."""
        results = [
            ToolOutput(success=True, data={"test": "data"}, tool_name="test1", raw_output="output1"),
            ToolOutput(success=False, data={}, tool_name="test2", error="failed"),
            ToolOutput(success=True, data={"more": "data"}, tool_name="test3")
        ]

        formatted = self.agent._format_results(results)

        # Should include successful results only
        assert "test1" in formatted
        assert "test3" in formatted
        assert "test2" not in formatted  # Failed result excluded

    def test_parse_llm_response_valid_json(self):
        """Test _parse_llm_response parses valid JSON."""
        response = '{"confirmed": true, "confidence": "high", "evidence": "test", "severity": "critical", "remediation": "fix it"}'

        parsed = self.agent._parse_llm_response(response)

        assert parsed["confirmed"] is True
        assert parsed["confidence"] == "high"
        assert parsed["severity"] == "critical"

    def test_parse_llm_response_with_markdown(self):
        """Test _parse_llm_response handles markdown code blocks."""
        response = '```json\n{"confirmed": false, "confidence": "low", "evidence": "", "severity": "low", "remediation": ""}\n```'

        parsed = self.agent._parse_llm_response(response)

        assert parsed["confirmed"] is False
        assert parsed["confidence"] == "low"

    def test_parse_llm_response_invalid_json(self):
        """Test _parse_llm_response handles invalid JSON gracefully."""
        response = "This is not JSON at all"

        parsed = self.agent._parse_llm_response(response)

        # Should return safe defaults
        assert parsed["confirmed"] is False
        assert parsed["confidence"] == "low"

    def test_build_action(self):
        """Test _build_action creates correct action dict."""
        hypothesis = VulnHypothesis(
            id="test-1",
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
            priority_score=0.9
        )

        action = self.agent._build_action("nuclei_scan", hypothesis, "http://test.com")

        assert action["action_type"] == "NUCLEI_SCAN"
        assert action["target"] == "http://test.com"
        assert action["agent"] == "vuln_analyst"
        assert action["risk_level"] == "HIGH"
