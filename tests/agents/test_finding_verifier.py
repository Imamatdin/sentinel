"""Tests for FindingVerifier."""
import pytest
from unittest.mock import AsyncMock

from sentinel.agents.finding_verifier import FindingVerifier, VerifiedFinding


class TestFindingVerifier:
    """Test FindingVerifier functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.verifier = FindingVerifier()

    def test_generate_poc_with_traces(self):
        """Test PoC generation with HTTP traces."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "injection",
            "target_url": "http://test.com/api/users",
            "target_param": "id",
            "severity": "high"
        }

        traces = [
            {
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": '{"id": "1\' OR \'1\'=\'1"}'
            }
        ]

        poc = self.verifier._generate_poc(finding, traces)

        # Check PoC contains key elements
        assert "#!/usr/bin/env python3" in poc
        assert "import requests" in poc
        assert "http://test.com/api/users" in poc
        assert "requests.post" in poc
        assert "Content-Type" in poc

    def test_generate_poc_no_traces(self):
        """Test PoC generation without traces."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "xss",
            "target_url": "http://test.com",
            "severity": "medium"
        }

        poc = self.verifier._generate_poc(finding, [])

        # Should return comment indicating no traces
        assert "No HTTP traces available" in poc

    def test_generate_replay_commands_curl(self):
        """Test curl command generation."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "sqli",
            "target_url": "http://test.com/login"
        }

        traces = [
            {
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=admin&password=password"
            }
        ]

        commands = self.verifier._generate_replay_commands(finding, traces)

        assert len(commands) == 1
        assert "curl" in commands[0]
        assert "-X POST" in commands[0]
        assert "http://test.com/login" in commands[0]
        assert "Content-Type" in commands[0]

    def test_generate_replay_commands_multiple_traces(self):
        """Test curl command generation for multiple traces."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "xss",
            "target_url": "http://test.com/search"
        }

        traces = [
            {"method": "GET", "headers": {}, "body": ""},
            {"method": "POST", "headers": {}, "body": "q=<script>alert(1)</script>"}
        ]

        commands = self.verifier._generate_replay_commands(finding, traces)

        assert len(commands) == 2
        assert any("GET" in cmd for cmd in commands)
        assert any("POST" in cmd for cmd in commands)

    @pytest.mark.asyncio
    async def test_verify_returns_verified_finding(self):
        """Test verify returns VerifiedFinding object."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "injection",
            "target_url": "http://test.com/api",
            "severity": "high",
            "evidence": "SQL error detected",
            "remediation": "Use parameterized queries",
            "mitre_technique": "T1190"
        }

        # Mock replay to always succeed
        self.verifier._replay_exploit = AsyncMock(return_value={
            "success": True,
            "trace": {"method": "GET", "headers": {}, "body": ""}
        })

        result = await self.verifier.verify(finding, replay_count=3)

        # Should return VerifiedFinding
        assert isinstance(result, VerifiedFinding)
        assert result.finding_id == "test-1"
        assert result.category == "injection"
        assert result.severity == "high"
        assert result.confirmed_count == 3  # All 3 succeeded
        assert result.false_positive_check is True  # >= 2/3 succeeded

    @pytest.mark.asyncio
    async def test_verify_confirmation_threshold(self):
        """Test 2/3 success threshold for confirmation."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "xss",
            "target_url": "http://test.com",
            "severity": "medium",
            "evidence": "XSS detected",
            "remediation": "Escape output"
        }

        # Mock replay to succeed 2/3 times
        call_count = 0

        async def mock_replay(f):
            nonlocal call_count
            call_count += 1
            return {
                "success": call_count <= 2,  # First 2 succeed, 3rd fails
                "trace": {"method": "GET", "headers": {}, "body": ""}
            }

        self.verifier._replay_exploit = mock_replay

        result = await self.verifier.verify(finding, replay_count=3)

        # Should be confirmed (2/3 = threshold)
        assert result.confirmed_count == 2
        assert result.false_positive_check is True

    @pytest.mark.asyncio
    async def test_verify_below_threshold_not_confirmed(self):
        """Test findings below 2/3 threshold are not confirmed."""
        finding = {
            "hypothesis_id": "test-1",
            "category": "idor",
            "target_url": "http://test.com",
            "severity": "medium",
            "evidence": "Unauthorized access",
            "remediation": "Add authorization checks"
        }

        # Mock replay to succeed only 1/3 times
        call_count = 0

        async def mock_replay(f):
            nonlocal call_count
            call_count += 1
            return {
                "success": call_count == 1,  # Only first succeeds
                "trace": {"method": "GET", "headers": {}, "body": ""}
            }

        self.verifier._replay_exploit = mock_replay

        result = await self.verifier.verify(finding, replay_count=3)

        # Should NOT be confirmed (1/3 < threshold)
        assert result.confirmed_count == 1
        assert result.false_positive_check is False

    def test_verified_finding_structure(self):
        """Test VerifiedFinding has all required fields."""
        finding = VerifiedFinding(
            finding_id="test-1",
            category="sqli",
            target_url="http://test.com",
            severity="critical",
            evidence="SQL error",
            poc_script="# PoC script",
            replay_commands=["curl -X GET http://test.com"],
            http_trace=[{"method": "GET"}],
            confirmed_count=3,
            false_positive_check=True,
            remediation="Fix it",
            mitre_technique="T1190"
        )

        # Verify all fields are accessible
        assert finding.finding_id == "test-1"
        assert finding.category == "sqli"
        assert finding.confirmed_count == 3
        assert finding.false_positive_check is True
        assert len(finding.replay_commands) == 1
        assert len(finding.http_trace) == 1
