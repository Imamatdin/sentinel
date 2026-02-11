"""Tests for structured output schemas."""

import pytest
from datetime import datetime
from pydantic import ValidationError

from sentinel.agents.schemas import (
    Confidence,
    VulnerabilityType,
    DiscoveredHost,
    DiscoveredPort,
    DiscoveredEndpoint,
    ReconPlan,
    VulnerabilityHypothesis,
    VulnerabilityFinding,
    VulnAnalysisPlan,
    ExploitPlan,
    ExploitResult,
    AgentThought,
    ActionProposal,
    AgentResponse,
)


class TestDiscoveredHost:
    """Tests for DiscoveredHost schema."""

    def test_valid_host(self):
        host = DiscoveredHost(
            ip_address="192.168.1.1",
            hostname="web.example.com",
            evidence="Found via nmap scan",
        )
        assert host.ip_address == "192.168.1.1"
        assert host.confidence == Confidence.MEDIUM

    def test_invalid_ip_rejected(self):
        with pytest.raises(ValidationError):
            DiscoveredHost(
                ip_address="not-an-ip",
                evidence="test",
            )

    def test_ip_format_validation(self):
        with pytest.raises(ValidationError):
            DiscoveredHost(
                ip_address="999.999.999.999.999",
                evidence="test",
            )


class TestDiscoveredPort:
    """Tests for DiscoveredPort schema."""

    def test_valid_port(self):
        port = DiscoveredPort(
            port_number=443,
            service_guess="https",
            evidence="nmap output: 443/tcp open https",
        )
        assert port.port_number == 443
        assert port.protocol == "tcp"

    def test_port_too_low(self):
        with pytest.raises(ValidationError):
            DiscoveredPort(port_number=0, evidence="test")

    def test_port_too_high(self):
        with pytest.raises(ValidationError):
            DiscoveredPort(port_number=70000, evidence="test")


class TestVulnerabilityHypothesis:
    """Tests for VulnerabilityHypothesis schema."""

    def test_valid_hypothesis(self):
        h = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            location="https://example.com/login",
            hypothesis="The login form may be vulnerable to SQL injection",
            test_to_confirm="Send payload: ' OR 1=1-- in username field",
            indicators=["Error message contains 'SQL syntax'"],
        )
        assert h.confidence == Confidence.LOW

    def test_confirmed_confidence_rejected(self):
        """Hypotheses cannot be CONFIRMED - must use VulnerabilityFinding."""
        with pytest.raises(ValidationError) as exc_info:
            VulnerabilityHypothesis(
                vuln_type=VulnerabilityType.XSS_REFLECTED,
                location="/search",
                hypothesis="XSS exists",
                test_to_confirm="inject script tag",
                indicators=["reflected input"],
                confidence=Confidence.CONFIRMED,
            )
        assert "CONFIRMED" in str(exc_info.value)


class TestVulnerabilityFinding:
    """Tests for VulnerabilityFinding schema."""

    def test_valid_finding(self):
        finding = VulnerabilityFinding(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            title="SQL Injection in login form",
            description="The username parameter is vulnerable to SQL injection",
            location="https://example.com/login",
            severity="high",
            cvss_score=8.5,
            cve_id="CVE-2024-1234",
            cwe_id="CWE-89",
            poc_request="POST /login HTTP/1.1\nusername=' OR 1=1--",
            poc_response="HTTP/1.1 200 OK\nWelcome admin",
            reproduction_steps=[
                "1. Navigate to /login",
                "2. Enter ' OR 1=1-- in username field",
                "3. Observe admin access granted",
            ],
            false_positive_check="Verified by re-executing PoC 3 times with consistent results",
            remediation="Use parameterized queries for all SQL operations",
        )
        assert finding.validated is True
        assert finding.severity == "high"

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                vuln_type=VulnerabilityType.XSS_REFLECTED,
                title="test",
                description="test",
                location="/test",
                severity="super_critical",  # Invalid
                poc_request="GET /test",
                poc_response="<script>alert(1)</script>",
                reproduction_steps=["step 1"],
                false_positive_check="checked",
                remediation="fix it",
            )

    def test_cvss_bounds(self):
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                vuln_type=VulnerabilityType.XSS_REFLECTED,
                title="test",
                description="test",
                location="/test",
                severity="high",
                cvss_score=11.0,  # Over 10.0
                poc_request="GET /test",
                poc_response="<script>alert(1)</script>",
                reproduction_steps=["step 1"],
                false_positive_check="checked",
                remediation="fix it",
            )

    def test_empty_reproduction_steps_rejected(self):
        with pytest.raises(ValidationError):
            VulnerabilityFinding(
                vuln_type=VulnerabilityType.XSS_REFLECTED,
                title="test",
                description="test",
                location="/test",
                severity="high",
                poc_request="GET /test",
                poc_response="<script>alert(1)</script>",
                reproduction_steps=[],  # Must have at least 1
                false_positive_check="checked",
                remediation="fix it",
            )


class TestReconPlan:
    """Tests for ReconPlan schema."""

    def test_valid_plan(self):
        plan = ReconPlan(
            target="example.com",
            techniques=["nmap_scan", "dns_enum"],
            justification="Initial reconnaissance",
        )
        assert plan.max_depth == 3
        assert 80 in plan.priority_ports

    def test_empty_techniques_rejected(self):
        with pytest.raises(ValidationError):
            ReconPlan(
                target="example.com",
                techniques=[],  # Must have at least 1
                justification="test",
            )


class TestAgentResponse:
    """Tests for AgentResponse schema."""

    def test_valid_response(self):
        response = AgentResponse(
            thought=AgentThought(
                observation="Port 80 is open",
                analysis="Web server is running",
                hypothesis="May have web vulnerabilities",
                next_action="Crawl endpoints",
                justification="Need to discover attack surface",
                confidence=Confidence.MEDIUM,
            ),
            proposed_actions=[
                ActionProposal(
                    action_type="crawl_endpoint",
                    target="https://example.com",
                    parameters={"depth": 3},
                    justification="Discover endpoints",
                    expected_outcome="List of endpoints",
                    risk_level="low",
                    rollback_possible=True,
                ),
            ],
        )
        assert len(response.proposed_actions) == 1
        assert response.needs_human_input is False

    def test_invalid_risk_level_rejected(self):
        with pytest.raises(ValidationError):
            ActionProposal(
                action_type="test",
                target="test",
                parameters={},
                justification="test",
                expected_outcome="test",
                risk_level="super_high",  # Invalid
                rollback_possible=True,
            )


class TestExploitResult:
    """Tests for ExploitResult schema."""

    def test_successful_exploit(self):
        result = ExploitResult(
            vulnerability_id="vuln-001",
            success=True,
            technique_used="SQL injection",
            session_type="web",
            access_level="admin",
            request_sent="POST /login HTTP/1.1",
            response_received="HTTP/1.1 200 OK",
            replay_command="curl -X POST -d \"username=' OR 1=1--\" https://example.com/login",
        )
        assert result.success is True
        assert result.failure_reason is None

    def test_failed_exploit(self):
        result = ExploitResult(
            vulnerability_id="vuln-002",
            success=False,
            technique_used="XSS",
            request_sent="GET /search?q=<script>",
            response_received="HTTP/1.1 200 OK\nFiltered output",
            failure_reason="Input was sanitized",
        )
        assert result.success is False
        assert result.session_type is None
