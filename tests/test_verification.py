"""Tests for hallucination prevention and verification."""

import pytest

from sentinel.agents.verification import FindingVerifier, VerificationResult
from sentinel.agents.schemas import (
    VulnerabilityHypothesis,
    VulnerabilityFinding,
    VulnerabilityType,
    ExploitResult,
    Confidence,
)


@pytest.fixture
def verifier() -> FindingVerifier:
    return FindingVerifier()


class TestHypothesisVerification:
    """Tests for vulnerability hypothesis verification."""

    @pytest.mark.asyncio
    async def test_valid_hypothesis_passes(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            location="https://example.com/login",
            hypothesis="Login form may be vulnerable to SQL injection",
            test_to_confirm="Send payload ' OR 1=1-- in the username field",
            indicators=["Error message contains 'SQL syntax error'"],
        )
        results = await verifier.verify_hypothesis(hypothesis)
        assert all(r.passed for r in results)

    @pytest.mark.asyncio
    async def test_invalid_location_fails(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            location="somewhere maybe",  # No URL/path format
            hypothesis="test",
            test_to_confirm="Send a test request",
            indicators=["error found"],
        )
        results = await verifier.verify_hypothesis(hypothesis)
        location_check = next(r for r in results if r.check_name == "location_format")
        assert location_check.passed is False

    @pytest.mark.asyncio
    async def test_vague_indicators_fail(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.XSS_REFLECTED,
            location="https://example.com/search",
            hypothesis="XSS might exist",
            test_to_confirm="Try injecting script tag",
            indicators=[
                "Might be vulnerable",
                "Could be exploitable",
                "Seems like input is reflected",
            ],
        )
        results = await verifier.verify_hypothesis(hypothesis)
        indicators_check = next(r for r in results if r.check_name == "indicators_specific")
        assert indicators_check.passed is False

    @pytest.mark.asyncio
    async def test_non_actionable_test_fails(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SSRF,
            location="https://example.com/api",
            hypothesis="SSRF possible",
            test_to_confirm="Maybe check it later",  # No actionable keywords
            indicators=["Internal IP in response"],
        )
        results = await verifier.verify_hypothesis(hypothesis)
        test_check = next(r for r in results if r.check_name == "test_actionable")
        assert test_check.passed is False

    @pytest.mark.asyncio
    async def test_evidence_in_response_check(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            location="https://example.com/login",
            hypothesis="SQL injection in login",
            test_to_confirm="Send SQL payload",
            indicators=['Response contains "SQL syntax error near"'],
        )
        results = await verifier.verify_hypothesis(
            hypothesis,
            actual_response="Error: SQL syntax error near 'OR' at line 1",
        )
        evidence_check = next(r for r in results if r.check_name == "evidence_in_response")
        assert evidence_check.passed is True

    @pytest.mark.asyncio
    async def test_evidence_not_in_response(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            location="https://example.com/login",
            hypothesis="SQL injection in login",
            test_to_confirm="Send SQL payload",
            indicators=['Response contains "SQL syntax error"'],
        )
        results = await verifier.verify_hypothesis(
            hypothesis,
            actual_response="Login successful. Welcome back!",
        )
        evidence_check = next(r for r in results if r.check_name == "evidence_in_response")
        assert evidence_check.passed is False


class TestFindingVerification:
    """Tests for confirmed finding verification."""

    @pytest.mark.asyncio
    async def test_valid_finding_passes(self, verifier: FindingVerifier):
        finding = VulnerabilityFinding(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            title="SQL Injection in login",
            description="Username param vulnerable",
            location="https://example.com/login",
            severity="high",
            cvss_score=8.5,
            cve_id="CVE-2024-1234",
            cwe_id="CWE-89",
            poc_request="POST /login HTTP/1.1\nusername=' OR 1=1--",
            poc_response="HTTP/1.1 200 OK\nSQL error: syntax near 'OR'",
            reproduction_steps=[
                "1. Navigate to login page",
                "2. Enter payload in username field",
                "3. Observe SQL error in response",
            ],
            false_positive_check="Re-executed 3 times",
            remediation="Use parameterized queries",
        )
        results = await verifier.verify_finding(finding)
        # Most checks should pass for a well-formed finding
        passed = sum(1 for r in results if r.passed)
        assert passed >= len(results) - 1  # Allow 1 soft failure

    @pytest.mark.asyncio
    async def test_severity_cvss_mismatch(self, verifier: FindingVerifier):
        finding = VulnerabilityFinding(
            vuln_type=VulnerabilityType.XSS_REFLECTED,
            title="XSS test",
            description="test",
            location="https://example.com/search",
            severity="low",
            cvss_score=9.5,  # Critical CVSS with low severity = mismatch
            poc_request="GET /search?q=<script>",
            poc_response="<script>alert(1)</script>",
            reproduction_steps=[
                "1. Go to search page",
                "2. Enter script payload",
            ],
            false_positive_check="checked",
            remediation="sanitize input",
        )
        results = await verifier.verify_finding(finding)
        cvss_check = next(r for r in results if r.check_name == "severity_cvss_match")
        assert cvss_check.passed is False

    @pytest.mark.asyncio
    async def test_invalid_cve_format(self, verifier: FindingVerifier):
        finding = VulnerabilityFinding(
            vuln_type=VulnerabilityType.SSRF,
            title="SSRF test",
            description="test",
            location="https://example.com/api",
            severity="high",
            cve_id="NOT-A-CVE",  # Invalid format
            poc_request="GET /api?url=http://localhost",
            poc_response="HTTP/1.1 200 OK\nlocalhost response",
            reproduction_steps=[
                "1. Send request with internal URL",
                "2. Observe internal response",
            ],
            false_positive_check="checked",
            remediation="validate URLs",
        )
        results = await verifier.verify_finding(finding)
        cve_check = next(r for r in results if r.check_name == "cve_exists")
        assert cve_check.passed is False


class TestExploitResultVerification:
    """Tests for exploit result verification."""

    @pytest.mark.asyncio
    async def test_valid_exploit_result(self, verifier: FindingVerifier):
        result = ExploitResult(
            vulnerability_id="vuln-001",
            success=True,
            technique_used="SQL injection",
            session_type="web",
            access_level="admin",
            request_sent="POST /login HTTP/1.1\nusername=admin'--",
            response_received="HTTP/1.1 200 OK\nWelcome admin, access granted",
            replay_command="curl -X POST -d 'username=admin\\'--' https://example.com/login",
        )
        results = await verifier.verify_exploit_result(result)
        passed = sum(1 for r in results if r.passed)
        assert passed >= len(results) - 1

    @pytest.mark.asyncio
    async def test_fabricated_success_detected(self, verifier: FindingVerifier):
        result = ExploitResult(
            vulnerability_id="vuln-002",
            success=True,  # Claims success
            technique_used="XSS",
            request_sent="GET /search?q=test HTTP/1.1",
            response_received="Nothing special happened",  # No success evidence
        )
        results = await verifier.verify_exploit_result(result, re_execute=False)
        success_check = next(r for r in results if r.check_name == "success_matches_evidence")
        assert success_check.passed is False

    @pytest.mark.asyncio
    async def test_failed_exploit_needs_no_evidence(self, verifier: FindingVerifier):
        result = ExploitResult(
            vulnerability_id="vuln-003",
            success=False,
            technique_used="Command injection",
            request_sent="POST /api HTTP/1.1",
            response_received="HTTP/1.1 400 Bad Request",
            failure_reason="Input sanitized",
        )
        results = await verifier.verify_exploit_result(result, re_execute=False)
        success_check = next(r for r in results if r.check_name == "success_matches_evidence")
        assert success_check.passed is True  # No evidence needed for failure


class TestVerificationSummary:
    """Tests for verification summary."""

    @pytest.mark.asyncio
    async def test_summary_tracks_all_checks(self, verifier: FindingVerifier):
        hypothesis = VulnerabilityHypothesis(
            vuln_type=VulnerabilityType.SQL_INJECTION,
            location="https://example.com/login",
            hypothesis="SQL injection possible",
            test_to_confirm="Send a test payload via POST request",
            indicators=["SQL error in response"],
        )
        await verifier.verify_hypothesis(hypothesis)

        summary = verifier.get_summary()
        assert summary["total_checks"] > 0
        assert summary["passed"] + summary["failed"] == summary["total_checks"]
        assert 0 <= summary["pass_rate"] <= 1

    def test_empty_summary(self, verifier: FindingVerifier):
        summary = verifier.get_summary()
        assert summary["total_checks"] == 0
        assert summary["pass_rate"] == 0
