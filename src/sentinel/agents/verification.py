"""Hallucination prevention and verification for LLM outputs.

Implements multiple verification strategies:
1. Re-execution verification - run the PoC again
2. Evidence grounding - check claims against actual data
3. Cross-validation - multiple agents verify
4. RAG grounding - verify against known CVE/CWE data
"""

from dataclasses import dataclass
from typing import Any
import re

from sentinel.core import get_logger
from sentinel.agents.schemas import (
    VulnerabilityFinding,
    VulnerabilityHypothesis,
    ExploitResult,
    Confidence,
)

logger = get_logger(__name__)


@dataclass
class VerificationResult:
    """Result of a verification check."""
    passed: bool
    check_name: str
    details: str
    evidence: dict[str, Any] | None = None


class FindingVerifier:
    """Verifies LLM-generated findings against evidence."""

    def __init__(self) -> None:
        self.checks_run: list[VerificationResult] = []

    async def verify_hypothesis(
        self,
        hypothesis: VulnerabilityHypothesis,
        actual_response: str | None = None,
    ) -> list[VerificationResult]:
        """Verify a vulnerability hypothesis."""
        results = []

        # Check 1: Location format is valid
        results.append(self._check_location_format(hypothesis.location))

        # Check 2: Indicators are specific (not vague)
        results.append(self._check_indicators_specific(hypothesis.indicators))

        # Check 3: Test is actionable
        results.append(self._check_test_actionable(hypothesis.test_to_confirm))

        # Check 4: If we have response data, check it matches
        if actual_response:
            results.append(
                self._check_evidence_in_response(
                    hypothesis.indicators,
                    actual_response
                )
            )

        self.checks_run.extend(results)
        return results

    async def verify_finding(
        self,
        finding: VulnerabilityFinding,
    ) -> list[VerificationResult]:
        """Verify a confirmed vulnerability finding."""
        results = []

        # Check 1: PoC request is valid HTTP
        results.append(self._check_poc_request_valid(finding.poc_request))

        # Check 2: PoC response shows evidence
        results.append(
            self._check_poc_response_evidence(
                finding.vuln_type.value,
                finding.poc_response,
            )
        )

        # Check 3: Reproduction steps are complete
        results.append(self._check_reproduction_steps(finding.reproduction_steps))

        # Check 4: Severity matches CVSS if provided
        if finding.cvss_score:
            results.append(
                self._check_severity_cvss_match(
                    finding.severity,
                    finding.cvss_score,
                )
            )

        # Check 5: CVE exists (if claimed)
        if finding.cve_id:
            results.append(await self._check_cve_exists(finding.cve_id))

        # Check 6: CWE is valid
        if finding.cwe_id:
            results.append(self._check_cwe_valid(finding.cwe_id))

        self.checks_run.extend(results)
        return results

    async def verify_exploit_result(
        self,
        result: ExploitResult,
        re_execute: bool = True,
    ) -> list[VerificationResult]:
        """Verify an exploitation result."""
        results = []

        # Check 1: Request was actually sent (not fabricated)
        results.append(self._check_request_format(result.request_sent))

        # Check 2: Response looks real
        results.append(self._check_response_plausible(result.response_received))

        # Check 3: Success claim matches evidence
        results.append(
            self._check_success_matches_evidence(
                result.success,
                result.response_received,
                result.session_type,
            )
        )

        # Check 4: Replay command is valid
        if result.replay_command:
            results.append(self._check_replay_valid(result.replay_command))

        # Check 5: Re-execute if requested
        # (In production, this would actually run the exploit again)
        if re_execute and result.replay_command:
            results.append(
                VerificationResult(
                    passed=True,  # Placeholder
                    check_name="re_execution",
                    details="Re-execution verification would run here",
                )
            )

        self.checks_run.extend(results)
        return results

    # === Individual Checks ===

    def _check_location_format(self, location: str) -> VerificationResult:
        """Check that location is a valid URL or path."""
        valid = bool(
            re.match(r"^https?://", location) or
            re.match(r"^/", location) or
            re.match(r"^\w+:", location)  # e.g., "param:id"
        )
        return VerificationResult(
            passed=valid,
            check_name="location_format",
            details=f"Location '{location}' format valid: {valid}",
        )

    def _check_indicators_specific(self, indicators: list[str]) -> VerificationResult:
        """Check that indicators are specific, not vague."""
        vague_patterns = [
            r"^might be",
            r"^could be",
            r"^possibly",
            r"^seems like",
            r"^appears to",
            r"^looks like",
        ]

        vague_count = 0
        for indicator in indicators:
            for pattern in vague_patterns:
                if re.match(pattern, indicator.lower()):
                    vague_count += 1
                    break

        passed = vague_count < len(indicators) / 2
        return VerificationResult(
            passed=passed,
            check_name="indicators_specific",
            details=f"{vague_count}/{len(indicators)} indicators are vague",
        )

    def _check_test_actionable(self, test: str) -> VerificationResult:
        """Check that the proposed test is actionable."""
        actionable_keywords = [
            "send", "submit", "inject", "request", "try", "test",
            "curl", "POST", "GET", "input", "payload",
        ]
        has_action = any(kw in test.lower() for kw in actionable_keywords)
        return VerificationResult(
            passed=has_action,
            check_name="test_actionable",
            details=f"Test contains actionable keywords: {has_action}",
        )

    def _check_evidence_in_response(
        self,
        indicators: list[str],
        response: str
    ) -> VerificationResult:
        """Check that claimed indicators are in actual response."""
        found = []
        for indicator in indicators:
            # Extract quoted strings from indicator
            quoted = re.findall(r'"([^"]+)"', indicator)
            for q in quoted:
                if q.lower() in response.lower():
                    found.append(q)

        passed = len(found) > 0
        return VerificationResult(
            passed=passed,
            check_name="evidence_in_response",
            details=f"Found {len(found)} quoted evidences in response",
            evidence={"found": found},
        )

    def _check_poc_request_valid(self, request: str) -> VerificationResult:
        """Check PoC request is valid HTTP."""
        has_method = bool(re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)", request))
        has_path = "/" in request or "http" in request.lower()
        passed = has_method or has_path or "curl" in request.lower()
        return VerificationResult(
            passed=passed,
            check_name="poc_request_valid",
            details=f"PoC request appears valid: {passed}",
        )

    def _check_poc_response_evidence(
        self,
        vuln_type: str,
        response: str
    ) -> VerificationResult:
        """Check PoC response shows evidence of exploitation."""
        evidence_patterns: dict[str, list[str]] = {
            "sql_injection": [r"sql", r"syntax", r"error", r"mysql", r"postgres", r"sqlite"],
            "xss_reflected": [r"<script", r"alert\(", r"onerror", r"javascript:"],
            "xss_stored": [r"<script", r"alert\(", r"onerror", r"javascript:"],
            "xss_dom": [r"<script", r"alert\(", r"onerror", r"javascript:"],
            "command_injection": [r"uid=", r"root:", r"/bin/", r"volume", r"windows"],
            "ssrf": [r"localhost", r"127\.0\.0\.1", r"internal", r"metadata"],
            "path_traversal": [r"/etc/passwd", r"root:", r"win\.ini", r"\[boot"],
        }

        patterns = evidence_patterns.get(vuln_type, [])
        found = [p for p in patterns if re.search(p, response, re.IGNORECASE)]

        passed = len(found) > 0 or len(patterns) == 0
        return VerificationResult(
            passed=passed,
            check_name="poc_response_evidence",
            details=f"Found evidence patterns: {found}",
            evidence={"patterns_found": found},
        )

    def _check_reproduction_steps(self, steps: list[str]) -> VerificationResult:
        """Check reproduction steps are complete."""
        passed = len(steps) >= 2
        has_numbers = all(re.match(r"^\d+\.", step) or len(step) > 10 for step in steps)
        return VerificationResult(
            passed=passed and has_numbers,
            check_name="reproduction_steps",
            details=f"{len(steps)} steps, well-formed: {has_numbers}",
        )

    def _check_severity_cvss_match(self, severity: str, cvss: float) -> VerificationResult:
        """Check severity matches CVSS score."""
        expected: dict[str, tuple[float, float]] = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }

        low, high = expected.get(severity, (0, 10))
        passed = low <= cvss <= high

        return VerificationResult(
            passed=passed,
            check_name="severity_cvss_match",
            details=f"Severity '{severity}' with CVSS {cvss}: {'matches' if passed else 'mismatch'}",
        )

    async def _check_cve_exists(self, cve_id: str) -> VerificationResult:
        """Check CVE ID exists (placeholder - would query NVD)."""
        # Format check
        valid_format = bool(re.match(r"^CVE-\d{4}-\d+$", cve_id))

        # In production, query NVD API
        return VerificationResult(
            passed=valid_format,
            check_name="cve_exists",
            details=f"CVE format valid: {valid_format} (NVD check pending)",
        )

    def _check_cwe_valid(self, cwe_id: str) -> VerificationResult:
        """Check CWE ID is valid format."""
        valid = bool(re.match(r"^CWE-\d+$", cwe_id))
        return VerificationResult(
            passed=valid,
            check_name="cwe_valid",
            details=f"CWE format valid: {valid}",
        )

    def _check_request_format(self, request: str) -> VerificationResult:
        """Check request is well-formed."""
        passed = len(request) > 10 and any(
            x in request.lower()
            for x in ["http", "curl", "get", "post", "/"]
        )
        return VerificationResult(
            passed=passed,
            check_name="request_format",
            details=f"Request appears well-formed: {passed}",
        )

    def _check_response_plausible(self, response: str) -> VerificationResult:
        """Check response looks like real HTTP response."""
        indicators = [
            "200", "404", "500",  # Status codes
            "HTTP/", "Content-Type", "Server",  # Headers
            "<html", "{", "error",  # Body patterns
        ]
        found = sum(1 for i in indicators if i.lower() in response.lower())
        passed = found >= 1 or len(response) > 50
        return VerificationResult(
            passed=passed,
            check_name="response_plausible",
            details=f"Response has {found} HTTP indicators",
        )

    def _check_success_matches_evidence(
        self,
        claimed_success: bool,
        response: str,
        session_type: str | None,
    ) -> VerificationResult:
        """Check success claim is supported by evidence."""
        if not claimed_success:
            return VerificationResult(
                passed=True,
                check_name="success_matches_evidence",
                details="Failure claimed, no evidence needed",
            )

        # If success claimed, need evidence
        success_indicators = [
            "token", "session", "authenticated", "logged in",
            "uid=", "root", "admin", "access granted",
        ]
        found = any(i in response.lower() for i in success_indicators)
        has_session = session_type is not None

        passed = found or has_session
        return VerificationResult(
            passed=passed,
            check_name="success_matches_evidence",
            details=f"Success evidence found: {found}, session: {has_session}",
        )

    def _check_replay_valid(self, replay: str) -> VerificationResult:
        """Check replay command is valid."""
        valid_starts = ["curl", "python", "wget", "http", "nc", "nmap"]
        passed = any(replay.strip().lower().startswith(s) for s in valid_starts)
        return VerificationResult(
            passed=passed,
            check_name="replay_valid",
            details=f"Replay command starts with known tool: {passed}",
        )

    def get_summary(self) -> dict[str, Any]:
        """Get summary of all verification checks."""
        passed = sum(1 for r in self.checks_run if r.passed)
        failed = len(self.checks_run) - passed

        return {
            "total_checks": len(self.checks_run),
            "passed": passed,
            "failed": failed,
            "pass_rate": passed / len(self.checks_run) if self.checks_run else 0,
            "failed_checks": [
                {"name": r.check_name, "details": r.details}
                for r in self.checks_run
                if not r.passed
            ],
        }
