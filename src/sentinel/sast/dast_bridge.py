"""
SAST->DAST Bridge — Converts static findings into targeted DAST hypotheses.

The hybrid loop:
1. SAST finds "unsanitized input to SQL query at /api/users line 42"
2. Bridge creates a targeted VulnHypothesis: "Test /api/users for SQLi on 'id' param"
3. VulnAgent runs the DAST test
4. If confirmed: high-confidence finding. If not: lower SAST confidence for that pattern.
"""

from dataclasses import dataclass

from sentinel.sast.llm_analyzer import SASTFinding
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class TargetedHypothesis:
    """A DAST hypothesis generated from a SAST finding."""
    source_finding: SASTFinding
    target_url: str
    method: str
    parameter: str
    test_category: str
    payload_hints: list[str]
    priority: float


class SASTtoDAST:
    """Convert SAST findings into targeted DAST test hypotheses."""

    VULN_TO_DAST: dict[str, dict] = {
        "sqli": {"category": "injection", "payloads": ["' OR '1'='1", "1; SELECT", "admin'--"]},
        "xss": {"category": "xss", "payloads": ["<script>alert(1)</script>", "{{7*7}}"]},
        "command_injection": {"category": "command_injection", "payloads": ["; ls", "| id", "$(whoami)"]},
        "ssrf": {"category": "ssrf", "payloads": ["http://169.254.169.254/", "http://localhost:"]},
        "path_traversal": {"category": "path_traversal", "payloads": ["../../../etc/passwd"]},
        "idor": {"category": "idor", "payloads": []},
        "auth_bypass": {"category": "auth_bypass", "payloads": []},
    }

    def convert(self, findings: list[SASTFinding], base_url: str) -> list[TargetedHypothesis]:
        """Convert SAST findings to targeted DAST hypotheses."""
        hypotheses: list[TargetedHypothesis] = []

        for finding in findings:
            mapping = self.VULN_TO_DAST.get(finding.vuln_type)
            if not mapping:
                continue

            target = self._build_target(finding, base_url)
            if not target:
                continue

            hypotheses.append(TargetedHypothesis(
                source_finding=finding,
                target_url=target["url"],
                method=target["method"],
                parameter=target["param"],
                test_category=mapping["category"],
                payload_hints=mapping["payloads"],
                priority=finding.confidence * 1.5,
            ))

        return sorted(hypotheses, key=lambda h: h.priority, reverse=True)

    def _build_target(self, finding: SASTFinding, base_url: str) -> dict | None:
        """Extract target URL, method, and parameter from SAST finding context."""
        result = {"url": base_url, "method": "GET", "param": ""}

        if finding.exploit_hint:
            hint = finding.exploit_hint.lower()
            for method in ["post", "put", "delete", "get"]:
                if method in hint:
                    result["method"] = method.upper()
                    break

            if "/" in finding.exploit_hint:
                parts = finding.exploit_hint.split()
                for part in parts:
                    if part.startswith("/"):
                        result["url"] = base_url.rstrip("/") + part
                        break

        return result
