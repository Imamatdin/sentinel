"""
Data Anonymizer — Strip PII and deployment-specific data before federation.

Rules:
- Replace IPs with stable placeholders (10.0.0.1 → HOST_1)
- Replace hostnames/domains with generic labels
- Normalize URL path IDs (/users/12345 → /users/{id})
- Strip credentials, tokens, session IDs, emails, UUIDs
- Classify findings into technique families for cross-deployment aggregation
"""

import re
from dataclasses import dataclass

from sentinel.core import get_logger

logger = get_logger(__name__)

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b", re.IGNORECASE
)
PATH_ID_PATTERN = re.compile(r"/\d+(?=/|$)")
UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
TOKEN_PATTERN = re.compile(
    r"(?:Bearer\s+|token=|key=|secret=)[A-Za-z0-9_\-\.]+", re.IGNORECASE
)
EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
)


@dataclass
class AnonymizedRecord:
    technique_family: str
    target_stack: str
    success: bool
    confidence: float
    payload_template: str
    response_pattern: str
    metadata: dict


class Anonymizer:
    """Strip PII and deployment-specific data from findings."""

    MIN_AGGREGATION = 5

    def __init__(self):
        self._ip_map: dict[str, str] = {}
        self._domain_map: dict[str, str] = {}
        self._ip_counter = 0
        self._domain_counter = 0

    def anonymize_text(self, text: str) -> str:
        """Replace all PII in a text string with stable placeholders."""
        result = text

        # Tokens first (longest matches, before shorter patterns consume parts)
        result = TOKEN_PATTERN.sub("[REDACTED_TOKEN]", result)
        result = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", result)
        result = UUID_PATTERN.sub("[REDACTED_UUID]", result)

        # IPs — stable mapping across calls
        for ip in set(IP_PATTERN.findall(result)):
            if ip not in self._ip_map:
                self._ip_counter += 1
                self._ip_map[ip] = f"HOST_{self._ip_counter}"
            result = result.replace(ip, self._ip_map[ip])

        # Domains — stable mapping across calls
        for domain in set(DOMAIN_PATTERN.findall(result)):
            if domain not in self._domain_map:
                self._domain_counter += 1
                self._domain_map[domain] = f"DOMAIN_{self._domain_counter}"
            result = result.replace(domain, self._domain_map[domain])

        # Normalize path integer IDs
        result = PATH_ID_PATTERN.sub("/{id}", result)

        return result

    def anonymize_finding(self, finding: dict) -> AnonymizedRecord:
        """Convert a raw finding into an anonymized federated record."""
        return AnonymizedRecord(
            technique_family=self._classify_technique(finding),
            target_stack=finding.get("target_stack", "unknown"),
            success=finding.get("verified", False),
            confidence=finding.get("confidence", 0.5),
            payload_template=self._templatize_payload(
                finding.get("payload", "")
            ),
            response_pattern=self.anonymize_text(
                finding.get("response", "")[:200]
            ),
            metadata={
                "severity": finding.get("severity", ""),
                "category": finding.get("category", ""),
                "detection_method": finding.get("detection_method", ""),
            },
        )

    def _classify_technique(self, finding: dict) -> str:
        """Map a finding to a technique family for cross-deployment comparison."""
        category = finding.get("category", "").lower()
        payload = finding.get("payload", "").lower()

        if category == "sqli":
            if "union" in payload:
                return "sqli_union"
            if "sleep" in payload or "benchmark" in payload:
                return "sqli_blind_time"
            if "and" in payload and "=" in payload:
                return "sqli_blind_boolean"
            return "sqli_error"

        if category == "xss":
            if "onerror" in payload or "onload" in payload:
                return "xss_event"
            if "<script" in payload:
                return "xss_script"
            return "xss_other"

        if category == "ssrf":
            return "ssrf_internal"

        if category == "command":
            return "command_injection"

        if category == "idor":
            return "idor_horizontal"

        return f"{category}_generic"

    def _templatize_payload(self, payload: str) -> str:
        """Convert a specific payload into a reusable pattern template."""
        template = self.anonymize_text(payload)
        template = re.sub(r"'\w+'", "'{value}'", template)
        template = re.sub(r'"\w+"', '"{value}"', template)
        return template[:500]
