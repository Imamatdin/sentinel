"""
Adaptive WAF Rule Synthesizer.

Takes red team attack traces and generates ModSecurity-compatible WAF rules.
Two strategies:
1. Pattern extraction: Analyze successful exploit payloads -> extract common patterns -> generate rules
2. Behavioral rules: Block requests matching anomaly profile from TrafficProfiler
"""

import re
from dataclasses import dataclass

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class WAFRule:
    rule_id: int
    description: str
    pattern: str          # Regex pattern to match
    action: str           # "deny" | "log" | "redirect"
    phase: int            # ModSec phase (1=request headers, 2=request body)
    severity: str
    source: str           # "red_team_trace" | "anomaly_profile" | "manual"
    modsec_rule: str      # Full ModSecurity rule string


class AdaptiveWAF:
    """Generate WAF rules from red team attack traces."""

    NEXT_RULE_ID = 900000  # Custom rule ID range

    def __init__(self):
        self.rules: list[WAFRule] = []

    def generate_from_attack(self, attack_trace: dict) -> WAFRule | None:
        """Generate a WAF rule from a successful attack trace.

        Args:
            attack_trace: {category, payload, target_param, method, path}
        """
        payload = attack_trace.get("payload", "")
        if not payload:
            return None

        category = attack_trace.get("category", "")
        param = attack_trace.get("target_param", "")

        pattern = self._extract_pattern(payload, category)
        if not pattern:
            return None

        rule_id = self.NEXT_RULE_ID + len(self.rules)

        modsec = (
            f'SecRule ARGS "{pattern}" '
            f'"id:{rule_id},phase:2,deny,status:403,'
            f"msg:'Sentinel auto-rule: {category} pattern detected',"
            f'severity:CRITICAL,tag:sentinel/auto"'
        )

        rule = WAFRule(
            rule_id=rule_id,
            description=f"Auto-generated rule for {category} via {param}",
            pattern=pattern,
            action="deny",
            phase=2,
            severity="critical",
            source="red_team_trace",
            modsec_rule=modsec,
        )

        self.rules.append(rule)
        logger.info("waf_rule_generated", rule_id=rule_id, category=category)
        return rule

    def generate_from_anomaly(
        self, profiler_route: str, anomaly_details: str
    ) -> WAFRule | None:
        """Generate a WAF rule from TrafficProfiler anomaly patterns."""
        rule_id = self.NEXT_RULE_ID + len(self.rules)

        modsec = (
            f'SecRule REQUEST_URI "@streq {profiler_route}" '
            f'"id:{rule_id},phase:2,chain,'
            f"msg:'Sentinel behavioral rule: anomalous traffic to {profiler_route}',"
            f'severity:WARNING,tag:sentinel/behavioral"\n'
            f'  SecRule ARGS "@validateByteRange 1-255" '
            f'"setvar:tx.anomaly_score=+5"'
        )

        rule = WAFRule(
            rule_id=rule_id,
            description=f"Behavioral rule for anomalous traffic to {profiler_route}: {anomaly_details}",
            pattern=f"@streq {profiler_route}",
            action="log",
            phase=2,
            severity="warning",
            source="anomaly_profile",
            modsec_rule=modsec,
        )
        self.rules.append(rule)
        return rule

    def _extract_pattern(self, payload: str, category: str) -> str:
        """Extract a regex pattern from an attack payload."""
        if category == "sqli":
            if re.search(r"(?i)(union|select|insert|drop|delete|update|or\s+\d)", payload):
                return r"(?i)(union\s+select|drop\s+table|;\s*delete|;\s*update|or\s+1\s*=\s*1)"

        elif category == "xss":
            if "<script" in payload.lower() or "onerror" in payload.lower():
                return r"(?i)(<script|on\w+\s*=|javascript:|data:text/html)"

        elif category == "command":
            if any(c in payload for c in [";", "|", "`", "$("]):
                return r"(;\s*\w+|`[^`]+`|\$\([^)]+\)|\|\s*\w+)"

        elif category == "path_traversal":
            if ".." in payload:
                return r"(\.\.\/|\.\.\\|%2e%2e)"

        elif category == "ssrf":
            return r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254|10\.\d|172\.(1[6-9]|2\d|3[01]))"

        # Generic fallback: escape a fragment of the payload
        if len(payload) >= 10:
            fragment = re.escape(payload[:30])
            return fragment

        return ""

    def export_rules(self) -> str:
        """Export all rules as a ModSecurity config file."""
        lines = [
            "# Sentinel Auto-Generated WAF Rules",
            f"# Generated: {len(self.rules)} rules from red team traces",
            "",
        ]
        for rule in self.rules:
            lines.append(f"# {rule.description}")
            lines.append(rule.modsec_rule)
            lines.append("")
        return "\n".join(lines)
