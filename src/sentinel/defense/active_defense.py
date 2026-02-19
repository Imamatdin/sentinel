"""ActiveDefense -- Automated defense response system.

Actions:
- Block IP (firewall rule)
- Rate limit IP
- Deploy CSP headers
- Add WAF rules
- Harden response headers
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.core import get_logger
from sentinel.defense.behavioral_detector import DetectionAlert

logger = get_logger(__name__)


@dataclass
class DefenseAction:
    """A defense action taken in response to a detection alert."""

    action_type: str  # "block_ip", "rate_limit", "challenge", "log", "add_waf_rule", "deploy_csp"
    target: str  # IP, endpoint, or "global"
    parameters: dict[str, Any]
    triggered_by: str  # Alert identifier
    expires_at: datetime | None = None
    mitre_mitigation: str = ""  # MITRE mitigation ID


class ActiveDefense:
    """Automated defense execution.

    Takes detection alerts and executes appropriate countermeasures.
    Tracks all actions for defense effectiveness scoring.
    """

    def __init__(self) -> None:
        self.blocked_ips: set[str] = set()
        self.rate_limited_ips: dict[str, int] = {}  # IP -> max requests/min
        self.waf_rules: list[dict[str, Any]] = []
        self.defense_actions: list[DefenseAction] = []
        self.csp_policy: str = ""

    def respond(self, alert: DetectionAlert) -> DefenseAction:
        """Generate and execute defense response for a detection alert."""
        action_map = {
            "block_ip": self._block_ip,
            "rate_limit": self._rate_limit,
            "challenge": self._add_challenge,
            "log": self._log_only,
        }

        handler = action_map.get(alert.recommended_action, self._log_only)
        action = handler(alert)
        self.defense_actions.append(action)

        logger.info(
            "defense_action",
            action_type=action.action_type,
            source_ip=alert.source_ip,
            alert_type=alert.alert_type,
        )
        return action

    def _block_ip(self, alert: DetectionAlert) -> DefenseAction:
        """Block an IP address."""
        self.blocked_ips.add(alert.source_ip)
        return DefenseAction(
            action_type="block_ip",
            target=alert.source_ip,
            parameters={"duration_minutes": 60},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=60),
            mitre_mitigation="M1035",  # Limit Access to Resource Over Network
        )

    def _rate_limit(self, alert: DetectionAlert) -> DefenseAction:
        """Apply rate limiting to an IP."""
        self.rate_limited_ips[alert.source_ip] = 10  # 10 req/min
        return DefenseAction(
            action_type="rate_limit",
            target=alert.source_ip,
            parameters={"max_requests_per_minute": 10},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=30),
            mitre_mitigation="M1031",  # Network Intrusion Prevention
        )

    def _add_challenge(self, alert: DetectionAlert) -> DefenseAction:
        """Add CAPTCHA/challenge for suspicious requests."""
        return DefenseAction(
            action_type="challenge",
            target=alert.source_ip,
            parameters={"type": "captcha"},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
            mitre_mitigation="M1036",  # Account Use Policies
        )

    def _log_only(self, alert: DetectionAlert) -> DefenseAction:
        """Log-only response for low-confidence alerts."""
        return DefenseAction(
            action_type="log",
            target=alert.source_ip,
            parameters={"severity": alert.alert_type},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
        )

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        return ip in self.blocked_ips

    def get_rate_limit(self, ip: str) -> int | None:
        """Get rate limit for an IP, or None if not rate limited."""
        return self.rate_limited_ips.get(ip)

    def suggest_hardening(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Suggest hardening measures based on findings.

        For each finding category, suggest:
        - Specific WAF rule
        - Header configuration
        - Code-level fix
        """
        suggestions: list[dict[str, Any]] = []
        for finding in findings:
            category = finding.get("category", "")

            if category in ("injection", "sqli"):
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "waf_rule",
                    "rule": "Block requests with SQL keywords in parameters",
                    "config": {"pattern": "UNION|SELECT|INSERT|UPDATE|DELETE|DROP", "action": "block"},
                    "header": {"X-Content-Type-Options": "nosniff"},
                    "code_fix": "Use parameterized queries / prepared statements",
                })
            elif category == "xss":
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "csp",
                    "rule": "Deploy Content Security Policy",
                    "config": {"Content-Security-Policy": "default-src 'self'; script-src 'self'"},
                    "header": {"X-XSS-Protection": "1; mode=block"},
                    "code_fix": "HTML-encode all user input in templates",
                })
            elif category == "ssrf":
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "network",
                    "rule": "Block outbound requests to internal IPs",
                    "config": {"blocked_ranges": ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]},
                    "code_fix": "Validate and whitelist allowed URL schemes and hosts",
                })
            elif category == "cmd_injection":
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "waf_rule",
                    "rule": "Block shell metacharacters in parameters",
                    "config": {"pattern": r"[;|`$&]", "action": "block"},
                    "code_fix": "Never pass user input to shell commands; use subprocess with arg lists",
                })

        return suggestions
