"""Action policy enforcement for Tool-Guarded LLM execution.

Implements the "Plan-Then-Execute" pattern:
1. LLM proposes actions
2. Policy engine validates against allowlist
3. Only approved actions execute
4. All rejections logged for audit
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import re
import uuid

from pydantic import BaseModel, Field

from sentinel.core import get_logger, AuthorizationError

logger = get_logger(__name__)


class ActionType(str, Enum):
    """Types of actions the LLM can request."""
    # Reconnaissance
    NMAP_SCAN = "nmap_scan"
    DNS_LOOKUP = "dns_lookup"
    HTTP_REQUEST = "http_request"
    CRAWL_ENDPOINT = "crawl_endpoint"

    # Vulnerability Analysis
    VULN_SCAN = "vuln_scan"
    NUCLEI_SCAN = "nuclei_scan"
    ZAP_SCAN = "zap_scan"

    # Exploitation
    EXPLOIT_ATTEMPT = "exploit_attempt"
    CREDENTIAL_TEST = "credential_test"
    INJECTION_TEST = "injection_test"

    # Post-Exploitation
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"

    # System
    SHELL_COMMAND = "shell_command"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"

    # Reporting
    CREATE_FINDING = "create_finding"
    UPDATE_GRAPH = "update_graph"


class RiskLevel(str, Enum):
    """Risk levels for actions."""
    LOW = "low"           # Passive recon
    MEDIUM = "medium"     # Active scanning
    HIGH = "high"         # Exploitation
    CRITICAL = "critical" # Destructive/exfiltration


@dataclass
class ActionRequest:
    """A request from the LLM to perform an action."""
    action_type: ActionType
    parameters: dict[str, Any]
    justification: str
    target: str
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: str = ""

    def __post_init__(self) -> None:
        if not self.request_id:
            self.request_id = str(uuid.uuid4())[:8]


@dataclass
class ActionDecision:
    """Decision on an action request."""
    request: ActionRequest
    approved: bool
    reason: str
    modified_params: dict[str, Any] | None = None
    decided_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    requires_human_approval: bool = False


class PolicyRule(BaseModel):
    """A single policy rule."""
    action_type: ActionType
    allowed: bool = True
    risk_level: RiskLevel = RiskLevel.MEDIUM
    requires_scope_check: bool = True
    requires_human_approval: bool = False
    max_rate_per_minute: int = 60
    parameter_constraints: dict[str, Any] = Field(default_factory=dict)


class EngagementPolicy(BaseModel):
    """Policy configuration for an engagement."""
    engagement_id: str

    # Scope definition
    scope_includes: list[str] = Field(default_factory=list)  # Regex patterns
    scope_excludes: list[str] = Field(default_factory=list)  # Regex patterns

    # Allowed actions by risk level
    allow_low_risk: bool = True
    allow_medium_risk: bool = True
    allow_high_risk: bool = False  # Requires explicit enable
    allow_critical_risk: bool = False  # Always requires approval

    # Specific rules (override defaults)
    custom_rules: list[PolicyRule] = Field(default_factory=list)

    # Rate limits
    global_rate_limit_per_minute: int = 100

    # Time constraints
    allowed_start_hour: int = 0  # 24h format
    allowed_end_hour: int = 24

    # Dangerous action blocklist
    blocked_commands: list[str] = Field(default_factory=lambda: [
        "rm -rf",
        "mkfs",
        "dd if=",
        "> /dev/",
        "shutdown",
        "reboot",
        ":(){ :|:& };:",  # Fork bomb
    ])


# Default risk levels for each action
DEFAULT_RISK_LEVELS: dict[ActionType, RiskLevel] = {
    # Low risk - passive
    ActionType.DNS_LOOKUP: RiskLevel.LOW,
    ActionType.HTTP_REQUEST: RiskLevel.LOW,
    ActionType.CREATE_FINDING: RiskLevel.LOW,
    ActionType.UPDATE_GRAPH: RiskLevel.LOW,

    # Medium risk - active scanning
    ActionType.NMAP_SCAN: RiskLevel.MEDIUM,
    ActionType.CRAWL_ENDPOINT: RiskLevel.MEDIUM,
    ActionType.VULN_SCAN: RiskLevel.MEDIUM,
    ActionType.NUCLEI_SCAN: RiskLevel.MEDIUM,
    ActionType.ZAP_SCAN: RiskLevel.MEDIUM,
    ActionType.FILE_READ: RiskLevel.MEDIUM,

    # High risk - exploitation
    ActionType.EXPLOIT_ATTEMPT: RiskLevel.HIGH,
    ActionType.CREDENTIAL_TEST: RiskLevel.HIGH,
    ActionType.INJECTION_TEST: RiskLevel.HIGH,
    ActionType.SHELL_COMMAND: RiskLevel.HIGH,

    # Critical risk - destructive
    ActionType.PRIVILEGE_ESCALATION: RiskLevel.CRITICAL,
    ActionType.LATERAL_MOVEMENT: RiskLevel.CRITICAL,
    ActionType.DATA_EXFILTRATION: RiskLevel.CRITICAL,
    ActionType.FILE_WRITE: RiskLevel.CRITICAL,
}


class PolicyEngine:
    """Enforces action policies for tool-guarded LLM execution."""

    def __init__(self, policy: EngagementPolicy):
        self.policy = policy
        self._action_counts: dict[str, list[datetime]] = {}

    def evaluate(self, request: ActionRequest) -> ActionDecision:
        """Evaluate an action request against policy."""
        logger.debug(
            "Evaluating action request",
            action=request.action_type.value,
            target=request.target,
            request_id=request.request_id,
        )

        # Check 1: Is target in scope?
        if not self._is_in_scope(request.target):
            return ActionDecision(
                request=request,
                approved=False,
                reason=f"Target '{request.target}' is out of scope",
            )

        # Check 2: Get risk level
        risk_level = DEFAULT_RISK_LEVELS.get(request.action_type, RiskLevel.HIGH)

        # Check 3: Is risk level allowed?
        if not self._is_risk_allowed(risk_level):
            return ActionDecision(
                request=request,
                approved=False,
                reason=f"Risk level '{risk_level.value}' not allowed for this engagement",
                requires_human_approval=True,
            )

        # Check 4: Rate limiting
        if not self._check_rate_limit(request.action_type):
            return ActionDecision(
                request=request,
                approved=False,
                reason="Rate limit exceeded",
            )

        # Check 5: Check for blocked commands (shell commands)
        if request.action_type == ActionType.SHELL_COMMAND:
            cmd = request.parameters.get("command", "")
            if self._is_blocked_command(cmd):
                return ActionDecision(
                    request=request,
                    approved=False,
                    reason="Command contains blocked pattern",
                )

        # Check 6: Custom rules
        custom_decision = self._check_custom_rules(request)
        if custom_decision:
            return custom_decision

        # Check 7: Critical actions always need approval
        requires_approval = risk_level == RiskLevel.CRITICAL

        logger.info(
            "Action approved",
            action=request.action_type.value,
            target=request.target,
            risk_level=risk_level.value,
            requires_approval=requires_approval,
        )

        return ActionDecision(
            request=request,
            approved=True,
            reason="Policy check passed",
            requires_human_approval=requires_approval,
        )

    def _is_in_scope(self, target: str) -> bool:
        """Check if target is in scope."""
        # Check exclusions first
        for pattern in self.policy.scope_excludes:
            if re.search(pattern, target, re.IGNORECASE):
                return False

        # Check inclusions
        if not self.policy.scope_includes:
            return True  # No includes = everything in scope

        for pattern in self.policy.scope_includes:
            if re.search(pattern, target, re.IGNORECASE):
                return True

        return False

    def _is_risk_allowed(self, risk_level: RiskLevel) -> bool:
        """Check if risk level is allowed."""
        if risk_level == RiskLevel.LOW:
            return self.policy.allow_low_risk
        elif risk_level == RiskLevel.MEDIUM:
            return self.policy.allow_medium_risk
        elif risk_level == RiskLevel.HIGH:
            return self.policy.allow_high_risk
        elif risk_level == RiskLevel.CRITICAL:
            return self.policy.allow_critical_risk
        return False

    def _check_rate_limit(self, action_type: ActionType) -> bool:
        """Check if action is within rate limits."""
        now = datetime.now(timezone.utc)
        key = action_type.value

        # Initialize or clean old entries
        if key not in self._action_counts:
            self._action_counts[key] = []

        # Remove entries older than 1 minute
        self._action_counts[key] = [
            t for t in self._action_counts[key]
            if (now - t).total_seconds() < 60
        ]

        # Check limit
        if len(self._action_counts[key]) >= self.policy.global_rate_limit_per_minute:
            return False

        # Record this action
        self._action_counts[key].append(now)
        return True

    def _is_blocked_command(self, command: str) -> bool:
        """Check if command contains blocked patterns."""
        for blocked in self.policy.blocked_commands:
            if blocked in command:
                logger.warning("Blocked command detected", pattern=blocked)
                return True
        return False

    def _check_custom_rules(self, request: ActionRequest) -> ActionDecision | None:
        """Check custom policy rules."""
        for rule in self.policy.custom_rules:
            if rule.action_type == request.action_type:
                if not rule.allowed:
                    return ActionDecision(
                        request=request,
                        approved=False,
                        reason="Action blocked by custom rule",
                    )
                if rule.requires_human_approval:
                    return ActionDecision(
                        request=request,
                        approved=True,
                        reason="Approved but requires human confirmation",
                        requires_human_approval=True,
                    )
        return None
