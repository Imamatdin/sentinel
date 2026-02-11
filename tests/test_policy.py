"""Tests for action policy enforcement."""

import pytest
from datetime import datetime

from sentinel.agents.policy import (
    PolicyEngine,
    EngagementPolicy,
    ActionRequest,
    ActionDecision,
    ActionType,
    RiskLevel,
    PolicyRule,
    DEFAULT_RISK_LEVELS,
)


@pytest.fixture
def basic_policy() -> EngagementPolicy:
    """Policy that allows low and medium risk on example.com."""
    return EngagementPolicy(
        engagement_id="test-001",
        scope_includes=[r"example\.com", r"192\.168\.1\.\d+"],
        scope_excludes=[r"production\.example\.com"],
        allow_low_risk=True,
        allow_medium_risk=True,
        allow_high_risk=False,
        allow_critical_risk=False,
    )


@pytest.fixture
def permissive_policy() -> EngagementPolicy:
    """Policy that allows all risk levels."""
    return EngagementPolicy(
        engagement_id="test-002",
        allow_low_risk=True,
        allow_medium_risk=True,
        allow_high_risk=True,
        allow_critical_risk=True,
    )


def make_request(
    action_type: ActionType,
    target: str = "https://example.com",
    params: dict | None = None,
) -> ActionRequest:
    """Helper to create action requests."""
    return ActionRequest(
        action_type=action_type,
        parameters=params or {},
        justification="Testing",
        target=target,
    )


class TestPolicyEngineScope:
    """Tests for scope checking."""

    def test_in_scope_target_approved(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.DNS_LOOKUP, "https://example.com")
        decision = engine.evaluate(request)
        assert decision.approved is True

    def test_ip_in_scope_approved(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.DNS_LOOKUP, "192.168.1.50")
        decision = engine.evaluate(request)
        assert decision.approved is True

    def test_out_of_scope_rejected(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.DNS_LOOKUP, "https://evil.com")
        decision = engine.evaluate(request)
        assert decision.approved is False
        assert "out of scope" in decision.reason.lower()

    def test_excluded_target_rejected(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.DNS_LOOKUP, "https://production.example.com")
        decision = engine.evaluate(request)
        assert decision.approved is False

    def test_no_scope_includes_allows_all(self):
        policy = EngagementPolicy(engagement_id="open")
        engine = PolicyEngine(policy)
        request = make_request(ActionType.DNS_LOOKUP, "https://anything.com")
        decision = engine.evaluate(request)
        assert decision.approved is True


class TestPolicyEngineRiskLevels:
    """Tests for risk level enforcement."""

    def test_low_risk_allowed(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.DNS_LOOKUP)  # Low risk
        decision = engine.evaluate(request)
        assert decision.approved is True

    def test_medium_risk_allowed(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.NMAP_SCAN)  # Medium risk
        decision = engine.evaluate(request)
        assert decision.approved is True

    def test_high_risk_rejected(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.EXPLOIT_ATTEMPT)  # High risk
        decision = engine.evaluate(request)
        assert decision.approved is False
        assert decision.requires_human_approval is True

    def test_critical_risk_rejected(self, basic_policy: EngagementPolicy):
        engine = PolicyEngine(basic_policy)
        request = make_request(ActionType.PRIVILEGE_ESCALATION)  # Critical
        decision = engine.evaluate(request)
        assert decision.approved is False

    def test_critical_requires_approval_when_allowed(self, permissive_policy: EngagementPolicy):
        engine = PolicyEngine(permissive_policy)
        request = make_request(ActionType.PRIVILEGE_ESCALATION)
        decision = engine.evaluate(request)
        assert decision.approved is True
        assert decision.requires_human_approval is True


class TestPolicyEngineBlockedCommands:
    """Tests for blocked command patterns."""

    def test_rm_rf_blocked(self, permissive_policy: EngagementPolicy):
        engine = PolicyEngine(permissive_policy)
        request = make_request(
            ActionType.SHELL_COMMAND,
            params={"command": "rm -rf /tmp/test"},
        )
        decision = engine.evaluate(request)
        assert decision.approved is False
        assert "blocked" in decision.reason.lower()

    def test_fork_bomb_blocked(self, permissive_policy: EngagementPolicy):
        engine = PolicyEngine(permissive_policy)
        request = make_request(
            ActionType.SHELL_COMMAND,
            params={"command": ":(){ :|:& };:"},
        )
        decision = engine.evaluate(request)
        assert decision.approved is False

    def test_safe_command_allowed(self, permissive_policy: EngagementPolicy):
        engine = PolicyEngine(permissive_policy)
        request = make_request(
            ActionType.SHELL_COMMAND,
            params={"command": "nmap -sV 192.168.1.1"},
        )
        decision = engine.evaluate(request)
        assert decision.approved is True


class TestPolicyEngineCustomRules:
    """Tests for custom policy rules."""

    def test_custom_block_rule(self):
        policy = EngagementPolicy(
            engagement_id="custom",
            custom_rules=[
                PolicyRule(
                    action_type=ActionType.NMAP_SCAN,
                    allowed=False,
                )
            ],
        )
        engine = PolicyEngine(policy)
        request = make_request(ActionType.NMAP_SCAN)
        decision = engine.evaluate(request)
        assert decision.approved is False
        assert "custom rule" in decision.reason.lower()

    def test_custom_approval_required(self):
        policy = EngagementPolicy(
            engagement_id="custom",
            custom_rules=[
                PolicyRule(
                    action_type=ActionType.HTTP_REQUEST,
                    allowed=True,
                    requires_human_approval=True,
                )
            ],
        )
        engine = PolicyEngine(policy)
        request = make_request(ActionType.HTTP_REQUEST)
        decision = engine.evaluate(request)
        assert decision.approved is True
        assert decision.requires_human_approval is True


class TestPolicyEngineRateLimit:
    """Tests for rate limiting."""

    def test_rate_limit_exceeded(self):
        policy = EngagementPolicy(
            engagement_id="rate-test",
            global_rate_limit_per_minute=3,
        )
        engine = PolicyEngine(policy)

        # First 3 should succeed
        for _ in range(3):
            decision = engine.evaluate(make_request(ActionType.DNS_LOOKUP))
            assert decision.approved is True

        # 4th should fail
        decision = engine.evaluate(make_request(ActionType.DNS_LOOKUP))
        assert decision.approved is False
        assert "rate limit" in decision.reason.lower()


class TestDefaultRiskLevels:
    """Tests for default risk level mappings."""

    def test_passive_recon_is_low(self):
        assert DEFAULT_RISK_LEVELS[ActionType.DNS_LOOKUP] == RiskLevel.LOW
        assert DEFAULT_RISK_LEVELS[ActionType.HTTP_REQUEST] == RiskLevel.LOW

    def test_active_scanning_is_medium(self):
        assert DEFAULT_RISK_LEVELS[ActionType.NMAP_SCAN] == RiskLevel.MEDIUM
        assert DEFAULT_RISK_LEVELS[ActionType.VULN_SCAN] == RiskLevel.MEDIUM

    def test_exploitation_is_high(self):
        assert DEFAULT_RISK_LEVELS[ActionType.EXPLOIT_ATTEMPT] == RiskLevel.HIGH
        assert DEFAULT_RISK_LEVELS[ActionType.INJECTION_TEST] == RiskLevel.HIGH

    def test_destructive_is_critical(self):
        assert DEFAULT_RISK_LEVELS[ActionType.DATA_EXFILTRATION] == RiskLevel.CRITICAL
        assert DEFAULT_RISK_LEVELS[ActionType.PRIVILEGE_ESCALATION] == RiskLevel.CRITICAL


class TestActionRequest:
    """Tests for ActionRequest dataclass."""

    def test_auto_generates_request_id(self):
        request = ActionRequest(
            action_type=ActionType.DNS_LOOKUP,
            parameters={},
            justification="test",
            target="example.com",
        )
        assert len(request.request_id) == 8

    def test_preserves_explicit_request_id(self):
        request = ActionRequest(
            action_type=ActionType.DNS_LOOKUP,
            parameters={},
            justification="test",
            target="example.com",
            request_id="custom-id",
        )
        assert request.request_id == "custom-id"
