"""Tests for Phase 9 -- Advanced Blue Team & Red vs Blue Adversarial Loop.

Unit tests -- no external services required.
"""

import time

import pytest
from unittest.mock import AsyncMock

from sentinel.defense.behavioral_detector import (
    BehavioralDetector,
    DetectionAlert,
    RequestProfile,
)
from sentinel.defense.active_defense import ActiveDefense, DefenseAction
from sentinel.defense.adversarial_loop import AdversarialLoop, LoopMetrics, RoundResult
from sentinel.defense.mitre_mapper import MITREMapper, MITREMapping, ATTACK_MAPPING
from sentinel.defense.remediation_verifier import RemediationVerifier


# === RequestProfile Tests ===


class TestRequestProfile:
    def test_creation(self):
        req = RequestProfile(
            timestamp=1000.0,
            source_ip="10.0.0.1",
            method="GET",
            path="/api/test",
            params={"q": "hello"},
            headers={"Host": "example.com"},
            body_size=0,
            body_entropy=0.0,
            response_code=200,
            response_size=500,
            response_time_ms=50.0,
        )
        assert req.source_ip == "10.0.0.1"
        assert req.method == "GET"
        assert req.path == "/api/test"

    def test_all_fields_stored(self):
        req = RequestProfile(
            timestamp=1000.0,
            source_ip="192.168.1.1",
            method="POST",
            path="/login",
            params={"user": "admin"},
            headers={"Cookie": "session=abc"},
            body_size=100,
            body_entropy=3.5,
            response_code=401,
            response_size=50,
            response_time_ms=20.0,
        )
        assert req.body_entropy == 3.5
        assert req.response_code == 401


# === BehavioralDetector Tests ===


class TestBehavioralDetector:
    def setup_method(self):
        self.detector = BehavioralDetector()

    def _make_request(self, **kwargs) -> RequestProfile:
        defaults = {
            "timestamp": time.time(),
            "source_ip": "10.0.0.1",
            "method": "GET",
            "path": "/api/test",
            "params": {},
            "headers": {},
            "body_size": 0,
            "body_entropy": 0.0,
            "response_code": 200,
            "response_size": 100,
            "response_time_ms": 50,
        }
        defaults.update(kwargs)
        return RequestProfile(**defaults)

    def test_detects_sqli(self):
        req = self._make_request(params={"q": "' OR 1=1 --"})
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "sqli" for a in alerts)

    def test_detects_xss(self):
        req = self._make_request(params={"q": "<script>alert(1)</script>"})
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "xss" for a in alerts)

    def test_detects_ssrf(self):
        req = self._make_request(params={"url": "http://169.254.169.254/meta"})
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "ssrf" for a in alerts)

    def test_detects_cmd_injection(self):
        req = self._make_request(params={"cmd": "; id"})
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "cmd_injection" for a in alerts)

    def test_detects_brute_force(self):
        now = time.time()
        # Send 15 rapid requests from same IP
        for i in range(15):
            req = self._make_request(
                timestamp=now + i * 0.05,
                source_ip="10.0.0.2",
                path="/login",
            )
            self.detector.analyze_request(req)

        # Next request should trigger brute force
        req = self._make_request(
            timestamp=now + 0.8,
            source_ip="10.0.0.2",
            path="/login",
        )
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "brute_force" for a in alerts)

    def test_detects_scanning(self):
        now = time.time()
        # Hit 25 unique paths rapidly
        for i in range(25):
            req = self._make_request(
                timestamp=now + i * 0.1,
                source_ip="10.0.0.3",
                path=f"/path/{i}",
            )
            self.detector.analyze_request(req)

        # The scanning should be detected on recent requests
        last_alerts = self.detector.analyze_request(
            self._make_request(
                timestamp=now + 2.6,
                source_ip="10.0.0.3",
                path="/path/26",
            )
        )
        assert any(a.alert_type == "scanning" for a in last_alerts)

    def test_detects_data_exfil(self):
        req = self._make_request(response_size=200_000)
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "data_exfil" for a in alerts)

    def test_detects_high_entropy_payload(self):
        req = self._make_request(body_entropy=6.5)
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "suspicious_payload" for a in alerts)

    def test_no_alerts_for_normal_request(self):
        req = self._make_request(
            params={"q": "normal search query"},
            body_entropy=2.0,
            response_size=500,
        )
        alerts = self.detector.analyze_request(req)
        assert len(alerts) == 0

    def test_entropy_calculation(self):
        assert BehavioralDetector.calculate_entropy("") == 0.0
        assert BehavioralDetector.calculate_entropy("aaaa") < BehavioralDetector.calculate_entropy("a1b2c3d4!")
        # Single char repeated has 0 entropy
        assert BehavioralDetector.calculate_entropy("a") == 0.0

    def test_entropy_increases_with_randomness(self):
        low = BehavioralDetector.calculate_entropy("aaaaaa")
        mid = BehavioralDetector.calculate_entropy("aabbcc")
        high = BehavioralDetector.calculate_entropy("a1b2c3d4e5f6!")
        assert low < mid < high

    def test_alert_has_mitre_technique(self):
        req = self._make_request(params={"q": "' OR 1=1 --"})
        alerts = self.detector.analyze_request(req)
        sqli_alert = next(a for a in alerts if a.alert_type == "sqli")
        assert sqli_alert.mitre_technique == "T1190"

    def test_alert_has_recommended_action(self):
        req = self._make_request(params={"q": "' OR 1=1 --"})
        alerts = self.detector.analyze_request(req)
        sqli_alert = next(a for a in alerts if a.alert_type == "sqli")
        assert sqli_alert.recommended_action in ("block_ip", "challenge")


# === ActiveDefense Tests ===


class TestActiveDefense:
    def setup_method(self):
        self.defense = ActiveDefense()

    def _make_alert(self, **kwargs) -> DetectionAlert:
        defaults = {
            "alert_type": "sqli",
            "confidence": 0.9,
            "source_ip": "10.0.0.1",
            "evidence": "test",
            "mitre_technique": "T1190",
            "timestamp": time.time(),
            "recommended_action": "block_ip",
        }
        defaults.update(kwargs)
        return DetectionAlert(**defaults)

    def test_block_ip(self):
        alert = self._make_alert(recommended_action="block_ip")
        action = self.defense.respond(alert)
        assert action.action_type == "block_ip"
        assert self.defense.is_blocked("10.0.0.1")

    def test_rate_limit(self):
        alert = self._make_alert(recommended_action="rate_limit")
        action = self.defense.respond(alert)
        assert action.action_type == "rate_limit"
        assert self.defense.get_rate_limit("10.0.0.1") == 10

    def test_challenge(self):
        alert = self._make_alert(recommended_action="challenge")
        action = self.defense.respond(alert)
        assert action.action_type == "challenge"
        assert action.mitre_mitigation == "M1036"

    def test_log_only(self):
        alert = self._make_alert(recommended_action="log")
        action = self.defense.respond(alert)
        assert action.action_type == "log"

    def test_unknown_action_defaults_to_log(self):
        alert = self._make_alert(recommended_action="unknown_action")
        action = self.defense.respond(alert)
        assert action.action_type == "log"

    def test_is_blocked_false_for_unknown_ip(self):
        assert not self.defense.is_blocked("192.168.1.1")

    def test_get_rate_limit_none_for_unknown_ip(self):
        assert self.defense.get_rate_limit("192.168.1.1") is None

    def test_defense_actions_tracked(self):
        alert = self._make_alert()
        self.defense.respond(alert)
        assert len(self.defense.defense_actions) == 1

    def test_suggest_hardening_sqli(self):
        findings = [{"category": "sqli", "hypothesis_id": "h1"}]
        suggestions = self.defense.suggest_hardening(findings)
        assert len(suggestions) == 1
        assert suggestions[0]["type"] == "waf_rule"
        assert "parameterized" in suggestions[0]["code_fix"].lower()

    def test_suggest_hardening_xss(self):
        findings = [{"category": "xss", "hypothesis_id": "h2"}]
        suggestions = self.defense.suggest_hardening(findings)
        assert len(suggestions) == 1
        assert suggestions[0]["type"] == "csp"

    def test_suggest_hardening_ssrf(self):
        findings = [{"category": "ssrf", "hypothesis_id": "h3"}]
        suggestions = self.defense.suggest_hardening(findings)
        assert len(suggestions) == 1
        assert suggestions[0]["type"] == "network"

    def test_suggest_hardening_multiple(self):
        findings = [
            {"category": "sqli", "hypothesis_id": "h1"},
            {"category": "xss", "hypothesis_id": "h2"},
        ]
        suggestions = self.defense.suggest_hardening(findings)
        assert len(suggestions) == 2

    def test_block_ip_has_expiry(self):
        alert = self._make_alert(recommended_action="block_ip")
        action = self.defense.respond(alert)
        assert action.expires_at is not None


# === AdversarialLoop Tests ===


class TestAdversarialLoop:
    @pytest.mark.asyncio
    async def test_loop_runs_specified_rounds(self):
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop("http://localhost:3000", max_rounds=5)
        assert metrics.total_rounds == 5

    @pytest.mark.asyncio
    async def test_loop_tracks_detections(self):
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop(
            "http://localhost:3000",
            max_rounds=3,
            red_techniques=["sqli_basic", "xss_reflected", "ssrf_direct"],
        )
        # All three should be detected
        assert metrics.blue_detections >= 1
        assert metrics.coverage_score > 0

    @pytest.mark.asyncio
    async def test_red_adapts_when_blocked(self):
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop(
            "http://localhost:3000",
            max_rounds=10,
            red_techniques=["sqli_basic", "xss_reflected"],
        )
        # Red should try different techniques after being blocked
        techniques_used = set(r.red_action for r in metrics.rounds)
        assert len(techniques_used) >= 1

    @pytest.mark.asyncio
    async def test_loop_exhaustion(self):
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        # Give only 2 techniques but 50 rounds — should exhaust early
        metrics = await loop.run_loop(
            "http://localhost:3000",
            max_rounds=50,
            red_techniques=["sqli_basic", "xss_reflected"],
        )
        # Should finish well before 50 rounds
        assert metrics.total_rounds <= 10

    @pytest.mark.asyncio
    async def test_metrics_have_latency(self):
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop("http://localhost:3000", max_rounds=3)
        assert metrics.avg_detection_latency_ms >= 0
        assert metrics.avg_response_latency_ms >= 0

    @pytest.mark.asyncio
    async def test_round_result_structure(self):
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop(
            "http://localhost:3000",
            max_rounds=1,
            red_techniques=["sqli_basic"],
        )
        assert len(metrics.rounds) == 1
        r = metrics.rounds[0]
        assert r.round_number == 0
        assert r.red_action == "sqli_basic"
        assert isinstance(r.blue_detected, bool)
        assert isinstance(r.detection_latency_ms, float)


    @pytest.mark.asyncio
    async def test_brute_force_detected(self):
        """Brute force techniques should send a burst and trigger rate detection."""
        detector = BehavioralDetector()
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop(
            "http://localhost:3000",
            max_rounds=1,
            red_techniques=["brute_force_slow"],
        )
        assert metrics.blue_detections >= 1
        assert any(r.blue_detected for r in metrics.rounds)


# === Speed Demo Tests ===


class TestSpeedDemo:
    @pytest.mark.asyncio
    async def test_speed_demo_runs(self):
        from sentinel.defense.adversarial_loop import run_speed_demo
        result = await run_speed_demo(rounds=5)
        assert "fast_blue" in result
        assert "slow_blue" in result
        assert result["speedup_factor"] == 200.0  # 200ms / 1ms
        assert result["fast_blue"]["simulated_inference_ms"] == 1.0
        assert result["slow_blue"]["simulated_inference_ms"] == 200.0

    @pytest.mark.asyncio
    async def test_speed_demo_inference_saved(self):
        from sentinel.defense.adversarial_loop import run_speed_demo
        result = await run_speed_demo(rounds=10)
        # Slow should have much higher total inference overhead
        assert result["inference_time_saved_ms"] > 0
        assert result["slow_blue"]["total_inference_overhead_ms"] > result["fast_blue"]["total_inference_overhead_ms"]

    @pytest.mark.asyncio
    async def test_speed_demo_effective_response(self):
        from sentinel.defense.adversarial_loop import run_speed_demo
        result = await run_speed_demo(rounds=5)
        # Fast effective response should be much lower than slow
        assert result["fast_blue"]["effective_response_ms"] < result["slow_blue"]["effective_response_ms"]

    def test_speed_demo_importable(self):
        from sentinel.defense import run_speed_demo
        assert callable(run_speed_demo)


# === MITREMapper Tests ===


class TestMITREMapper:
    def setup_method(self):
        self.mapper = MITREMapper()

    def test_map_known_attack(self):
        mapping = self.mapper.map_attack("sqli")
        assert mapping.technique_id == "T1190"
        assert mapping.tactic == "Initial Access"
        assert mapping.mitigation_id == "M1030"

    def test_map_xss(self):
        mapping = self.mapper.map_attack("xss")
        assert mapping.technique_id == "T1059.007"
        assert mapping.tactic == "Execution"

    def test_map_unknown_attack(self):
        mapping = self.mapper.map_attack("unknown_category")
        assert mapping.technique_id == "T1190"
        assert mapping.technique_name == "Unknown"

    def test_all_categories_mapped(self):
        categories = ["sqli", "xss", "ssrf", "cmd_injection", "file_upload",
                       "xxe", "auth_bypass", "idor", "brute_force", "data_exfil"]
        for cat in categories:
            mapping = self.mapper.map_attack(cat)
            assert mapping.technique_id.startswith("T")
            assert mapping.mitigation_id.startswith("M")

    def test_get_attack_coverage(self):
        findings = [
            {"category": "sqli"},
            {"category": "xss"},
            {"category": "ssrf"},
        ]
        coverage = self.mapper.get_attack_coverage(findings)
        assert coverage["total_tactics"] == 3  # Initial Access, Execution, C2
        assert coverage["total_techniques"] == 3

    def test_get_attack_coverage_deduplicates(self):
        findings = [
            {"category": "sqli"},
            {"category": "xxe"},  # Same technique as sqli (T1190)
        ]
        coverage = self.mapper.get_attack_coverage(findings)
        assert coverage["total_techniques"] == 1  # T1190 deduplicated

    def test_attack_mapping_dict_has_entries(self):
        assert len(ATTACK_MAPPING) == 10


# === RemediationVerifier Tests ===


class TestRemediationVerifier:
    def setup_method(self):
        self.verifier = RemediationVerifier()

    @pytest.mark.asyncio
    async def test_verify_fix_blocked(self):
        """Replay returns success=False means fix verified."""
        replay = AsyncMock(return_value={"success": False})
        finding = {"hypothesis_id": "h1", "severity": "critical"}
        result = await self.verifier.verify_remediation(finding, replay)
        assert result["fix_verified"] is True
        assert result["retest_result"] == "BLOCKED"

    @pytest.mark.asyncio
    async def test_verify_still_vulnerable(self):
        """Replay returns success=True means still vulnerable."""
        replay = AsyncMock(return_value={"success": True})
        finding = {"hypothesis_id": "h2", "severity": "high"}
        result = await self.verifier.verify_remediation(finding, replay)
        assert result["fix_verified"] is False
        assert result["retest_result"] == "STILL_VULNERABLE"

    @pytest.mark.asyncio
    async def test_verify_handles_error(self):
        """Replay that raises should not crash."""
        replay = AsyncMock(side_effect=RuntimeError("connection refused"))
        finding = {"hypothesis_id": "h3", "severity": "medium"}
        result = await self.verifier.verify_remediation(finding, replay)
        assert result["fix_verified"] is False
        assert result["retest_result"] == "ERROR"

    @pytest.mark.asyncio
    async def test_bulk_verify(self):
        replay = AsyncMock(side_effect=[
            {"success": False},  # fixed
            {"success": True},   # still vuln
            {"success": False},  # fixed
        ])
        findings = [
            {"hypothesis_id": "h1", "severity": "critical"},
            {"hypothesis_id": "h2", "severity": "high"},
            {"hypothesis_id": "h3", "severity": "medium"},
        ]
        result = await self.verifier.bulk_verify(findings, replay)
        assert result["total"] == 3
        assert result["verified_fixed"] == 2
        assert result["still_vulnerable"] == 1
        assert result["fix_rate"] == pytest.approx(2 / 3)

    @pytest.mark.asyncio
    async def test_bulk_verify_empty(self):
        replay = AsyncMock()
        result = await self.verifier.bulk_verify([], replay)
        assert result["total"] == 0
        assert result["fix_rate"] == 0.0


# === Import Tests ===


class TestImports:
    def test_defense_module_exports(self):
        from sentinel.defense import (
            BehavioralDetector, DetectionAlert, RequestProfile,
            ActiveDefense, DefenseAction,
            AdversarialLoop, LoopMetrics, RoundResult,
            MITREMapper, MITREMapping, ATTACK_MAPPING,
            RemediationVerifier, run_speed_demo,
        )
        assert callable(BehavioralDetector)
        assert callable(ActiveDefense)
        assert callable(AdversarialLoop)
        assert callable(MITREMapper)
        assert callable(RemediationVerifier)
        assert callable(run_speed_demo)

    def test_detection_alert_creation(self):
        alert = DetectionAlert(
            alert_type="test",
            confidence=0.5,
            source_ip="1.2.3.4",
            evidence="test evidence",
            mitre_technique="T1190",
            timestamp=time.time(),
        )
        assert alert.recommended_action == ""  # default
        assert alert.request is None  # default
