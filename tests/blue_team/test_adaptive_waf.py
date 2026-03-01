"""Tests for AdaptiveWAF."""

from sentinel.blue_team.adaptive_waf import AdaptiveWAF


class TestAdaptiveWAF:
    def setup_method(self):
        self.waf = AdaptiveWAF()

    def test_generate_sqli_rule(self):
        rule = self.waf.generate_from_attack({
            "category": "sqli",
            "payload": "' UNION SELECT * FROM users--",
            "target_param": "id",
            "method": "GET",
            "path": "/api/users",
        })
        assert rule is not None
        assert rule.action == "deny"
        assert "SecRule" in rule.modsec_rule

    def test_generate_xss_rule(self):
        rule = self.waf.generate_from_attack({
            "category": "xss",
            "payload": "<script>alert(document.cookie)</script>",
            "target_param": "name",
        })
        assert rule is not None
        assert "script" in rule.pattern.lower()

    def test_generate_command_injection_rule(self):
        rule = self.waf.generate_from_attack({
            "category": "command",
            "payload": "; rm -rf /",
            "target_param": "cmd",
        })
        assert rule is not None

    def test_export_rules(self):
        self.waf.generate_from_attack({
            "category": "sqli", "payload": "' OR 1=1--", "target_param": "q",
        })
        export = self.waf.export_rules()
        assert "Sentinel Auto-Generated" in export
        assert "SecRule" in export

    def test_no_rule_for_empty_payload(self):
        rule = self.waf.generate_from_attack({"category": "sqli", "payload": ""})
        assert rule is None

    def test_behavioral_rule(self):
        rule = self.waf.generate_from_anomaly("/api/search", "High entropy z=4.2")
        assert rule is not None
        assert rule.source == "anomaly_profile"

    def test_rule_ids_increment(self):
        self.waf.generate_from_attack({
            "category": "sqli", "payload": "' OR 1=1--", "target_param": "q",
        })
        self.waf.generate_from_attack({
            "category": "xss", "payload": "<script>alert(1)</script>", "target_param": "x",
        })
        assert self.waf.rules[0].rule_id < self.waf.rules[1].rule_id
