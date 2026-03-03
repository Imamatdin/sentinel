import pytest
from sentinel.inference.active_scanner import ActiveScanner


class TestActiveScanner:
    def setup_method(self):
        self.scanner = ActiveScanner()

    def test_initialize_host(self):
        self.scanner.initialize_host("h1")
        assert "h1" in self.scanner.beliefs
        assert len(self.scanner.beliefs["h1"].port_beliefs) == 22

    def test_select_next_action(self):
        self.scanner.initialize_host("h1")
        action = self.scanner.select_next_action("h1")
        assert action is not None
        assert action.action_type == "port_scan"
        assert action.expected_info_gain >= 0

    def test_update_reduces_uncertainty(self):
        self.scanner.initialize_host("h1", common_ports=[80])
        before = self.scanner.beliefs["h1"].total_uncertainty()
        action = self.scanner.select_next_action("h1")
        self.scanner.update_belief("h1", action, True)
        after = self.scanner.beliefs["h1"].total_uncertainty()
        assert after < before

    def test_no_action_when_certain(self):
        self.scanner.initialize_host("h1", common_ports=[80])
        for _ in range(20):
            self.scanner.beliefs["h1"].port_beliefs[80].update(True)
        action = self.scanner.select_next_action("h1")
        assert action is None  # Below uncertainty threshold

    def test_get_plan(self):
        self.scanner.initialize_host("h1", common_ports=[22, 80, 443])
        plan = self.scanner.get_plan("h1")
        assert len(plan) > 0

    def test_get_plan_restores_beliefs(self):
        self.scanner.initialize_host("h1", common_ports=[80])
        before = self.scanner.beliefs["h1"].port_beliefs[80].alpha
        self.scanner.get_plan("h1")
        after = self.scanner.beliefs["h1"].port_beliefs[80].alpha
        assert before == after  # Plan should not modify beliefs

    def test_uncertainty_report(self):
        self.scanner.initialize_host("h1", common_ports=[80, 443])
        report = self.scanner.get_uncertainty_report("h1")
        assert "total_uncertainty" in report
        assert "port_uncertainties" in report
        assert "actions_taken" in report

    def test_unknown_host_returns_none(self):
        action = self.scanner.select_next_action("nonexistent")
        assert action is None

    def test_unknown_host_report_empty(self):
        report = self.scanner.get_uncertainty_report("nonexistent")
        assert report == {}

    def test_vuln_and_cred_actions(self):
        self.scanner.initialize_host("h1", common_ports=[])
        beliefs = self.scanner.beliefs["h1"]
        beliefs.add_vuln("CVE-2021-44228")
        from sentinel.inference.belief_model import BetaBelief
        beliefs.cred_beliefs["admin:pass"] = BetaBelief("cred_admin")
        action = self.scanner.select_next_action("h1")
        assert action is not None
        assert action.action_type in ("vuln_check", "cred_test")
