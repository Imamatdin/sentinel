import pytest
from sentinel.benchmark.targets import TargetRegistry, Difficulty, BUILTIN_TARGETS


class TestTargetRegistry:
    def test_builtin_targets_loaded(self):
        reg = TargetRegistry()
        assert len(reg.targets) >= 3

    def test_get_target(self):
        reg = TargetRegistry()
        target = reg.get("juice-shop")
        assert target is not None
        assert target.name == "OWASP Juice Shop"

    def test_ground_truth_exists(self):
        reg = TargetRegistry()
        for t in reg.list_targets():
            assert len(t.ground_truth) > 0, f"{t.name} has no ground truth"

    def test_negative_controls_exist(self):
        reg = TargetRegistry()
        for t in reg.list_targets():
            assert len(t.negative_controls) > 0, f"{t.name} has no negative controls"

    def test_filter_by_difficulty(self):
        reg = TargetRegistry()
        easy = reg.list_targets(difficulty=Difficulty.EASY)
        assert all(t.difficulty == Difficulty.EASY for t in easy)

    def test_filter_by_domain(self):
        reg = TargetRegistry()
        api = reg.list_targets(domain="api")
        assert all("api" in t.domains for t in api)

    def test_all_vulns_have_cwe(self):
        for t in BUILTIN_TARGETS:
            for v in t.ground_truth:
                assert v.cwe_id.startswith("CWE-"), f"{v.vuln_id} missing CWE"
