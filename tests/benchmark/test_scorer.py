import pytest
from sentinel.benchmark.scorer import BenchmarkScorer, Finding
from sentinel.benchmark.targets import TargetRegistry


class TestBenchmarkScorer:
    def setup_method(self):
        self.scorer = BenchmarkScorer()
        self.target = TargetRegistry().get("juice-shop")

    def test_perfect_score(self):
        findings = [
            Finding("sqli", "/rest/products/search", "q", "high", "union select"),
            Finding("xss", "/api/Users", "email", "medium", "script tag"),
            Finding("idor", "/api/BasketItems/5", "id", "high", "other user data"),
            Finding("auth_bypass", "/rest/user/login", "email", "critical", "admin login"),
        ]
        score = self.scorer.score(self.target, findings)
        assert score.recall == 1.0
        assert score.true_positives == 4
        assert score.false_negatives == 0

    def test_zero_findings(self):
        score = self.scorer.score(self.target, [])
        assert score.recall == 0.0
        assert score.false_negatives == len(self.target.ground_truth)

    def test_false_positive_on_negative_control(self):
        findings = [
            Finding("xss", "/", "page", "low", "false alarm"),
        ]
        score = self.scorer.score(self.target, findings)
        assert score.false_positives >= 1
        assert score.false_positive_rate > 0

    def test_partial_match(self):
        findings = [
            Finding("sqli", "/rest/products/search", "other_param", "high", "union"),
        ]
        score = self.scorer.score(self.target, findings)
        assert score.true_positives >= 1  # Partial match on category+location

    def test_path_parameter_matching(self):
        assert self.scorer._path_matches("/api/BasketItems/42", "/api/BasketItems/{id}")
        assert not self.scorer._path_matches("/api/Users/42", "/api/BasketItems/{id}")
