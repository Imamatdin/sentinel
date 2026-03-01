"""Tests for BayesianConfidence."""

from sentinel.federated.confidence import BayesianConfidence, TechniqueStats


class TestBayesianConfidence:
    def setup_method(self):
        self.bc = BayesianConfidence()

    def test_uninformed_prior(self):
        assert self.bc.get_confidence("sqli", "nodejs") == 0.5

    def test_successes_increase_confidence(self):
        for _ in range(10):
            self.bc.update("sqli_union", "nodejs_express", True)
        assert self.bc.get_confidence("sqli_union", "nodejs_express") > 0.7

    def test_failures_decrease_confidence(self):
        for _ in range(10):
            self.bc.update("xss_script", "react", False)
        assert self.bc.get_confidence("xss_script", "react") < 0.3

    def test_mixed_results_moderate_confidence(self):
        for _ in range(5):
            self.bc.update("ssrf", "flask", True)
        for _ in range(5):
            self.bc.update("ssrf", "flask", False)
        conf = self.bc.get_confidence("ssrf", "flask")
        assert 0.35 < conf < 0.65

    def test_thompson_sampling_returns_all_techniques(self):
        self.bc.update("sqli", "node", True)
        self.bc.update("xss", "node", False)
        results = self.bc.thompson_sample(["sqli", "xss", "ssrf"], "node")
        assert len(results) == 3
        techniques = [r[0] for r in results]
        assert "sqli" in techniques
        assert "xss" in techniques
        assert "ssrf" in techniques

    def test_thompson_sampling_values_between_0_and_1(self):
        for _ in range(5):
            self.bc.update("sqli", "node", True)
        results = self.bc.thompson_sample(["sqli"], "node")
        assert 0 <= results[0][1] <= 1

    def test_merge_remote(self):
        self.bc.merge_remote([{
            "technique": "ssrf",
            "stack": "python_flask",
            "alpha": 5.0,
            "beta": 2.0,
            "total_trials": 6,
        }])
        assert self.bc.get_confidence("ssrf", "python_flask") > 0.5

    def test_merge_remote_adds_to_existing(self):
        self.bc.update("sqli", "node", True)
        self.bc.update("sqli", "node", True)
        self.bc.merge_remote([{
            "technique": "sqli",
            "stack": "node",
            "alpha": 5.0,
            "beta": 1.0,
            "total_trials": 5,
        }])
        key = self.bc._key("sqli", "node")
        s = self.bc.stats[key]
        # Original: alpha=3 (1+2), beta=1. After merge: alpha += 4 (5-1), beta += 0
        assert s.alpha == 7.0
        assert s.total_trials == 7

    def test_get_all_stats(self):
        self.bc.update("a", "stack", True)
        self.bc.update("b", "stack", False)
        stats = self.bc.get_all_stats()
        assert len(stats) == 2


class TestTechniqueStats:
    def test_mean_uniform_prior(self):
        s = TechniqueStats(technique="t", stack="s")
        assert s.mean == 0.5

    def test_variance_decreases_with_data(self):
        s1 = TechniqueStats(technique="t", stack="s", alpha=1, beta=1)
        s2 = TechniqueStats(technique="t", stack="s", alpha=10, beta=10)
        assert s2.variance < s1.variance

    def test_confidence_interval(self):
        s = TechniqueStats(technique="t", stack="s", alpha=10, beta=10)
        lo, hi = s.confidence_interval
        assert lo >= 0
        assert hi <= 1
        assert lo < s.mean < hi
