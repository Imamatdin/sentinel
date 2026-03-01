"""Tests for TrafficProfiler."""

from sentinel.blue_team.traffic_profiler import TrafficProfiler


class TestTrafficProfiler:
    def setup_method(self):
        self.profiler = TrafficProfiler()

    def test_insufficient_data_returns_not_anomalous(self):
        score = self.profiler.score("/api/login", {"user": "test"})
        assert not score.is_anomalous
        assert "Insufficient" in score.details

    def test_normal_traffic_not_anomalous(self):
        for i in range(25):
            self.profiler.learn("/api/search", {"q": f"term{i}", "page": "1"})
        score = self.profiler.score("/api/search", {"q": "normal", "page": "2"})
        assert not score.is_anomalous

    def test_injection_triggers_deviation(self):
        for i in range(25):
            self.profiler.learn("/api/search", {"q": f"word{i}"})
        score = self.profiler.score("/api/search", {
            "q": "' UNION SELECT username,password FROM users WHERE '1'='1"
        })
        # Injection payload is much longer and higher-entropy than training data
        assert score.entropy_z > 0 or score.param_length_z > 0

    def test_shannon_entropy_empty(self):
        assert self.profiler._shannon_entropy("") == 0.0

    def test_shannon_entropy_uniform(self):
        assert self.profiler._shannon_entropy("aaaa") == 0.0

    def test_shannon_entropy_varied(self):
        assert self.profiler._shannon_entropy("abcd") > 1.0
