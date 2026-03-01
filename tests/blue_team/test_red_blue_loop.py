"""Tests for RedBlueLoop."""

from sentinel.blue_team.red_blue_loop import RedBlueLoop, AttackAttempt


class TestRedBlueLoop:
    def setup_method(self):
        self.loop = RedBlueLoop()

    def test_undetected_generates_rule(self):
        attempt = AttackAttempt(
            attempt_id="a1", category="sqli",
            payload="' UNION SELECT * FROM users--",
            target_route="/api/search", target_param="q", method="GET",
        )
        result = self.loop.submit_attack(attempt)
        assert result.attempt_id == "a1"
        # Without profiler training, WAF auto-generates a rule from undetected attack
        assert len(self.loop.waf.rules) >= 1

    def test_second_attack_caught_by_waf(self):
        a1 = AttackAttempt(
            attempt_id="a1", category="xss",
            payload="<script>alert(1)</script>",
            target_route="/api/comment", target_param="body", method="POST",
        )
        self.loop.submit_attack(a1)

        a2 = AttackAttempt(
            attempt_id="a2", category="xss",
            payload="<script>alert(document.cookie)</script>",
            target_route="/api/comment", target_param="body", method="POST",
        )
        result = self.loop.submit_attack(a2)
        # The auto-generated XSS rule from a1 should catch a2
        assert result.detected is True
        assert result.detected_by == "waf"

    def test_profiler_catches_trained_anomaly(self):
        normal = [{"q": f"search{i}"} for i in range(25)]
        self.loop.train_profiler("/api/search", normal)

        attempt = AttackAttempt(
            attempt_id="a3", category="sqli",
            payload="';EXEC xp_cmdshell('net user hacker P@ss1 /add')--",
            target_route="/api/search", target_param="q", method="GET",
        )
        result = self.loop.submit_attack(attempt)
        assert result.anomaly_score >= 0

    def test_metrics_empty(self):
        metrics = self.loop.get_metrics()
        assert metrics.total_attacks == 0

    def test_metrics_after_attacks(self):
        self.loop.submit_attack(AttackAttempt(
            attempt_id="m1", category="sqli", payload="1' OR '1'='1",
            target_route="/api", target_param="id", method="GET",
        ))
        metrics = self.loop.get_metrics()
        assert metrics.total_attacks == 1

    def test_metrics_rates_sum_to_one(self):
        for i in range(5):
            self.loop.submit_attack(AttackAttempt(
                attempt_id=f"m{i}", category="sqli",
                payload=f"payload_{i}' OR '1'='1",
                target_route="/api", target_param="id", method="GET",
            ))
        metrics = self.loop.get_metrics()
        assert metrics.total_attacks == 5
        assert abs(metrics.detection_rate + metrics.evasion_rate - 1.0) < 0.001
