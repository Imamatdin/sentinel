"""Tests for FederatedAggregator."""

from datetime import datetime, timezone

from sentinel.federated.aggregator import FederatedAggregator, FederatedUpdate


class TestFederatedAggregator:
    def setup_method(self):
        self.agg = FederatedAggregator()

    def _make_update(self, deployment_id, technique="sqli", stack="node",
                     alpha=5, beta=2, trials=6, eng_count=3):
        return FederatedUpdate(
            deployment_id=deployment_id,
            timestamp=datetime.now(timezone.utc),
            technique_stats=[{
                "technique": technique, "stack": stack,
                "alpha": alpha, "beta": beta, "total_trials": trials,
            }],
            pattern_records=[],
            deployment_count=eng_count,
        )

    def test_receive_update(self):
        self.agg.receive_update(self._make_update("d1"))
        assert self.agg.model.total_deployments == 1
        assert self.agg.model.version == 1

    def test_multiple_updates_increment(self):
        self.agg.receive_update(self._make_update("d1"))
        self.agg.receive_update(self._make_update("d2"))
        assert self.agg.model.total_deployments == 2
        assert self.agg.model.version == 2
        assert self.agg.model.total_engagements == 6

    def test_below_min_deployments_not_published(self):
        self.agg.receive_update(self._make_update("d1", trials=20, eng_count=10))
        model = self.agg.publish_model()
        assert len(model["technique_stats"]) == 0

    def test_below_min_engagements_not_published(self):
        for i in range(3):
            self.agg.receive_update(
                self._make_update(f"d{i}", trials=1, eng_count=1)
            )
        model = self.agg.publish_model()
        assert len(model["technique_stats"]) == 0

    def test_publish_after_threshold_met(self):
        for i in range(5):
            self.agg.receive_update(
                self._make_update(f"d{i}", trials=3, eng_count=2)
            )
        model = self.agg.publish_model()
        assert len(model["technique_stats"]) >= 1
        entry = model["technique_stats"][0]
        assert entry["technique"] == "sqli"
        assert "mean_success_rate" in entry

    def test_published_model_has_version(self):
        for i in range(5):
            self.agg.receive_update(self._make_update(f"d{i}"))
        model = self.agg.publish_model()
        assert model["version"] == 5
        assert model["total_deployments"] == 5

    def test_differential_privacy_noise(self):
        for i in range(5):
            self.agg.receive_update(
                self._make_update(f"d{i}", alpha=10, beta=2, trials=11)
            )
        # Noise is random, so just verify it doesn't crash and produces valid output
        model = self.agg.publish_model()
        for entry in model["technique_stats"]:
            assert entry["alpha"] >= 1.0
            assert entry["beta"] >= 1.0
            assert 0 <= entry["mean_success_rate"] <= 1

    def test_laplace_noise_varies(self):
        # Sample noise 100 times, should get some variance
        noises = [self.agg._laplace_noise() for _ in range(100)]
        assert max(noises) != min(noises)

    def test_multiple_techniques(self):
        for i in range(4):
            self.agg.receive_update(FederatedUpdate(
                deployment_id=f"d{i}",
                timestamp=datetime.now(timezone.utc),
                technique_stats=[
                    {"technique": "sqli", "stack": "node", "alpha": 5, "beta": 2, "total_trials": 6},
                    {"technique": "xss", "stack": "node", "alpha": 3, "beta": 4, "total_trials": 6},
                ],
                pattern_records=[],
                deployment_count=3,
            ))
        assert len(self.agg.model.technique_stats) == 2
