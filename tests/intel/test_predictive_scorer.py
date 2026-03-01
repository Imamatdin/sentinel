import pytest

from sentinel.intel.predictive_scorer import (
    PredictiveScorer,
    TechStackProfile,
    VulnPrediction,
)


class TestPredictiveScorer:
    def setup_method(self):
        self.scorer = PredictiveScorer()

    def test_django_stack_predictions(self):
        stack = TechStackProfile(
            languages=["python"],
            frameworks=["django"],
            databases=["postgresql"],
        )
        preds = self.scorer.predict(stack)
        assert len(preds) > 0
        idor = next((p for p in preds if p.vuln_class == "idor"), None)
        assert idor is not None
        assert idor.probability > 0.3

    def test_express_stack_predictions(self):
        stack = TechStackProfile(
            languages=["javascript"],
            frameworks=["express"],
            databases=["mongodb"],
        )
        preds = self.scorer.predict(stack)
        nosqli = next((p for p in preds if p.vuln_class == "nosqli"), None)
        assert nosqli is not None
        assert nosqli.probability > 0.35  # MongoDB Beta(6,4) + default prior dilution

    def test_spring_stack_predictions(self):
        stack = TechStackProfile(
            languages=["java"],
            frameworks=["spring"],
        )
        preds = self.scorer.predict(stack)
        deser = next((p for p in preds if p.vuln_class == "deserialization"), None)
        assert deser is not None
        assert deser.probability > 0.3

    def test_historical_data_updates_posterior(self):
        stack = TechStackProfile(frameworks=["django"])
        historical = {("django", "idor"): (8, 10)}  # 80% success rate
        preds = self.scorer.predict(stack, historical=historical)
        idor = next(p for p in preds if p.vuln_class == "idor")
        assert idor.probability > 0.5

    def test_historical_boosts_confidence(self):
        stack = TechStackProfile(frameworks=["django"])
        preds_no_hist = self.scorer.predict(stack)
        preds_with_hist = self.scorer.predict(
            stack, historical={("django", "idor"): (20, 25)}
        )
        idor_no = next(p for p in preds_no_hist if p.vuln_class == "idor")
        idor_yes = next(p for p in preds_with_hist if p.vuln_class == "idor")
        assert idor_yes.confidence > idor_no.confidence

    def test_thompson_sampling_changes_order(self):
        stack = TechStackProfile(frameworks=["express"])
        preds = self.scorer.predict(stack)
        orders = set()
        for _ in range(50):
            sampled = self.scorer.thompson_sample(preds)
            orders.add(tuple(p.vuln_class for p in sampled[:3]))
        assert len(orders) > 1

    def test_predictions_are_ranked(self):
        stack = TechStackProfile(frameworks=["spring"])
        preds = self.scorer.predict(stack)
        for i, pred in enumerate(preds):
            assert pred.priority_rank == i + 1

    def test_predictions_sorted_by_probability(self):
        stack = TechStackProfile(frameworks=["django"])
        preds = self.scorer.predict(stack)
        for i in range(len(preds) - 1):
            assert preds[i].probability >= preds[i + 1].probability

    def test_predictions_have_reasoning(self):
        stack = TechStackProfile(frameworks=["django"])
        preds = self.scorer.predict(stack)
        for p in preds:
            assert len(p.reasoning) > 0

    def test_predictions_have_suggested_tools(self):
        stack = TechStackProfile(frameworks=["express"])
        preds = self.scorer.predict(stack)
        for p in preds:
            assert len(p.suggested_tools) > 0

    def test_empty_stack_uses_defaults(self):
        stack = TechStackProfile()
        preds = self.scorer.predict(stack)
        # All predictions should use default prior only
        for p in preds:
            assert "Default prior only" in p.reasoning

    def test_probabilities_in_valid_range(self):
        stack = TechStackProfile(
            frameworks=["django", "express"],
            databases=["postgresql", "mongodb"],
        )
        preds = self.scorer.predict(stack)
        for p in preds:
            assert 0.0 <= p.probability <= 1.0
            assert 0.0 <= p.confidence <= 1.0
