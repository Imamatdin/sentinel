"""Tests for FlipIt solver."""

from sentinel.game_theory.flipit import (
    FlipItAsset, FlipItSolver, build_schedule_from_solutions,
)


class TestFlipItSolver:
    def setup_method(self):
        self.solver = FlipItSolver()

    def test_high_value_shorter_interval(self):
        high = FlipItAsset("db", "Database", value_per_day=1000,
                           retest_cost=10, estimated_attack_rate=0.1,
                           vulnerability_score=0.8)
        low = FlipItAsset("blog", "Blog", value_per_day=10,
                          retest_cost=10, estimated_attack_rate=0.01,
                          vulnerability_score=0.2)
        sol_high = self.solver.solve_periodic(high)
        sol_low = self.solver.solve_periodic(low)
        assert sol_high.optimal_interval_days < sol_low.optimal_interval_days

    def test_zero_attack_rate(self):
        asset = FlipItAsset("safe", "Safe", value_per_day=100,
                            retest_cost=5, estimated_attack_rate=0,
                            vulnerability_score=0.5)
        sol = self.solver.solve_periodic(asset)
        assert sol.expected_control_time == 1.0

    def test_exponential_control_fraction(self):
        asset = FlipItAsset("web", "Web", value_per_day=500,
                            retest_cost=5, estimated_attack_rate=0.05,
                            vulnerability_score=0.7)
        sol = self.solver.solve_exponential(asset)
        assert 0 < sol.expected_control_time <= 1.0
        assert sol.optimal_interval_days > 0

    def test_recommend_returns_best(self):
        asset = FlipItAsset("app", "App", value_per_day=200,
                            retest_cost=8, estimated_attack_rate=0.03,
                            vulnerability_score=0.6)
        sol = self.solver.recommend(asset)
        assert sol.strategy in ("periodic", "exponential")

    def test_simulation_runs(self):
        asset = FlipItAsset("web", "Web", value_per_day=100,
                            retest_cost=5, estimated_attack_rate=0.05,
                            vulnerability_score=0.5)
        result = self.solver.simulate(asset, days=365)
        assert abs(result.defender_control_fraction +
                   result.attacker_control_fraction - 1.0) < 0.01
        assert result.defender_flips > 0

    def test_schedule_sorted_by_frequency(self):
        assets = [
            FlipItAsset("a", "A", 1000, 10, 0.1, 0.8),
            FlipItAsset("b", "B", 10, 10, 0.01, 0.2),
        ]
        solutions = [self.solver.recommend(a) for a in assets]
        schedule = build_schedule_from_solutions(solutions, assets)
        assert len(schedule) == 2
        assert schedule[0].retest_interval_days <= schedule[1].retest_interval_days
