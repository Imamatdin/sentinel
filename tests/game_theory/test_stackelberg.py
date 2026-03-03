"""Tests for Stackelberg planner."""

from sentinel.game_theory.stackelberg import StackelbergPlanner, Target


class TestStackelbergPlanner:
    def setup_method(self):
        self.planner = StackelbergPlanner()

    def test_single_target_full_coverage(self):
        targets = [Target("t1", "web", value=50, vulnerability=0.8, scan_cost=2)]
        sol = self.planner.solve(targets, budget=10)
        assert len(sol.allocations) == 1
        assert sol.allocations[0].coverage > 0.9  # should allocate fully

    def test_budget_constraint(self):
        targets = [
            Target("t1", "web", value=80, vulnerability=0.9, scan_cost=5),
            Target("t2", "api", value=60, vulnerability=0.7, scan_cost=5),
        ]
        sol = self.planner.solve(targets, budget=5)
        assert sol.total_cost <= 5.01  # within budget (float tolerance)

    def test_high_value_gets_more_coverage(self):
        targets = [
            Target("high", "db", value=100, vulnerability=1.0, scan_cost=3),
            Target("low", "blog", value=5, vulnerability=0.1, scan_cost=3),
        ]
        sol = self.planner.solve(targets, budget=4)
        alloc_map = {a.target_id: a for a in sol.allocations}
        assert alloc_map["high"].coverage > alloc_map["low"].coverage

    def test_zero_budget(self):
        targets = [Target("t1", "web", value=50, vulnerability=0.5, scan_cost=2)]
        sol = self.planner.solve(targets, budget=0)
        assert sol.allocations[0].coverage < 0.01

    def test_no_targets(self):
        sol = self.planner.solve([], budget=100)
        assert len(sol.allocations) == 0
        assert sol.worst_case_loss == 0

    def test_multi_round_reduces_vulnerability(self):
        targets = [Target("t1", "web", value=80, vulnerability=0.9, scan_cost=2)]
        schedule = self.planner.solve_with_schedule(targets, budget_per_round=3, rounds=3)
        assert len(schedule.rounds) == 3
        # Later rounds should show lower expected loss
        first_loss = schedule.rounds[0].allocations[0].expected_loss
        last_loss = schedule.rounds[-1].allocations[0].expected_loss
        assert last_loss <= first_loss

    def test_priority_ranking(self):
        targets = [
            Target("a", "a", value=10, vulnerability=0.1, scan_cost=1),
            Target("b", "b", value=90, vulnerability=0.9, scan_cost=1),
            Target("c", "c", value=50, vulnerability=0.5, scan_cost=1),
        ]
        sol = self.planner.solve(targets, budget=1.5)
        priorities = {a.target_id: a.priority for a in sol.allocations}
        # All should have unique priorities
        assert len(set(priorities.values())) == 3
