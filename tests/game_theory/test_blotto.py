import pytest
from sentinel.game_theory.blotto import BlottoAllocator, Battlefield


class TestBlottoAllocator:
    def setup_method(self):
        self.alloc = BlottoAllocator()

    def _add_standard_targets(self):
        self.alloc.add_battlefield(Battlefield(
            "b1", "CRM", value=80, attack_surface=0.7,
            current_security=0.3, min_effort=2, max_effort=20,
        ))
        self.alloc.add_battlefield(Battlefield(
            "b2", "Blog", value=10, attack_surface=0.2,
            current_security=0.8, min_effort=1, max_effort=5,
        ))
        self.alloc.add_battlefield(Battlefield(
            "b3", "API", value=90, attack_surface=0.9,
            current_security=0.2, min_effort=3, max_effort=30,
        ))

    def test_weighted_respects_budget(self):
        self._add_standard_targets()
        sol = self.alloc.solve_weighted(budget=30)
        assert sol.budget_used <= 30.01

    def test_weighted_high_risk_gets_more(self):
        self._add_standard_targets()
        sol = self.alloc.solve_weighted(budget=40)
        alloc_map = {a.bf_id: a for a in sol.allocations}
        assert alloc_map["b3"].allocated_hours > alloc_map["b2"].allocated_hours

    def test_minimax_respects_budget(self):
        self._add_standard_targets()
        sol = self.alloc.solve_minimax(budget=30)
        assert sol.budget_used <= 30.01

    def test_minimax_spreads_coverage(self):
        self._add_standard_targets()
        sol = self.alloc.solve_minimax(budget=50)
        for alloc in sol.allocations:
            assert alloc.allocated_hours >= 0

    def test_empty_battlefields(self):
        sol = self.alloc.solve_weighted(budget=100)
        assert len(sol.allocations) == 0

    def test_multi_stage(self):
        self._add_standard_targets()
        solutions = self.alloc.solve_multi_stage(budget=60, stages=3)
        assert len(solutions) == 3

    def test_win_probability_range(self):
        self._add_standard_targets()
        sol = self.alloc.solve_weighted(budget=40)
        for alloc in sol.allocations:
            assert 0 <= alloc.win_probability <= 1

    def test_coverage_fraction_range(self):
        self._add_standard_targets()
        sol = self.alloc.solve_weighted(budget=100)
        for alloc in sol.allocations:
            assert 0 <= alloc.coverage_fraction <= 1.01

    def test_minimax_empty(self):
        sol = self.alloc.solve_minimax(budget=100)
        assert len(sol.allocations) == 0
        assert sol.strategy_type == "minimax"

    def test_expected_value_saved_positive(self):
        self._add_standard_targets()
        sol = self.alloc.solve_weighted(budget=40)
        assert sol.expected_value_saved > 0
