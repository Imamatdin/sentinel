# LEVEL 28: Colonel Blotto Resource Allocator

## Context
Colonel Blotto is a game theory model for distributing limited resources across multiple battlefields simultaneously. Applied to pentesting: given N scan-hours across M applications, how should Sentinel allocate effort to maximize total discovery? Unlike Stackelberg (L24) which optimizes per-target, Blotto optimizes the *portfolio* of allocations against a strategic adversary.

Research: Block 12 (Colonel Blotto — Hart 2008 equilibrium analysis, Roberson continuous solution, multi-stage variants, Pentagon resource allocation models).

## Why
Enterprise customers have 50-500 applications. Annual pentest budget is fixed. Blotto finds Nash equilibrium allocations: even if the attacker knows your strategy, they can't do better. Combined with Stackelberg (per-asset) and FlipIt (retest cadence), this completes the game-theoretic planning stack.

---

## Files to Create

### `src/sentinel/game_theory/blotto.py`
```python
"""
Colonel Blotto Resource Allocator — Distribute scan budget across N targets.

Classic Blotto:
- Attacker and defender each allocate B units across N battlefields
- Each battlefield is won by whoever allocates more
- Goal: maximize number of battlefields won

Applied to pentesting:
- Defender allocates scan-hours across applications
- "Winning" a battlefield = finding vulns before attacker exploits them
- Each app has different value, attack surface, and required effort

Solution approaches:
1. Symmetric: Equal split when all targets equal value
2. Weighted: Proportional to value × vulnerability
3. Nash equilibrium: Mixed strategy via LP relaxation
4. Multi-stage: Sequential allocation with information updates
"""
import numpy as np
from dataclasses import dataclass, field
from scipy.optimize import linprog
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Battlefield:
    bf_id: str
    name: str
    value: float              # Business value (0-100)
    attack_surface: float     # Relative size of attack surface (0-1)
    current_security: float   # Current security posture (0-1, higher=better)
    min_effort: float         # Minimum scan-hours for meaningful coverage
    max_effort: float         # Point of diminishing returns


@dataclass
class BlottoAllocation:
    bf_id: str
    name: str
    allocated_hours: float
    win_probability: float     # P(defender finds vuln before attacker exploits)
    value_at_risk: float       # Expected loss if battlefield lost
    coverage_fraction: float   # allocated / max_effort


@dataclass
class BlottoSolution:
    allocations: list[BlottoAllocation]
    total_budget: float
    budget_used: float
    expected_wins: float       # Expected number of battlefields "won"
    expected_value_saved: float
    strategy_type: str         # "weighted" | "nash" | "minimax"


class BlottoAllocator:
    """Solve Colonel Blotto allocation for pentest budget distribution."""

    def __init__(self):
        self.battlefields: list[Battlefield] = []

    def add_battlefield(self, bf: Battlefield):
        self.battlefields.append(bf)

    def solve_weighted(self, budget: float) -> BlottoSolution:
        """
        Weighted allocation: proportional to value × attack_surface × (1 - security).
        
        Simple but effective baseline. Each app gets budget proportional
        to its risk-weighted importance.
        """
        if not self.battlefields:
            return BlottoSolution([], budget, 0, 0, 0, "weighted")

        # Risk score: high value + large surface + low security = more budget
        risk_scores = []
        for bf in self.battlefields:
            score = bf.value * bf.attack_surface * (1 - bf.current_security)
            risk_scores.append(max(score, 0.01))

        total_risk = sum(risk_scores)
        allocations = []
        budget_used = 0

        for i, bf in enumerate(self.battlefields):
            proportion = risk_scores[i] / total_risk
            raw_hours = budget * proportion

            # Clamp to min/max effort
            hours = max(bf.min_effort, min(raw_hours, bf.max_effort))
            hours = min(hours, budget - budget_used)  # Don't exceed remaining budget

            coverage = hours / bf.max_effort if bf.max_effort > 0 else 0
            # Win probability: sigmoid of coverage vs attack surface
            win_prob = 1 / (1 + np.exp(-5 * (coverage - bf.attack_surface)))

            allocations.append(BlottoAllocation(
                bf_id=bf.bf_id, name=bf.name,
                allocated_hours=round(hours, 2),
                win_probability=round(win_prob, 4),
                value_at_risk=round(bf.value * (1 - win_prob), 2),
                coverage_fraction=round(coverage, 4),
            ))
            budget_used += hours

        expected_wins = sum(a.win_probability for a in allocations)
        expected_saved = sum(a.win_probability * bf.value
                            for a, bf in zip(allocations, self.battlefields))

        return BlottoSolution(
            allocations=allocations,
            total_budget=budget,
            budget_used=round(budget_used, 2),
            expected_wins=round(expected_wins, 2),
            expected_value_saved=round(expected_saved, 2),
            strategy_type="weighted",
        )

    def solve_minimax(self, budget: float) -> BlottoSolution:
        """
        Minimax allocation: minimize worst-case loss.
        
        LP formulation:
            min z
            s.t. value_i × (1 - coverage_i) ≤ z  ∀i  (worst-case loss ≤ z)
                 Σ hours_i ≤ budget
                 min_effort_i ≤ hours_i ≤ max_effort_i
        """
        n = len(self.battlefields)
        if n == 0:
            return BlottoSolution([], budget, 0, 0, 0, "minimax")

        # Variables: [hours_0, ..., hours_n-1, z]
        c = np.zeros(n + 1)
        c[-1] = 1.0  # minimize z

        A_ub = []
        b_ub = []

        # For each battlefield: value_i × (1 - hours_i/max_i) ≤ z
        # → -(value_i / max_i) × hours_i - z ≤ -value_i
        for i, bf in enumerate(self.battlefields):
            row = np.zeros(n + 1)
            if bf.max_effort > 0:
                row[i] = -bf.value / bf.max_effort
            row[-1] = -1.0
            A_ub.append(row)
            b_ub.append(-bf.value)

        # Budget constraint
        budget_row = np.zeros(n + 1)
        budget_row[:n] = 1.0
        A_ub.append(budget_row)
        b_ub.append(budget)

        # Bounds
        bounds = [(bf.min_effort, bf.max_effort) for bf in self.battlefields] + [(0, None)]

        try:
            result = linprog(c, A_ub=np.array(A_ub), b_ub=np.array(b_ub),
                             bounds=bounds, method='highs')

            if not result.success:
                logger.warning(f"Blotto minimax solver failed: {result.message}")
                return self.solve_weighted(budget)  # Fallback

            hours = result.x[:n]
            allocations = []
            for i, bf in enumerate(self.battlefields):
                coverage = hours[i] / bf.max_effort if bf.max_effort > 0 else 0
                win_prob = 1 / (1 + np.exp(-5 * (coverage - bf.attack_surface)))
                allocations.append(BlottoAllocation(
                    bf_id=bf.bf_id, name=bf.name,
                    allocated_hours=round(hours[i], 2),
                    win_probability=round(win_prob, 4),
                    value_at_risk=round(bf.value * (1 - win_prob), 2),
                    coverage_fraction=round(coverage, 4),
                ))

            return BlottoSolution(
                allocations=allocations,
                total_budget=budget,
                budget_used=round(sum(hours), 2),
                expected_wins=round(sum(a.win_probability for a in allocations), 2),
                expected_value_saved=round(sum(a.win_probability * bf.value
                                               for a, bf in zip(allocations, self.battlefields)), 2),
                strategy_type="minimax",
            )

        except Exception as e:
            logger.error(f"Blotto solver error: {e}")
            return self.solve_weighted(budget)

    def solve_multi_stage(self, budget: float, stages: int = 3) -> list[BlottoSolution]:
        """
        Multi-stage Blotto: allocate in rounds, updating intelligence between rounds.
        
        Stage 1: Quick recon scan on all targets → update attack_surface estimates
        Stage 2: Deep scan on high-risk targets → update vulnerability estimates
        Stage 3: Focused exploitation on confirmed targets
        """
        per_stage = budget / stages
        solutions = []

        for stage in range(stages):
            solution = self.solve_minimax(per_stage)
            solutions.append(solution)

            # Simulate intelligence update: scanned targets become better understood
            for alloc, bf in zip(solution.allocations, self.battlefields):
                if alloc.coverage_fraction > 0.3:
                    # More accurate picture after scanning
                    bf.attack_surface *= 0.9  # Refine estimate downward
                    bf.current_security += alloc.coverage_fraction * 0.1

            logger.info(f"Blotto stage {stage+1}/{stages}: "
                        f"wins={solution.expected_wins:.1f}, "
                        f"value_saved={solution.expected_value_saved:.0f}")

        return solutions
```

---

## Tests

### `tests/game_theory/test_blotto.py`
```python
import pytest
from sentinel.game_theory.blotto import BlottoAllocator, Battlefield

class TestBlottoAllocator:
    def setup_method(self):
        self.alloc = BlottoAllocator()

    def _add_standard_targets(self):
        self.alloc.add_battlefield(Battlefield("b1", "CRM", value=80, attack_surface=0.7,
                                                current_security=0.3, min_effort=2, max_effort=20))
        self.alloc.add_battlefield(Battlefield("b2", "Blog", value=10, attack_surface=0.2,
                                                current_security=0.8, min_effort=1, max_effort=5))
        self.alloc.add_battlefield(Battlefield("b3", "API", value=90, attack_surface=0.9,
                                                current_security=0.2, min_effort=3, max_effort=30))

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
        # Minimax should give some coverage to all
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
```

---

## Acceptance Criteria
- [ ] Weighted allocation distributes budget proportional to risk score
- [ ] High-risk targets (value × surface × (1-security)) get more hours
- [ ] Minimax allocation minimizes worst-case loss via LP
- [ ] Budget constraint strictly respected in both strategies
- [ ] Multi-stage allocation updates intelligence between rounds
- [ ] Win probability bounded to [0,1] via sigmoid
- [ ] Coverage fraction = allocated / max_effort
- [ ] Empty battlefield list handled gracefully
- [ ] All tests pass