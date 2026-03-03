"""
Colonel Blotto Resource Allocator -- Distribute scan budget across N targets.

Classic Blotto:
- Attacker and defender each allocate B units across N battlefields
- Each battlefield is won by whoever allocates more
- Goal: maximize number of battlefields won

Applied to pentesting:
- Defender allocates scan-hours across applications
- "Winning" a battlefield = finding vulns before attacker exploits them
- Each app has different value, attack surface, and required effort

Solution approaches:
1. Weighted: Proportional to value x vulnerability
2. Minimax: Minimize worst-case loss via LP
3. Multi-stage: Sequential allocation with information updates
"""

import numpy as np
from dataclasses import dataclass, field
from scipy.optimize import linprog

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class Battlefield:
    bf_id: str
    name: str
    value: float  # Business value (0-100)
    attack_surface: float  # Relative size of attack surface (0-1)
    current_security: float  # Current security posture (0-1, higher=better)
    min_effort: float  # Minimum scan-hours for meaningful coverage
    max_effort: float  # Point of diminishing returns


@dataclass
class BlottoAllocation:
    bf_id: str
    name: str
    allocated_hours: float
    win_probability: float  # P(defender finds vuln before attacker exploits)
    value_at_risk: float  # Expected loss if battlefield lost
    coverage_fraction: float  # allocated / max_effort


@dataclass
class BlottoSolution:
    allocations: list[BlottoAllocation]
    total_budget: float
    budget_used: float
    expected_wins: float  # Expected number of battlefields "won"
    expected_value_saved: float
    strategy_type: str  # "weighted" | "minimax"


class BlottoAllocator:
    """Solve Colonel Blotto allocation for pentest budget distribution."""

    def __init__(self):
        self.battlefields: list[Battlefield] = []

    def add_battlefield(self, bf: Battlefield):
        self.battlefields.append(bf)

    def solve_weighted(self, budget: float) -> BlottoSolution:
        """
        Weighted allocation: proportional to value x attack_surface x (1 - security).
        Each app gets budget proportional to its risk-weighted importance.
        """
        if not self.battlefields:
            return BlottoSolution([], budget, 0, 0, 0, "weighted")

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

            hours = max(bf.min_effort, min(raw_hours, bf.max_effort))
            hours = min(hours, budget - budget_used)

            coverage = hours / bf.max_effort if bf.max_effort > 0 else 0
            win_prob = 1 / (1 + np.exp(-5 * (coverage - bf.attack_surface)))

            allocations.append(BlottoAllocation(
                bf_id=bf.bf_id,
                name=bf.name,
                allocated_hours=round(hours, 2),
                win_probability=round(float(win_prob), 4),
                value_at_risk=round(bf.value * (1 - float(win_prob)), 2),
                coverage_fraction=round(coverage, 4),
            ))
            budget_used += hours

        expected_wins = sum(a.win_probability for a in allocations)
        expected_saved = sum(
            a.win_probability * bf.value
            for a, bf in zip(allocations, self.battlefields)
        )

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
            s.t. value_i x (1 - coverage_i) <= z  for all i
                 sum(hours_i) <= budget
                 min_effort_i <= hours_i <= max_effort_i
        """
        n = len(self.battlefields)
        if n == 0:
            return BlottoSolution([], budget, 0, 0, 0, "minimax")

        # Variables: [hours_0, ..., hours_n-1, z]
        c = np.zeros(n + 1)
        c[-1] = 1.0  # minimize z

        A_ub = []
        b_ub = []

        # For each battlefield: value_i * (1 - hours_i/max_i) <= z
        # => -(value_i / max_i) * hours_i - z <= -value_i
        for i, bf in enumerate(self.battlefields):
            row = np.zeros(n + 1)
            if bf.max_effort > 0:
                row[i] = -bf.value / bf.max_effort
            row[-1] = -1.0
            A_ub.append(row)
            b_ub.append(-bf.value)

        # Budget constraint: sum(hours_i) <= budget
        budget_row = np.zeros(n + 1)
        budget_row[:n] = 1.0
        A_ub.append(budget_row)
        b_ub.append(budget)

        bounds = [(bf.min_effort, bf.max_effort) for bf in self.battlefields] + [(0, None)]

        try:
            result = linprog(
                c,
                A_ub=np.array(A_ub),
                b_ub=np.array(b_ub),
                bounds=bounds,
                method="highs",
            )

            if not result.success:
                logger.warning(f"Blotto minimax solver failed: {result.message}")
                return self.solve_weighted(budget)

            hours = result.x[:n]
            allocations = []
            for i, bf in enumerate(self.battlefields):
                coverage = hours[i] / bf.max_effort if bf.max_effort > 0 else 0
                win_prob = 1 / (1 + np.exp(-5 * (coverage - bf.attack_surface)))
                allocations.append(BlottoAllocation(
                    bf_id=bf.bf_id,
                    name=bf.name,
                    allocated_hours=round(hours[i], 2),
                    win_probability=round(float(win_prob), 4),
                    value_at_risk=round(bf.value * (1 - float(win_prob)), 2),
                    coverage_fraction=round(coverage, 4),
                ))

            return BlottoSolution(
                allocations=allocations,
                total_budget=budget,
                budget_used=round(float(sum(hours)), 2),
                expected_wins=round(sum(a.win_probability for a in allocations), 2),
                expected_value_saved=round(
                    sum(a.win_probability * bf.value for a, bf in zip(allocations, self.battlefields)),
                    2,
                ),
                strategy_type="minimax",
            )

        except Exception as e:
            logger.error(f"Blotto solver error: {e}")
            return self.solve_weighted(budget)

    def solve_multi_stage(self, budget: float, stages: int = 3) -> list[BlottoSolution]:
        """
        Multi-stage Blotto: allocate in rounds, updating intelligence between rounds.
        """
        per_stage = budget / stages
        solutions = []

        for stage in range(stages):
            solution = self.solve_minimax(per_stage)
            solutions.append(solution)

            # Simulate intelligence update
            for alloc, bf in zip(solution.allocations, self.battlefields):
                if alloc.coverage_fraction > 0.3:
                    bf.attack_surface *= 0.9
                    bf.current_security += alloc.coverage_fraction * 0.1

            logger.info(
                f"Blotto stage {stage + 1}/{stages}: "
                f"wins={solution.expected_wins:.1f}, "
                f"value_saved={solution.expected_value_saved:.0f}"
            )

        return solutions
