"""
Stackelberg Security Game scan planner.

Defender (Sentinel) commits to a scan allocation; rational attacker observes
and targets the highest expected-payoff unprotected asset.  LP minimises the
worst-case expected loss.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from scipy.optimize import linprog

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class Target:
    target_id: str
    name: str
    value: float  # attacker payoff 1-100
    vulnerability: float  # risk score 0-1
    scan_cost: float  # hours to scan


@dataclass
class Allocation:
    target_id: str
    coverage: float  # 0-1
    expected_loss: float
    priority: int


@dataclass
class GameSolution:
    allocations: list[Allocation]
    worst_case_loss: float
    total_cost: float
    budget: float


@dataclass
class ScheduleRound:
    round_number: int
    allocations: list[Allocation]
    budget_used: float


@dataclass
class MultiRoundSchedule:
    rounds: list[ScheduleRound] = field(default_factory=list)
    total_budget: float = 0.0
    total_used: float = 0.0


class StackelbergPlanner:
    """Solves the Stackelberg security game via LP."""

    def solve(self, targets: list[Target], budget: float) -> GameSolution:
        if not targets:
            return GameSolution(allocations=[], worst_case_loss=0.0,
                                total_cost=0.0, budget=budget)

        n = len(targets)

        # Decision variables: coverage_i for each target, plus z (worst-case loss)
        # Minimize z
        # Subject to: for each target j, z >= value_j * vuln_j * (1 - coverage_j)
        #             sum(cost_i * coverage_i) <= budget
        #             0 <= coverage_i <= 1

        # Variables: [c_0, c_1, ..., c_{n-1}, z]
        # Objective: min z -> c = [0, 0, ..., 0, 1]
        c = np.zeros(n + 1)
        c[n] = 1.0

        # Inequality constraints: A_ub @ x <= b_ub
        # For each j: value_j * vuln_j * (1 - c_j) <= z
        # => -value_j * vuln_j * c_j - z <= -value_j * vuln_j
        # => value_j * vuln_j * c_j + z >= value_j * vuln_j
        A_ub = []
        b_ub = []
        for j in range(n):
            row = np.zeros(n + 1)
            ev = targets[j].value * targets[j].vulnerability
            row[j] = -ev  # -ev * c_j
            row[n] = -1.0  # -z
            A_ub.append(row)
            b_ub.append(-ev)

        # Budget constraint: sum(cost_i * c_i) <= budget
        budget_row = np.zeros(n + 1)
        for i in range(n):
            budget_row[i] = targets[i].scan_cost
        A_ub.append(budget_row)
        b_ub.append(budget)

        # Bounds: 0 <= c_i <= 1, z >= 0
        bounds = [(0.0, 1.0)] * n + [(0.0, None)]

        result = linprog(c, A_ub=np.array(A_ub), b_ub=np.array(b_ub),
                         bounds=bounds, method="highs")

        if not result.success:
            logger.warning("stackelberg_lp_failed", message=result.message)
            return self._fallback_weighted(targets, budget)

        coverages = result.x[:n]
        z_val = result.x[n]

        allocations = []
        for i, t in enumerate(targets):
            ev = t.value * t.vulnerability
            allocations.append(Allocation(
                target_id=t.target_id,
                coverage=float(coverages[i]),
                expected_loss=ev * (1 - coverages[i]),
                priority=0,
            ))

        # Assign priority by expected loss (highest loss = highest priority)
        allocations.sort(key=lambda a: a.expected_loss, reverse=True)
        for rank, alloc in enumerate(allocations):
            alloc.priority = rank + 1

        total_cost = sum(t.scan_cost * coverages[i] for i, t in enumerate(targets))

        return GameSolution(
            allocations=allocations,
            worst_case_loss=float(z_val),
            total_cost=float(total_cost),
            budget=budget,
        )

    def solve_with_schedule(
        self, targets: list[Target], budget_per_round: float, rounds: int = 5,
    ) -> MultiRoundSchedule:
        """Multi-round scheduling — re-optimise after each round."""
        schedule = MultiRoundSchedule(total_budget=budget_per_round * rounds)
        current_targets = [Target(t.target_id, t.name, t.value,
                                  t.vulnerability, t.scan_cost) for t in targets]

        for r in range(rounds):
            sol = self.solve(current_targets, budget_per_round)
            schedule.rounds.append(ScheduleRound(
                round_number=r + 1,
                allocations=sol.allocations,
                budget_used=sol.total_cost,
            ))
            schedule.total_used += sol.total_cost

            # Simulate: scanned targets have reduced vulnerability
            for alloc in sol.allocations:
                for t in current_targets:
                    if t.target_id == alloc.target_id:
                        t.vulnerability *= (1 - 0.3 * alloc.coverage)

        return schedule

    def _fallback_weighted(self, targets: list[Target], budget: float) -> GameSolution:
        """Proportional allocation if LP fails."""
        risk_scores = [t.value * t.vulnerability for t in targets]
        total_risk = sum(risk_scores) or 1.0
        allocations = []
        total_cost = 0.0

        for i, t in enumerate(targets):
            weight = risk_scores[i] / total_risk
            desired = weight * budget / t.scan_cost if t.scan_cost > 0 else 0
            cov = min(desired, 1.0)
            total_cost += cov * t.scan_cost
            allocations.append(Allocation(
                target_id=t.target_id, coverage=cov,
                expected_loss=t.value * t.vulnerability * (1 - cov),
                priority=0,
            ))

        allocations.sort(key=lambda a: a.expected_loss, reverse=True)
        for rank, alloc in enumerate(allocations):
            alloc.priority = rank + 1

        return GameSolution(
            allocations=allocations,
            worst_case_loss=max((a.expected_loss for a in allocations), default=0),
            total_cost=total_cost, budget=budget,
        )
