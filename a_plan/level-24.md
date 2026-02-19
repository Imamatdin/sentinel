# LEVEL 24: Stackelberg Game Theory Scan Planner

## Context
Enterprise networks have limited scan budgets (time, bandwidth, stealth). Stackelberg game theory models the attacker-defender interaction as a leader-follower game where the defender (Sentinel) allocates scan resources optimally, assuming a rational attacker will target the weakest points.

Research: Block 12 (Game Theory — Stackelberg security games, MILP optimization, Colonel Blotto for resource allocation, provable worst-case guarantees). Used by TSA for airport security scheduling.

## Why
Random scanning wastes budget on low-value targets. Pure risk scoring ignores attacker incentives. Stackelberg models provide mathematically optimal scan allocation: given N hours of scan time, where should each hour go to minimize expected damage? This is how Sentinel allocates resources across a 50-app enterprise portfolio.

---

## Files to Create

### `src/sentinel/game_theory/__init__.py`
```python
"""Game theory scan planning — Stackelberg games, resource allocation, optimal scheduling."""
```

### `src/sentinel/game_theory/stackelberg.py`
```python
"""
Stackelberg Security Game Solver.

Model:
- Defender (Sentinel) allocates scan coverage across N targets
- Attacker observes defender's mixed strategy and attacks the most attractive target
- Each target has: value (to attacker), vulnerability score, scan cost
- Defender's goal: minimize expected loss = Σ P(attack_i) × (1 - coverage_i) × value_i

Solved via MILP (Mixed Integer Linear Programming):
- Decision vars: coverage_i ∈ [0,1] for each target
- Constraint: Σ cost_i × coverage_i ≤ budget
- Objective: minimize max expected loss across all attacker pure strategies

Uses scipy.optimize.linprog for LP relaxation.
"""
import numpy as np
from dataclasses import dataclass, field
from scipy.optimize import linprog
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Target:
    target_id: str
    name: str
    value: float          # Attacker's payoff for compromising this target (1-100)
    vulnerability: float  # Current vulnerability score (0-1), from EPSS/risk analysis
    scan_cost: float      # Cost (hours/compute) to scan this target
    current_coverage: float = 0.0  # Current scan coverage (0-1)


@dataclass
class ScanAllocation:
    target_id: str
    name: str
    coverage: float       # Optimal coverage level (0-1)
    scan_hours: float     # Hours to allocate
    expected_loss: float  # Expected loss if attacked at this coverage
    priority_rank: int


@dataclass
class GameSolution:
    allocations: list[ScanAllocation]
    total_budget_used: float
    budget_remaining: float
    worst_case_loss: float
    solver_status: str


class StackelbergPlanner:
    """
    Solve a Stackelberg security game for optimal scan allocation.
    
    The defender moves first (allocates scans), then the attacker observes
    and attacks the most profitable target.
    """
    
    def __init__(self):
        self.targets: list[Target] = []
    
    def add_target(self, target: Target):
        self.targets.append(target)
    
    def solve(self, budget: float) -> GameSolution:
        """
        Find optimal scan allocation given a budget constraint.
        
        Uses the Stackelberg formulation:
        - For each possible attacker target, compute defender's best response
        - Minimize the maximum expected loss (minimax)
        
        LP formulation:
            min z
            s.t. value_i × (1 - coverage_i) × vuln_i ≤ z  ∀i
                 Σ cost_i × coverage_i ≤ budget
                 0 ≤ coverage_i ≤ 1
        """
        n = len(self.targets)
        if n == 0:
            return GameSolution([], 0, budget, 0, "no_targets")
        
        # Variables: [coverage_0, ..., coverage_n-1, z]
        # z is the worst-case expected loss we're minimizing
        
        # Objective: minimize z (last variable)
        c = np.zeros(n + 1)
        c[-1] = 1.0  # minimize z
        
        # Inequality constraints: A_ub @ x <= b_ub
        A_ub = []
        b_ub = []
        
        # For each target: value_i × vuln_i × (1 - coverage_i) ≤ z
        # Rewritten: -value_i × vuln_i × coverage_i - z ≤ -value_i × vuln_i
        # Or: value_i × vuln_i - value_i × vuln_i × coverage_i ≤ z
        # → -value_i × vuln_i × coverage_i - z ≤ -value_i × vuln_i
        for i, t in enumerate(self.targets):
            row = np.zeros(n + 1)
            row[i] = -t.value * t.vulnerability  # coefficient for coverage_i
            row[-1] = -1.0                        # coefficient for z
            A_ub.append(row)
            b_ub.append(-t.value * t.vulnerability)
        
        # Budget constraint: Σ cost_i × coverage_i ≤ budget
        budget_row = np.zeros(n + 1)
        for i, t in enumerate(self.targets):
            budget_row[i] = t.scan_cost
        A_ub.append(budget_row)
        b_ub.append(budget)
        
        # Bounds: 0 ≤ coverage_i ≤ 1, z ≥ 0
        bounds = [(0, 1)] * n + [(0, None)]
        
        try:
            result = linprog(
                c, A_ub=np.array(A_ub), b_ub=np.array(b_ub),
                bounds=bounds, method='highs',
            )
            
            if not result.success:
                return GameSolution([], 0, budget, float('inf'), f"solver_failed: {result.message}")
            
            coverages = result.x[:n]
            z_optimal = result.x[-1]
            
            # Build allocation list
            allocations = []
            for i, t in enumerate(self.targets):
                scan_hours = coverages[i] * t.scan_cost
                expected_loss = t.value * t.vulnerability * (1 - coverages[i])
                allocations.append(ScanAllocation(
                    target_id=t.target_id,
                    name=t.name,
                    coverage=round(coverages[i], 4),
                    scan_hours=round(scan_hours, 2),
                    expected_loss=round(expected_loss, 4),
                    priority_rank=0,
                ))
            
            # Rank by coverage (highest first)
            allocations.sort(key=lambda a: a.coverage, reverse=True)
            for i, a in enumerate(allocations):
                a.priority_rank = i + 1
            
            total_used = sum(a.scan_hours for a in allocations)
            
            return GameSolution(
                allocations=allocations,
                total_budget_used=round(total_used, 2),
                budget_remaining=round(budget - total_used, 2),
                worst_case_loss=round(z_optimal, 4),
                solver_status="optimal",
            )
            
        except Exception as e:
            logger.error(f"Stackelberg solver error: {e}")
            return GameSolution([], 0, budget, float('inf'), f"error: {str(e)}")
    
    def solve_with_schedule(self, budget: float, time_slots: int = 5) -> list[GameSolution]:
        """
        Multi-round scan scheduling: allocate budget across time slots.
        
        Each round updates vulnerability scores based on previous scan results,
        then re-solves the game. This models continuous threat exposure management (CTEM).
        """
        solutions = []
        per_slot_budget = budget / time_slots
        
        for slot in range(time_slots):
            solution = self.solve(per_slot_budget)
            solutions.append(solution)
            
            # Simulate: scanned targets have reduced vulnerability
            for alloc in solution.allocations:
                for t in self.targets:
                    if t.target_id == alloc.target_id:
                        t.vulnerability *= (1 - alloc.coverage * 0.5)  # Partial reduction
            
            logger.info(f"Slot {slot+1}/{time_slots}: worst_case_loss={solution.worst_case_loss:.4f}")
        
        return solutions


def build_targets_from_graph(graph_data: list[dict]) -> list[Target]:
    """Convert Neo4j host nodes into Stackelberg targets."""
    targets = []
    for node in graph_data:
        targets.append(Target(
            target_id=node.get("host_id", ""),
            name=node.get("hostname", node.get("ip", "")),
            value=_estimate_value(node),
            vulnerability=node.get("risk_score", 0.5),
            scan_cost=_estimate_cost(node),
        ))
    return targets


def _estimate_value(node: dict) -> float:
    """Estimate attacker value of a target based on its properties."""
    value = 10.0  # Base value
    if node.get("has_crown_jewel"): value += 50.0
    if node.get("has_credentials"): value += 20.0
    if node.get("is_external"): value += 15.0
    if node.get("service_count", 0) > 5: value += 10.0
    return min(value, 100.0)


def _estimate_cost(node: dict) -> float:
    """Estimate scan cost (hours) based on target complexity."""
    cost = 1.0  # Base cost
    cost += node.get("service_count", 0) * 0.5
    cost += node.get("endpoint_count", 0) * 0.1
    return cost
```

---

## Files to Modify

### `src/sentinel/api/` — Add game theory endpoints
```python
@app.post("/api/v1/plan/optimize")
async def optimize_scan_plan(body: dict):
    """Run Stackelberg optimization on current attack graph."""
    planner = StackelbergPlanner()
    # Build targets from Neo4j graph...
    solution = planner.solve(body.get("budget", 40.0))
    return solution.__dict__

@app.post("/api/v1/plan/schedule")
async def schedule_scans(body: dict):
    """Multi-round scan scheduling with CTEM-style re-optimization."""
    planner = StackelbergPlanner()
    solutions = planner.solve_with_schedule(
        body.get("budget", 40.0), body.get("time_slots", 5)
    )
    return [s.__dict__ for s in solutions]
```

---

## Tests

### `tests/game_theory/test_stackelberg.py`
```python
import pytest
from sentinel.game_theory.stackelberg import StackelbergPlanner, Target, build_targets_from_graph

class TestStackelbergPlanner:
    def setup_method(self):
        self.planner = StackelbergPlanner()

    def test_single_target_full_coverage(self):
        self.planner.add_target(Target("t1", "webapp", value=50, vulnerability=0.8, scan_cost=5))
        solution = self.planner.solve(budget=10)
        assert solution.solver_status == "optimal"
        assert solution.allocations[0].coverage == 1.0  # Should fully cover only target

    def test_budget_constraint(self):
        self.planner.add_target(Target("t1", "webapp", value=50, vulnerability=0.8, scan_cost=10))
        self.planner.add_target(Target("t2", "api", value=30, vulnerability=0.6, scan_cost=10))
        solution = self.planner.solve(budget=10)
        # Can only afford one target fully
        assert solution.total_budget_used <= 10.01

    def test_high_value_gets_more_coverage(self):
        self.planner.add_target(Target("t1", "crown_jewel", value=100, vulnerability=0.9, scan_cost=5))
        self.planner.add_target(Target("t2", "blog", value=5, vulnerability=0.3, scan_cost=5))
        solution = self.planner.solve(budget=8)
        assert solution.solver_status == "optimal"
        # Crown jewel should get more coverage
        alloc_map = {a.target_id: a for a in solution.allocations}
        assert alloc_map["t1"].coverage > alloc_map["t2"].coverage

    def test_zero_budget(self):
        self.planner.add_target(Target("t1", "webapp", value=50, vulnerability=0.8, scan_cost=5))
        solution = self.planner.solve(budget=0)
        assert solution.solver_status == "optimal"
        assert all(a.coverage == 0 for a in solution.allocations)

    def test_no_targets(self):
        solution = self.planner.solve(budget=100)
        assert solution.solver_status == "no_targets"

    def test_multi_round_scheduling(self):
        self.planner.add_target(Target("t1", "webapp", value=50, vulnerability=0.8, scan_cost=5))
        self.planner.add_target(Target("t2", "api", value=30, vulnerability=0.6, scan_cost=5))
        solutions = self.planner.solve_with_schedule(budget=20, time_slots=3)
        assert len(solutions) == 3
        # Vulnerability should decrease over rounds
        # Later rounds should have lower worst_case_loss

    def test_priority_ranking(self):
        self.planner.add_target(Target("t1", "a", value=10, vulnerability=0.3, scan_cost=2))
        self.planner.add_target(Target("t2", "b", value=90, vulnerability=0.9, scan_cost=5))
        self.planner.add_target(Target("t3", "c", value=40, vulnerability=0.5, scan_cost=3))
        solution = self.planner.solve(budget=15)
        assert solution.allocations[0].priority_rank == 1
        assert solution.allocations[0].coverage >= solution.allocations[1].coverage

    def test_build_targets_from_graph(self):
        graph_data = [
            {"host_id": "h1", "hostname": "webapp.internal", "risk_score": 0.7, "has_crown_jewel": True, "service_count": 3},
            {"host_id": "h2", "hostname": "blog.internal", "risk_score": 0.2, "service_count": 1},
        ]
        targets = build_targets_from_graph(graph_data)
        assert len(targets) == 2
        assert targets[0].value > targets[1].value  # Crown jewel has higher value
```

---

## Acceptance Criteria
- [ ] StackelbergPlanner models targets with value, vulnerability, and scan cost
- [ ] LP solver minimizes worst-case expected loss under budget constraint
- [ ] High-value targets receive proportionally more coverage
- [ ] Budget constraint is strictly respected
- [ ] Zero budget → zero coverage for all targets
- [ ] Multi-round scheduling reduces vulnerability over time
- [ ] Priority ranking sorts by coverage (highest first)
- [ ] build_targets_from_graph converts Neo4j host data to Stackelberg targets
- [ ] Crown jewel targets automatically get higher value scores
- [ ] API endpoints expose optimization and scheduling
- [ ] All tests pass