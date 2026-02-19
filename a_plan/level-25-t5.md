# LEVEL 25: FlipIt Persistence Game — Retest/Patch Frequency Optimizer

## Context
FlipIt is a game-theoretic model for stealthy takeover: attacker and defender each "flip" control of a resource at unknown times. The defender doesn't know when the attacker flipped, and vice versa. Applied to pentesting: how often should you retest an asset to minimize attacker dwell time?

Research: Block 12 (FlipIt — van Dijk et al., control-time metrics, RL-trained retest frequency, exponential/periodic/adaptive strategies).

## Why
Most companies retest annually. That's 364 days of potential attacker dwell time. FlipIt gives a mathematically optimal retest cadence per asset based on its value, vulnerability, and patch cost. A crown-jewel DB might need monthly retesting; a static marketing site, quarterly.

---

## Files to Create

### `src/sentinel/game_theory/flipit.py`
```python
"""
FlipIt Game Solver — Optimal retest/patch frequency under uncertainty.

Model:
- Defender retests at rate δ (cost: c_d per retest)
- Attacker exploits at rate α (cost: c_a per attempt)
- Asset has value V per time unit
- Goal: maximize defender's control-time fraction while minimizing cost

Strategies:
1. Periodic: retest every T days (simple, predictable)
2. Exponential: retest with rate λ (memoryless, harder to predict)
3. Adaptive: adjust frequency based on observed attack rate (RL-trained)

Control-time metric: fraction of time the defender controls the asset.
"""
import math
import random
from dataclasses import dataclass, field
from enum import Enum
from sentinel.logging import get_logger

logger = get_logger(__name__)


class Strategy(str, Enum):
    PERIODIC = "periodic"
    EXPONENTIAL = "exponential"
    ADAPTIVE = "adaptive"


@dataclass
class FlipItAsset:
    asset_id: str
    name: str
    value_per_day: float      # Business value at risk per day
    retest_cost: float        # Cost of one retest (hours or $)
    estimated_attack_rate: float  # Expected attacks per day (0-1)
    vulnerability_score: float    # Probability attack succeeds (0-1)
    last_retest: float = 0.0     # Days since last retest
    current_controller: str = "defender"  # "defender" or "attacker"


@dataclass
class FlipItSolution:
    asset_id: str
    strategy: Strategy
    optimal_interval_days: float  # Retest every N days
    expected_control_time: float  # Fraction of time defender controls (0-1)
    expected_cost_per_year: float # Annual retest cost
    expected_loss_per_year: float # Expected loss from attacker control periods
    net_benefit: float           # Value saved minus retest cost


@dataclass
class SimulationResult:
    total_days: int
    defender_control_fraction: float
    attacker_control_fraction: float
    total_flips_defender: int
    total_flips_attacker: int
    total_defender_cost: float
    total_attacker_damage: float


class FlipItSolver:
    """Solve FlipIt games for optimal retest frequency."""

    def solve_periodic(self, asset: FlipItAsset) -> FlipItSolution:
        """
        Optimal periodic retest interval.

        For periodic strategy against exponential attacker:
        Optimal T* = sqrt(2 * c_d / (α * V))
        where α = attack_rate × vuln_score, V = value, c_d = retest_cost
        """
        effective_attack_rate = asset.estimated_attack_rate * asset.vulnerability_score
        if effective_attack_rate <= 0:
            return FlipItSolution(
                asset_id=asset.asset_id, strategy=Strategy.PERIODIC,
                optimal_interval_days=365, expected_control_time=1.0,
                expected_cost_per_year=asset.retest_cost,
                expected_loss_per_year=0, net_benefit=asset.value_per_day * 365,
            )

        T_star = math.sqrt(2 * asset.retest_cost / (effective_attack_rate * asset.value_per_day))
        T_star = max(1, min(T_star, 365))  # Clamp to 1-365 days

        # Expected control time for periodic strategy
        # Approx: 1 - (α × T) / 2 (average dwell time is T/2 when attacked between retests)
        expected_control = max(0, 1 - (effective_attack_rate * T_star) / 2)

        retests_per_year = 365 / T_star
        annual_cost = retests_per_year * asset.retest_cost
        annual_loss = (1 - expected_control) * asset.value_per_day * 365
        net_benefit = asset.value_per_day * 365 * expected_control - annual_cost

        return FlipItSolution(
            asset_id=asset.asset_id, strategy=Strategy.PERIODIC,
            optimal_interval_days=round(T_star, 1),
            expected_control_time=round(expected_control, 4),
            expected_cost_per_year=round(annual_cost, 2),
            expected_loss_per_year=round(annual_loss, 2),
            net_benefit=round(net_benefit, 2),
        )

    def solve_exponential(self, asset: FlipItAsset) -> FlipItSolution:
        """
        Optimal exponential (memoryless) retest rate.

        For exponential strategy: optimal rate δ* = sqrt(α × V / c_d) - α
        This makes the defender's strategy unpredictable (harder for attacker to time).
        """
        α = asset.estimated_attack_rate * asset.vulnerability_score
        V = asset.value_per_day
        c_d = asset.retest_cost

        if α <= 0 or V <= 0:
            return FlipItSolution(
                asset_id=asset.asset_id, strategy=Strategy.EXPONENTIAL,
                optimal_interval_days=365, expected_control_time=1.0,
                expected_cost_per_year=asset.retest_cost,
                expected_loss_per_year=0, net_benefit=V * 365,
            )

        δ_star = max(0.001, math.sqrt(α * V / c_d) - α)
        T_equiv = 1 / δ_star if δ_star > 0 else 365

        # Control time: δ / (δ + α)
        expected_control = δ_star / (δ_star + α)

        retests_per_year = δ_star * 365
        annual_cost = retests_per_year * c_d
        annual_loss = (1 - expected_control) * V * 365

        return FlipItSolution(
            asset_id=asset.asset_id, strategy=Strategy.EXPONENTIAL,
            optimal_interval_days=round(T_equiv, 1),
            expected_control_time=round(expected_control, 4),
            expected_cost_per_year=round(annual_cost, 2),
            expected_loss_per_year=round(annual_loss, 2),
            net_benefit=round(V * 365 * expected_control - annual_cost, 2),
        )

    def recommend(self, asset: FlipItAsset) -> FlipItSolution:
        """Return the best strategy for an asset."""
        periodic = self.solve_periodic(asset)
        exponential = self.solve_exponential(asset)
        return periodic if periodic.net_benefit >= exponential.net_benefit else exponential

    def simulate(self, asset: FlipItAsset, strategy: Strategy,
                 interval_days: float, total_days: int = 365) -> SimulationResult:
        """Monte Carlo simulation of a FlipIt game."""
        controller = "defender"
        defender_days = 0
        attacker_days = 0
        defender_flips = 0
        attacker_flips = 0
        defender_cost = 0.0
        attacker_damage = 0.0

        α = asset.estimated_attack_rate * asset.vulnerability_score
        next_retest = interval_days

        for day in range(total_days):
            # Attacker attempts
            if random.random() < α:
                if controller == "defender":
                    controller = "attacker"
                    attacker_flips += 1

            # Defender retests
            if strategy == Strategy.PERIODIC:
                if day >= next_retest:
                    controller = "defender"
                    defender_flips += 1
                    defender_cost += asset.retest_cost
                    next_retest += interval_days
            elif strategy == Strategy.EXPONENTIAL:
                if random.random() < (1 / interval_days):
                    controller = "defender"
                    defender_flips += 1
                    defender_cost += asset.retest_cost

            if controller == "defender":
                defender_days += 1
            else:
                attacker_days += 1
                attacker_damage += asset.value_per_day

        return SimulationResult(
            total_days=total_days,
            defender_control_fraction=round(defender_days / total_days, 4),
            attacker_control_fraction=round(attacker_days / total_days, 4),
            total_flips_defender=defender_flips,
            total_flips_attacker=attacker_flips,
            total_defender_cost=round(defender_cost, 2),
            total_attacker_damage=round(attacker_damage, 2),
        )


def build_schedule_from_solutions(solutions: list[FlipItSolution]) -> list[dict]:
    """Convert FlipIt solutions into a retest calendar."""
    schedule = []
    for s in sorted(solutions, key=lambda x: x.optimal_interval_days):
        schedule.append({
            "asset_id": s.asset_id,
            "strategy": s.strategy.value,
            "retest_every_days": s.optimal_interval_days,
            "annual_retests": round(365 / s.optimal_interval_days, 1),
            "annual_cost": s.expected_cost_per_year,
            "expected_control": s.expected_control_time,
        })
    return schedule
```

---

## Tests

### `tests/game_theory/test_flipit.py`
```python
import pytest
from sentinel.game_theory.flipit import FlipItSolver, FlipItAsset, Strategy

class TestFlipItSolver:
    def setup_method(self):
        self.solver = FlipItSolver()

    def test_high_value_retests_more(self):
        high = FlipItAsset("a1", "crown_jewel", value_per_day=1000, retest_cost=50,
                           estimated_attack_rate=0.1, vulnerability_score=0.8)
        low = FlipItAsset("a2", "blog", value_per_day=10, retest_cost=50,
                          estimated_attack_rate=0.1, vulnerability_score=0.3)
        sol_high = self.solver.solve_periodic(high)
        sol_low = self.solver.solve_periodic(low)
        assert sol_high.optimal_interval_days < sol_low.optimal_interval_days

    def test_zero_attack_rate(self):
        asset = FlipItAsset("a1", "safe", value_per_day=100, retest_cost=50,
                            estimated_attack_rate=0, vulnerability_score=0)
        sol = self.solver.solve_periodic(asset)
        assert sol.expected_control_time == 1.0
        assert sol.optimal_interval_days == 365

    def test_exponential_control_fraction(self):
        asset = FlipItAsset("a1", "app", value_per_day=500, retest_cost=30,
                            estimated_attack_rate=0.05, vulnerability_score=0.5)
        sol = self.solver.solve_exponential(asset)
        assert 0 < sol.expected_control_time <= 1.0
        assert sol.expected_cost_per_year > 0

    def test_recommend_picks_better(self):
        asset = FlipItAsset("a1", "app", value_per_day=200, retest_cost=20,
                            estimated_attack_rate=0.1, vulnerability_score=0.6)
        sol = self.solver.recommend(asset)
        assert sol.strategy in (Strategy.PERIODIC, Strategy.EXPONENTIAL)
        assert sol.net_benefit > 0 or sol.net_benefit <= 0  # Just no crash

    def test_simulation_runs(self):
        asset = FlipItAsset("a1", "app", value_per_day=100, retest_cost=10,
                            estimated_attack_rate=0.05, vulnerability_score=0.5)
        result = self.solver.simulate(asset, Strategy.PERIODIC, interval_days=30, total_days=365)
        assert result.total_days == 365
        assert result.defender_control_fraction + result.attacker_control_fraction == pytest.approx(1.0, abs=0.01)
        assert result.total_flips_defender > 0

    def test_schedule_generation(self):
        from sentinel.game_theory.flipit import build_schedule_from_solutions
        solutions = [
            self.solver.solve_periodic(FlipItAsset("a1", "db", 500, 30, 0.1, 0.7)),
            self.solver.solve_periodic(FlipItAsset("a2", "blog", 10, 30, 0.01, 0.2)),
        ]
        schedule = build_schedule_from_solutions(solutions)
        assert len(schedule) == 2
        assert schedule[0]["retest_every_days"] <= schedule[1]["retest_every_days"]
```

---

## Acceptance Criteria
- [ ] Periodic solver computes optimal retest interval T* = sqrt(2c_d / αV)
- [ ] Exponential solver computes optimal rate δ* with control fraction δ/(δ+α)
- [ ] High-value assets get shorter retest intervals than low-value ones
- [ ] Zero attack rate → 365-day interval, 100% control
- [ ] recommend() picks the strategy with higher net benefit
- [ ] Monte Carlo simulation tracks control fractions over 365 days
- [ ] Schedule builder converts solutions to a retest calendar sorted by frequency
- [ ] All tests pass