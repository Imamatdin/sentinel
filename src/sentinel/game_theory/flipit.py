"""
FlipIt Persistence Game — retest/patch frequency optimiser.

Attacker and defender "flip" control of a resource at unknown times.
Optimal retest interval minimises attacker dwell time.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class FlipItAsset:
    asset_id: str
    name: str
    value_per_day: float  # business risk $ / day
    retest_cost: float  # cost per retest
    estimated_attack_rate: float  # attacks/day (lambda)
    vulnerability_score: float  # P(attack succeeds) 0-1
    current_controller: str = "defender"  # "defender" | "attacker"


@dataclass
class FlipItSolution:
    asset_id: str
    strategy: str  # "periodic" | "exponential"
    optimal_interval_days: float
    expected_control_time: float  # fraction 0-1
    expected_cost_per_year: float
    expected_loss_per_year: float
    net_benefit: float  # value saved - cost


@dataclass
class SimulationResult:
    defender_control_fraction: float
    attacker_control_fraction: float
    defender_flips: int
    attacker_flips: int
    total_cost: float
    total_loss: float


@dataclass
class RetestScheduleEntry:
    asset_id: str
    name: str
    retest_interval_days: float
    annual_retests: int
    expected_control: float
    strategy: str


class FlipItSolver:
    """Solves FlipIt for optimal retest frequency."""

    def solve_periodic(self, asset: FlipItAsset) -> FlipItSolution:
        """Periodic (fixed interval) strategy."""
        alpha = asset.estimated_attack_rate * asset.vulnerability_score
        c_d = asset.retest_cost
        v = asset.value_per_day

        if alpha <= 0 or v <= 0:
            return FlipItSolution(
                asset_id=asset.asset_id, strategy="periodic",
                optimal_interval_days=365.0, expected_control_time=1.0,
                expected_cost_per_year=c_d, expected_loss_per_year=0.0,
                net_benefit=0.0,
            )

        # Optimal interval: T* = sqrt(2 * c_d / (alpha * V))
        t_star = math.sqrt(2 * c_d / (alpha * v))
        t_star = max(t_star, 0.5)  # minimum half a day

        # Expected control time fraction: 1 - alpha*T/2
        control = max(0.0, 1.0 - alpha * t_star / 2)

        annual_retests = 365.0 / t_star
        cost_year = annual_retests * c_d
        loss_year = (1 - control) * v * 365
        benefit = control * v * 365 - cost_year

        return FlipItSolution(
            asset_id=asset.asset_id, strategy="periodic",
            optimal_interval_days=t_star, expected_control_time=control,
            expected_cost_per_year=cost_year, expected_loss_per_year=loss_year,
            net_benefit=benefit,
        )

    def solve_exponential(self, asset: FlipItAsset) -> FlipItSolution:
        """Exponential (memoryless) strategy — harder for attacker to predict."""
        alpha = asset.estimated_attack_rate * asset.vulnerability_score
        c_d = asset.retest_cost
        v = asset.value_per_day

        if alpha <= 0 or v <= 0:
            return FlipItSolution(
                asset_id=asset.asset_id, strategy="exponential",
                optimal_interval_days=365.0, expected_control_time=1.0,
                expected_cost_per_year=c_d, expected_loss_per_year=0.0,
                net_benefit=0.0,
            )

        # Optimal rate: delta* = sqrt(alpha * V / c_d) - alpha
        delta = math.sqrt(alpha * v / c_d) - alpha
        delta = max(delta, 1 / 365)  # at least once a year

        # Control fraction: delta / (delta + alpha)
        control = delta / (delta + alpha)
        interval = 1.0 / delta

        cost_year = delta * 365 * c_d
        loss_year = (1 - control) * v * 365
        benefit = control * v * 365 - cost_year

        return FlipItSolution(
            asset_id=asset.asset_id, strategy="exponential",
            optimal_interval_days=interval, expected_control_time=control,
            expected_cost_per_year=cost_year, expected_loss_per_year=loss_year,
            net_benefit=benefit,
        )

    def recommend(self, asset: FlipItAsset) -> FlipItSolution:
        """Pick whichever strategy yields better net benefit."""
        periodic = self.solve_periodic(asset)
        exponential = self.solve_exponential(asset)
        return periodic if periodic.net_benefit >= exponential.net_benefit else exponential

    def simulate(
        self, asset: FlipItAsset, days: int = 365, retest_interval: float | None = None,
    ) -> SimulationResult:
        """Monte Carlo simulation of FlipIt dynamics."""
        if retest_interval is None:
            sol = self.recommend(asset)
            retest_interval = sol.optimal_interval_days

        controller = "defender"
        defender_time = 0.0
        attacker_time = 0.0
        defender_flips = 0
        attacker_flips = 0
        total_cost = 0.0

        alpha = asset.estimated_attack_rate * asset.vulnerability_score
        t = 0.0
        next_retest = retest_interval

        while t < days:
            # Time to next attack
            if alpha > 0:
                time_to_attack = random.expovariate(alpha)
            else:
                time_to_attack = days + 1

            time_to_retest = next_retest - t
            dt = min(time_to_attack, time_to_retest, days - t)

            if controller == "defender":
                defender_time += dt
            else:
                attacker_time += dt

            t += dt

            if t >= days:
                break

            if dt == time_to_retest:
                # Defender retests
                controller = "defender"
                defender_flips += 1
                total_cost += asset.retest_cost
                next_retest = t + retest_interval
            else:
                # Attack occurs
                controller = "attacker"
                attacker_flips += 1

        total = defender_time + attacker_time or 1.0
        total_loss = attacker_time * asset.value_per_day

        return SimulationResult(
            defender_control_fraction=defender_time / total,
            attacker_control_fraction=attacker_time / total,
            defender_flips=defender_flips,
            attacker_flips=attacker_flips,
            total_cost=total_cost,
            total_loss=total_loss,
        )


def build_schedule_from_solutions(
    solutions: list[FlipItSolution],
    assets: list[FlipItAsset],
) -> list[RetestScheduleEntry]:
    """Convert solutions to a retest calendar, sorted by frequency."""
    entries = []
    asset_map = {a.asset_id: a for a in assets}
    for sol in solutions:
        a = asset_map.get(sol.asset_id)
        name = a.name if a else sol.asset_id
        entries.append(RetestScheduleEntry(
            asset_id=sol.asset_id, name=name,
            retest_interval_days=sol.optimal_interval_days,
            annual_retests=max(1, int(365 / sol.optimal_interval_days)),
            expected_control=sol.expected_control_time,
            strategy=sol.strategy,
        ))
    entries.sort(key=lambda e: e.retest_interval_days)
    return entries
