"""
Bayesian Confidence Scoring — Beta-Bernoulli per (technique, stack) pair.

Each technique-stack pair maintains a Beta(alpha, beta) distribution:
- alpha = successes + 1 (prior)
- beta = failures + 1 (prior)
- Mean = alpha / (alpha + beta)

Thompson Sampling selects which techniques to try next by sampling
from each Beta distribution. This naturally balances exploration
(uncertain techniques) vs exploitation (proven ones).

Time decay: exponential discount on old trials to adapt to patching.
"""

import math
import random
from dataclasses import dataclass
from datetime import datetime, timezone

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class TechniqueStats:
    technique: str
    stack: str
    alpha: float = 1.0
    beta: float = 1.0
    total_trials: int = 0
    last_updated: datetime | None = None

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        a, b = self.alpha, self.beta
        return (a * b) / ((a + b) ** 2 * (a + b + 1))

    @property
    def confidence_interval(self) -> tuple[float, float]:
        """95% credible interval (normal approximation)."""
        std = math.sqrt(self.variance)
        return (max(0.0, self.mean - 1.96 * std), min(1.0, self.mean + 1.96 * std))


class BayesianConfidence:
    """Track technique effectiveness with Bayesian confidence scoring."""

    DECAY_HALFLIFE_DAYS = 90

    def __init__(self):
        self.stats: dict[str, TechniqueStats] = {}

    def _key(self, technique: str, stack: str) -> str:
        return f"{technique}::{stack}"

    def update(self, technique: str, stack: str, success: bool):
        """Record a trial result."""
        key = self._key(technique, stack)
        if key not in self.stats:
            self.stats[key] = TechniqueStats(technique=technique, stack=stack)

        s = self.stats[key]
        if success:
            s.alpha += 1
        else:
            s.beta += 1
        s.total_trials += 1
        s.last_updated = datetime.now(timezone.utc)

    def get_confidence(self, technique: str, stack: str) -> float:
        """Get current mean confidence for a technique-stack pair."""
        key = self._key(technique, stack)
        s = self.stats.get(key)
        if not s:
            return 0.5  # Uninformative prior
        return self._decayed_mean(s)

    def thompson_sample(
        self, techniques: list[str], stack: str
    ) -> list[tuple[str, float]]:
        """
        Thompson Sampling: sample from each technique's Beta distribution
        and return sorted by sampled probability (highest first).
        """
        samples: list[tuple[str, float]] = []
        for tech in techniques:
            key = self._key(tech, stack)
            s = self.stats.get(key, TechniqueStats(technique=tech, stack=stack))
            a_decayed, b_decayed = self._decay_params(s)
            sample = random.betavariate(
                max(a_decayed, 0.01), max(b_decayed, 0.01)
            )
            samples.append((tech, sample))
        return sorted(samples, key=lambda x: x[1], reverse=True)

    def get_all_stats(self) -> list[TechniqueStats]:
        return list(self.stats.values())

    def merge_remote(self, remote_stats: list[dict]):
        """Merge stats from federated aggregation server."""
        for rs in remote_stats:
            key = self._key(rs["technique"], rs["stack"])
            if key not in self.stats:
                self.stats[key] = TechniqueStats(
                    technique=rs["technique"],
                    stack=rs["stack"],
                    alpha=rs["alpha"],
                    beta=rs["beta"],
                    total_trials=rs["total_trials"],
                )
            else:
                local = self.stats[key]
                local.alpha += rs["alpha"] - 1  # Subtract prior to avoid double-counting
                local.beta += rs["beta"] - 1
                local.total_trials += rs["total_trials"]

    def _decayed_mean(self, s: TechniqueStats) -> float:
        if not s.last_updated:
            return s.mean
        days_old = (datetime.now(timezone.utc) - s.last_updated).days
        decay = math.exp(-0.693 * days_old / self.DECAY_HALFLIFE_DAYS)
        decayed_alpha = 1 + (s.alpha - 1) * decay
        decayed_beta = 1 + (s.beta - 1) * decay
        return decayed_alpha / (decayed_alpha + decayed_beta)

    def _decay_params(self, s: TechniqueStats) -> tuple[float, float]:
        if not s.last_updated:
            return s.alpha, s.beta
        days_old = (datetime.now(timezone.utc) - s.last_updated).days
        decay = math.exp(-0.693 * days_old / self.DECAY_HALFLIFE_DAYS)
        return 1 + (s.alpha - 1) * decay, 1 + (s.beta - 1) * decay
