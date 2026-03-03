"""
Bayesian Belief Model -- Maintains probability distributions over network state.

Each discoverable fact has a belief: P(fact=true | observations).
- Port open: Beta(alpha, beta) updated by scan results
- Vulnerability present: Beta(alpha, beta) updated by exploit attempts
- Credential valid: Beta(alpha, beta) updated by auth attempts

Information gain = expected variance reduction after one observation.
The agent selects actions that maximize expected information gain.
"""

import math
from dataclasses import dataclass, field

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class BetaBelief:
    """Beta distribution belief for binary facts (open/closed, vuln/safe)."""

    name: str
    alpha: float = 1.0  # Successes + prior
    beta: float = 1.0  # Failures + prior

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        a, b = self.alpha, self.beta
        return (a * b) / ((a + b) ** 2 * (a + b + 1))

    @property
    def entropy(self) -> float:
        """Approximate entropy of the Beta distribution."""
        a, b = self.alpha, self.beta
        # Use digamma approximation: psi(x) ~ ln(x) - 1/(2x) for large x
        # For small x, use the series expansion
        def _digamma(x: float) -> float:
            """Simple digamma approximation."""
            if x < 1e-6:
                return -1.0 / x
            result = 0.0
            while x < 6:
                result -= 1.0 / x
                x += 1
            result += math.log(x) - 1.0 / (2 * x)
            x2 = 1.0 / (x * x)
            result -= x2 * (1.0 / 12 - x2 * (1.0 / 120 - x2 / 252))
            return result

        def _betaln(a: float, b: float) -> float:
            return math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)

        return (
            _betaln(a, b)
            - (a - 1) * _digamma(a)
            - (b - 1) * _digamma(b)
            + (a + b - 2) * _digamma(a + b)
        )

    @property
    def uncertainty(self) -> float:
        """Simple uncertainty: max entropy when alpha=beta=1 (uniform)."""
        return 4 * self.variance  # Normalized to [0,1], max at uniform

    def update(self, observation: bool):
        """Bayesian update with observation."""
        if observation:
            self.alpha += 1
        else:
            self.beta += 1

    def expected_info_gain(self) -> float:
        """Expected information gain from one more observation."""
        p = self.mean
        current_var = self.variance
        if 0 < p < 1:
            post_var_if_true = self._var_after(True)
            post_var_if_false = self._var_after(False)
            expected_post_var = p * post_var_if_true + (1 - p) * post_var_if_false
            return max(0, current_var - expected_post_var)
        return 0.0

    def _var_after(self, success: bool) -> float:
        a = self.alpha + (1 if success else 0)
        b = self.beta + (0 if success else 1)
        return (a * b) / ((a + b) ** 2 * (a + b + 1))


@dataclass
class NetworkBeliefs:
    """Full belief state over a network."""

    host_id: str
    port_beliefs: dict[int, BetaBelief] = field(default_factory=dict)
    vuln_beliefs: dict[str, BetaBelief] = field(default_factory=dict)
    cred_beliefs: dict[str, BetaBelief] = field(default_factory=dict)

    def add_port(self, port: int):
        if port not in self.port_beliefs:
            self.port_beliefs[port] = BetaBelief(f"port_{port}_open")

    def add_vuln(self, vuln_id: str):
        if vuln_id not in self.vuln_beliefs:
            self.vuln_beliefs[vuln_id] = BetaBelief(f"vuln_{vuln_id}")

    def total_uncertainty(self) -> float:
        total = 0.0
        for b in self.port_beliefs.values():
            total += b.uncertainty
        for b in self.vuln_beliefs.values():
            total += b.uncertainty
        for b in self.cred_beliefs.values():
            total += b.uncertainty
        return total
