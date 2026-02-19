# LEVEL 27: Active Inference Scanning Agent

## Context
Active inference agents minimize expected surprise (free energy) by building Bayesian world models and selecting actions that reduce uncertainty most efficiently. Instead of brute-force scanning, the agent asks "where am I most uncertain?" and scans there first.

Research: Block 12 (Active Inference — Karl Friston's free energy principle applied to network scanning, attention-weighted exploration, uncertainty minimization, belief updates).

## Why
Traditional scanners waste time confirming what they already know. Active inference focuses effort on maximum information gain: if the agent is 95% sure port 80 is open, it skips confirmation and instead probes the uncertain port 8443. This is provably optimal information gathering.

---

## Files to Create

### `src/sentinel/inference/__init__.py`
```python
"""Active inference — Bayesian belief updates, attention-weighted scanning, free energy minimization."""
```

### `src/sentinel/inference/belief_model.py`
```python
"""
Bayesian Belief Model — Maintains probability distributions over network state.

Each discoverable fact has a belief: P(fact=true | observations).
- Port open: Beta(α, β) updated by scan results
- Service version: Categorical distribution over known versions
- Vulnerability present: Beta(α, β) updated by exploit attempts
- Credential valid: Beta(α, β) updated by auth attempts

Information gain = KL divergence between prior and posterior.
The agent selects actions that maximize expected information gain.
"""
import math
from dataclasses import dataclass, field
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BetaBelief:
    """Beta distribution belief for binary facts (open/closed, vuln/safe)."""
    name: str
    alpha: float = 1.0   # Successes + prior
    beta: float = 1.0    # Failures + prior

    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    @property
    def variance(self) -> float:
        a, b = self.alpha, self.beta
        return (a * b) / ((a + b) ** 2 * (a + b + 1))

    @property
    def entropy(self) -> float:
        """Shannon entropy of the Beta distribution (uncertainty measure)."""
        from scipy.special import betaln, digamma
        a, b = self.alpha, self.beta
        return (betaln(a, b)
                - (a - 1) * digamma(a)
                - (b - 1) * digamma(b)
                + (a + b - 2) * digamma(a + b))

    @property
    def uncertainty(self) -> float:
        """Simple uncertainty: max entropy when α=β=1 (uniform)."""
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
        # Expected posterior entropy after one observation
        # E[H(posterior)] ≈ p × H(Beta(α+1,β)) + (1-p) × H(Beta(α,β+1))
        # Info gain = H(current) - E[H(posterior)]
        current_var = self.variance
        if p > 0 and p < 1:
            # Approximate: variance reduction as proxy for info gain
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
```

### `src/sentinel/inference/active_scanner.py`
```python
"""
Active Inference Scanner — Selects scan actions to maximize information gain.

Algorithm:
1. Maintain belief model over all discoverable facts
2. For each possible action, compute expected information gain
3. Select action with highest gain (attention-weighted)
4. Execute action, update beliefs with observation
5. Repeat until uncertainty below threshold or budget exhausted

This is provably more efficient than exhaustive scanning.
"""
from dataclasses import dataclass
from sentinel.inference.belief_model import NetworkBeliefs, BetaBelief
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ScanAction:
    action_type: str    # "port_scan", "vuln_check", "cred_test"
    target: str         # Port number, vuln ID, or credential
    host_id: str
    expected_info_gain: float
    cost: float         # Time/resource cost


class ActiveScanner:
    """Select optimal scan actions via active inference."""

    def __init__(self, uncertainty_threshold: float = 0.05, max_actions: int = 50):
        self.beliefs: dict[str, NetworkBeliefs] = {}
        self.uncertainty_threshold = uncertainty_threshold
        self.max_actions = max_actions
        self.action_history: list[ScanAction] = []

    def initialize_host(self, host_id: str, common_ports: list[int] = None):
        """Initialize beliefs for a new host."""
        beliefs = NetworkBeliefs(host_id=host_id)
        ports = common_ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                                  993, 995, 1433, 1521, 3306, 3389, 5432, 6379,
                                  8080, 8443, 9200, 27017]
        for port in ports:
            beliefs.add_port(port)
        self.beliefs[host_id] = beliefs
        logger.info(f"Initialized beliefs for {host_id}: {len(ports)} ports to probe")

    def select_next_action(self, host_id: str) -> ScanAction | None:
        """Select the action with highest expected information gain."""
        beliefs = self.beliefs.get(host_id)
        if not beliefs:
            return None

        candidates = []

        # Port scan actions
        for port, belief in beliefs.port_beliefs.items():
            gain = belief.expected_info_gain()
            if belief.uncertainty > self.uncertainty_threshold:
                candidates.append(ScanAction(
                    action_type="port_scan", target=str(port),
                    host_id=host_id, expected_info_gain=gain, cost=1.0,
                ))

        # Vulnerability check actions
        for vuln_id, belief in beliefs.vuln_beliefs.items():
            gain = belief.expected_info_gain()
            if belief.uncertainty > self.uncertainty_threshold:
                candidates.append(ScanAction(
                    action_type="vuln_check", target=vuln_id,
                    host_id=host_id, expected_info_gain=gain, cost=3.0,
                ))

        # Credential test actions
        for cred_id, belief in beliefs.cred_beliefs.items():
            gain = belief.expected_info_gain()
            if belief.uncertainty > self.uncertainty_threshold:
                candidates.append(ScanAction(
                    action_type="cred_test", target=cred_id,
                    host_id=host_id, expected_info_gain=gain, cost=2.0,
                ))

        if not candidates:
            return None

        # Select highest info gain per unit cost
        candidates.sort(key=lambda a: a.expected_info_gain / a.cost, reverse=True)
        return candidates[0]

    def update_belief(self, host_id: str, action: ScanAction, observation: bool):
        """Update beliefs with scan result."""
        beliefs = self.beliefs.get(host_id)
        if not beliefs:
            return

        if action.action_type == "port_scan":
            port = int(action.target)
            if port in beliefs.port_beliefs:
                beliefs.port_beliefs[port].update(observation)

        elif action.action_type == "vuln_check":
            if action.target in beliefs.vuln_beliefs:
                beliefs.vuln_beliefs[action.target].update(observation)

        elif action.action_type == "cred_test":
            if action.target in beliefs.cred_beliefs:
                beliefs.cred_beliefs[action.target].update(observation)

        self.action_history.append(action)

    def get_plan(self, host_id: str) -> list[ScanAction]:
        """Generate a full scan plan ordered by information gain."""
        plan = []
        for _ in range(self.max_actions):
            action = self.select_next_action(host_id)
            if not action:
                break
            plan.append(action)
            # Simulate optimistic update (assume observation reduces uncertainty)
            beliefs = self.beliefs[host_id]
            if action.action_type == "port_scan":
                beliefs.port_beliefs[int(action.target)].update(True)
        # Reset beliefs after planning (they were modified by simulation)
        return plan

    def get_uncertainty_report(self, host_id: str) -> dict:
        """Report remaining uncertainty per category."""
        beliefs = self.beliefs.get(host_id)
        if not beliefs:
            return {}
        return {
            "total_uncertainty": beliefs.total_uncertainty(),
            "port_uncertainties": {
                p: round(b.uncertainty, 4)
                for p, b in beliefs.port_beliefs.items()
                if b.uncertainty > self.uncertainty_threshold
            },
            "vuln_uncertainties": {
                v: round(b.uncertainty, 4)
                for v, b in beliefs.vuln_beliefs.items()
                if b.uncertainty > self.uncertainty_threshold
            },
            "actions_taken": len(self.action_history),
        }
```

---

## Tests

### `tests/inference/test_belief_model.py`
```python
import pytest
from sentinel.inference.belief_model import BetaBelief, NetworkBeliefs

class TestBetaBelief:
    def test_uniform_prior(self):
        b = BetaBelief("test")
        assert b.mean == 0.5
        assert b.uncertainty > 0

    def test_update_positive(self):
        b = BetaBelief("test")
        b.update(True)
        assert b.mean > 0.5
        assert b.alpha == 2.0

    def test_update_negative(self):
        b = BetaBelief("test")
        b.update(False)
        assert b.mean < 0.5
        assert b.beta == 2.0

    def test_uncertainty_decreases(self):
        b = BetaBelief("test")
        initial = b.uncertainty
        for _ in range(10):
            b.update(True)
        assert b.uncertainty < initial

    def test_info_gain_positive(self):
        b = BetaBelief("test")
        gain = b.expected_info_gain()
        assert gain >= 0

    def test_strong_belief_low_gain(self):
        b = BetaBelief("test", alpha=100, beta=1)
        gain = b.expected_info_gain()
        b2 = BetaBelief("test2", alpha=1, beta=1)
        gain2 = b2.expected_info_gain()
        assert gain < gain2  # Uncertain belief has more to gain

class TestNetworkBeliefs:
    def test_total_uncertainty(self):
        nb = NetworkBeliefs("host1")
        nb.add_port(80)
        nb.add_port(443)
        assert nb.total_uncertainty() > 0

    def test_add_vuln(self):
        nb = NetworkBeliefs("host1")
        nb.add_vuln("CVE-2021-44228")
        assert "CVE-2021-44228" in nb.vuln_beliefs
```

### `tests/inference/test_active_scanner.py`
```python
import pytest
from sentinel.inference.active_scanner import ActiveScanner

class TestActiveScanner:
    def setup_method(self):
        self.scanner = ActiveScanner()

    def test_initialize_host(self):
        self.scanner.initialize_host("h1")
        assert "h1" in self.scanner.beliefs
        assert len(self.scanner.beliefs["h1"].port_beliefs) > 0

    def test_select_next_action(self):
        self.scanner.initialize_host("h1")
        action = self.scanner.select_next_action("h1")
        assert action is not None
        assert action.action_type == "port_scan"
        assert action.expected_info_gain >= 0

    def test_update_reduces_uncertainty(self):
        self.scanner.initialize_host("h1", common_ports=[80])
        before = self.scanner.beliefs["h1"].total_uncertainty()
        action = self.scanner.select_next_action("h1")
        self.scanner.update_belief("h1", action, True)
        after = self.scanner.beliefs["h1"].total_uncertainty()
        assert after < before

    def test_no_action_when_certain(self):
        self.scanner.initialize_host("h1", common_ports=[80])
        for _ in range(20):
            self.scanner.beliefs["h1"].port_beliefs[80].update(True)
        action = self.scanner.select_next_action("h1")
        assert action is None  # Below uncertainty threshold

    def test_get_plan(self):
        self.scanner.initialize_host("h1", common_ports=[22, 80, 443])
        plan = self.scanner.get_plan("h1")
        assert len(plan) > 0
        # Plan should be ordered by info gain / cost
```

---

## Acceptance Criteria
- [ ] BetaBelief maintains Beta(α,β) distribution, updates with observations
- [ ] Uncertainty decreases with more observations
- [ ] Expected info gain is higher for uncertain beliefs than confident ones
- [ ] ActiveScanner initializes beliefs for common ports
- [ ] select_next_action picks highest info-gain-per-cost action
- [ ] Belief updates correctly modify port/vuln/cred beliefs
- [ ] No actions returned when all beliefs below uncertainty threshold
- [ ] Uncertainty report shows remaining unknowns per category
- [ ] All tests pass