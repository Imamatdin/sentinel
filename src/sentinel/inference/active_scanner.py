"""
Active Inference Scanner -- Selects scan actions to maximize information gain.

Algorithm:
1. Maintain belief model over all discoverable facts
2. For each possible action, compute expected information gain
3. Select action with highest gain per unit cost
4. Execute action, update beliefs with observation
5. Repeat until uncertainty below threshold or budget exhausted
"""

from dataclasses import dataclass

from sentinel.core import get_logger
from sentinel.inference.belief_model import BetaBelief, NetworkBeliefs

logger = get_logger(__name__)


@dataclass
class ScanAction:
    action_type: str  # "port_scan", "vuln_check", "cred_test"
    target: str  # Port number, vuln ID, or credential
    host_id: str
    expected_info_gain: float
    cost: float  # Time/resource cost


class ActiveScanner:
    """Select optimal scan actions via active inference."""

    def __init__(self, uncertainty_threshold: float = 0.05, max_actions: int = 50):
        self.beliefs: dict[str, NetworkBeliefs] = {}
        self.uncertainty_threshold = uncertainty_threshold
        self.max_actions = max_actions
        self.action_history: list[ScanAction] = []

    def initialize_host(self, host_id: str, common_ports: list[int] | None = None):
        """Initialize beliefs for a new host."""
        beliefs = NetworkBeliefs(host_id=host_id)
        ports = common_ports if common_ports is not None else [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
            993, 995, 1433, 1521, 3306, 3389, 5432, 6379,
            8080, 8443, 9200, 27017,
        ]
        for port in ports:
            beliefs.add_port(port)
        self.beliefs[host_id] = beliefs
        logger.info(f"Initialized beliefs for {host_id}: {len(ports)} ports to probe")

    def select_next_action(self, host_id: str) -> ScanAction | None:
        """Select the action with highest expected information gain per unit cost."""
        beliefs = self.beliefs.get(host_id)
        if not beliefs:
            return None

        candidates: list[ScanAction] = []

        # Port scan actions
        for port, belief in beliefs.port_beliefs.items():
            if belief.uncertainty > self.uncertainty_threshold:
                gain = belief.expected_info_gain()
                candidates.append(ScanAction(
                    action_type="port_scan",
                    target=str(port),
                    host_id=host_id,
                    expected_info_gain=gain,
                    cost=1.0,
                ))

        # Vulnerability check actions
        for vuln_id, belief in beliefs.vuln_beliefs.items():
            if belief.uncertainty > self.uncertainty_threshold:
                gain = belief.expected_info_gain()
                candidates.append(ScanAction(
                    action_type="vuln_check",
                    target=vuln_id,
                    host_id=host_id,
                    expected_info_gain=gain,
                    cost=3.0,
                ))

        # Credential test actions
        for cred_id, belief in beliefs.cred_beliefs.items():
            if belief.uncertainty > self.uncertainty_threshold:
                gain = belief.expected_info_gain()
                candidates.append(ScanAction(
                    action_type="cred_test",
                    target=cred_id,
                    host_id=host_id,
                    expected_info_gain=gain,
                    cost=2.0,
                ))

        if not candidates:
            return None

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
        # Save original beliefs so we can restore after simulation
        original_beliefs = self.beliefs.get(host_id)
        if not original_beliefs:
            return []

        # Deep-copy port beliefs for simulation
        saved_alphas = {p: (b.alpha, b.beta) for p, b in original_beliefs.port_beliefs.items()}
        saved_vuln = {v: (b.alpha, b.beta) for v, b in original_beliefs.vuln_beliefs.items()}
        saved_cred = {c: (b.alpha, b.beta) for c, b in original_beliefs.cred_beliefs.items()}

        plan: list[ScanAction] = []
        for _ in range(self.max_actions):
            action = self.select_next_action(host_id)
            if not action:
                break
            plan.append(action)
            # Simulate optimistic update
            beliefs = self.beliefs[host_id]
            if action.action_type == "port_scan":
                beliefs.port_beliefs[int(action.target)].update(True)
            elif action.action_type == "vuln_check":
                beliefs.vuln_beliefs[action.target].update(True)
            elif action.action_type == "cred_test":
                beliefs.cred_beliefs[action.target].update(True)

        # Restore beliefs
        for p, (a, b) in saved_alphas.items():
            original_beliefs.port_beliefs[p].alpha = a
            original_beliefs.port_beliefs[p].beta = b
        for v, (a, b) in saved_vuln.items():
            original_beliefs.vuln_beliefs[v].alpha = a
            original_beliefs.vuln_beliefs[v].beta = b
        for c, (a, b) in saved_cred.items():
            original_beliefs.cred_beliefs[c].alpha = a
            original_beliefs.cred_beliefs[c].beta = b

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
