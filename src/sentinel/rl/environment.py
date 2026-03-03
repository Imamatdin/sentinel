"""
Gymnasium-compatible pentesting environment.

State: per-node vector (discovered, owned, privilege, service_count, vuln_count, has_creds)
Actions: SCAN_PORT, SCAN_VULN, EXPLOIT_KNOWN, BRUTE_FORCE, PIVOT, ESCALATE, EXFILTRATE
Rewards: -0.01/step, +1.0/exploit, +5.0/crown-jewel, -0.5/failed-exploit
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from sentinel.core import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

STATE_FEATURES_PER_NODE = 6  # discovered, owned, privilege, services, vulns, creds


class ActionType(IntEnum):
    SCAN_PORT = 0
    SCAN_VULN = 1
    EXPLOIT_KNOWN = 2
    BRUTE_FORCE = 3
    PIVOT = 4
    ESCALATE = 5
    EXFILTRATE = 6


@dataclass
class NodeState:
    node_id: str
    discovered: bool = False
    owned: bool = False
    privilege: int = 0  # 0=none, 1=user, 2=root
    services: list[str] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    has_credentials: bool = False
    is_crown_jewel: bool = False
    neighbours: list[str] = field(default_factory=list)

    def to_vector(self) -> list[float]:
        return [
            float(self.discovered),
            float(self.owned),
            self.privilege / 2.0,
            min(len(self.services) / 5.0, 1.0),
            min(len(self.vulns) / 5.0, 1.0),
            float(self.has_credentials),
        ]


# ---------------------------------------------------------------------------
# Topologies
# ---------------------------------------------------------------------------


def _small_network() -> dict[str, NodeState]:
    """3-node linear: gateway → app → db (crown jewel)."""
    gw = NodeState("gateway", discovered=True, services=["ssh", "http"],
                   vulns=["CVE-2024-0001"], neighbours=["app"])
    app = NodeState("app", services=["http", "api"],
                    vulns=["CVE-2024-0002"], neighbours=["gateway", "db"])
    db = NodeState("db", services=["mysql"], vulns=["CVE-2024-0003"],
                   is_crown_jewel=True, neighbours=["app"])
    return {"gateway": gw, "app": app, "db": db}


def _medium_network() -> dict[str, NodeState]:
    """6-node: dmz → web1/web2 → app → db + admin (crown jewel)."""
    dmz = NodeState("dmz", discovered=True, services=["http"],
                    vulns=["CVE-2024-0010"], neighbours=["web1", "web2"])
    web1 = NodeState("web1", services=["http", "https"],
                     vulns=["CVE-2024-0011"], neighbours=["dmz", "app"])
    web2 = NodeState("web2", services=["http"],
                     vulns=[], neighbours=["dmz", "app"])
    app = NodeState("app", services=["http", "rpc"],
                    vulns=["CVE-2024-0012"], neighbours=["web1", "web2", "db", "admin"])
    db = NodeState("db", services=["postgres"],
                   vulns=["CVE-2024-0013"], neighbours=["app"])
    admin = NodeState("admin", services=["ssh", "rdp"],
                      vulns=["CVE-2024-0014"], is_crown_jewel=True,
                      neighbours=["app"])
    return {"dmz": dmz, "web1": web1, "web2": web2,
            "app": app, "db": db, "admin": admin}


TOPOLOGIES = {"small": _small_network, "medium": _medium_network}


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------


class PentestEnv:
    """Gymnasium-style (no gym dependency) pentesting environment."""

    def __init__(self, topology: str = "small", max_steps: int = 100):
        self.topology_name = topology
        self.max_steps = max_steps
        self.nodes: dict[str, NodeState] = {}
        self.node_ids: list[str] = []
        self.step_count = 0
        self.done = False
        # Spaces
        self.n_actions = len(ActionType) * 1  # will be multiplied by n_nodes
        self.observation_size = 0

    def reset(self) -> list[float]:
        builder = TOPOLOGIES.get(self.topology_name, _small_network)
        self.nodes = builder()
        self.node_ids = sorted(self.nodes.keys())
        self.observation_size = len(self.node_ids) * STATE_FEATURES_PER_NODE
        self.n_actions = len(ActionType) * len(self.node_ids)
        self.step_count = 0
        self.done = False
        return self._get_obs()

    def step(self, action: int) -> tuple[list[float], float, bool, dict[str, Any]]:
        if self.done:
            return self._get_obs(), 0.0, True, {"reason": "already_done"}

        self.step_count += 1
        n_nodes = len(self.node_ids)
        action_type = ActionType(action // n_nodes)
        target_idx = action % n_nodes
        target_id = self.node_ids[target_idx]
        node = self.nodes[target_id]

        reward = -0.01  # step penalty
        info: dict[str, Any] = {"action": action_type.name, "target": target_id}

        if action_type == ActionType.SCAN_PORT:
            reward += self._scan_port(node)
        elif action_type == ActionType.SCAN_VULN:
            reward += self._scan_vuln(node)
        elif action_type == ActionType.EXPLOIT_KNOWN:
            reward += self._exploit(node)
        elif action_type == ActionType.BRUTE_FORCE:
            reward += self._brute_force(node)
        elif action_type == ActionType.PIVOT:
            reward += self._pivot(node)
        elif action_type == ActionType.ESCALATE:
            reward += self._escalate(node)
        elif action_type == ActionType.EXFILTRATE:
            reward += self._exfiltrate(node, info)

        if self.step_count >= self.max_steps:
            self.done = True
            info["reason"] = "max_steps"

        return self._get_obs(), reward, self.done, info

    # --- Action implementations ---

    def _scan_port(self, node: NodeState) -> float:
        if not node.discovered:
            return -0.1  # can't scan undiscovered
        return 0.05 if node.services else 0.0

    def _scan_vuln(self, node: NodeState) -> float:
        if not node.discovered:
            return -0.1
        return 0.1 * len(node.vulns)

    def _exploit(self, node: NodeState) -> float:
        if not node.discovered or node.owned:
            return -0.5 if not node.discovered else 0.0
        if node.vulns:
            node.owned = True
            node.privilege = max(node.privilege, 1)
            return 1.0
        return -0.5  # failed exploit

    def _brute_force(self, node: NodeState) -> float:
        if not node.discovered or node.owned:
            return 0.0
        if node.has_credentials or "ssh" in node.services:
            node.owned = True
            node.privilege = max(node.privilege, 1)
            return 0.8
        return -0.3

    def _pivot(self, node: NodeState) -> float:
        if not node.owned:
            return -0.2
        reward = 0.0
        for nid in node.neighbours:
            neighbour = self.nodes[nid]
            if not neighbour.discovered:
                neighbour.discovered = True
                reward += 0.3
        return reward

    def _escalate(self, node: NodeState) -> float:
        if not node.owned:
            return -0.2
        if node.privilege < 2:
            node.privilege = 2
            return 0.5
        return 0.0

    def _exfiltrate(self, node: NodeState, info: dict) -> float:
        if not node.owned or node.privilege < 1:
            return -0.2
        if node.is_crown_jewel:
            self.done = True
            info["reason"] = "crown_jewel"
            return 5.0
        return 0.1

    # --- Helpers ---

    def _get_obs(self) -> list[float]:
        obs: list[float] = []
        for nid in self.node_ids:
            obs.extend(self.nodes[nid].to_vector())
        return obs

    def get_valid_actions(self) -> list[int]:
        """Return action indices that are at least somewhat sensible."""
        valid = []
        n_nodes = len(self.node_ids)
        for i, nid in enumerate(self.node_ids):
            node = self.nodes[nid]
            if node.discovered:
                for at in ActionType:
                    valid.append(at * n_nodes + i)
        return valid or list(range(self.n_actions))
