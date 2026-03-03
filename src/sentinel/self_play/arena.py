"""
Red vs Blue Arena -- Game environment for adversarial co-training.

Rules:
- Simulated network with N nodes, services, and vulnerabilities
- Red team: selects attack actions (scan, exploit, pivot, escalate, exfiltrate, hide)
- Blue team: selects defense actions (monitor, patch, block, deploy_tripwire, investigate, harden)
- Simultaneous moves each turn
- Red wins by reaching crown jewel; blue wins by detecting red or stalemate

This is a two-player zero-sum partially observable stochastic game (POSG).
"""

import numpy as np
from dataclasses import dataclass, field
from enum import IntEnum

from sentinel.core import get_logger

logger = get_logger(__name__)


class RedAction(IntEnum):
    SCAN = 0
    EXPLOIT = 1
    PIVOT = 2
    ESCALATE = 3
    EXFILTRATE = 4
    HIDE = 5


class BlueAction(IntEnum):
    MONITOR = 0
    PATCH = 1
    BLOCK_IP = 2
    DEPLOY_TRIPWIRE = 3
    INVESTIGATE = 4
    HARDEN = 5


@dataclass
class ArenaNode:
    node_id: int
    value: float
    is_crown_jewel: bool = False
    vulnerability_count: int = 2
    patched_vulns: int = 0
    has_tripwire: bool = False
    is_monitored: bool = False
    red_owns: bool = False
    red_detected: bool = False


@dataclass
class ArenaState:
    nodes: list[ArenaNode]
    edges: list[tuple[int, int]]
    turn: int = 0
    red_position: int = 0
    red_stealth: float = 1.0
    blue_alert_level: float = 0.0
    game_over: bool = False
    winner: str = ""


class RedBlueArena:
    """Two-player adversarial environment for self-play training."""

    DETECTION_BASE_PROB = 0.1
    TRIPWIRE_DETECT_PROB = 0.9
    MAX_TURNS = 50

    def __init__(self, num_nodes: int = 5):
        self.num_nodes = num_nodes
        self.state: ArenaState | None = None
        self.reset()

    def reset(self) -> tuple[np.ndarray, np.ndarray]:
        """Reset arena and return initial observations for both agents."""
        nodes = []
        for i in range(self.num_nodes):
            nodes.append(ArenaNode(
                node_id=i,
                value=float(np.random.uniform(10, 100)),
                is_crown_jewel=(i == self.num_nodes - 1),
                vulnerability_count=int(np.random.randint(1, 4)),
            ))

        edges = [(i, i + 1) for i in range(self.num_nodes - 1)]
        if self.num_nodes > 3:
            edges.append((0, self.num_nodes // 2))

        self.state = ArenaState(
            nodes=nodes,
            edges=edges,
            red_position=0,
            red_stealth=1.0,
        )

        return self._red_obs(), self._blue_obs()

    def step(
        self, red_action: int, blue_action: int
    ) -> tuple[np.ndarray, np.ndarray, float, float, bool]:
        """Execute one turn. Returns (red_obs, blue_obs, red_reward, blue_reward, done)."""
        s = self.state
        s.turn += 1
        red_reward = -0.01
        blue_reward = 0.01

        current_node = s.nodes[s.red_position]

        # --- Red action ---
        if red_action == RedAction.SCAN:
            s.red_stealth *= 0.95
            red_reward += 0.1

        elif red_action == RedAction.EXPLOIT:
            if current_node.vulnerability_count > current_node.patched_vulns:
                if not current_node.red_owns:
                    current_node.red_owns = True
                    red_reward += 1.0
                    s.red_stealth *= 0.8
                    if current_node.has_tripwire:
                        s.red_stealth *= 0.1
                        blue_reward += 2.0
                    if current_node.is_crown_jewel:
                        red_reward += 5.0
                        s.game_over = True
                        s.winner = "red"
            else:
                red_reward -= 0.1

        elif red_action == RedAction.PIVOT:
            neighbors = (
                [dst for src, dst in s.edges if src == s.red_position]
                + [src for src, dst in s.edges if dst == s.red_position]
            )
            if neighbors:
                s.red_position = int(np.random.choice(neighbors))
                s.red_stealth *= 0.9

        elif red_action == RedAction.ESCALATE:
            if current_node.red_owns:
                red_reward += 0.3
                s.red_stealth *= 0.85

        elif red_action == RedAction.EXFILTRATE:
            if current_node.red_owns:
                red_reward += 0.5
                s.red_stealth *= 0.7

        elif red_action == RedAction.HIDE:
            s.red_stealth = min(1.0, s.red_stealth * 1.2)

        # --- Blue action ---
        if blue_action == BlueAction.MONITOR:
            detect_prob = self.DETECTION_BASE_PROB + (1 - s.red_stealth) * 0.5
            if np.random.random() < detect_prob:
                current_node.red_detected = True
                blue_reward += 3.0
                red_reward -= 2.0
                s.game_over = True
                s.winner = "blue"

        elif blue_action == BlueAction.PATCH:
            target = int(np.random.randint(0, self.num_nodes))
            node = s.nodes[target]
            if node.patched_vulns < node.vulnerability_count:
                node.patched_vulns += 1
                blue_reward += 0.3

        elif blue_action == BlueAction.BLOCK_IP:
            if np.random.random() < 0.3:
                s.red_stealth *= 0.7
                blue_reward += 0.5

        elif blue_action == BlueAction.DEPLOY_TRIPWIRE:
            target = int(np.random.randint(0, self.num_nodes))
            s.nodes[target].has_tripwire = True
            blue_reward += 0.1

        elif blue_action == BlueAction.INVESTIGATE:
            detect_prob = 0.3 + (1 - s.red_stealth) * 0.4
            if np.random.random() < detect_prob:
                current_node.red_detected = True
                blue_reward += 3.0
                red_reward -= 2.0
                s.game_over = True
                s.winner = "blue"

        elif blue_action == BlueAction.HARDEN:
            target = int(np.random.randint(0, self.num_nodes))
            s.nodes[target].vulnerability_count = max(0, s.nodes[target].vulnerability_count - 1)

        # Check max turns
        if s.turn >= self.MAX_TURNS and not s.game_over:
            s.game_over = True
            s.winner = "blue"
            blue_reward += 1.0

        return self._red_obs(), self._blue_obs(), float(red_reward), float(blue_reward), s.game_over

    def _red_obs(self) -> np.ndarray:
        """Red team's partial observation."""
        obs = []
        for node in self.state.nodes:
            obs.extend([
                float(node.red_owns),
                float(node.vulnerability_count - node.patched_vulns),
                float(node.is_crown_jewel),
            ])
        obs.extend([
            float(self.state.red_position),
            float(self.state.red_stealth),
            float(self.state.turn / self.MAX_TURNS),
        ])
        return np.array(obs, dtype=np.float32)

    def _blue_obs(self) -> np.ndarray:
        """Blue team's partial observation."""
        obs = []
        for node in self.state.nodes:
            obs.extend([
                float(node.has_tripwire),
                float(node.is_monitored),
                float(node.patched_vulns),
                float(node.red_detected),
            ])
        obs.extend([
            float(self.state.blue_alert_level),
            float(1 - self.state.red_stealth),
            float(self.state.turn / self.MAX_TURNS),
        ])
        return np.array(obs, dtype=np.float32)
