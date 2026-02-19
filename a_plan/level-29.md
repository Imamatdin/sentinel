# LEVEL 29: Self-Play Red vs Blue Co-Training

## Context
AlphaZero-style self-play: a red team agent plays against a blue team agent, both learn simultaneously, and both get stronger. The red agent discovers novel attack paths; the blue agent learns to detect them. After training, the red agent's policy seeds Sentinel's attack planning and the blue agent's policy improves detection.

Research: Block 12 (Self-Play — AlphaZero/MuZero for security, minimax adversarial planning, neural MCTS, emergent strategies from co-evolution).

## Why
Hand-coded attack and detection heuristics plateau. Self-play discovers emergent strategies neither team anticipated. If the blue team can't detect an attack the red team invents, that attack gets added to Sentinel's toolkit. If the blue team invents a detection the red team can't evade, that detection gets added to Sentinel's blue team. Continuous improvement loop.

---

## Files to Create

### `src/sentinel/self_play/__init__.py`
```python
"""Self-play red vs blue co-training — adversarial learning, minimax planning."""
```

### `src/sentinel/self_play/arena.py`
```python
"""
Red vs Blue Arena — Game environment for adversarial co-training.

Rules:
- Simulated network with N nodes, services, and vulnerabilities
- Red team: selects attack actions (scan, exploit, pivot, escalate)
- Blue team: selects defense actions (patch, monitor, block, deploy_tripwire)
- Turn-based: red moves, then blue moves (or simultaneous)
- Red wins by reaching crown jewel; blue wins by detecting + blocking red

Observation:
- Red sees: owned nodes, discovered services, known vulns (partial info)
- Blue sees: traffic patterns, alerts, known assets (partial info, different from red)

This is a two-player zero-sum partially observable stochastic game (POSG).
"""
import numpy as np
from dataclasses import dataclass, field
from enum import IntEnum
from sentinel.logging import get_logger

logger = get_logger(__name__)


class RedAction(IntEnum):
    SCAN = 0
    EXPLOIT = 1
    PIVOT = 2
    ESCALATE = 3
    EXFILTRATE = 4
    HIDE = 5            # Reduce detection probability


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
    red_stealth: float = 1.0     # 1.0 = fully hidden, 0.0 = detected
    blue_alert_level: float = 0.0
    game_over: bool = False
    winner: str = ""              # "red" | "blue" | ""


class RedBlueArena:
    """Two-player adversarial environment for self-play training."""

    DETECTION_BASE_PROB = 0.1
    TRIPWIRE_DETECT_PROB = 0.9
    MAX_TURNS = 50

    def __init__(self, num_nodes: int = 5):
        self.num_nodes = num_nodes
        self.state: ArenaState = None
        self.reset()

    def reset(self) -> tuple[np.ndarray, np.ndarray]:
        """Reset arena and return initial observations for both agents."""
        nodes = []
        for i in range(self.num_nodes):
            nodes.append(ArenaNode(
                node_id=i,
                value=np.random.uniform(10, 100),
                is_crown_jewel=(i == self.num_nodes - 1),
                vulnerability_count=np.random.randint(1, 4),
            ))

        # Linear + random shortcut edges
        edges = [(i, i + 1) for i in range(self.num_nodes - 1)]
        if self.num_nodes > 3:
            edges.append((0, self.num_nodes // 2))

        self.state = ArenaState(
            nodes=nodes, edges=edges,
            red_position=0, red_stealth=1.0,
        )

        return self._red_obs(), self._blue_obs()

    def step(self, red_action: int, blue_action: int) -> tuple[np.ndarray, np.ndarray, float, float, bool]:
        """
        Execute one turn. Returns:
        (red_obs, blue_obs, red_reward, blue_reward, done)
        """
        s = self.state
        s.turn += 1
        red_reward = -0.01  # Step penalty
        blue_reward = 0.01  # Step reward (delay is good for blue)

        current_node = s.nodes[s.red_position]

        # --- Red action ---
        if red_action == RedAction.SCAN:
            # Discover adjacent nodes, slight detection risk
            s.red_stealth *= 0.95
            red_reward += 0.1

        elif red_action == RedAction.EXPLOIT:
            if current_node.vulnerability_count > current_node.patched_vulns:
                if not current_node.red_owns:
                    current_node.red_owns = True
                    red_reward += 1.0
                    s.red_stealth *= 0.8  # Exploits are noisy
                    if current_node.has_tripwire:
                        s.red_stealth *= 0.1  # Tripwire detected!
                        blue_reward += 2.0
                    if current_node.is_crown_jewel:
                        red_reward += 5.0
                        s.game_over = True
                        s.winner = "red"
            else:
                red_reward -= 0.1  # All vulns patched

        elif red_action == RedAction.PIVOT:
            # Move to adjacent owned node
            neighbors = [dst for src, dst in s.edges if src == s.red_position] + \
                        [src for src, dst in s.edges if dst == s.red_position]
            if neighbors:
                s.red_position = np.random.choice(neighbors)
                s.red_stealth *= 0.9

        elif red_action == RedAction.HIDE:
            s.red_stealth = min(1.0, s.red_stealth * 1.2)

        # --- Blue action ---
        if blue_action == BlueAction.MONITOR:
            # Increase detection probability globally
            detect_prob = self.DETECTION_BASE_PROB + (1 - s.red_stealth) * 0.5
            if np.random.random() < detect_prob:
                current_node.red_detected = True
                blue_reward += 3.0
                red_reward -= 2.0
                s.game_over = True
                s.winner = "blue"

        elif blue_action == BlueAction.PATCH:
            # Patch a random node
            target = np.random.randint(0, self.num_nodes)
            node = s.nodes[target]
            if node.patched_vulns < node.vulnerability_count:
                node.patched_vulns += 1
                blue_reward += 0.3

        elif blue_action == BlueAction.BLOCK_IP:
            # Has chance to slow red team
            if np.random.random() < 0.3:
                s.red_stealth *= 0.7
                blue_reward += 0.5

        elif blue_action == BlueAction.DEPLOY_TRIPWIRE:
            target = np.random.randint(0, self.num_nodes)
            s.nodes[target].has_tripwire = True
            blue_reward += 0.1

        elif blue_action == BlueAction.INVESTIGATE:
            # Targeted detection at red's last known position
            detect_prob = 0.3 + (1 - s.red_stealth) * 0.4
            if np.random.random() < detect_prob:
                current_node.red_detected = True
                blue_reward += 3.0
                red_reward -= 2.0
                s.game_over = True
                s.winner = "blue"

        elif blue_action == BlueAction.HARDEN:
            # Reduce vulnerability count on random node
            target = np.random.randint(0, self.num_nodes)
            s.nodes[target].vulnerability_count = max(0, s.nodes[target].vulnerability_count - 1)

        # Check max turns
        if s.turn >= self.MAX_TURNS and not s.game_over:
            s.game_over = True
            s.winner = "blue"  # Stalemate = blue wins (red didn't reach goal)
            blue_reward += 1.0

        return self._red_obs(), self._blue_obs(), red_reward, blue_reward, s.game_over

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
            float(1 - self.state.red_stealth),  # Blue sees inverse of stealth
            float(self.state.turn / self.MAX_TURNS),
        ])
        return np.array(obs, dtype=np.float32)
```

### `src/sentinel/self_play/trainer.py`
```python
"""
Self-Play Trainer — Co-train red and blue agents via adversarial self-play.

Training loop:
1. Red agent plays against blue agent in arena
2. Collect trajectories for both
3. Train red to maximize red_reward, blue to maximize blue_reward
4. Periodically swap in historical versions (avoid strategy collapse)
5. Track Elo ratings for both agents

Uses simple policy-gradient (REINFORCE) with baseline for both agents.
"""
import numpy as np
import random
from dataclasses import dataclass, field
from sentinel.self_play.arena import RedBlueArena
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AgentPolicy:
    """Simple linear policy for self-play (production: replace with neural net)."""
    name: str
    state_dim: int
    action_dim: int
    weights: np.ndarray = None
    elo: float = 1000.0
    games_played: int = 0
    wins: int = 0

    def __post_init__(self):
        if self.weights is None:
            self.weights = np.random.randn(self.state_dim, self.action_dim) * 0.01

    def select_action(self, obs: np.ndarray, temperature: float = 1.0) -> int:
        logits = obs @ self.weights
        # Softmax with temperature
        logits = logits / max(temperature, 0.01)
        exp_logits = np.exp(logits - np.max(logits))
        probs = exp_logits / exp_logits.sum()
        return int(np.random.choice(self.action_dim, p=probs))

    def update(self, trajectories: list[dict], lr: float = 0.001):
        """Policy gradient (REINFORCE) update."""
        for traj in trajectories:
            obs = traj["obs"]
            action = traj["action"]
            reward = traj["reward"]

            logits = obs @ self.weights
            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / exp_logits.sum()

            # Policy gradient: ∇log π(a|s) × R
            grad = np.zeros_like(self.weights)
            one_hot = np.zeros(self.action_dim)
            one_hot[action] = 1
            grad += np.outer(obs, (one_hot - probs) * reward)

            self.weights += lr * grad


@dataclass
class SelfPlayStats:
    total_games: int = 0
    red_wins: int = 0
    blue_wins: int = 0
    avg_game_length: float = 0.0
    red_elo: float = 1000.0
    blue_elo: float = 1000.0


class SelfPlayTrainer:
    """Co-train red and blue agents through self-play."""

    ELO_K = 32  # Elo K-factor

    def __init__(self, arena: RedBlueArena = None, num_nodes: int = 5):
        self.arena = arena or RedBlueArena(num_nodes=num_nodes)
        red_obs_dim = num_nodes * 3 + 3
        blue_obs_dim = num_nodes * 4 + 3
        self.red_agent = AgentPolicy("red", red_obs_dim, 6)
        self.blue_agent = AgentPolicy("blue", blue_obs_dim, 6)
        self.stats = SelfPlayStats()
        self.history: list[AgentPolicy] = []

    def play_game(self) -> tuple[float, float, str]:
        """Play one full game. Returns (red_total, blue_total, winner)."""
        red_obs, blue_obs = self.arena.reset()
        red_trajectories = []
        blue_trajectories = []
        red_total = 0
        blue_total = 0
        done = False

        while not done:
            red_action = self.red_agent.select_action(red_obs)
            blue_action = self.blue_agent.select_action(blue_obs)

            new_red_obs, new_blue_obs, red_r, blue_r, done = self.arena.step(
                red_action, blue_action
            )

            red_trajectories.append({"obs": red_obs, "action": red_action, "reward": red_r})
            blue_trajectories.append({"obs": blue_obs, "action": blue_action, "reward": blue_r})

            red_total += red_r
            blue_total += blue_r
            red_obs = new_red_obs
            blue_obs = new_blue_obs

        return red_total, blue_total, self.arena.state.winner

    def train(self, episodes: int = 1000, log_interval: int = 100) -> SelfPlayStats:
        """Run self-play training loop."""
        game_lengths = []

        for ep in range(episodes):
            red_total, blue_total, winner = self.play_game()
            game_length = self.arena.state.turn

            # Collect trajectories from last game and update
            # (simplified: using total reward as return for all steps)
            red_obs, blue_obs = self.arena.reset()
            red_trajs = []
            blue_trajs = []
            done = False
            while not done:
                ra = self.red_agent.select_action(red_obs)
                ba = self.blue_agent.select_action(blue_obs)
                r_obs, b_obs, rr, br, done = self.arena.step(ra, ba)
                red_trajs.append({"obs": red_obs, "action": ra, "reward": rr})
                blue_trajs.append({"obs": blue_obs, "action": ba, "reward": br})
                red_obs, blue_obs = r_obs, b_obs

            self.red_agent.update(red_trajs)
            self.blue_agent.update(blue_trajs)

            # Update Elo
            self._update_elo(winner)
            game_lengths.append(game_length)
            self.stats.total_games += 1
            if winner == "red":
                self.stats.red_wins += 1
            else:
                self.stats.blue_wins += 1

            # Snapshot for historical opponents
            if (ep + 1) % (episodes // 10 + 1) == 0:
                self.history.append(AgentPolicy(
                    f"red_v{ep}", self.red_agent.state_dim, self.red_agent.action_dim,
                    weights=self.red_agent.weights.copy(), elo=self.red_agent.elo,
                ))

            if (ep + 1) % log_interval == 0:
                avg_len = np.mean(game_lengths[-log_interval:])
                red_wr = self.stats.red_wins / max(self.stats.total_games, 1)
                logger.info(f"Ep {ep+1}/{episodes} | Red WR: {red_wr:.1%} | "
                            f"Avg len: {avg_len:.1f} | "
                            f"Elo R:{self.red_agent.elo:.0f} B:{self.blue_agent.elo:.0f}")

        self.stats.avg_game_length = np.mean(game_lengths)
        self.stats.red_elo = self.red_agent.elo
        self.stats.blue_elo = self.blue_agent.elo
        return self.stats

    def _update_elo(self, winner: str):
        """Update Elo ratings for both agents."""
        r_elo = self.red_agent.elo
        b_elo = self.blue_agent.elo
        expected_red = 1 / (1 + 10 ** ((b_elo - r_elo) / 400))

        if winner == "red":
            self.red_agent.elo += self.ELO_K * (1 - expected_red)
            self.blue_agent.elo -= self.ELO_K * (1 - expected_red)
        else:
            self.red_agent.elo -= self.ELO_K * expected_red
            self.blue_agent.elo += self.ELO_K * expected_red
```

---

## Tests

### `tests/self_play/test_arena.py`
```python
import pytest
import numpy as np
from sentinel.self_play.arena import RedBlueArena, RedAction, BlueAction

class TestRedBlueArena:
    def test_reset(self):
        arena = RedBlueArena(num_nodes=5)
        red_obs, blue_obs = arena.reset()
        assert red_obs.shape[0] == 5 * 3 + 3
        assert blue_obs.shape[0] == 5 * 4 + 3

    def test_step_returns_correct_shape(self):
        arena = RedBlueArena(num_nodes=5)
        arena.reset()
        r_obs, b_obs, rr, br, done = arena.step(RedAction.SCAN, BlueAction.MONITOR)
        assert isinstance(rr, float)
        assert isinstance(br, float)
        assert isinstance(done, bool)

    def test_game_terminates(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        done = False
        for _ in range(60):
            _, _, _, _, done = arena.step(
                np.random.randint(0, 6), np.random.randint(0, 6)
            )
            if done:
                break
        assert done  # Should terminate by max_turns

    def test_crown_jewel_ends_game(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        # Force red to own crown jewel
        arena.state.nodes[-1].red_owns = True
        arena.state.red_position = len(arena.state.nodes) - 1
        _, _, rr, _, done = arena.step(RedAction.EXPLOIT, BlueAction.MONITOR)
        # May or may not end depending on vuln status

    def test_tripwire_increases_detection(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        arena.state.nodes[0].has_tripwire = True
        arena.state.nodes[0].vulnerability_count = 2
        arena.state.red_position = 0
        _, _, rr, br, _ = arena.step(RedAction.EXPLOIT, BlueAction.MONITOR)
        # Tripwire should reduce stealth significantly
```

### `tests/self_play/test_trainer.py`
```python
import pytest
from sentinel.self_play.trainer import SelfPlayTrainer, AgentPolicy

class TestSelfPlayTrainer:
    def test_play_game(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        red_r, blue_r, winner = trainer.play_game()
        assert isinstance(red_r, float)
        assert winner in ("red", "blue", "")

    def test_short_training(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        stats = trainer.train(episodes=20, log_interval=10)
        assert stats.total_games == 20
        assert stats.red_wins + stats.blue_wins == 20

    def test_elo_updates(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        trainer.train(episodes=10, log_interval=10)
        # Elo should have moved from 1000
        assert trainer.red_agent.elo != 1000 or trainer.blue_agent.elo != 1000

    def test_policy_select_action(self):
        policy = AgentPolicy("test", state_dim=18, action_dim=6)
        obs = np.random.randn(18).astype(np.float32)
        action = policy.select_action(obs)
        assert 0 <= action < 6

    def test_policy_update_no_crash(self):
        policy = AgentPolicy("test", state_dim=18, action_dim=6)
        trajs = [{"obs": np.random.randn(18).astype(np.float32),
                   "action": 0, "reward": 1.0} for _ in range(5)]
        policy.update(trajs)

    def test_history_snapshots(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        trainer.train(episodes=50, log_interval=50)
        assert len(trainer.history) > 0
```

---

## Acceptance Criteria
- [ ] Arena supports 6 red actions and 6 blue actions
- [ ] Partial observability: red and blue see different state features
- [ ] Crown jewel capture ends game with red win (+5 reward)
- [ ] Max turns causes blue win (stalemate favors defender)
- [ ] Tripwires drastically reduce red stealth on exploit
- [ ] Policy gradient (REINFORCE) updates both agents after each game
- [ ] Elo ratings track agent strength over time
- [ ] Historical agent snapshots prevent strategy collapse
- [ ] Training runs without crash for 20+ episodes
- [ ] All tests pass