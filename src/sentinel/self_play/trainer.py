"""
Self-Play Trainer -- Co-train red and blue agents via adversarial self-play.

Training loop:
1. Red agent plays against blue agent in arena
2. Collect trajectories for both
3. Train red to maximize red_reward, blue to maximize blue_reward
4. Periodically snapshot historical versions to prevent strategy collapse
5. Track Elo ratings for both agents

Uses simple policy-gradient (REINFORCE) with baseline for both agents.
"""

import numpy as np
from dataclasses import dataclass, field

from sentinel.core import get_logger
from sentinel.self_play.arena import RedBlueArena

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

            one_hot = np.zeros(self.action_dim)
            one_hot[action] = 1
            grad = np.outer(obs, (one_hot - probs) * reward)
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

    ELO_K = 32

    def __init__(self, arena: RedBlueArena | None = None, num_nodes: int = 5):
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
        red_total = 0.0
        blue_total = 0.0
        done = False

        while not done:
            red_action = self.red_agent.select_action(red_obs)
            blue_action = self.blue_agent.select_action(blue_obs)
            new_red_obs, new_blue_obs, red_r, blue_r, done = self.arena.step(
                red_action, blue_action,
            )
            red_total += red_r
            blue_total += blue_r
            red_obs = new_red_obs
            blue_obs = new_blue_obs

        return red_total, blue_total, self.arena.state.winner

    def train(self, episodes: int = 1000, log_interval: int = 100) -> SelfPlayStats:
        """Run self-play training loop."""
        game_lengths = []

        for ep in range(episodes):
            # Play and collect trajectories
            red_obs, blue_obs = self.arena.reset()
            red_trajs: list[dict] = []
            blue_trajs: list[dict] = []
            done = False

            while not done:
                ra = self.red_agent.select_action(red_obs)
                ba = self.blue_agent.select_action(blue_obs)
                r_obs, b_obs, rr, br, done = self.arena.step(ra, ba)
                red_trajs.append({"obs": red_obs, "action": ra, "reward": rr})
                blue_trajs.append({"obs": blue_obs, "action": ba, "reward": br})
                red_obs, blue_obs = r_obs, b_obs

            winner = self.arena.state.winner
            game_length = self.arena.state.turn

            # Update policies
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
            snapshot_interval = max(episodes // 10, 1)
            if (ep + 1) % snapshot_interval == 0:
                self.history.append(AgentPolicy(
                    f"red_v{ep}",
                    self.red_agent.state_dim,
                    self.red_agent.action_dim,
                    weights=self.red_agent.weights.copy(),
                    elo=self.red_agent.elo,
                ))

            if log_interval > 0 and (ep + 1) % log_interval == 0:
                avg_len = float(np.mean(game_lengths[-log_interval:]))
                red_wr = self.stats.red_wins / max(self.stats.total_games, 1)
                logger.info(
                    f"Ep {ep + 1}/{episodes} | Red WR: {red_wr:.1%} | "
                    f"Avg len: {avg_len:.1f} | "
                    f"Elo R:{self.red_agent.elo:.0f} B:{self.blue_agent.elo:.0f}"
                )

        self.stats.avg_game_length = float(np.mean(game_lengths)) if game_lengths else 0
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
