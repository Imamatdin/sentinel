"""
NumPy-only DQN agent — no PyTorch dependency.

Two-layer MLP Q-network, experience replay, target network soft-update.
"""

from __future__ import annotations

import random
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class Transition:
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool


class QNetwork:
    """Two-layer ReLU MLP implemented in pure NumPy."""

    def __init__(self, input_size: int, hidden_size: int, output_size: int):
        scale1 = np.sqrt(2.0 / input_size)
        scale2 = np.sqrt(2.0 / hidden_size)
        self.w1 = np.random.randn(input_size, hidden_size).astype(np.float32) * scale1
        self.b1 = np.zeros(hidden_size, dtype=np.float32)
        self.w2 = np.random.randn(hidden_size, output_size).astype(np.float32) * scale2
        self.b2 = np.zeros(output_size, dtype=np.float32)

    def forward(self, x: np.ndarray) -> np.ndarray:
        h = np.maximum(0, x @ self.w1 + self.b1)  # ReLU
        return h @ self.w2 + self.b2

    def copy_from(self, other: QNetwork):
        self.w1 = other.w1.copy()
        self.b1 = other.b1.copy()
        self.w2 = other.w2.copy()
        self.b2 = other.b2.copy()

    def save(self, path: Path):
        np.savez(path, w1=self.w1, b1=self.b1, w2=self.w2, b2=self.b2)

    def load(self, path: Path):
        data = np.load(path)
        self.w1 = data["w1"]
        self.b1 = data["b1"]
        self.w2 = data["w2"]
        self.b2 = data["b2"]


class DQNAgent:
    """DQN with experience replay and target network."""

    def __init__(
        self,
        state_size: int,
        action_size: int,
        hidden_size: int = 64,
        lr: float = 0.001,
        gamma: float = 0.99,
        epsilon: float = 1.0,
        epsilon_min: float = 0.05,
        epsilon_decay: float = 0.995,
        buffer_size: int = 10000,
        batch_size: int = 32,
        target_update_freq: int = 100,
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.lr = lr
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.target_update_freq = target_update_freq

        self.q_net = QNetwork(state_size, hidden_size, action_size)
        self.target_net = QNetwork(state_size, hidden_size, action_size)
        self.target_net.copy_from(self.q_net)

        self.replay_buffer: deque[Transition] = deque(maxlen=buffer_size)
        self.train_steps = 0

    def select_action(self, state: list[float] | np.ndarray,
                      valid_actions: list[int] | None = None) -> int:
        if random.random() < self.epsilon:
            if valid_actions:
                return random.choice(valid_actions)
            return random.randint(0, self.action_size - 1)

        s = np.array(state, dtype=np.float32).reshape(1, -1)
        q_values = self.q_net.forward(s)[0]

        if valid_actions:
            mask = np.full(self.action_size, -1e9)
            for a in valid_actions:
                mask[a] = q_values[a]
            return int(np.argmax(mask))
        return int(np.argmax(q_values))

    def store(self, state, action: int, reward: float, next_state, done: bool):
        self.replay_buffer.append(Transition(
            state=np.array(state, dtype=np.float32),
            action=action,
            reward=reward,
            next_state=np.array(next_state, dtype=np.float32),
            done=done,
        ))

    def train_step(self) -> float:
        """One gradient step. Returns loss (MSE)."""
        if len(self.replay_buffer) < self.batch_size:
            return 0.0

        batch = random.sample(list(self.replay_buffer), self.batch_size)
        states = np.array([t.state for t in batch])
        actions = np.array([t.action for t in batch])
        rewards = np.array([t.reward for t in batch])
        next_states = np.array([t.next_state for t in batch])
        dones = np.array([t.done for t in batch], dtype=np.float32)

        # Current Q
        q_all = self.q_net.forward(states)
        q_current = q_all[np.arange(self.batch_size), actions]

        # Target Q
        q_next = self.target_net.forward(next_states)
        q_target = rewards + self.gamma * np.max(q_next, axis=1) * (1 - dones)

        # MSE gradient
        error = q_current - q_target
        loss = float(np.mean(error ** 2))

        # Backprop through 2-layer network (manual)
        # Forward pass cached values
        h1 = np.maximum(0, states @ self.q_net.w1 + self.q_net.b1)

        # dL/dQ for selected actions only
        dq = np.zeros_like(q_all)
        dq[np.arange(self.batch_size), actions] = 2 * error / self.batch_size

        # Layer 2
        dw2 = h1.T @ dq
        db2 = np.sum(dq, axis=0)

        # Layer 1
        dh1 = dq @ self.q_net.w2.T
        dh1[h1 <= 0] = 0  # ReLU derivative
        dw1 = states.T @ dh1
        db1 = np.sum(dh1, axis=0)

        # SGD update
        self.q_net.w2 -= self.lr * dw2
        self.q_net.b2 -= self.lr * db2
        self.q_net.w1 -= self.lr * dw1
        self.q_net.b1 -= self.lr * db1

        self.train_steps += 1
        if self.train_steps % self.target_update_freq == 0:
            self.target_net.copy_from(self.q_net)

        # Epsilon decay
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)

        return loss

    def save(self, path: str | Path):
        self.q_net.save(Path(path))

    def load(self, path: str | Path):
        p = Path(path)
        self.q_net.load(p)
        self.target_net.copy_from(self.q_net)
