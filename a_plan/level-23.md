# LEVEL 23: Reinforcement Learning Pentesting Agent

## Context
Train an RL agent to learn optimal attack strategies through interaction with simulated network environments. Instead of hand-coded heuristics, the agent discovers effective attack paths via reward signals from successful exploitation.

Research: Block 12 (RL Pentesting — CyberBattleSim, PenGym/NASimEmu benchmarks, DQN/PPO, curriculum learning from toy→real, reward shaping: -0.01/step + 1.0/exploit + 5.0/crown_jewel).

## Why
Current Sentinel uses rule-based hypothesis ranking. RL discovers non-obvious attack paths that humans wouldn't try. CyberBattleSim showed RL agents finding shorter attack chains than scripted strategies. Combined with Thompson Sampling (L21), RL handles novel environments while Bayesian handles known stacks.

---

## Files to Create

### `src/sentinel/rl/__init__.py`
```python
"""Reinforcement learning pentesting agent — environment simulation, DQN/PPO training."""
```

### `src/sentinel/rl/environment.py`
```python
"""
Pentest Environment — Gymnasium-compatible environment for RL agent training.

State: Current knowledge of the network (discovered hosts, ports, vulns, owned credentials)
Actions: Scan, exploit, pivot, escalate, exfiltrate
Rewards: -0.01 per step (time pressure), +1.0 per new exploit, +5.0 for crown jewel access
Episodes: End when crown jewel reached, all actions exhausted, or max steps hit.

Based on CyberBattleSim/PenGym action space design.
"""
import gymnasium as gym
import numpy as np
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional
from sentinel.logging import get_logger

logger = get_logger(__name__)


class ActionType(IntEnum):
    SCAN_PORT = 0
    SCAN_VULN = 1
    EXPLOIT_KNOWN = 2
    BRUTE_FORCE = 3
    PIVOT = 4
    ESCALATE = 5
    EXFILTRATE = 6


@dataclass
class NetworkNode:
    node_id: int
    ip: str
    services: list[dict] = field(default_factory=list)  # [{port, service, version, vulns}]
    is_owned: bool = False
    is_crown_jewel: bool = False
    credentials: list[str] = field(default_factory=list)
    os: str = "linux"
    privilege_level: int = 0  # 0=none, 1=user, 2=root


@dataclass
class NetworkTopology:
    """Defines a simulated network for training."""
    nodes: list[NetworkNode]
    edges: list[tuple[int, int]]  # (src, dst) connectivity
    name: str = "default"


def create_small_network() -> NetworkTopology:
    """3-node training network: entry → app → database (crown jewel)."""
    return NetworkTopology(
        name="small_office",
        nodes=[
            NetworkNode(0, "10.0.0.1", services=[
                {"port": 22, "service": "ssh", "version": "8.4", "vulns": []},
                {"port": 80, "service": "http", "version": "nginx/1.21", "vulns": ["CVE-2021-23017"]},
            ]),
            NetworkNode(1, "10.0.0.2", services=[
                {"port": 8080, "service": "http", "version": "express/4.17", "vulns": ["sqli_login"]},
                {"port": 22, "service": "ssh", "version": "8.4", "vulns": []},
            ], credentials=["admin:admin123"]),
            NetworkNode(2, "10.0.0.3", services=[
                {"port": 5432, "service": "postgresql", "version": "14.2", "vulns": []},
                {"port": 22, "service": "ssh", "version": "8.4", "vulns": []},
            ], is_crown_jewel=True),
        ],
        edges=[(0, 1), (1, 2)],  # Linear path
    )


def create_medium_network() -> NetworkTopology:
    """6-node network with branches and dead ends for curriculum learning."""
    return NetworkTopology(
        name="medium_corp",
        nodes=[
            NetworkNode(0, "10.0.0.1", services=[
                {"port": 80, "service": "http", "version": "apache/2.4", "vulns": ["CVE-2021-41773"]},
            ]),
            NetworkNode(1, "10.0.1.1", services=[
                {"port": 8080, "service": "http", "version": "tomcat/9.0", "vulns": ["CVE-2020-1938"]},
                {"port": 22, "service": "ssh", "version": "8.4", "vulns": []},
            ]),
            NetworkNode(2, "10.0.1.2", services=[
                {"port": 445, "service": "smb", "version": "3.0", "vulns": []},
            ]),  # Dead end
            NetworkNode(3, "10.0.2.1", services=[
                {"port": 3306, "service": "mysql", "version": "8.0", "vulns": ["weak_password"]},
            ], credentials=["root:toor"]),
            NetworkNode(4, "10.0.2.2", services=[
                {"port": 22, "service": "ssh", "version": "7.4", "vulns": ["CVE-2018-15473"]},
            ]),
            NetworkNode(5, "10.0.3.1", services=[
                {"port": 5432, "service": "postgresql", "version": "14.2", "vulns": []},
            ], is_crown_jewel=True),
        ],
        edges=[(0, 1), (0, 2), (1, 3), (1, 4), (3, 5), (4, 5)],
    )


class PentestEnv(gym.Env):
    """
    Gymnasium environment for RL pentesting agent training.
    
    Observation space: Flattened vector of node states
    Action space: (action_type, target_node, target_service)
    """
    
    metadata = {"render_modes": ["human"]}
    
    # Reward shaping
    STEP_PENALTY = -0.01
    EXPLOIT_REWARD = 1.0
    CROWN_JEWEL_REWARD = 5.0
    CREDENTIAL_REWARD = 0.5
    NEW_HOST_REWARD = 0.3
    INVALID_ACTION_PENALTY = -0.1
    
    def __init__(self, topology: NetworkTopology = None, max_steps: int = 100):
        super().__init__()
        self.topology = topology or create_small_network()
        self.max_steps = max_steps
        
        n_nodes = len(self.topology.nodes)
        n_actions = len(ActionType)
        max_services = 5
        
        # Observation: per-node [discovered, owned, privilege_level, n_services, n_vulns, has_creds]
        self.observation_space = gym.spaces.Box(
            low=0, high=10, shape=(n_nodes * 6,), dtype=np.float32
        )
        
        # Action: (action_type, target_node, target_service_index)
        self.action_space = gym.spaces.MultiDiscrete([n_actions, n_nodes, max_services])
        
        self.reset()
    
    def reset(self, seed=None, options=None):
        super().reset(seed=seed)
        self.step_count = 0
        self.discovered = {0}  # Start with first node discovered
        self.owned = set()
        self.owned_creds = set()
        self.total_reward = 0
        
        # Reset node states
        for node in self.topology.nodes:
            node.is_owned = False
            node.privilege_level = 0
        
        return self._get_obs(), {}
    
    def step(self, action):
        action_type, target_node, target_svc = action
        self.step_count += 1
        reward = self.STEP_PENALTY
        info = {"action": ActionType(action_type).name, "target": target_node}
        
        node = self.topology.nodes[target_node] if target_node < len(self.topology.nodes) else None
        
        if node is None or target_node not in self.discovered:
            reward += self.INVALID_ACTION_PENALTY
        elif action_type == ActionType.SCAN_PORT:
            # Discover adjacent nodes
            for src, dst in self.topology.edges:
                if src == target_node and dst not in self.discovered:
                    self.discovered.add(dst)
                    reward += self.NEW_HOST_REWARD
                elif dst == target_node and src not in self.discovered:
                    self.discovered.add(src)
                    reward += self.NEW_HOST_REWARD
        
        elif action_type == ActionType.EXPLOIT_KNOWN:
            if target_svc < len(node.services):
                svc = node.services[target_svc]
                if svc["vulns"] and not node.is_owned:
                    node.is_owned = True
                    node.privilege_level = 1
                    self.owned.add(target_node)
                    reward += self.EXPLOIT_REWARD
                    
                    if node.credentials:
                        self.owned_creds.update(node.credentials)
                        reward += self.CREDENTIAL_REWARD
                    
                    if node.is_crown_jewel:
                        reward += self.CROWN_JEWEL_REWARD
        
        elif action_type == ActionType.BRUTE_FORCE:
            if target_svc < len(node.services):
                svc = node.services[target_svc]
                if svc["service"] == "ssh" and node.credentials:
                    if not node.is_owned:
                        node.is_owned = True
                        node.privilege_level = 2
                        self.owned.add(target_node)
                        reward += self.EXPLOIT_REWARD
        
        elif action_type == ActionType.PIVOT:
            # Use owned node to discover connected nodes
            if target_node in self.owned:
                for src, dst in self.topology.edges:
                    if src == target_node and dst not in self.discovered:
                        self.discovered.add(dst)
                        reward += self.NEW_HOST_REWARD
        
        # Check termination
        crown_reached = any(
            n.is_crown_jewel and n.is_owned for n in self.topology.nodes
        )
        truncated = self.step_count >= self.max_steps
        terminated = crown_reached
        
        self.total_reward += reward
        return self._get_obs(), reward, terminated, truncated, info
    
    def _get_obs(self):
        obs = []
        for i, node in enumerate(self.topology.nodes):
            obs.extend([
                float(i in self.discovered),
                float(node.is_owned),
                float(node.privilege_level),
                float(len(node.services)),
                float(sum(len(s["vulns"]) for s in node.services)),
                float(len(node.credentials) > 0),
            ])
        return np.array(obs, dtype=np.float32)
    
    def render(self):
        print(f"Step {self.step_count} | Discovered: {self.discovered} | Owned: {self.owned} | Reward: {self.total_reward:.2f}")
```

### `src/sentinel/rl/agent.py`
```python
"""
DQN Agent for pentest environment.

Architecture: Simple DQN with experience replay and target network.
For production: upgrade to PPO or SAC for better sample efficiency.

Curriculum learning: train on small_network → medium_network → real targets.
"""
import random
import numpy as np
from collections import deque
from dataclasses import dataclass
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Experience:
    state: np.ndarray
    action: tuple
    reward: float
    next_state: np.ndarray
    done: bool


class DQNAgent:
    """
    Deep Q-Network agent for pentesting.
    
    Uses a simple neural network to approximate Q(s,a).
    Falls back to NumPy-only implementation if PyTorch not available.
    """
    
    def __init__(
        self,
        state_dim: int,
        action_dims: list[int],
        learning_rate: float = 0.001,
        gamma: float = 0.99,
        epsilon: float = 1.0,
        epsilon_min: float = 0.05,
        epsilon_decay: float = 0.995,
        buffer_size: int = 10000,
        batch_size: int = 64,
    ):
        self.state_dim = state_dim
        self.action_dims = action_dims  # [n_action_types, n_nodes, n_services]
        self.total_actions = int(np.prod(action_dims))
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.buffer = deque(maxlen=buffer_size)
        
        # Simple linear Q-network (NumPy fallback)
        self.lr = learning_rate
        self.weights = np.random.randn(state_dim, self.total_actions) * 0.01
        self.target_weights = self.weights.copy()
        self.update_counter = 0
        self.target_update_freq = 100
    
    def select_action(self, state: np.ndarray) -> tuple:
        """Epsilon-greedy action selection."""
        if random.random() < self.epsilon:
            # Random action
            return tuple(random.randint(0, d - 1) for d in self.action_dims)
        
        # Greedy action
        q_values = state @ self.weights
        flat_action = int(np.argmax(q_values))
        return self._unflatten_action(flat_action)
    
    def store(self, experience: Experience):
        """Store experience in replay buffer."""
        self.buffer.append(experience)
    
    def train_step(self) -> float:
        """Sample batch from buffer and perform one gradient step."""
        if len(self.buffer) < self.batch_size:
            return 0.0
        
        batch = random.sample(list(self.buffer), self.batch_size)
        
        states = np.array([e.state for e in batch])
        actions = [self._flatten_action(e.action) for e in batch]
        rewards = np.array([e.reward for e in batch])
        next_states = np.array([e.next_state for e in batch])
        dones = np.array([e.done for e in batch], dtype=np.float32)
        
        # Current Q values
        q_current = states @ self.weights
        
        # Target Q values
        q_next = next_states @ self.target_weights
        q_target = rewards + self.gamma * np.max(q_next, axis=1) * (1 - dones)
        
        # Compute loss and update
        loss = 0.0
        for i, action_idx in enumerate(actions):
            error = q_target[i] - q_current[i, action_idx]
            # Simple gradient step
            self.weights[:, action_idx] += self.lr * error * states[i]
            loss += error ** 2
        
        loss /= self.batch_size
        
        # Decay epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        
        # Update target network
        self.update_counter += 1
        if self.update_counter % self.target_update_freq == 0:
            self.target_weights = self.weights.copy()
        
        return loss
    
    def _flatten_action(self, action: tuple) -> int:
        """Convert multi-dimensional action to flat index."""
        flat = 0
        multiplier = 1
        for i in range(len(action) - 1, -1, -1):
            flat += action[i] * multiplier
            multiplier *= self.action_dims[i]
        return min(flat, self.total_actions - 1)
    
    def _unflatten_action(self, flat: int) -> tuple:
        """Convert flat index to multi-dimensional action."""
        action = []
        for d in reversed(self.action_dims):
            action.append(flat % d)
            flat //= d
        return tuple(reversed(action))
    
    def save(self, path: str):
        np.savez(path, weights=self.weights, epsilon=self.epsilon)
    
    def load(self, path: str):
        data = np.load(path)
        self.weights = data["weights"]
        self.target_weights = self.weights.copy()
        self.epsilon = float(data["epsilon"])


def train_agent(
    env,
    agent: DQNAgent,
    episodes: int = 1000,
    log_interval: int = 100,
) -> list[float]:
    """Train the DQN agent on the environment."""
    episode_rewards = []
    
    for ep in range(episodes):
        state, _ = env.reset()
        total_reward = 0
        done = False
        
        while not done:
            action = agent.select_action(state)
            next_state, reward, terminated, truncated, info = env.step(action)
            done = terminated or truncated
            
            agent.store(Experience(state, action, reward, next_state, done))
            loss = agent.train_step()
            
            state = next_state
            total_reward += reward
        
        episode_rewards.append(total_reward)
        
        if (ep + 1) % log_interval == 0:
            avg = np.mean(episode_rewards[-log_interval:])
            logger.info(f"Episode {ep+1}/{episodes} | Avg Reward: {avg:.2f} | Epsilon: {agent.epsilon:.3f}")
    
    return episode_rewards
```

---

## Tests

### `tests/rl/test_environment.py`
```python
import pytest
import numpy as np
from sentinel.rl.environment import PentestEnv, create_small_network, create_medium_network, ActionType

class TestPentestEnv:
    def test_reset(self):
        env = PentestEnv()
        obs, info = env.reset()
        assert obs.shape == (len(env.topology.nodes) * 6,)
        assert 0 in env.discovered

    def test_scan_discovers_neighbors(self):
        env = PentestEnv()
        env.reset()
        obs, reward, term, trunc, info = env.step((ActionType.SCAN_PORT, 0, 0))
        assert 1 in env.discovered  # Node 1 adjacent to node 0

    def test_exploit_owned(self):
        env = PentestEnv()
        env.reset()
        # Discover node 1
        env.step((ActionType.SCAN_PORT, 0, 0))
        # Exploit node 0 (has CVE)
        obs, reward, term, trunc, info = env.step((ActionType.EXPLOIT_KNOWN, 0, 1))
        assert 0 in env.owned or reward > 0  # Depends on vuln index

    def test_crown_jewel_terminates(self):
        env = PentestEnv(create_small_network())
        env.reset()
        # Manually own the crown jewel
        env.topology.nodes[2].is_owned = True
        env.owned.add(2)
        env.discovered.add(2)
        _, _, terminated, _, _ = env.step((ActionType.SCAN_PORT, 0, 0))
        assert terminated

    def test_max_steps_truncates(self):
        env = PentestEnv(max_steps=5)
        env.reset()
        for _ in range(5):
            _, _, _, truncated, _ = env.step((ActionType.SCAN_PORT, 0, 0))
        assert truncated

    def test_medium_network_topology(self):
        topo = create_medium_network()
        assert len(topo.nodes) == 6
        assert any(n.is_crown_jewel for n in topo.nodes)
```

### `tests/rl/test_agent.py`
```python
import pytest
import numpy as np
from sentinel.rl.agent import DQNAgent, Experience, train_agent
from sentinel.rl.environment import PentestEnv, create_small_network

class TestDQNAgent:
    def test_action_selection(self):
        agent = DQNAgent(state_dim=18, action_dims=[7, 3, 5], epsilon=0.0)
        state = np.zeros(18, dtype=np.float32)
        action = agent.select_action(state)
        assert len(action) == 3
        assert 0 <= action[0] < 7
        assert 0 <= action[1] < 3

    def test_exploration(self):
        agent = DQNAgent(state_dim=18, action_dims=[7, 3, 5], epsilon=1.0)
        state = np.zeros(18, dtype=np.float32)
        # All random — just check it doesn't crash
        actions = [agent.select_action(state) for _ in range(100)]
        unique = len(set(actions))
        assert unique > 1  # Should explore

    def test_flatten_unflatten(self):
        agent = DQNAgent(state_dim=18, action_dims=[7, 3, 5])
        for _ in range(50):
            action = (np.random.randint(0, 7), np.random.randint(0, 3), np.random.randint(0, 5))
            flat = agent._flatten_action(action)
            unflat = agent._unflatten_action(flat)
            assert unflat == action

    def test_train_step_with_data(self):
        agent = DQNAgent(state_dim=18, action_dims=[7, 3, 5], batch_size=4)
        for _ in range(10):
            agent.store(Experience(
                state=np.random.randn(18).astype(np.float32),
                action=(0, 0, 0), reward=1.0,
                next_state=np.random.randn(18).astype(np.float32),
                done=False,
            ))
        loss = agent.train_step()
        assert isinstance(loss, float)

    def test_short_training_run(self):
        env = PentestEnv(create_small_network())
        agent = DQNAgent(
            state_dim=env.observation_space.shape[0],
            action_dims=list(env.action_space.nvec),
            epsilon=1.0,
        )
        rewards = train_agent(env, agent, episodes=10, log_interval=5)
        assert len(rewards) == 10

    def test_save_load(self, tmp_path):
        agent = DQNAgent(state_dim=18, action_dims=[7, 3, 5])
        path = str(tmp_path / "model.npz")
        agent.save(path)
        
        agent2 = DQNAgent(state_dim=18, action_dims=[7, 3, 5])
        agent2.load(path)
        np.testing.assert_array_equal(agent.weights, agent2.weights)
```

---

## Acceptance Criteria
- [ ] PentestEnv is Gymnasium-compatible: reset() → obs, step() → (obs, reward, term, trunc, info)
- [ ] Small network (3 nodes) and medium network (6 nodes) topologies work
- [ ] SCAN_PORT discovers adjacent nodes
- [ ] EXPLOIT_KNOWN exploits vulnerable services and gives reward
- [ ] Crown jewel access terminates episode with +5.0 reward
- [ ] Max steps causes truncation
- [ ] DQNAgent selects actions with epsilon-greedy policy
- [ ] Replay buffer stores and samples experiences
- [ ] Training loop runs without crash for 10+ episodes
- [ ] Flatten/unflatten action conversion is bijective
- [ ] Agent save/load preserves weights
- [ ] All tests pass