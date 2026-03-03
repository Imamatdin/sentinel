"""
Training loop with curriculum learning: small → medium topologies.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.rl.environment import PentestEnv
from sentinel.rl.dqn_agent import DQNAgent
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class TrainingResult:
    episodes: int = 0
    rewards: list[float] = field(default_factory=list)
    crown_jewels_found: int = 0
    final_epsilon: float = 1.0


def train_agent(
    episodes_per_stage: int = 50,
    max_steps: int = 100,
    topologies: list[str] | None = None,
) -> tuple[DQNAgent, TrainingResult]:
    """Train DQN with curriculum learning across topologies."""
    if topologies is None:
        topologies = ["small", "medium"]

    result = TrainingResult()

    # Initialise agent with small env to get sizes
    env = PentestEnv(topology=topologies[0], max_steps=max_steps)
    obs = env.reset()
    agent = DQNAgent(state_size=len(obs), action_size=env.n_actions)

    for topo in topologies:
        env = PentestEnv(topology=topo, max_steps=max_steps)
        logger.info("curriculum_stage", topology=topo, episodes=episodes_per_stage)

        for ep in range(episodes_per_stage):
            obs = env.reset()

            # Re-initialise agent networks if action/state space changed
            if len(obs) != agent.state_size or env.n_actions != agent.action_size:
                agent = DQNAgent(state_size=len(obs), action_size=env.n_actions,
                                 epsilon=agent.epsilon)

            total_reward = 0.0
            for _ in range(max_steps):
                valid = env.get_valid_actions()
                action = agent.select_action(obs, valid)
                next_obs, reward, done, info = env.step(action)
                agent.store(obs, action, reward, next_obs, done)
                agent.train_step()
                obs = next_obs
                total_reward += reward
                if done:
                    if info.get("reason") == "crown_jewel":
                        result.crown_jewels_found += 1
                    break

            result.rewards.append(total_reward)
            result.episodes += 1

    result.final_epsilon = agent.epsilon
    logger.info("training_complete", episodes=result.episodes,
                crown_jewels=result.crown_jewels_found)
    return agent, result
