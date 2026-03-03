import pytest
import numpy as np
from sentinel.self_play.trainer import SelfPlayTrainer, AgentPolicy


class TestAgentPolicy:
    def test_select_action_in_range(self):
        policy = AgentPolicy("test", state_dim=18, action_dim=6)
        obs = np.random.randn(18).astype(np.float32)
        action = policy.select_action(obs)
        assert 0 <= action < 6

    def test_update_no_crash(self):
        policy = AgentPolicy("test", state_dim=18, action_dim=6)
        trajs = [
            {"obs": np.random.randn(18).astype(np.float32), "action": 0, "reward": 1.0}
            for _ in range(5)
        ]
        policy.update(trajs)

    def test_weights_shape(self):
        policy = AgentPolicy("test", state_dim=18, action_dim=6)
        assert policy.weights.shape == (18, 6)


class TestSelfPlayTrainer:
    def test_play_game(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        red_r, blue_r, winner = trainer.play_game()
        assert isinstance(red_r, float)
        assert winner in ("red", "blue")

    def test_short_training(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        stats = trainer.train(episodes=20, log_interval=20)
        assert stats.total_games == 20
        assert stats.red_wins + stats.blue_wins == 20

    def test_elo_updates(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        trainer.train(episodes=10, log_interval=0)
        assert trainer.red_agent.elo != 1000 or trainer.blue_agent.elo != 1000

    def test_history_snapshots(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        trainer.train(episodes=50, log_interval=0)
        assert len(trainer.history) > 0

    def test_stats_avg_game_length(self):
        trainer = SelfPlayTrainer(num_nodes=3)
        stats = trainer.train(episodes=10, log_interval=0)
        assert stats.avg_game_length > 0
