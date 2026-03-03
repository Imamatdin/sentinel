"""Tests for training loop."""

from sentinel.rl.training import train_agent


class TestTraining:
    def test_train_small_runs(self):
        agent, result = train_agent(episodes_per_stage=5, max_steps=20,
                                    topologies=["small"])
        assert result.episodes == 5
        assert len(result.rewards) == 5

    def test_curriculum_two_stages(self):
        agent, result = train_agent(episodes_per_stage=3, max_steps=15,
                                    topologies=["small", "medium"])
        assert result.episodes == 6  # 3 per stage
        assert result.final_epsilon < 1.0
