"""Tests for DQNAgent."""

import numpy as np

from sentinel.rl.dqn_agent import DQNAgent, QNetwork


class TestQNetwork:
    def test_forward_shape(self):
        net = QNetwork(input_size=6, hidden_size=8, output_size=4)
        out = net.forward(np.zeros((1, 6), dtype=np.float32))
        assert out.shape == (1, 4)

    def test_copy_from(self):
        net1 = QNetwork(4, 8, 2)
        net2 = QNetwork(4, 8, 2)
        net2.copy_from(net1)
        np.testing.assert_array_equal(net1.w1, net2.w1)
        np.testing.assert_array_equal(net1.w2, net2.w2)


class TestDQNAgent:
    def test_select_action_in_range(self):
        agent = DQNAgent(state_size=6, action_size=10, epsilon=0.0)
        action = agent.select_action([0.0] * 6)
        assert 0 <= action < 10

    def test_select_action_respects_valid(self):
        agent = DQNAgent(state_size=6, action_size=10, epsilon=0.0)
        valid = [2, 5, 7]
        action = agent.select_action([0.0] * 6, valid_actions=valid)
        assert action in valid

    def test_exploration_random(self):
        agent = DQNAgent(state_size=6, action_size=10, epsilon=1.0)
        # With epsilon=1.0, should always explore (random)
        actions = {agent.select_action([0.0] * 6) for _ in range(50)}
        assert len(actions) > 1  # should get multiple different actions

    def test_store_and_train(self):
        agent = DQNAgent(state_size=4, action_size=3, batch_size=4)
        for _ in range(10):
            agent.store([0.1, 0.2, 0.3, 0.4], 1, 0.5,
                        [0.2, 0.3, 0.4, 0.5], False)
        loss = agent.train_step()
        assert loss >= 0

    def test_save_load(self, tmp_path):
        agent = DQNAgent(state_size=4, action_size=3)
        path = tmp_path / "weights.npz"
        agent.save(path)
        agent2 = DQNAgent(state_size=4, action_size=3)
        agent2.load(path)
        np.testing.assert_array_equal(agent.q_net.w1, agent2.q_net.w1)

    def test_epsilon_decays(self):
        agent = DQNAgent(state_size=4, action_size=3, batch_size=2,
                         epsilon=1.0, epsilon_decay=0.9)
        for _ in range(5):
            agent.store([0, 0, 0, 0], 0, 1.0, [0, 0, 0, 0], False)
        agent.train_step()
        assert agent.epsilon < 1.0
