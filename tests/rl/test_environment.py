"""Tests for PentestEnv."""

from sentinel.rl.environment import PentestEnv, ActionType, NodeState, STATE_FEATURES_PER_NODE


class TestPentestEnv:
    def setup_method(self):
        self.env = PentestEnv(topology="small", max_steps=50)

    def test_reset_returns_observation(self):
        obs = self.env.reset()
        assert len(obs) == 3 * STATE_FEATURES_PER_NODE  # 3 nodes in small

    def test_gateway_discovered_on_reset(self):
        self.env.reset()
        assert self.env.nodes["gateway"].discovered

    def test_scan_port_discovered_node(self):
        self.env.reset()
        gw_idx = self.env.node_ids.index("gateway")
        action = ActionType.SCAN_PORT * len(self.env.node_ids) + gw_idx
        _, reward, done, _ = self.env.step(action)
        assert reward > -0.05  # small positive or step penalty

    def test_exploit_with_vulns(self):
        self.env.reset()
        gw_idx = self.env.node_ids.index("gateway")
        action = ActionType.EXPLOIT_KNOWN * len(self.env.node_ids) + gw_idx
        _, reward, _, info = self.env.step(action)
        assert reward > 0.5  # exploit reward minus step penalty
        assert self.env.nodes["gateway"].owned

    def test_pivot_discovers_neighbours(self):
        self.env.reset()
        # Own gateway first
        gw_idx = self.env.node_ids.index("gateway")
        self.env.step(ActionType.EXPLOIT_KNOWN * len(self.env.node_ids) + gw_idx)
        # Pivot
        _, reward, _, _ = self.env.step(ActionType.PIVOT * len(self.env.node_ids) + gw_idx)
        assert self.env.nodes["app"].discovered
        assert reward > 0

    def test_crown_jewel_ends_episode(self):
        self.env.reset()
        n = len(self.env.node_ids)
        # Exploit gateway, pivot to app, exploit app, pivot to db, exploit db, exfiltrate db
        gw = self.env.node_ids.index("gateway")
        app = self.env.node_ids.index("app")
        db = self.env.node_ids.index("db")

        self.env.step(ActionType.EXPLOIT_KNOWN * n + gw)
        self.env.step(ActionType.PIVOT * n + gw)
        self.env.step(ActionType.EXPLOIT_KNOWN * n + app)
        self.env.step(ActionType.PIVOT * n + app)
        self.env.step(ActionType.EXPLOIT_KNOWN * n + db)
        _, reward, done, info = self.env.step(ActionType.EXFILTRATE * n + db)
        assert done
        assert info.get("reason") == "crown_jewel"
        assert reward > 4.0

    def test_max_steps_terminates(self):
        env = PentestEnv(topology="small", max_steps=3)
        env.reset()
        n = len(env.node_ids)
        for _ in range(3):
            _, _, done, _ = env.step(ActionType.SCAN_PORT * n + 0)
        assert done

    def test_medium_topology_larger(self):
        env = PentestEnv(topology="medium")
        obs = env.reset()
        assert len(env.node_ids) == 6
        assert len(obs) == 6 * STATE_FEATURES_PER_NODE

    def test_valid_actions_only_discovered(self):
        self.env.reset()
        valid = self.env.get_valid_actions()
        n = len(self.env.node_ids)
        gw_idx = self.env.node_ids.index("gateway")
        # Gateway is discovered so its actions should be valid
        assert ActionType.SCAN_PORT * n + gw_idx in valid

    def test_node_state_to_vector(self):
        node = NodeState("test", discovered=True, owned=True, privilege=2,
                         services=["a", "b"], vulns=["v1"], has_credentials=True)
        vec = node.to_vector()
        assert vec == [1.0, 1.0, 1.0, 0.4, 0.2, 1.0]
