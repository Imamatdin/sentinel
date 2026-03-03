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
                int(np.random.randint(0, 6)), int(np.random.randint(0, 6))
            )
            if done:
                break
        assert done  # Should terminate by max_turns at latest

    def test_crown_jewel_exploit(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        # Position red at crown jewel with vulns available
        arena.state.red_position = 2
        arena.state.nodes[2].vulnerability_count = 3
        arena.state.nodes[2].patched_vulns = 0
        arena.state.nodes[2].red_owns = False
        # Use HARDEN for blue so no detection
        _, _, rr, _, done = arena.step(RedAction.EXPLOIT, BlueAction.HARDEN)
        # Red should have exploited crown jewel
        assert arena.state.nodes[2].red_owns is True

    def test_tripwire_reduces_stealth(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        arena.state.nodes[0].has_tripwire = True
        arena.state.nodes[0].vulnerability_count = 2
        arena.state.nodes[0].patched_vulns = 0
        arena.state.red_position = 0
        stealth_before = arena.state.red_stealth
        arena.step(RedAction.EXPLOIT, BlueAction.HARDEN)
        # Tripwire should reduce stealth: *0.8 * 0.1 = much less
        assert arena.state.red_stealth < stealth_before * 0.5

    def test_hide_increases_stealth(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        arena.state.red_stealth = 0.5
        arena.step(RedAction.HIDE, BlueAction.HARDEN)
        assert arena.state.red_stealth > 0.5

    def test_red_action_enum(self):
        assert len(RedAction) == 6

    def test_blue_action_enum(self):
        assert len(BlueAction) == 6

    def test_max_turns_blue_wins(self):
        arena = RedBlueArena(num_nodes=3)
        arena.reset()
        # Fast-forward to near end
        arena.state.turn = 49
        _, _, _, _, done = arena.step(RedAction.HIDE, BlueAction.HARDEN)
        assert done is True
        assert arena.state.winner == "blue"
