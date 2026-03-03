import pytest
from sentinel.inference.belief_model import BetaBelief, NetworkBeliefs


class TestBetaBelief:
    def test_uniform_prior(self):
        b = BetaBelief("test")
        assert b.mean == 0.5
        assert b.uncertainty > 0

    def test_update_positive(self):
        b = BetaBelief("test")
        b.update(True)
        assert b.mean > 0.5
        assert b.alpha == 2.0

    def test_update_negative(self):
        b = BetaBelief("test")
        b.update(False)
        assert b.mean < 0.5
        assert b.beta == 2.0

    def test_uncertainty_decreases(self):
        b = BetaBelief("test")
        initial = b.uncertainty
        for _ in range(10):
            b.update(True)
        assert b.uncertainty < initial

    def test_info_gain_positive(self):
        b = BetaBelief("test")
        gain = b.expected_info_gain()
        assert gain >= 0

    def test_strong_belief_low_gain(self):
        b = BetaBelief("test", alpha=100, beta=1)
        gain = b.expected_info_gain()
        b2 = BetaBelief("test2", alpha=1, beta=1)
        gain2 = b2.expected_info_gain()
        assert gain < gain2  # Uncertain belief has more to gain

    def test_entropy_computable(self):
        b = BetaBelief("test")
        e = b.entropy
        assert isinstance(e, float)

    def test_variance_decreases_with_observations(self):
        b = BetaBelief("test")
        v1 = b.variance
        b.update(True)
        b.update(True)
        v2 = b.variance
        assert v2 < v1


class TestNetworkBeliefs:
    def test_total_uncertainty(self):
        nb = NetworkBeliefs("host1")
        nb.add_port(80)
        nb.add_port(443)
        assert nb.total_uncertainty() > 0

    def test_add_vuln(self):
        nb = NetworkBeliefs("host1")
        nb.add_vuln("CVE-2021-44228")
        assert "CVE-2021-44228" in nb.vuln_beliefs

    def test_add_port_idempotent(self):
        nb = NetworkBeliefs("host1")
        nb.add_port(80)
        nb.add_port(80)
        assert len(nb.port_beliefs) == 1

    def test_cred_beliefs(self):
        nb = NetworkBeliefs("host1")
        nb.cred_beliefs["admin:password"] = BetaBelief("cred_admin")
        assert nb.total_uncertainty() > 0
