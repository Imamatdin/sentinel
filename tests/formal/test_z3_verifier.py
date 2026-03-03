"""Tests for Z3Verifier."""

import pytest

from sentinel.formal.z3_verifier import Z3Verifier
from sentinel.formal.property_generator import FormalProperty, PropertyType

z3 = pytest.importorskip("z3", reason="z3-solver not installed")


class TestZ3Verifier:
    def setup_method(self):
        self.verifier = Z3Verifier()

    def test_tautology_holds(self):
        prop = FormalProperty(
            property_id="p1", property_type=PropertyType.ARITHMETIC,
            description="x equals x",
            z3_expression="z3.Int('x') == z3.Int('x')",
            source_function="test", confidence=1.0,
        )
        result = self.verifier.verify(prop)
        assert result.status == "holds"

    def test_contradiction_violated(self):
        prop = FormalProperty(
            property_id="p2", property_type=PropertyType.ARITHMETIC,
            description="x > x is impossible",
            z3_expression="z3.Int('x') > z3.Int('x')",
            source_function="test", confidence=1.0,
        )
        result = self.verifier.verify(prop)
        assert result.status == "violated"
        assert result.counterexample  # Should have a counterexample

    def test_error_on_bad_expression(self):
        prop = FormalProperty(
            property_id="p3", property_type=PropertyType.INVARIANT,
            description="bad expression",
            z3_expression="this is not valid python",
            source_function="test", confidence=0.5,
        )
        result = self.verifier.verify(prop)
        assert result.status == "error"

    def test_verify_all_updates_properties(self):
        props = [
            FormalProperty(
                property_id="v1", property_type=PropertyType.ARITHMETIC,
                description="holds", z3_expression="z3.Int('a') == z3.Int('a')",
                source_function="f", confidence=1.0,
            ),
            FormalProperty(
                property_id="v2", property_type=PropertyType.ARITHMETIC,
                description="violated", z3_expression="z3.Int('a') > z3.Int('a')",
                source_function="f", confidence=1.0,
            ),
        ]
        results = self.verifier.verify_all(props)
        assert len(results) == 2
        assert props[0].verified is True
        assert props[1].verified is False

    def test_bound_check_property(self):
        prop = FormalProperty(
            property_id="bound1", property_type=PropertyType.PRECONDITION,
            description="index in bounds",
            z3_expression="z3.And(index >= 0, index < length)",
            source_function="test", confidence=0.9,
        )
        result = self.verifier.verify(prop)
        # This should be violated because there exist index/length combos that break it
        assert result.status == "violated"
