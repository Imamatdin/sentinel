"""Tests for HybridFuzzer."""

from sentinel.formal.hybrid_fuzzer import HybridFuzzer, FuzzResult, FuzzInput
from sentinel.formal.property_generator import FormalProperty, PropertyType


class TestHybridFuzzer:
    def setup_method(self):
        self.fuzzer = HybridFuzzer()

    def test_seed_corpus(self):
        self.fuzzer.seed([b"test1", b"test2"])
        assert len(self.fuzzer.corpus) == 2
        assert self.fuzzer.corpus[0].source == "seed"

    def test_mutation_returns_bytes(self):
        result = self.fuzzer.mutate(b"hello world")
        assert isinstance(result, bytes)

    def test_mutation_respects_max_size(self):
        large = b"x" * 8000
        result = self.fuzzer.mutate(large)
        assert len(result) <= self.fuzzer.MAX_INPUT_SIZE

    def test_mutation_handles_empty_input(self):
        result = self.fuzzer.mutate(b"")
        assert isinstance(result, bytes)
        assert len(result) > 0

    def test_run_iteration_new_coverage(self):
        self.fuzzer.seed([b"seed"])

        def executor(data):
            return FuzzResult(
                input_data=data, crash=False, new_coverage=True,
                coverage_bitmap={"branch_1", "branch_2"},
            )

        result = self.fuzzer.run_iteration(executor)
        assert result.new_coverage
        assert self.fuzzer.stats.total_executions == 1
        assert self.fuzzer.stats.unique_paths == 2
        assert len(self.fuzzer.corpus) == 2  # seed + new

    def test_run_iteration_crash_tracked(self):
        self.fuzzer.seed([b"seed"])

        def executor(data):
            return FuzzResult(
                input_data=data, crash=True, new_coverage=False,
                coverage_bitmap=set(), error_message="segfault",
            )

        self.fuzzer.run_iteration(executor)
        assert self.fuzzer.stats.unique_crashes == 1
        assert len(self.fuzzer.crashes) == 1

    def test_run_iteration_no_coverage_increments_stuck(self):
        self.fuzzer.seed([b"seed"])

        def executor(data):
            return FuzzResult(
                input_data=data, crash=False, new_coverage=False,
                coverage_bitmap=set(),
            )

        self.fuzzer.run_iteration(executor)
        assert self.fuzzer._iterations_without_progress == 1

    def test_stuck_detection(self):
        assert not self.fuzzer.is_stuck
        self.fuzzer._iterations_without_progress = 500
        assert self.fuzzer.is_stuck

    def test_seed_from_counterexample(self):
        prop = FormalProperty(
            property_id="ce1", property_type=PropertyType.ARITHMETIC,
            description="test", z3_expression="",
            source_function="f", confidence=1.0,
            counterexample={"x": "42", "y": "-1"},
        )
        self.fuzzer.seed_from_counterexample(prop)
        assert len(self.fuzzer.corpus) == 1
        assert self.fuzzer.corpus[0].source == "z3_counterexample"

    def test_seed_from_empty_counterexample_noop(self):
        prop = FormalProperty(
            property_id="ce2", property_type=PropertyType.ARITHMETIC,
            description="test", z3_expression="",
            source_function="f", confidence=1.0,
        )
        self.fuzzer.seed_from_counterexample(prop)
        assert len(self.fuzzer.corpus) == 0

    def test_interesting_values_inserted(self):
        data = bytearray(b"test")
        result = self.fuzzer._insert_interesting(data)
        assert len(result) > 4

    def test_property_violation_tracked(self):
        self.fuzzer.seed([b"seed"])

        def executor(data):
            return FuzzResult(
                input_data=data, crash=False, new_coverage=False,
                coverage_bitmap=set(), violation="overflow_check",
            )

        self.fuzzer.run_iteration(executor)
        assert self.fuzzer.stats.property_violations == 1

    def test_run_without_corpus(self):
        def executor(data):
            return FuzzResult(
                input_data=data, crash=False, new_coverage=True,
                coverage_bitmap={"auto_branch"},
            )

        result = self.fuzzer.run_iteration(executor)
        assert result.new_coverage
