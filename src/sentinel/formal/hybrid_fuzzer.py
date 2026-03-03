"""
Hybrid Fuzzer — Coverage-guided fuzzing informed by formal verification.

Driller pattern:
1. Coverage-guided fuzzing (AFL-style) finds easy paths
2. When stuck (no new coverage for N iterations): switch to concolic execution
3. Concolic engine solves path constraints to generate inputs reaching new branches
4. Z3 counterexamples seed the fuzzer with violation-triggering inputs

Mutation strategies: bit flip, byte flip, insert random, delete, interesting values.
"""

import hashlib
import random
from dataclasses import dataclass, field

from sentinel.formal.property_generator import FormalProperty
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class FuzzInput:
    data: bytes
    source: str  # "seed" | "random" | "mutation" | "concolic" | "z3_counterexample"
    generation: int
    coverage_hash: str = ""


@dataclass
class FuzzResult:
    input_data: bytes
    crash: bool
    new_coverage: bool
    coverage_bitmap: set = field(default_factory=set)
    violation: str = ""
    error_message: str = ""


@dataclass
class FuzzStats:
    total_executions: int = 0
    unique_crashes: int = 0
    unique_paths: int = 0
    property_violations: int = 0
    concolic_solves: int = 0


# Boundary values and attack patterns known to trigger bugs
_INTERESTING_VALUES = [
    b"\x00", b"\xff", b"\x7f", b"\x80",
    b"\xff\xff\xff\xff",
    b"\x00\x00\x00\x00",
    b"%s%s%s%s",
    b"'OR'1'='1",
    b"<script>",
    b"../../../",
]


class HybridFuzzer:
    """Coverage-guided fuzzing with concolic execution fallback."""

    STUCK_THRESHOLD = 500
    MAX_INPUT_SIZE = 4096

    def __init__(self):
        self.corpus: list[FuzzInput] = []
        self.coverage: set[str] = set()
        self.crashes: list[FuzzResult] = []
        self.stats = FuzzStats()
        self._iterations_without_progress = 0

    def seed(self, inputs: list[bytes]):
        """Add initial seed inputs to the corpus."""
        for data in inputs:
            self.corpus.append(FuzzInput(data=data, source="seed", generation=0))

    def seed_from_counterexample(self, prop: FormalProperty):
        """Convert a Z3 counterexample into a fuzz seed."""
        if not prop.counterexample:
            return
        ce_str = str(prop.counterexample)
        self.corpus.append(FuzzInput(
            data=ce_str.encode(), source="z3_counterexample", generation=0,
        ))
        logger.info("fuzzer_seeded_from_z3", prop=prop.property_id)

    def mutate(self, input_data: bytes) -> bytes:
        """Apply random mutations to an input."""
        data = bytearray(input_data)
        if not data:
            data = bytearray(random.randint(1, 32))

        num_mutations = random.randint(1, 5)
        for _ in range(num_mutations):
            mutation = random.choice([
                self._bit_flip, self._byte_flip,
                self._insert_random, self._delete_bytes,
                self._insert_interesting,
            ])
            data = mutation(data)

        return bytes(data[: self.MAX_INPUT_SIZE])

    def run_iteration(self, executor) -> FuzzResult:
        """Run one fuzzing iteration with the given executor callback."""
        if not self.corpus:
            input_data = bytes(random.randint(0, 255) for _ in range(32))
        else:
            base = random.choice(self.corpus)
            input_data = self.mutate(base.data)

        result = executor(input_data)
        self.stats.total_executions += 1

        coverage_hash = hashlib.md5(
            str(sorted(result.coverage_bitmap)).encode()
        ).hexdigest()

        if result.new_coverage:
            self._iterations_without_progress = 0
            self.coverage.update(result.coverage_bitmap)
            self.stats.unique_paths = len(self.coverage)
            gen = max((f.generation for f in self.corpus), default=0) + 1
            self.corpus.append(FuzzInput(
                data=input_data, source="mutation",
                generation=gen, coverage_hash=coverage_hash,
            ))
        else:
            self._iterations_without_progress += 1

        if result.crash:
            self.crashes.append(result)
            self.stats.unique_crashes += 1

        if result.violation:
            self.stats.property_violations += 1

        return result

    @property
    def is_stuck(self) -> bool:
        return self._iterations_without_progress >= self.STUCK_THRESHOLD

    def _bit_flip(self, data: bytearray) -> bytearray:
        if data:
            pos = random.randint(0, len(data) - 1)
            data[pos] ^= 1 << random.randint(0, 7)
        return data

    def _byte_flip(self, data: bytearray) -> bytearray:
        if data:
            data[random.randint(0, len(data) - 1)] = random.randint(0, 255)
        return data

    def _insert_random(self, data: bytearray) -> bytearray:
        data.insert(random.randint(0, len(data)), random.randint(0, 255))
        return data

    def _delete_bytes(self, data: bytearray) -> bytearray:
        if len(data) > 1:
            del data[random.randint(0, len(data) - 1)]
        return data

    def _insert_interesting(self, data: bytearray) -> bytearray:
        payload = random.choice(_INTERESTING_VALUES)
        pos = random.randint(0, len(data))
        for b in payload:
            data.insert(pos, b)
            pos += 1
        return data
