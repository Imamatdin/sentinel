"""
WebAssembly type-aware fuzzer (WALTZZ-style).

Mutation strategies preserve Wasm type invariants while maximizing coverage.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field

from sentinel.tools.wasm.wasm_analyzer import WasmAnalyzer, WasmModule, WASM_MAGIC, WASM_VERSION
from sentinel.core import get_logger

logger = get_logger(__name__)

# Wasm opcode groups for type-aware mutation
I32_ARITHMETIC = [0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77]
I32_COMPARISON = [0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F]
MEMORY_OPS = [0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33,
              0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E]

INTERESTING_I32 = [0, 1, -1, 0x7FFFFFFF, -0x80000000, 0xFF, 0xFFFF, 0xFFFFFFFF]


@dataclass
class FuzzCase:
    wasm_bytes: bytes
    mutation: str
    parent_hash: str
    coverage_hash: str = ""


@dataclass
class WasmCrash:
    input_bytes: bytes
    mutation: str
    error: str


@dataclass
class WasmFuzzStats:
    total_runs: int = 0
    unique_paths: int = 0
    crashes: int = 0
    mutations_applied: int = 0


class WasmFuzzer:
    """Type-aware Wasm mutation fuzzer with coverage guidance."""

    MAX_CORPUS = 500

    def __init__(self):
        self.corpus: list[FuzzCase] = []
        self.coverage: set[str] = set()
        self.crashes: list[WasmCrash] = []
        self.stats = WasmFuzzStats()
        self.analyzer = WasmAnalyzer()

    def seed(self, wasm_bytes: bytes):
        """Add a seed input to the corpus."""
        h = hashlib.md5(wasm_bytes).hexdigest()
        self.corpus.append(FuzzCase(wasm_bytes=wasm_bytes, mutation="seed",
                                    parent_hash=h))

    def mutate(self, wasm_bytes: bytes) -> tuple[bytes, str]:
        """Apply a type-aware mutation. Returns (mutated_bytes, mutation_name)."""
        data = bytearray(wasm_bytes)

        # Keep header intact
        if len(data) < 8:
            return bytes(data), "too_small"

        strategies = [
            ("arithmetic_swap", self._arithmetic_swap),
            ("comparison_swap", self._comparison_swap),
            ("const_replace", self._const_replace),
            ("memory_offset", self._memory_offset_mutate),
            ("random_byte_flip", self._random_byte_flip),
        ]

        name, fn = random.choice(strategies)
        result = fn(data)
        self.stats.mutations_applied += 1
        return bytes(result), name

    def run_iteration(self, executor) -> bool:
        """Run one fuzz iteration. executor(bytes) -> (crashed, coverage_set, error)."""
        if not self.corpus:
            return False

        parent = random.choice(self.corpus)
        mutated, mutation_name = self.mutate(parent.wasm_bytes)

        crashed, cov_set, error = executor(mutated)
        self.stats.total_runs += 1

        cov_hash = hashlib.md5(str(sorted(cov_set)).encode()).hexdigest()

        if cov_set - self.coverage:
            self.coverage.update(cov_set)
            self.stats.unique_paths = len(self.coverage)
            if len(self.corpus) < self.MAX_CORPUS:
                self.corpus.append(FuzzCase(
                    wasm_bytes=mutated, mutation=mutation_name,
                    parent_hash=hashlib.md5(parent.wasm_bytes).hexdigest(),
                    coverage_hash=cov_hash,
                ))

        if crashed:
            self.crashes.append(WasmCrash(
                input_bytes=mutated, mutation=mutation_name, error=error,
            ))
            self.stats.crashes += 1
            return True

        return False

    # --- Mutation strategies (operate on code section bytes, skip header) ---

    def _arithmetic_swap(self, data: bytearray) -> bytearray:
        """Swap one arithmetic opcode for another of the same type."""
        positions = [i for i in range(8, len(data)) if data[i] in I32_ARITHMETIC]
        if positions:
            pos = random.choice(positions)
            data[pos] = random.choice(I32_ARITHMETIC)
        return data

    def _comparison_swap(self, data: bytearray) -> bytearray:
        """Swap comparison operator (e.g., lt_s -> ge_s)."""
        positions = [i for i in range(8, len(data)) if data[i] in I32_COMPARISON]
        if positions:
            pos = random.choice(positions)
            data[pos] = random.choice(I32_COMPARISON)
        return data

    def _const_replace(self, data: bytearray) -> bytearray:
        """Replace i32.const values with interesting boundary values."""
        # i32.const opcode is 0x41
        positions = [i for i in range(8, len(data) - 4) if data[i] == 0x41]
        if positions:
            pos = random.choice(positions)
            val = random.choice(INTERESTING_I32)
            # Encode as signed LEB128
            encoded = self._encode_leb128_signed(val)
            # Replace bytes after the opcode (up to 5 bytes for LEB128)
            end = min(pos + 1 + 5, len(data))
            data[pos + 1:end] = encoded + bytes(end - pos - 1 - len(encoded))
        return data

    def _memory_offset_mutate(self, data: bytearray) -> bytearray:
        """Mutate memory access offsets to trigger OOB."""
        positions = [i for i in range(8, len(data)) if data[i] in MEMORY_OPS]
        if positions:
            pos = random.choice(positions)
            # Memory ops are followed by align + offset (both LEB128)
            if pos + 2 < len(data):
                data[pos + 2] = random.choice([0x00, 0xFF, 0x7F, 0x80])
        return data

    def _random_byte_flip(self, data: bytearray) -> bytearray:
        """Flip a random byte in the code section (skip magic/version header)."""
        if len(data) > 8:
            pos = random.randint(8, len(data) - 1)
            data[pos] ^= random.randint(1, 255)
        return data

    @staticmethod
    def _encode_leb128_signed(value: int) -> bytes:
        result = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if (value == 0 and (byte & 0x40) == 0) or \
               (value == -1 and (byte & 0x40) != 0):
                result.append(byte)
                break
            result.append(byte | 0x80)
        return bytes(result)
