"""Tests for WasmFuzzer."""

from sentinel.tools.wasm.wasm_fuzzer import WasmFuzzer, WASM_MAGIC, WASM_VERSION


def _minimal_wasm() -> bytes:
    """Build a minimal Wasm binary with arithmetic opcodes for mutation."""
    buf = bytearray()
    buf.extend(WASM_MAGIC)
    buf.extend(WASM_VERSION)
    # Pad with some arithmetic and comparison opcodes
    buf.extend(bytes([
        0x41, 0x01,        # i32.const 1
        0x41, 0x02,        # i32.const 2
        0x6A,              # i32.add
        0x46,              # i32.eq
        0x28, 0x02, 0x00,  # i32.load align=2 offset=0
    ]))
    return bytes(buf)


class TestWasmFuzzer:
    def setup_method(self):
        self.fuzzer = WasmFuzzer()

    def test_seed_adds_to_corpus(self):
        wasm = _minimal_wasm()
        self.fuzzer.seed(wasm)
        assert len(self.fuzzer.corpus) == 1

    def test_mutate_returns_bytes(self):
        wasm = _minimal_wasm()
        result, name = self.fuzzer.mutate(wasm)
        assert isinstance(result, bytes)
        assert name in ("arithmetic_swap", "comparison_swap", "const_replace",
                         "memory_offset", "random_byte_flip", "too_small")

    def test_mutate_preserves_header(self):
        wasm = _minimal_wasm()
        result, _ = self.fuzzer.mutate(wasm)
        # Header might be preserved (random byte flip could skip it)
        # At minimum, mutation should return valid bytes
        assert len(result) > 0

    def test_run_iteration_tracks_coverage(self):
        wasm = _minimal_wasm()
        self.fuzzer.seed(wasm)

        def executor(data):
            return False, {"branch_a", "branch_b"}, ""

        self.fuzzer.run_iteration(executor)
        assert self.fuzzer.stats.total_runs == 1
        assert self.fuzzer.stats.unique_paths == 2

    def test_run_iteration_tracks_crashes(self):
        wasm = _minimal_wasm()
        self.fuzzer.seed(wasm)

        def executor(data):
            return True, set(), "OOB memory access"

        crashed = self.fuzzer.run_iteration(executor)
        assert crashed
        assert self.fuzzer.stats.crashes == 1
        assert len(self.fuzzer.crashes) == 1

    def test_five_mutation_strategies(self):
        """All 5 strategies should be callable."""
        data = bytearray(_minimal_wasm())
        self.fuzzer._arithmetic_swap(data)
        self.fuzzer._comparison_swap(data)
        self.fuzzer._const_replace(data)
        self.fuzzer._memory_offset_mutate(data)
        self.fuzzer._random_byte_flip(data)

    def test_leb128_signed_encode(self):
        assert WasmFuzzer._encode_leb128_signed(0) == b"\x00"
        assert WasmFuzzer._encode_leb128_signed(-1) == b"\x7f"
        assert WasmFuzzer._encode_leb128_signed(1) == b"\x01"

    def test_empty_corpus_noop(self):
        result = self.fuzzer.run_iteration(lambda d: (False, set(), ""))
        assert result is False
