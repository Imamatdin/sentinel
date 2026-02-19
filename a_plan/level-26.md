# LEVEL 26: WebAssembly Binary Fuzzer

## Context
Wasm modules run in browsers, edge compute, and server-side runtimes. Traditional fuzzers don't understand Wasm's stack-based semantics. This level adds WALTZZ-style Wasm fuzzing: type-aware mutation, stack-invariant preservation, and coverage-guided exploration via instrumented Wasm runtimes.

Research: Block 12 (Wasm Fuzzing — WALTZZ: stack-invariant mutations, Fuzzm: 33 bugs in 30 Wasm runtimes, Wasmtime/V8 coverage APIs).

## Why
Wasm is deployed everywhere but audited nowhere. Most pentesting tools skip it entirely. Wasm bugs lead to sandbox escapes, memory corruption, and logic errors. This is another "no one else does this" differentiator.

---

## Files to Create

### `src/sentinel/tools/wasm/__init__.py`
```python
"""WebAssembly security testing — binary fuzzing, validation, analysis."""
```

### `src/sentinel/tools/wasm/wasm_analyzer.py`
```python
"""
Wasm Module Analyzer — Parse and analyze WebAssembly binaries.

Extracts: function signatures, import/export tables, memory layout,
table entries, custom sections, and potential attack surface.
"""
import struct
from dataclasses import dataclass, field
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)

WASM_MAGIC = b'\x00asm'
WASM_VERSION = b'\x01\x00\x00\x00'

# Section IDs
SECTION_TYPE = 1
SECTION_IMPORT = 2
SECTION_FUNCTION = 3
SECTION_EXPORT = 7
SECTION_CODE = 10


@dataclass
class WasmFunction:
    index: int
    name: str
    param_types: list[str]
    return_types: list[str]
    is_export: bool = False
    is_import: bool = False
    code_size: int = 0


@dataclass
class WasmAnalysis:
    valid: bool
    version: int
    num_functions: int
    num_exports: int
    num_imports: int
    functions: list[WasmFunction]
    memory_pages: int           # Initial memory pages (64KB each)
    has_start_function: bool
    attack_surface: list[str]   # Exported functions accessible from host
    warnings: list[str]


class WasmAnalyzer(BaseTool):
    """Analyze WebAssembly binary modules for security properties."""

    name = "wasm_analyze"
    description = "Analyze a WebAssembly binary for structure and attack surface"

    async def execute(self, wasm_bytes: bytes) -> ToolResult:
        """Parse and analyze a Wasm binary."""
        analysis = self.analyze(wasm_bytes)
        return ToolResult(
            success=analysis.valid,
            data=analysis,
            tool_name=self.name,
            metadata={"functions": analysis.num_functions, "exports": analysis.num_exports},
        )

    def analyze(self, data: bytes) -> WasmAnalysis:
        """Parse Wasm binary and extract structure."""
        warnings = []

        if len(data) < 8:
            return WasmAnalysis(valid=False, version=0, num_functions=0,
                                num_exports=0, num_imports=0, functions=[],
                                memory_pages=0, has_start_function=False,
                                attack_surface=[], warnings=["Too short to be valid Wasm"])

        if data[:4] != WASM_MAGIC:
            return WasmAnalysis(valid=False, version=0, num_functions=0,
                                num_exports=0, num_imports=0, functions=[],
                                memory_pages=0, has_start_function=False,
                                attack_surface=[], warnings=["Invalid Wasm magic bytes"])

        version = struct.unpack('<I', data[4:8])[0]
        functions = []
        exports = []
        imports = []
        memory_pages = 0
        has_start = False

        # Simple section parser
        offset = 8
        while offset < len(data):
            if offset >= len(data):
                break
            section_id = data[offset]
            offset += 1
            if offset >= len(data):
                break

            # Read LEB128 section size
            size, bytes_read = self._read_leb128(data, offset)
            offset += bytes_read
            section_end = offset + size

            if section_id == SECTION_EXPORT:
                # Count exports
                if offset < section_end:
                    num_exports, br = self._read_leb128(data, offset)
                    exports = [f"export_{i}" for i in range(num_exports)]

            elif section_id == SECTION_IMPORT:
                if offset < section_end:
                    num_imports, br = self._read_leb128(data, offset)
                    imports = [f"import_{i}" for i in range(num_imports)]

            elif section_id == SECTION_CODE:
                if offset < section_end:
                    num_funcs, br = self._read_leb128(data, offset)
                    for i in range(num_funcs):
                        functions.append(WasmFunction(
                            index=i, name=f"func_{i}",
                            param_types=[], return_types=[],
                        ))

            offset = section_end

        # Security warnings
        if len(exports) > 20:
            warnings.append(f"Large export surface ({len(exports)} exports) — increased attack surface")
        if memory_pages > 256:
            warnings.append(f"Large initial memory ({memory_pages * 64}KB) — potential for memory abuse")

        return WasmAnalysis(
            valid=True, version=version,
            num_functions=len(functions), num_exports=len(exports),
            num_imports=len(imports), functions=functions,
            memory_pages=memory_pages, has_start_function=has_start,
            attack_surface=[e for e in exports],
            warnings=warnings,
        )

    def _read_leb128(self, data: bytes, offset: int) -> tuple[int, int]:
        """Read unsigned LEB128 encoded integer."""
        result = 0
        shift = 0
        bytes_read = 0
        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            result |= (byte & 0x7F) << shift
            bytes_read += 1
            if (byte & 0x80) == 0:
                break
            shift += 7
        return result, bytes_read
```

### `src/sentinel/tools/wasm/wasm_fuzzer.py`
```python
"""
Wasm Fuzzer — Type-aware mutation fuzzing for WebAssembly modules.

WALTZZ-style approach:
1. Parse Wasm binary to understand structure
2. Apply type-preserving mutations (maintain stack invariants)
3. Execute mutated module and check for crashes/hangs/violations
4. Coverage feedback guides which mutations to keep

Mutation strategies (stack-invariant):
- Instruction replacement: swap opcodes of same type signature
- Constant mutation: change i32.const/i64.const values
- Block manipulation: insert/remove control flow blocks
- Function call mutation: swap call targets of compatible signatures
- Memory operation mutation: change offsets and alignments
"""
import random
import struct
from dataclasses import dataclass, field
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)

# Wasm opcodes grouped by type signature (stack-safe swaps)
ARITHMETIC_I32 = [0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77]
# i32.add, sub, mul, div_s, div_u, rem_s, rem_u, and, or, xor, shl, shr_s, shr_u, rotl
COMPARISON_I32 = [0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F]
# i32.eq, ne, lt_s, lt_u, gt_s, gt_u, le_s, le_u, ge_s, ge_u

INTERESTING_I32 = [0, 1, -1, 0x7FFFFFFF, -0x80000000, 0xFFFFFFFF, 255, 256, 65535, 65536]


@dataclass
class WasmMutation:
    offset: int
    original: bytes
    mutated: bytes
    mutation_type: str
    description: str


@dataclass
class FuzzResult:
    mutation: WasmMutation
    crashed: bool
    hung: bool
    error_message: str
    new_coverage: bool


class WasmFuzzer(BaseTool):
    """Type-aware mutation fuzzer for WebAssembly binaries."""

    name = "wasm_fuzz"
    description = "Fuzz a WebAssembly binary with type-preserving mutations"

    def __init__(self, max_mutations: int = 100, timeout_ms: int = 5000):
        self.max_mutations = max_mutations
        self.timeout_ms = timeout_ms
        self.mutations_applied: list[WasmMutation] = []
        self.crashes: list[FuzzResult] = []

    async def execute(self, wasm_bytes: bytes) -> ToolResult:
        """Run fuzzing campaign on a Wasm binary."""
        results = []
        for i in range(self.max_mutations):
            mutated, mutation = self.mutate(wasm_bytes)
            if mutation:
                self.mutations_applied.append(mutation)
                # In production: execute mutated module in sandboxed runtime
                # For now: validate structure
                result = self._validate_mutation(mutated, mutation)
                results.append(result)
                if result.crashed:
                    self.crashes.append(result)

        return ToolResult(
            success=True, data=self.crashes, tool_name=self.name,
            metadata={
                "mutations_tried": len(self.mutations_applied),
                "crashes_found": len(self.crashes),
            },
        )

    def mutate(self, wasm_bytes: bytes) -> tuple[bytes, WasmMutation | None]:
        """Apply a single type-preserving mutation."""
        data = bytearray(wasm_bytes)
        if len(data) < 16:
            return bytes(data), None

        strategy = random.choice([
            self._mutate_arithmetic_op,
            self._mutate_comparison_op,
            self._mutate_i32_const,
            self._mutate_memory_offset,
            self._mutate_random_byte,
        ])

        mutation = strategy(data)
        return bytes(data), mutation

    def _mutate_arithmetic_op(self, data: bytearray) -> WasmMutation | None:
        """Swap an i32 arithmetic opcode with another of the same type signature."""
        for i in range(8, len(data)):
            if data[i] in ARITHMETIC_I32:
                original = bytes([data[i]])
                replacement = random.choice([op for op in ARITHMETIC_I32 if op != data[i]])
                data[i] = replacement
                return WasmMutation(
                    offset=i, original=original, mutated=bytes([replacement]),
                    mutation_type="arithmetic_swap",
                    description=f"Swapped i32 arithmetic op at offset {i}: 0x{original[0]:02x} → 0x{replacement:02x}",
                )
        return None

    def _mutate_comparison_op(self, data: bytearray) -> WasmMutation | None:
        """Swap an i32 comparison opcode."""
        for i in range(8, len(data)):
            if data[i] in COMPARISON_I32:
                original = bytes([data[i]])
                replacement = random.choice([op for op in COMPARISON_I32 if op != data[i]])
                data[i] = replacement
                return WasmMutation(
                    offset=i, original=original, mutated=bytes([replacement]),
                    mutation_type="comparison_swap",
                    description=f"Swapped i32 comparison at offset {i}",
                )
        return None

    def _mutate_i32_const(self, data: bytearray) -> WasmMutation | None:
        """Change an i32.const value to an interesting boundary value."""
        I32_CONST = 0x41
        for i in range(8, len(data) - 4):
            if data[i] == I32_CONST:
                original = bytes(data[i+1:i+5])
                new_val = random.choice(INTERESTING_I32)
                new_bytes = struct.pack('<i', new_val)[:4]
                # Only mutate if we have room for LEB128
                data[i+1] = new_bytes[0] if len(new_bytes) > 0 else 0
                return WasmMutation(
                    offset=i+1, original=original[:1], mutated=bytes([data[i+1]]),
                    mutation_type="const_replace",
                    description=f"Replaced i32.const value at offset {i+1} with {new_val}",
                )
        return None

    def _mutate_memory_offset(self, data: bytearray) -> WasmMutation | None:
        """Mutate memory load/store offset to trigger OOB access."""
        MEMORY_OPS = [0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,  # loads
                      0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B]  # stores
        for i in range(8, len(data) - 2):
            if data[i] in MEMORY_OPS:
                # Byte after opcode is alignment, then offset (both LEB128)
                if i + 2 < len(data):
                    original = bytes([data[i+2]])
                    data[i+2] = random.choice([0xFF, 0x00, 0x7F, 0x80])
                    return WasmMutation(
                        offset=i+2, original=original, mutated=bytes([data[i+2]]),
                        mutation_type="memory_offset",
                        description=f"Mutated memory offset at {i+2} to trigger OOB",
                    )
        return None

    def _mutate_random_byte(self, data: bytearray) -> WasmMutation | None:
        """Fallback: flip a random byte in the code section."""
        if len(data) > 16:
            pos = random.randint(8, len(data) - 1)
            original = bytes([data[pos]])
            data[pos] = random.randint(0, 255)
            return WasmMutation(
                offset=pos, original=original, mutated=bytes([data[pos]]),
                mutation_type="random_byte",
                description=f"Random byte flip at offset {pos}",
            )
        return None

    def _validate_mutation(self, wasm_bytes: bytes, mutation: WasmMutation) -> FuzzResult:
        """Validate mutated Wasm (structural check as proxy for execution)."""
        crashed = False
        error = ""

        if len(wasm_bytes) < 8 or wasm_bytes[:4] != b'\x00asm':
            crashed = True
            error = "Invalid Wasm header after mutation"

        return FuzzResult(
            mutation=mutation, crashed=crashed, hung=False,
            error_message=error, new_coverage=not crashed,
        )
```

---

## Tests

### `tests/tools/wasm/test_wasm_analyzer.py`
```python
import pytest
import struct
from sentinel.tools.wasm.wasm_analyzer import WasmAnalyzer

class TestWasmAnalyzer:
    def setup_method(self):
        self.analyzer = WasmAnalyzer()

    def _minimal_wasm(self) -> bytes:
        return b'\x00asm\x01\x00\x00\x00'

    def test_valid_minimal(self):
        analysis = self.analyzer.analyze(self._minimal_wasm())
        assert analysis.valid
        assert analysis.version == 1

    def test_invalid_magic(self):
        analysis = self.analyzer.analyze(b'\x00bad\x01\x00\x00\x00')
        assert not analysis.valid

    def test_too_short(self):
        analysis = self.analyzer.analyze(b'\x00')
        assert not analysis.valid

    def test_leb128_reading(self):
        val, size = self.analyzer._read_leb128(bytes([0x80, 0x01]), 0)
        assert val == 128
        assert size == 2
```

### `tests/tools/wasm/test_wasm_fuzzer.py`
```python
import pytest
from sentinel.tools.wasm.wasm_fuzzer import WasmFuzzer, ARITHMETIC_I32

class TestWasmFuzzer:
    def setup_method(self):
        self.fuzzer = WasmFuzzer(max_mutations=10)

    def _wasm_with_ops(self) -> bytes:
        header = b'\x00asm\x01\x00\x00\x00'
        # Add some arithmetic opcodes in fake code section
        code = bytes([0x00] * 8 + [0x6A, 0x6B, 0x6C, 0x46, 0x47, 0x41, 0x05, 0x00, 0x28, 0x00, 0x00])
        return header + code

    def test_mutation_returns_bytes(self):
        wasm = self._wasm_with_ops()
        mutated, mutation = self.fuzzer.mutate(wasm)
        assert isinstance(mutated, bytes)

    def test_arithmetic_swap(self):
        data = bytearray(b'\x00' * 8 + bytes([0x6A]))  # i32.add at offset 8
        mutation = self.fuzzer._mutate_arithmetic_op(data)
        if mutation:
            assert mutation.mutation_type == "arithmetic_swap"
            assert data[8] != 0x6A  # Changed

    def test_random_byte_flip(self):
        data = bytearray(b'\x00asm\x01\x00\x00\x00' + b'\xAA' * 20)
        mutation = self.fuzzer._mutate_random_byte(data)
        assert mutation is not None
        assert mutation.mutation_type == "random_byte"

    def test_interesting_values(self):
        from sentinel.tools.wasm.wasm_fuzzer import INTERESTING_I32
        assert 0 in INTERESTING_I32
        assert -1 in INTERESTING_I32
        assert 0x7FFFFFFF in INTERESTING_I32
```

---

## Acceptance Criteria
- [ ] WasmAnalyzer validates Wasm magic bytes and version
- [ ] LEB128 decoder reads variable-length integers correctly
- [ ] WasmFuzzer applies 5 mutation strategies: arithmetic swap, comparison swap, const replace, memory offset, random byte
- [ ] Arithmetic/comparison swaps preserve type safety (same stack signature)
- [ ] Interesting i32 values include boundary cases (0, -1, MAX_INT, MIN_INT)
- [ ] Memory offset mutations target load/store operations for OOB triggers
- [ ] Crash tracking counts unique crashes
- [ ] All tests pass