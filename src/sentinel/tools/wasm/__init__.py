"""WebAssembly binary analysis and type-aware fuzzing."""

from sentinel.tools.wasm.wasm_analyzer import WasmAnalyzer, WasmModule
from sentinel.tools.wasm.wasm_fuzzer import WasmFuzzer

__all__ = ["WasmAnalyzer", "WasmModule", "WasmFuzzer"]
