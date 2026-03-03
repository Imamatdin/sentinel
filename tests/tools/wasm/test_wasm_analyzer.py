"""Tests for WasmAnalyzer."""

from sentinel.tools.wasm.wasm_analyzer import (
    WasmAnalyzer, decode_leb128_unsigned, WASM_MAGIC, WASM_VERSION, SectionID,
)


def _build_minimal_wasm() -> bytes:
    """Build a minimal valid Wasm binary with one export."""
    buf = bytearray()
    buf.extend(WASM_MAGIC)
    buf.extend(WASM_VERSION)

    # Type section: 1 type, func () -> ()
    type_payload = bytes([1, 0x60, 0, 0])
    buf.append(SectionID.TYPE)
    buf.append(len(type_payload))
    buf.extend(type_payload)

    # Function section: 1 function, type index 0
    func_payload = bytes([1, 0])
    buf.append(SectionID.FUNCTION)
    buf.append(len(func_payload))
    buf.extend(func_payload)

    # Export section: export "main" as function 0
    name = b"main"
    export_payload = bytearray([1])  # 1 export
    export_payload.append(len(name))
    export_payload.extend(name)
    export_payload.append(0)  # func kind
    export_payload.append(0)  # func index
    buf.append(SectionID.EXPORT)
    buf.append(len(export_payload))
    buf.extend(export_payload)

    # Code section: 1 body, empty function (just end opcode)
    code_body = bytes([0, 0x0B])  # 0 locals, end
    code_payload = bytearray([1])  # 1 body
    code_payload.append(len(code_body))
    code_payload.extend(code_body)
    buf.append(SectionID.CODE)
    buf.append(len(code_payload))
    buf.extend(code_payload)

    return bytes(buf)


class TestLEB128:
    def test_decode_single_byte(self):
        val, consumed = decode_leb128_unsigned(bytes([42]), 0)
        assert val == 42
        assert consumed == 1

    def test_decode_multi_byte(self):
        val, consumed = decode_leb128_unsigned(bytes([0xE5, 0x8E, 0x26]), 0)
        assert val == 624485
        assert consumed == 3


class TestWasmAnalyzer:
    def setup_method(self):
        self.analyzer = WasmAnalyzer()

    def test_invalid_magic(self):
        module = self.analyzer.analyze(b"\x00\x00\x00\x00\x01\x00\x00\x00")
        assert not module.valid

    def test_too_short(self):
        module = self.analyzer.analyze(b"\x00asm")
        assert not module.valid

    def test_valid_minimal(self):
        wasm = _build_minimal_wasm()
        module = self.analyzer.analyze(wasm)
        assert module.valid
        assert module.version == 1

    def test_exports_parsed(self):
        wasm = _build_minimal_wasm()
        module = self.analyzer.analyze(wasm)
        assert len(module.exports) == 1
        assert module.exports[0].name == "main"
        assert module.exports[0].kind == 0

    def test_type_count(self):
        wasm = _build_minimal_wasm()
        module = self.analyzer.analyze(wasm)
        assert module.type_count == 1

    def test_code_section_parsed(self):
        wasm = _build_minimal_wasm()
        module = self.analyzer.analyze(wasm)
        assert len(module.functions) == 1
        assert module.functions[0].body_size > 0

    def test_export_names_populated(self):
        wasm = _build_minimal_wasm()
        module = self.analyzer.analyze(wasm)
        assert "main" in module.export_names
