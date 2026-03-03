"""
WebAssembly binary analyser — parse Wasm structure for attack-surface mapping.

Parses: magic header, version, section headers, type/import/function/export/code sections.
Uses LEB128 decoding for variable-length integers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from sentinel.core import get_logger

logger = get_logger(__name__)

WASM_MAGIC = b"\x00asm"
WASM_VERSION = b"\x01\x00\x00\x00"


class SectionID(IntEnum):
    CUSTOM = 0
    TYPE = 1
    IMPORT = 2
    FUNCTION = 3
    TABLE = 4
    MEMORY = 5
    GLOBAL = 6
    EXPORT = 7
    START = 8
    ELEMENT = 9
    CODE = 10
    DATA = 11


@dataclass
class WasmExport:
    name: str
    kind: int  # 0=func, 1=table, 2=memory, 3=global
    index: int


@dataclass
class WasmImport:
    module: str
    name: str
    kind: int
    index: int = 0


@dataclass
class WasmFunction:
    index: int
    type_index: int
    body_offset: int = 0
    body_size: int = 0


@dataclass
class WasmModule:
    valid: bool = False
    version: int = 0
    sections: dict[int, tuple[int, int]] = field(default_factory=dict)  # id -> (offset, size)
    exports: list[WasmExport] = field(default_factory=list)
    imports: list[WasmImport] = field(default_factory=list)
    functions: list[WasmFunction] = field(default_factory=list)
    type_count: int = 0
    memory_pages: int = 0
    export_names: list[str] = field(default_factory=list)


def decode_leb128_unsigned(data: bytes, offset: int) -> tuple[int, int]:
    """Decode unsigned LEB128. Returns (value, bytes_consumed)."""
    result = 0
    shift = 0
    consumed = 0
    while offset < len(data):
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        consumed += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
        if consumed > 5:
            break
    return result, consumed


class WasmAnalyzer:
    """Parse Wasm binary and extract structure."""

    def analyze(self, wasm_bytes: bytes) -> WasmModule:
        module = WasmModule()

        if len(wasm_bytes) < 8:
            return module
        if wasm_bytes[:4] != WASM_MAGIC:
            return module
        if wasm_bytes[4:8] != WASM_VERSION:
            return module

        module.valid = True
        module.version = 1

        offset = 8
        while offset < len(wasm_bytes):
            if offset >= len(wasm_bytes):
                break

            section_id = wasm_bytes[offset]
            offset += 1

            size, consumed = decode_leb128_unsigned(wasm_bytes, offset)
            offset += consumed

            section_start = offset
            module.sections[section_id] = (section_start, size)

            try:
                if section_id == SectionID.TYPE:
                    self._parse_type_section(wasm_bytes, section_start, size, module)
                elif section_id == SectionID.IMPORT:
                    self._parse_import_section(wasm_bytes, section_start, size, module)
                elif section_id == SectionID.EXPORT:
                    self._parse_export_section(wasm_bytes, section_start, size, module)
                elif section_id == SectionID.MEMORY:
                    self._parse_memory_section(wasm_bytes, section_start, size, module)
                elif section_id == SectionID.CODE:
                    self._parse_code_section(wasm_bytes, section_start, size, module)
            except (IndexError, ValueError):
                logger.warning("wasm_section_parse_error", section_id=section_id)

            offset = section_start + size

        module.export_names = [e.name for e in module.exports]
        return module

    def _parse_type_section(self, data: bytes, offset: int, size: int, module: WasmModule):
        count, consumed = decode_leb128_unsigned(data, offset)
        module.type_count = count

    def _parse_import_section(self, data: bytes, offset: int, size: int, module: WasmModule):
        count, consumed = decode_leb128_unsigned(data, offset)
        pos = offset + consumed
        for _ in range(count):
            mod_len, c = decode_leb128_unsigned(data, pos)
            pos += c
            mod_name = data[pos:pos + mod_len].decode("utf-8", errors="replace")
            pos += mod_len

            name_len, c = decode_leb128_unsigned(data, pos)
            pos += c
            name = data[pos:pos + name_len].decode("utf-8", errors="replace")
            pos += name_len

            kind = data[pos]
            pos += 1

            # Skip type index based on kind
            if kind == 0:  # func
                _, c = decode_leb128_unsigned(data, pos)
                pos += c
            elif kind == 1:  # table
                pos += 1  # elem type
                _, c = decode_leb128_unsigned(data, pos)
                pos += c
                if data[pos - c] & 0x01:
                    _, c2 = decode_leb128_unsigned(data, pos)
                    pos += c2
            elif kind == 2:  # memory
                flag = data[pos]
                pos += 1
                _, c = decode_leb128_unsigned(data, pos)
                pos += c
                if flag & 0x01:
                    _, c2 = decode_leb128_unsigned(data, pos)
                    pos += c2
            elif kind == 3:  # global
                pos += 1  # value type
                pos += 1  # mutability

            module.imports.append(WasmImport(module=mod_name, name=name, kind=kind))

    def _parse_export_section(self, data: bytes, offset: int, size: int, module: WasmModule):
        count, consumed = decode_leb128_unsigned(data, offset)
        pos = offset + consumed
        for _ in range(count):
            name_len, c = decode_leb128_unsigned(data, pos)
            pos += c
            name = data[pos:pos + name_len].decode("utf-8", errors="replace")
            pos += name_len
            kind = data[pos]
            pos += 1
            index, c = decode_leb128_unsigned(data, pos)
            pos += c
            module.exports.append(WasmExport(name=name, kind=kind, index=index))

    def _parse_memory_section(self, data: bytes, offset: int, size: int, module: WasmModule):
        count, consumed = decode_leb128_unsigned(data, offset)
        pos = offset + consumed
        if count > 0:
            flag = data[pos]
            pos += 1
            pages, _ = decode_leb128_unsigned(data, pos)
            module.memory_pages = pages

    def _parse_code_section(self, data: bytes, offset: int, size: int, module: WasmModule):
        count, consumed = decode_leb128_unsigned(data, offset)
        pos = offset + consumed
        for i in range(count):
            body_size, c = decode_leb128_unsigned(data, pos)
            pos += c
            module.functions.append(WasmFunction(
                index=i, type_index=0, body_offset=pos, body_size=body_size,
            ))
            pos += body_size
