# LEVEL 12: gRPC & Protobuf Fuzzer

## Context
gRPC APIs are increasingly common but ignored by most DAST tools. This level auto-discovers gRPC services via server reflection, generates requests from .proto schemas, and fuzzes fields with type-aware mutations.

Research: Block 12 (Unconventional Attack Surfaces), Block 8 (API Fuzzing).

## Why
gRPC uses binary Protocol Buffers — HTTP-based scanners can't parse them. Sentinel gains coverage that XBOW and most competitors completely lack.

---

## Files to Create

### `src/sentinel/tools/grpc/__init__.py`
```python
"""gRPC security testing tools."""
```

### `src/sentinel/tools/grpc/grpc_fuzzer.py`
```python
"""
gRPC Fuzzer — Discovers and fuzz-tests gRPC services.

Strategy:
1. Use gRPC server reflection to discover services and methods
2. Parse message descriptors to understand field types
3. Generate valid baseline requests
4. Mutate fields with type-aware fuzz values
5. Detect errors, crashes, and unexpected behaviors
"""
import asyncio
import json
from dataclasses import dataclass, field
from typing import Any
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)

# Type-aware fuzz values for protobuf field types
FUZZ_VALUES = {
    "string": [
        "",                          # Empty
        "A" * 10000,                 # Long string
        "' OR '1'='1",              # SQLi
        "<script>alert(1)</script>", # XSS
        "../../../etc/passwd",       # Path traversal
        "\x00\x01\x02",            # Null bytes
        "{{7*7}}",                  # Template injection
    ],
    "int32": [0, -1, 2147483647, -2147483648, 1],
    "int64": [0, -1, 9223372036854775807, -9223372036854775808],
    "uint32": [0, 4294967295, 1],
    "uint64": [0, 18446744073709551615],
    "float": [0.0, -1.0, float("inf"), float("-inf"), float("nan")],
    "double": [0.0, -1.0, 1e308, -1e308, float("nan")],
    "bool": [True, False],
    "bytes": [b"", b"\x00" * 1000, b"\xff" * 100],
}


@dataclass
class GRPCService:
    name: str
    methods: list[dict]  # [{"name": str, "input_type": str, "output_type": str, "fields": [...]}]


@dataclass
class GRPCFinding:
    service: str
    method: str
    field_name: str
    fuzz_value: Any
    error_type: str      # "crash", "error_leak", "unexpected_success", "timeout"
    response_code: str
    response_detail: str
    severity: str


class GRPCFuzzer(BaseTool):
    name = "grpc_fuzz"
    description = "Fuzz gRPC services via server reflection"
    
    async def discover_services(self, host: str, port: int = 50051) -> list[GRPCService]:
        """
        Use gRPC server reflection to discover available services.
        Requires grpcurl or grpc_cli installed.
        """
        try:
            proc = await asyncio.create_subprocess_exec(
                "grpcurl", "-plaintext", f"{host}:{port}", "list",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            
            services = []
            for line in stdout.decode().strip().split("\n"):
                svc_name = line.strip()
                if svc_name and not svc_name.startswith("grpc.reflection"):
                    methods = await self._discover_methods(host, port, svc_name)
                    services.append(GRPCService(name=svc_name, methods=methods))
            
            return services
        except Exception as e:
            logger.error(f"gRPC discovery failed: {e}")
            return []
    
    async def _discover_methods(self, host: str, port: int, service: str) -> list[dict]:
        """Discover methods for a specific service."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "grpcurl", "-plaintext", f"{host}:{port}", "describe", service,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            
            methods = []
            for line in stdout.decode().split("\n"):
                line = line.strip()
                if "rpc " in line.lower():
                    # Parse: rpc MethodName ( .InputType ) returns ( .OutputType )
                    parts = line.split()
                    if len(parts) >= 6:
                        methods.append({
                            "name": parts[1],
                            "input_type": parts[3].strip("()."),
                            "output_type": parts[7].strip("().") if len(parts) > 7 else "",
                        })
            return methods
        except Exception:
            return []
    
    async def execute(self, host: str, port: int = 50051, 
                      services: list[GRPCService] = None) -> ToolResult:
        """Fuzz all discovered gRPC methods."""
        if not services:
            services = await self.discover_services(host, port)
        
        if not services:
            return ToolResult(success=False, error="No gRPC services found", tool_name=self.name)
        
        findings = []
        for svc in services:
            for method in svc.methods:
                method_findings = await self._fuzz_method(
                    host, port, svc.name, method
                )
                findings.extend(method_findings)
        
        return ToolResult(
            success=True,
            data=findings,
            tool_name=self.name,
            metadata={
                "services_found": len(services),
                "methods_fuzzed": sum(len(s.methods) for s in services),
                "findings": len(findings),
            },
        )
    
    async def _fuzz_method(self, host, port, service, method) -> list[GRPCFinding]:
        """Fuzz a single gRPC method with type-aware mutations."""
        findings = []
        
        # For each fuzz category, try sending malicious values
        for field_type, values in FUZZ_VALUES.items():
            if field_type == "bytes":
                continue  # Skip bytes for grpcurl-based fuzzing
            
            for fuzz_val in values:
                # Build JSON payload (grpcurl accepts JSON for protobuf)
                payload = json.dumps({"value": fuzz_val} if not isinstance(fuzz_val, bytes) else {})
                
                finding = await self._send_fuzz(
                    host, port, f"{service}/{method['name']}",
                    payload, field_type, fuzz_val, service
                )
                if finding:
                    findings.append(finding)
        
        return findings
    
    async def _send_fuzz(self, host, port, full_method, payload, 
                         field_type, fuzz_val, service) -> GRPCFinding | None:
        """Send a fuzzed request and analyze the response."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "grpcurl", "-plaintext",
                "-d", payload,
                f"{host}:{port}", full_method,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            
            stdout_str = stdout.decode()
            stderr_str = stderr.decode()
            
            # Analyze for interesting errors
            if self._is_interesting_error(stderr_str, stdout_str):
                return GRPCFinding(
                    service=service,
                    method=full_method,
                    field_name=field_type,
                    fuzz_value=str(fuzz_val)[:200],
                    error_type=self._classify_error(stderr_str),
                    response_code=self._extract_grpc_code(stderr_str),
                    response_detail=stderr_str[:500],
                    severity=self._severity_from_error(stderr_str),
                )
            return None
        except asyncio.TimeoutError:
            return GRPCFinding(
                service=service, method=full_method,
                field_name=field_type, fuzz_value=str(fuzz_val)[:200],
                error_type="timeout", response_code="DEADLINE_EXCEEDED",
                response_detail="Request timed out — possible DoS",
                severity="medium",
            )
        except Exception:
            return None
    
    def _is_interesting_error(self, stderr: str, stdout: str) -> bool:
        """Check if the error reveals something interesting."""
        interesting_patterns = [
            "internal", "panic", "stack trace", "null pointer",
            "sql", "syntax error", "permission", "unauthorized",
            "segfault", "core dump", "exception", "traceback",
        ]
        combined = (stderr + stdout).lower()
        return any(p in combined for p in interesting_patterns)
    
    def _classify_error(self, stderr: str) -> str:
        lower = stderr.lower()
        if "panic" in lower or "segfault" in lower:
            return "crash"
        if "sql" in lower or "syntax" in lower:
            return "error_leak"
        if "unauthorized" in lower or "permission" in lower:
            return "auth_error"
        return "unexpected_error"
    
    def _extract_grpc_code(self, stderr: str) -> str:
        if "INTERNAL" in stderr: return "INTERNAL"
        if "UNAVAILABLE" in stderr: return "UNAVAILABLE"
        if "UNAUTHENTICATED" in stderr: return "UNAUTHENTICATED"
        if "PERMISSION_DENIED" in stderr: return "PERMISSION_DENIED"
        return "UNKNOWN"
    
    def _severity_from_error(self, stderr: str) -> str:
        if "panic" in stderr.lower() or "segfault" in stderr.lower():
            return "critical"
        if "sql" in stderr.lower():
            return "high"
        return "medium"
```

---

## Tests

### `tests/tools/grpc/test_grpc_fuzzer.py`
```python
import pytest
from sentinel.tools.grpc.grpc_fuzzer import GRPCFuzzer, FUZZ_VALUES

class TestGRPCFuzzer:
    def setup_method(self):
        self.fuzzer = GRPCFuzzer()
    
    def test_fuzz_values_cover_types(self):
        assert "string" in FUZZ_VALUES
        assert "int32" in FUZZ_VALUES
        assert "float" in FUZZ_VALUES
        assert len(FUZZ_VALUES["string"]) >= 5
    
    def test_interesting_error_detection(self):
        assert self.fuzzer._is_interesting_error("ERROR: panic: nil pointer", "")
        assert self.fuzzer._is_interesting_error("", "SQL syntax error near")
        assert not self.fuzzer._is_interesting_error("OK", "success")
    
    def test_error_classification(self):
        assert self.fuzzer._classify_error("panic: runtime error") == "crash"
        assert self.fuzzer._classify_error("SQL syntax error") == "error_leak"
        assert self.fuzzer._classify_error("unauthorized access") == "auth_error"
    
    def test_severity(self):
        assert self.fuzzer._severity_from_error("panic in handler") == "critical"
        assert self.fuzzer._severity_from_error("sql error") == "high"
        assert self.fuzzer._severity_from_error("generic error") == "medium"
```

---

## Acceptance Criteria
- [ ] gRPC service discovery via server reflection works with grpcurl
- [ ] Type-aware fuzz values for all major protobuf types
- [ ] Interesting errors (panics, SQL leaks, auth failures) detected and classified
- [ ] Findings include method, fuzz value, error type, and severity
- [ ] All tests pass