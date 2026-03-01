import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from sentinel.tools.grpc.grpc_fuzzer import (
    GRPCFuzzer, GRPCService, GRPCFinding, FUZZ_VALUES,
)


class TestGRPCFuzzer:
    def setup_method(self):
        self.fuzzer = GRPCFuzzer()

    def test_fuzz_values_cover_types(self):
        assert "string" in FUZZ_VALUES
        assert "int32" in FUZZ_VALUES
        assert "int64" in FUZZ_VALUES
        assert "uint32" in FUZZ_VALUES
        assert "uint64" in FUZZ_VALUES
        assert "float" in FUZZ_VALUES
        assert "double" in FUZZ_VALUES
        assert "bool" in FUZZ_VALUES
        assert "bytes" in FUZZ_VALUES
        assert len(FUZZ_VALUES["string"]) >= 5

    def test_interesting_error_detection(self):
        assert self.fuzzer._is_interesting_error("ERROR: panic: nil pointer", "")
        assert self.fuzzer._is_interesting_error("", "SQL syntax error near")
        assert self.fuzzer._is_interesting_error("stack trace follows", "")
        assert self.fuzzer._is_interesting_error("", "traceback (most recent call)")
        assert not self.fuzzer._is_interesting_error("OK", "success")
        assert not self.fuzzer._is_interesting_error("", "")

    def test_error_classification(self):
        assert self.fuzzer._classify_error("panic: runtime error") == "crash"
        assert self.fuzzer._classify_error("segfault in handler") == "crash"
        assert self.fuzzer._classify_error("SQL syntax error") == "error_leak"
        assert self.fuzzer._classify_error("unauthorized access") == "auth_error"
        assert self.fuzzer._classify_error("permission denied") == "auth_error"
        assert self.fuzzer._classify_error("generic error") == "unexpected_error"

    def test_severity(self):
        assert self.fuzzer._severity_from_error("panic in handler") == "critical"
        assert self.fuzzer._severity_from_error("segfault detected") == "critical"
        assert self.fuzzer._severity_from_error("sql error") == "high"
        assert self.fuzzer._severity_from_error("generic error") == "medium"

    def test_grpc_code_extraction(self):
        assert self.fuzzer._extract_grpc_code("code: INTERNAL") == "INTERNAL"
        assert self.fuzzer._extract_grpc_code("code: UNAVAILABLE") == "UNAVAILABLE"
        assert self.fuzzer._extract_grpc_code("code: UNAUTHENTICATED") == "UNAUTHENTICATED"
        assert self.fuzzer._extract_grpc_code("code: PERMISSION_DENIED") == "PERMISSION_DENIED"
        assert self.fuzzer._extract_grpc_code("something else") == "UNKNOWN"

    def test_tool_name(self):
        assert self.fuzzer.name == "grpc_fuzz"

    def test_service_dataclass(self):
        svc = GRPCService(
            name="myapp.UserService",
            methods=[{"name": "GetUser", "input_type": "GetUserRequest", "output_type": "User"}],
        )
        assert svc.name == "myapp.UserService"
        assert len(svc.methods) == 1

    def test_finding_dataclass(self):
        f = GRPCFinding(
            service="myapp.UserService",
            method="myapp.UserService/GetUser",
            field_name="string",
            fuzz_value="' OR '1'='1",
            error_type="error_leak",
            response_code="INTERNAL",
            response_detail="SQL syntax error",
            severity="high",
        )
        assert f.error_type == "error_leak"
        assert f.severity == "high"

    @pytest.mark.asyncio
    async def test_execute_no_services_returns_error(self):
        """When no services discovered, returns error ToolOutput."""
        with patch.object(self.fuzzer, "discover_services", new_callable=AsyncMock, return_value=[]):
            result = await self.fuzzer.execute(host="localhost")

        assert result.success is False
        assert "No gRPC services" in result.error

    @pytest.mark.asyncio
    async def test_execute_with_provided_services(self):
        """Can provide services directly instead of discovering."""
        svc = GRPCService(
            name="test.Service",
            methods=[{"name": "Echo", "input_type": "EchoReq", "output_type": "EchoResp"}],
        )

        # Mock _send_fuzz to return None (no interesting errors)
        with patch.object(self.fuzzer, "_send_fuzz", new_callable=AsyncMock, return_value=None):
            result = await self.fuzzer.execute(
                host="localhost", port=50051, services=[svc],
            )

        assert result.success is True
        assert result.metadata["services_found"] == 1
        assert result.metadata["methods_fuzzed"] == 1
        assert result.metadata["findings"] == 0

    @pytest.mark.asyncio
    async def test_execute_with_findings(self):
        """Findings from fuzzing are collected in output."""
        svc = GRPCService(
            name="test.Service",
            methods=[{"name": "Echo", "input_type": "EchoReq", "output_type": "EchoResp"}],
        )

        finding = GRPCFinding(
            service="test.Service",
            method="test.Service/Echo",
            field_name="string",
            fuzz_value="' OR '1'='1",
            error_type="error_leak",
            response_code="INTERNAL",
            response_detail="SQL syntax error",
            severity="high",
        )

        call_count = {"n": 0}

        async def mock_send_fuzz(*args, **kwargs):
            call_count["n"] += 1
            # Return a finding on the first call only
            if call_count["n"] == 1:
                return finding
            return None

        with patch.object(self.fuzzer, "_send_fuzz", side_effect=mock_send_fuzz):
            result = await self.fuzzer.execute(
                host="localhost", services=[svc],
            )

        assert result.success is True
        assert result.metadata["findings"] >= 1
        assert len(result.data["findings"]) >= 1
        assert result.data["findings"][0]["error_type"] == "error_leak"

    @pytest.mark.asyncio
    async def test_discover_services_grpcurl_missing(self):
        """If grpcurl is not installed, returns empty list."""
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("grpcurl")):
            services = await self.fuzzer.discover_services("localhost")

        assert services == []

    def test_string_fuzz_includes_injection_payloads(self):
        """String fuzz values include common injection patterns."""
        string_vals = FUZZ_VALUES["string"]
        has_sqli = any("OR" in str(v) for v in string_vals)
        has_xss = any("script" in str(v) for v in string_vals)
        has_traversal = any(".." in str(v) for v in string_vals)
        assert has_sqli
        assert has_xss
        assert has_traversal

    def test_int_fuzz_includes_boundaries(self):
        """Int fuzz values include boundary values."""
        assert 2147483647 in FUZZ_VALUES["int32"]   # INT32_MAX
        assert -2147483648 in FUZZ_VALUES["int32"]  # INT32_MIN
        assert 0 in FUZZ_VALUES["int32"]
        assert -1 in FUZZ_VALUES["int32"]
