"""Tests for WebSocket fuzzer."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sentinel.tools.websocket.ws_fuzzer import (
    WebSocketFuzzer,
    WSFinding,
    FUZZ_PAYLOADS,
    EVIL_ORIGINS,
)


class TestVulnIndicators:
    """Test the detection logic without needing a WebSocket server."""

    def setup_method(self):
        self.fuzzer = WebSocketFuzzer()

    # --- SQLi detection ---
    def test_sqli_syntax_error(self):
        assert self.fuzzer._check_vuln_indicators(
            "SQL syntax error near '", "sqli", "' OR 1=1"
        )

    def test_sqli_mysql(self):
        assert self.fuzzer._check_vuln_indicators(
            "ERROR: MySQL server error", "sqli", "admin'--"
        )

    def test_sqli_postgresql(self):
        assert self.fuzzer._check_vuln_indicators(
            "ERROR:  postgresql syntax error at position 42", "sqli", "1; DROP TABLE"
        )

    def test_sqli_sqlite(self):
        assert self.fuzzer._check_vuln_indicators(
            "sqlite3.OperationalError: near", "sqli", "' OR '1'='1"
        )

    def test_sqli_clean_response(self):
        assert not self.fuzzer._check_vuln_indicators(
            "OK", "sqli", "' OR 1=1"
        )

    def test_sqli_json_response(self):
        assert not self.fuzzer._check_vuln_indicators(
            '{"status": "ok", "data": []}', "sqli", "admin'--"
        )

    # --- XSS detection ---
    def test_xss_reflected(self):
        payload = "<script>alert(1)</script>"
        assert self.fuzzer._check_vuln_indicators(
            f"echo: {payload}", "xss", payload
        )

    def test_xss_encoded(self):
        payload = "<script>alert(1)</script>"
        assert not self.fuzzer._check_vuln_indicators(
            "echo: &lt;script&gt;alert(1)&lt;/script&gt;", "xss", payload
        )

    def test_xss_partial_reflection(self):
        payload = "<img src=x onerror=alert(1)>"
        assert not self.fuzzer._check_vuln_indicators(
            "Invalid input: img src", "xss", payload
        )

    # --- Command injection detection ---
    def test_command_passwd(self):
        assert self.fuzzer._check_vuln_indicators(
            "root:x:0:0:root:/root:/bin/bash", "command", "; cat /etc/passwd"
        )

    def test_command_uid(self):
        assert self.fuzzer._check_vuln_indicators(
            "uid=1000(user) gid=1000", "command", "$(whoami)"
        )

    def test_command_clean(self):
        assert not self.fuzzer._check_vuln_indicators(
            "Invalid command", "command", "; ls"
        )

    def test_command_not_recognized(self):
        assert self.fuzzer._check_vuln_indicators(
            "'ls' is not recognized as an internal or external command",
            "command", "; ls"
        )

    # --- Path traversal detection ---
    def test_path_traversal_passwd(self):
        assert self.fuzzer._check_vuln_indicators(
            "root:x:0:0:", "path_traversal", "../../../etc/passwd"
        )

    def test_path_traversal_clean(self):
        assert not self.fuzzer._check_vuln_indicators(
            "File not found", "path_traversal", "../../../etc/passwd"
        )

    # --- NoSQLi detection ---
    def test_nosqli_data_leak(self):
        big_data = json.dumps({"users": [{"name": f"user{i}"} for i in range(10)]})
        assert self.fuzzer._check_vuln_indicators(
            big_data, "nosqli", '{"$gt": ""}'
        )

    def test_nosqli_no_data(self):
        assert not self.fuzzer._check_vuln_indicators(
            '{"error": "bad"}', "nosqli", '{"$gt": ""}'
        )

    # --- Unknown category ---
    def test_unknown_category_returns_false(self):
        assert not self.fuzzer._check_vuln_indicators(
            "anything", "unknown_category", "payload"
        )


class TestFuzzPayloads:
    def test_xss_payloads_exist(self):
        assert len(FUZZ_PAYLOADS["xss"]) >= 3

    def test_sqli_payloads_exist(self):
        assert len(FUZZ_PAYLOADS["sqli"]) >= 3

    def test_command_payloads_exist(self):
        assert len(FUZZ_PAYLOADS["command"]) >= 3

    def test_path_traversal_payloads_exist(self):
        assert len(FUZZ_PAYLOADS["path_traversal"]) >= 2

    def test_nosqli_payloads_exist(self):
        assert len(FUZZ_PAYLOADS["nosqli"]) >= 2

    def test_all_categories_have_payloads(self):
        for category, payloads in FUZZ_PAYLOADS.items():
            assert len(payloads) > 0, f"No payloads for {category}"


class TestWSFinding:
    def test_finding_fields(self):
        f = WSFinding(
            url="ws://localhost:8080",
            finding_type="xss",
            severity="high",
            payload_sent="<script>alert(1)</script>",
            response_received="echo: <script>alert(1)</script>",
            description="XSS reflected",
        )
        assert f.url == "ws://localhost:8080"
        assert f.finding_type == "xss"
        assert f.severity == "high"
        assert "<script>" in f.payload_sent
        assert "<script>" in f.response_received

    def test_finding_to_dict(self):
        f = WSFinding(
            url="ws://localhost:8080",
            finding_type="cswsh",
            severity="high",
            payload_sent="Origin: https://evil.com",
            response_received="Connection accepted",
            description="CSWSH detected",
        )
        d = WebSocketFuzzer._finding_to_dict(f)
        assert d["finding_type"] == "cswsh"
        assert d["severity"] == "high"
        assert d["payload_sent"] == "Origin: https://evil.com"


class TestSeverityMapping:
    def test_sqli_critical(self):
        assert WebSocketFuzzer._severity_for_category("sqli") == "critical"

    def test_command_critical(self):
        assert WebSocketFuzzer._severity_for_category("command") == "critical"

    def test_xss_high(self):
        assert WebSocketFuzzer._severity_for_category("xss") == "high"

    def test_cswsh_high(self):
        assert WebSocketFuzzer._severity_for_category("cswsh") == "high"

    def test_unknown_medium(self):
        assert WebSocketFuzzer._severity_for_category("something") == "medium"


class TestEvilOrigins:
    def test_has_evil_origins(self):
        assert len(EVIL_ORIGINS) >= 3

    def test_includes_evil_com(self):
        assert "https://evil.com" in EVIL_ORIGINS

    def test_includes_null(self):
        assert "null" in EVIL_ORIGINS


class TestFuzzerExecution:
    """Test the execute method with mocked WebSocket connections."""

    @pytest.mark.asyncio
    async def test_execute_returns_tool_output(self):
        fuzzer = WebSocketFuzzer(timeout=1.0)
        # Mock websockets.connect to raise ConnectionRefused
        with patch("sentinel.tools.websocket.ws_fuzzer.websockets") as mock_ws:
            mock_ws.connect.side_effect = ConnectionRefusedError("no server")
            result = await fuzzer.execute("ws://localhost:9999")
            assert result.success is True
            assert result.tool_name == "ws_fuzz"
            assert "total_findings" in result.data
            assert result.data["url"] == "ws://localhost:9999"

    @pytest.mark.asyncio
    async def test_execute_with_specific_categories(self):
        fuzzer = WebSocketFuzzer(timeout=1.0)
        with patch("sentinel.tools.websocket.ws_fuzzer.websockets") as mock_ws:
            mock_ws.connect.side_effect = ConnectionRefusedError()
            result = await fuzzer.execute(
                "ws://localhost:9999", categories=["xss"]
            )
            assert result.data["categories_tested"] == ["xss"]

    @pytest.mark.asyncio
    async def test_cswsh_detection_when_origin_accepted(self):
        fuzzer = WebSocketFuzzer(timeout=1.0)

        mock_ws = AsyncMock()
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "sentinel.tools.websocket.ws_fuzzer.websockets.connect",
            return_value=mock_ws,
        ):
            finding = await fuzzer._test_origin_validation("ws://localhost:8080")
            assert finding is not None
            assert finding.finding_type == "cswsh"
            assert finding.severity == "high"
            assert "evil.com" in finding.payload_sent

    @pytest.mark.asyncio
    async def test_cswsh_no_finding_when_rejected(self):
        fuzzer = WebSocketFuzzer(timeout=1.0)

        with patch(
            "sentinel.tools.websocket.ws_fuzzer.websockets.connect",
            side_effect=ConnectionRefusedError("Origin rejected"),
        ):
            finding = await fuzzer._test_origin_validation("ws://localhost:8080")
            assert finding is None

    @pytest.mark.asyncio
    async def test_fuzz_message_detects_sqli(self):
        fuzzer = WebSocketFuzzer(timeout=1.0)

        mock_ws = AsyncMock()
        mock_ws.__aenter__ = AsyncMock(return_value=mock_ws)
        mock_ws.__aexit__ = AsyncMock(return_value=False)
        mock_ws.send = AsyncMock()
        mock_ws.recv = AsyncMock(return_value="SQL syntax error near '")

        with patch(
            "sentinel.tools.websocket.ws_fuzzer.websockets.connect",
            return_value=mock_ws,
        ):
            finding = await fuzzer._fuzz_message(
                "ws://localhost:8080", "' OR '1'='1", "sqli"
            )
            assert finding is not None
            assert finding.finding_type == "sqli"
            assert finding.severity == "critical"
            assert "SQL syntax error" in finding.response_received
