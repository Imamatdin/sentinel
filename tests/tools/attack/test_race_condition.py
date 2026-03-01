import pytest
from unittest.mock import patch, MagicMock

from sentinel.tools.attack.race_condition import RaceConditionTester, RaceResult


class TestRaceCondition:
    def setup_method(self):
        self.tester = RaceConditionTester()

    def test_result_dataclass(self):
        r = RaceResult(
            endpoint="POST /apply-coupon",
            method="POST",
            num_requests=10,
            unique_responses=1,
            status_codes=[200] * 10,
            is_vulnerable=True,
            description="test",
            evidence=[],
        )
        assert r.is_vulnerable
        assert r.num_requests == 10

    def test_result_not_vulnerable(self):
        r = RaceResult(
            endpoint="POST /apply-coupon",
            method="POST",
            num_requests=10,
            unique_responses=10,
            status_codes=[200] + [409] * 9,
            is_vulnerable=False,
            description="test",
            evidence=[],
        )
        assert not r.is_vulnerable

    def test_tool_name(self):
        assert self.tester.name == "race_condition"

    @pytest.mark.asyncio
    async def test_execute_vulnerable(self):
        """All requests succeed -> vulnerable (race condition exploitable)."""
        # Build a fake HTTP response buffer: 10x "HTTP/1.1 200 OK\r\n\r\nbody"
        resp_part = "1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
        buffer = ("HTTP/1." + resp_part) * 10

        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[buffer.encode(), b""])
        mock_sock.sendall = MagicMock()
        mock_sock.connect = MagicMock()
        mock_sock.close = MagicMock()
        mock_sock.settimeout = MagicMock()

        with patch("socket.socket", return_value=mock_sock):
            result = await self.tester.execute(
                target_url="http://target.com/apply-coupon",
                method="POST",
                body='{"coupon":"SAVE10"}',
                num_concurrent=10,
            )

        assert result.success is True
        assert result.data["is_vulnerable"] is True
        assert len(result.data["status_codes"]) == 10
        assert all(s == 200 for s in result.data["status_codes"])

    @pytest.mark.asyncio
    async def test_execute_not_vulnerable(self):
        """Only first request succeeds, rest get 409 -> not easily exploitable."""
        parts = ["HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"]
        for _ in range(9):
            parts.append("HTTP/1.1 409 Conflict\r\nContent-Length: 5\r\n\r\nerror")
        buffer = "".join(parts)

        mock_sock = MagicMock()
        mock_sock.recv = MagicMock(side_effect=[buffer.encode(), b""])
        mock_sock.sendall = MagicMock()
        mock_sock.connect = MagicMock()
        mock_sock.close = MagicMock()
        mock_sock.settimeout = MagicMock()

        with patch("socket.socket", return_value=mock_sock):
            result = await self.tester.execute(
                target_url="http://target.com/apply-coupon",
                method="POST",
                num_concurrent=10,
            )

        assert result.success is True
        assert result.data["is_vulnerable"] is False

    @pytest.mark.asyncio
    async def test_execute_connection_error(self):
        """Socket connection failure -> returns error ToolOutput."""
        mock_sock = MagicMock()
        mock_sock.connect = MagicMock(side_effect=ConnectionRefusedError("refused"))
        mock_sock.close = MagicMock()
        mock_sock.settimeout = MagicMock()

        with patch("socket.socket", return_value=mock_sock):
            result = await self.tester.execute(
                target_url="http://target.com/test",
            )

        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_execute_https_wraps_ssl(self):
        """HTTPS target should wrap socket with SSL."""
        mock_sock = MagicMock()
        mock_ssl_sock = MagicMock()
        mock_ssl_sock.recv = MagicMock(side_effect=[b"HTTP/1.1 200 OK\r\n\r\n", b""])
        mock_ssl_sock.sendall = MagicMock()
        mock_ssl_sock.connect = MagicMock()
        mock_ssl_sock.close = MagicMock()

        mock_ctx = MagicMock()
        mock_ctx.wrap_socket = MagicMock(return_value=mock_ssl_sock)

        with patch("socket.socket", return_value=mock_sock), \
             patch("ssl.create_default_context", return_value=mock_ctx):
            result = await self.tester.execute(
                target_url="https://target.com/test",
            )

        mock_ctx.wrap_socket.assert_called_once()
        assert result.success is True

    @pytest.mark.asyncio
    async def test_builds_correct_payload(self):
        """Verify the raw HTTP request payload is constructed correctly."""
        sent_data = []

        mock_sock = MagicMock()
        mock_sock.sendall = MagicMock(side_effect=lambda d: sent_data.append(d))
        mock_sock.recv = MagicMock(side_effect=[b"HTTP/1.1 200 OK\r\n\r\n", b""])
        mock_sock.connect = MagicMock()
        mock_sock.close = MagicMock()
        mock_sock.settimeout = MagicMock()

        with patch("socket.socket", return_value=mock_sock):
            await self.tester.execute(
                target_url="http://example.com/api/coupon",
                method="POST",
                body='{"code":"SAVE"}',
                headers={"Authorization": "Bearer tok"},
                num_concurrent=3,
            )

        payload = sent_data[0].decode()
        # Should contain 3 copies of the request
        assert payload.count("POST /api/coupon HTTP/1.1") == 3
        assert "Authorization: Bearer tok" in payload
        assert "Host: example.com" in payload

    def test_evidence_fields(self):
        r = RaceResult(
            endpoint="POST /buy",
            method="POST",
            num_requests=5,
            unique_responses=1,
            status_codes=[200, 200, 200, 200, 200],
            is_vulnerable=True,
            description="All succeeded",
            evidence=["Status codes: [200, 200, 200, 200, 200]"],
        )
        assert len(r.evidence) > 0
        assert "Status codes" in r.evidence[0]
