"""Tests for ZAPTool."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from sentinel.tools.scanning.zap_tool import ZAPTool, ZAPAlert


class TestZAPTool:
    """Test ZAPTool functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Mock settings to avoid validation errors
        with patch('sentinel.tools.scanning.zap_tool.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                zap_api_url="http://localhost:8080",
                zap_api_key="",
                anthropic_api_key="test",
                cerebras_api_key="test"
            )
            self.tool = ZAPTool()

    def test_zap_tool_initialization(self):
        """Test ZAPTool initializes correctly."""
        assert self.tool.name == "zap_scan"
        assert self.tool.description is not None
        assert "localhost" in self.tool.base_url

    @pytest.mark.asyncio
    async def test_spider_completes_successfully(self):
        """Test spider completes successfully."""
        # Mock the _api_call method
        self.tool._api_call = AsyncMock(side_effect=[
            {"scan": "1"},  # Start scan
            {"status": "50"},  # Status check 1
            {"status": "100"},  # Status check 2 (complete)
            {"results": ["http://example.com/", "http://example.com/page1"]}  # Results
        ])

        result = await self.tool.spider("http://example.com")

        assert result.success is True
        assert "urls" in result.data
        assert len(result.data["urls"]) == 2

    @pytest.mark.asyncio
    async def test_active_scan_returns_alerts(self):
        """Test active scan returns alerts."""
        # Mock the _api_call method
        self.tool._api_call = AsyncMock(side_effect=[
            {"scan": "1"},  # Start scan
            {"status": "100"},  # Status check (complete)
            {"alerts": [{  # Alerts
                "id": "1",
                "name": "SQL Injection",
                "risk": "High",
                "confidence": "High",
                "description": "SQL injection found",
                "url": "http://example.com/vuln",
                "method": "GET",
                "param": "id",
                "attack": "1' OR '1'='1",
                "evidence": "MySQL error",
                "solution": "Use parameterized queries",
                "reference": "https://owasp.org/sqli",
                "cweid": "89",
                "wascid": "19",
                "tags": {}
            }]}
        ])

        result = await self.tool.active_scan("http://example.com")

        assert result.success is True
        assert "alerts" in result.data
        assert len(result.data["alerts"]) == 1
        assert isinstance(result.data["alerts"][0], ZAPAlert)
        assert result.data["alerts"][0].name == "SQL Injection"

    @pytest.mark.asyncio
    async def test_execute_full_scan(self):
        """Test full scan pipeline (spider + active scan)."""
        # Mock spider to succeed
        self.tool.spider = AsyncMock(return_value=MagicMock(
            success=True,
            data={"urls": ["http://example.com/"]}
        ))

        # Mock active_scan to succeed
        self.tool.active_scan = AsyncMock(return_value=MagicMock(
            success=True,
            data={"alerts": []},
            metadata={"phase": "active_scan"}
        ))

        result = await self.tool.execute("http://example.com", full_scan=True)

        assert result.success is True
        self.tool.spider.assert_called_once()
        self.tool.active_scan.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_spider_only(self):
        """Test spider-only execution."""
        # Mock spider to succeed
        spider_result = MagicMock(
            success=True,
            data={"urls": ["http://example.com/"]},
            metadata={"phase": "spider"}
        )
        self.tool.spider = AsyncMock(return_value=spider_result)

        result = await self.tool.execute("http://example.com", full_scan=False)

        assert result == spider_result
        self.tool.spider.assert_called_once()

    def test_count_by_risk(self):
        """Test alert risk counting."""
        alerts = [
            ZAPAlert(1, "Test 1", "High", "High", "", "", "", "", "", "", "", "", 0, 0, {}),
            ZAPAlert(2, "Test 2", "High", "Medium", "", "", "", "", "", "", "", "", 0, 0, {}),
            ZAPAlert(3, "Test 3", "Medium", "High", "", "", "", "", "", "", "", "", 0, 0, {}),
        ]

        counts = self.tool._count_by_risk(alerts)

        assert counts["High"] == 2
        assert counts["Medium"] == 1
