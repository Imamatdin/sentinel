"""Tests for NucleiTool."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
import json

from sentinel.tools.scanning.nuclei_tool import NucleiTool, NucleiSeverity, NucleiResult


class TestNucleiTool:
    """Test NucleiTool functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        # Mock settings to avoid validation errors
        with patch('sentinel.tools.scanning.nuclei_tool.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                nuclei_path="nuclei",
                nuclei_templates="",
                anthropic_api_key="test",
                cerebras_api_key="test"
            )
            self.tool = NucleiTool()

    def test_nuclei_tool_initialization(self):
        """Test NucleiTool initializes correctly."""
        assert self.tool.name == "nuclei_scan"
        assert self.tool.description is not None
        assert self.tool.nuclei_binary == "nuclei"

    def test_parse_output_valid_json(self):
        """Test parsing valid Nuclei JSON output."""
        sample_output = json.dumps({
            "template-id": "CVE-2021-44228",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "description": "Log4Shell vulnerability",
                "tags": ["cve", "log4j", "rce"],
                "reference": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"]
            },
            "matched-at": "http://example.com/vulnerable",
            "curl-command": "curl -X GET http://example.com/vulnerable",
            "extracted-results": ["proof"],
            "response": "HTTP/1.1 200 OK..."
        })

        results = self.tool._parse_output(sample_output)

        assert len(results) == 1
        assert results[0].template_id == "CVE-2021-44228"
        assert results[0].name == "Apache Log4j RCE"
        assert results[0].severity == NucleiSeverity.CRITICAL
        assert results[0].matched_url == "http://example.com/vulnerable"

    def test_parse_output_multiple_findings(self):
        """Test parsing multiple findings."""
        line1 = json.dumps({"template-id": "test-1", "info": {"name": "Test 1", "severity": "high"}, "matched-at": "http://test.com"})
        line2 = json.dumps({"template-id": "test-2", "info": {"name": "Test 2", "severity": "medium"}, "matched-at": "http://test.com"})
        output = f"{line1}\n{line2}"

        results = self.tool._parse_output(output)

        assert len(results) == 2
        assert results[0].template_id == "test-1"
        assert results[1].template_id == "test-2"

    def test_parse_output_empty(self):
        """Test parsing empty output."""
        results = self.tool._parse_output("")
        assert len(results) == 0

    def test_parse_output_invalid_json(self):
        """Test parsing invalid JSON gracefully."""
        results = self.tool._parse_output("not valid json\n{invalid}")
        assert len(results) == 0  # Should skip invalid lines

    def test_count_by_severity(self):
        """Test severity counting."""
        results = [
            NucleiResult("t1", "Test 1", NucleiSeverity.CRITICAL, "", "", ""),
            NucleiResult("t2", "Test 2", NucleiSeverity.CRITICAL, "", "", ""),
            NucleiResult("t3", "Test 3", NucleiSeverity.HIGH, "", "", ""),
            NucleiResult("t4", "Test 4", NucleiSeverity.MEDIUM, "", "", ""),
        ]

        counts = self.tool._count_by_severity(results)

        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1

    @pytest.mark.asyncio
    async def test_execute_builds_correct_command(self):
        """Test that execute builds correct command."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_proc:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(b'', b''))
            mock_proc.return_value = mock_process

            await self.tool.execute(
                target="http://example.com",
                tags=["sqli", "xss"],
                severity=[NucleiSeverity.CRITICAL, NucleiSeverity.HIGH]
            )

            # Verify subprocess was called
            mock_proc.assert_called_once()
            call_args = mock_proc.call_args[0]

            # Check key arguments are present
            assert "nuclei" in call_args
            assert "-target" in call_args
            assert "http://example.com" in call_args
            assert "-tags" in call_args
            assert "sqli,xss" in call_args
            assert "-severity" in call_args
            assert "critical,high" in call_args

    @pytest.mark.asyncio
    async def test_execute_timeout_handling(self):
        """Test that execute handles timeouts gracefully."""
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_proc:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_proc.return_value = mock_process

            result = await self.tool.execute(target="http://example.com")

            assert result.success is False
            assert "timed out" in result.error.lower()

    @pytest.mark.asyncio
    async def test_execute_returns_tool_output(self):
        """Test that execute returns proper ToolOutput."""
        sample_finding = json.dumps({
            "template-id": "test-id",
            "info": {"name": "Test", "severity": "medium"},
            "matched-at": "http://test.com"
        })

        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_proc:
            mock_process = AsyncMock()
            mock_process.communicate = AsyncMock(return_value=(sample_finding.encode(), b''))
            mock_proc.return_value = mock_process

            result = await self.tool.execute(target="http://test.com")

            assert result.success is True
            assert result.tool_name == "nuclei_scan"
            assert "findings" in result.data
            assert isinstance(result.data["findings"], list)
            assert result.metadata["total_findings"] == 1
