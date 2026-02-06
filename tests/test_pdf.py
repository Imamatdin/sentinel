"""Tests for PDF report generation.

Run: pytest tests/test_pdf.py -v

Note: These tests verify HTML template rendering. PDF conversion
requires weasyprint + system deps which may not be available in CI.
The generator falls back to HTML output if weasyprint is missing.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MockMetrics:
    output_tokens: int = 500


@dataclass
class MockAgentResult:
    agent_name: str = "test_agent"
    success: bool = True
    duration: float = 5.0
    tool_calls_made: int = 10
    metrics: MockMetrics = field(default_factory=MockMetrics)
    findings: dict = field(default_factory=dict)
    error: str | None = None


@dataclass
class MockEngagementResult:
    success: bool = True
    target_url: str = "http://localhost:3000"
    duration: float = 42.5
    event_count: int = 150
    speed_stats: dict = field(default_factory=lambda: {
        "total_tokens": 50000,
        "avg_tokens_per_second": 1200,
        "total_tool_calls": 45,
        "total_llm_time_seconds": 8.5,
    })
    agent_results: dict = field(default_factory=dict)
    red_report: str = "## Red Team Report\nFound SQL injection in /search endpoint."
    blue_report: str = "## Blue Team Report\nDetected and blocked 3 attacks."


class TestPDFGenerator:
    """Test PDF/HTML report generation."""

    def test_generate_html_fallback(self, tmp_path: Path):
        """Test that report generates even without weasyprint."""
        from sentinel.reporting.pdf_generator import PDFReportGenerator

        result = MockEngagementResult()
        result.agent_results = {
            "recon": MockAgentResult(agent_name="recon_agent"),
            "exploit": MockAgentResult(
                agent_name="exploit_agent",
                findings={
                    "vulnerabilities_found": [
                        {
                            "type": "SQL Injection",
                            "severity": "critical",
                            "endpoint": "/search?q=test",
                            "description": "Union-based SQLi",
                            "evidence": "1' UNION SELECT 1,2,3--",
                        }
                    ]
                },
            ),
        }

        generator = PDFReportGenerator()
        output = str(tmp_path / "test_report.pdf")
        actual_path = generator.generate(result, output_path=output)

        # Should produce either PDF or HTML
        assert Path(actual_path).exists()
        assert Path(actual_path).stat().st_size > 0

        # Read and check content
        content = Path(actual_path).read_text()
        assert "SENTINEL" in content
        assert "localhost:3000" in content
        assert "SQL Injection" in content

    def test_generate_with_genome_patterns(self, tmp_path: Path):
        """Test report includes genome patterns when provided."""
        from sentinel.reporting.pdf_generator import PDFReportGenerator
        from sentinel.genome.models import VulnPattern

        result = MockEngagementResult()
        result.agent_results = {"recon": MockAgentResult()}

        patterns = [
            VulnPattern(
                id="p1",
                attack_vector="sqli_union",
                payload_family="sql_injection",
                detection_signature=r"UNION\s+SELECT",
                root_cause="string_concat",
                affected_component="search",
                severity="high",
                remediation_pattern="parameterized_queries",
                source_finding_id="f1",
                confidence=0.9,
                cwe_id="CWE-89",
                capec_id="CAPEC-66",
            )
        ]

        generator = PDFReportGenerator()
        output = str(tmp_path / "test_report.pdf")
        actual_path = generator.generate(result, patterns, output)

        content = Path(actual_path).read_text()
        assert "CWE-89" in content
        assert "CAPEC-66" in content
        assert "sqli_union" in content

    def test_generate_empty_engagement(self, tmp_path: Path):
        """Test report handles empty engagement gracefully."""
        from sentinel.reporting.pdf_generator import PDFReportGenerator

        result = MockEngagementResult()
        result.agent_results = {}
        result.red_report = ""
        result.blue_report = ""

        generator = PDFReportGenerator()
        output = str(tmp_path / "test_report.pdf")
        actual_path = generator.generate(result, output_path=output)

        assert Path(actual_path).exists()
        assert Path(actual_path).stat().st_size > 0
