"""Tests for Trivy tool."""

import json
import pytest
from sentinel.tools.infra.trivy_tool import TrivyTool, TrivyVulnerability, SEVERITY_MAP


SAMPLE_TRIVY_OUTPUT = json.dumps({
    "Results": [
        {
            "Target": "python:3.9-slim (debian 11.6)",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-1234",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.1.1n-0+deb11u4",
                    "FixedVersion": "1.1.1n-0+deb11u5",
                    "Severity": "CRITICAL",
                    "Title": "OpenSSL buffer overflow",
                    "Description": "A buffer overflow in OpenSSL allows remote code execution.",
                },
                {
                    "VulnerabilityID": "CVE-2023-5678",
                    "PkgName": "libxml2",
                    "InstalledVersion": "2.9.13",
                    "FixedVersion": "2.9.14",
                    "Severity": "HIGH",
                    "Title": "libxml2 XXE vulnerability",
                    "Description": "XXE in libxml2 parser.",
                },
                {
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "curl",
                    "InstalledVersion": "7.74.0",
                    "FixedVersion": "",
                    "Severity": "LOW",
                    "Title": "Minor info disclosure",
                    "Description": "Curl leaks hostname.",
                },
            ],
        },
        {
            "Target": "app/requirements.txt",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-0001",
                    "PkgName": "requests",
                    "InstalledVersion": "2.28.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "MEDIUM",
                    "Title": "SSRF in requests",
                    "Description": "SSRF bypass in requests library.",
                },
            ],
        },
    ]
})

SAMPLE_EMPTY_OUTPUT = json.dumps({"Results": []})

SAMPLE_NO_VULNS = json.dumps({
    "Results": [
        {
            "Target": "alpine:3.18",
            "Vulnerabilities": None,
        }
    ]
})


class TestTrivyParsing:
    def test_parse_multi_target(self):
        vulns = TrivyTool.parse_output(SAMPLE_TRIVY_OUTPUT)
        assert len(vulns) == 4

    def test_parse_severity_mapping(self):
        vulns = TrivyTool.parse_output(SAMPLE_TRIVY_OUTPUT)
        severities = {v.vuln_id: v.severity for v in vulns}
        assert severities["CVE-2023-1234"] == "critical"
        assert severities["CVE-2023-5678"] == "high"
        assert severities["CVE-2023-9999"] == "low"
        assert severities["CVE-2023-0001"] == "medium"

    def test_parse_target_assignment(self):
        vulns = TrivyTool.parse_output(SAMPLE_TRIVY_OUTPUT)
        targets = {v.vuln_id: v.target for v in vulns}
        assert "python:3.9-slim" in targets["CVE-2023-1234"]
        assert targets["CVE-2023-0001"] == "app/requirements.txt"

    def test_parse_fields(self):
        vulns = TrivyTool.parse_output(SAMPLE_TRIVY_OUTPUT)
        v = next(v for v in vulns if v.vuln_id == "CVE-2023-1234")
        assert v.pkg_name == "openssl"
        assert v.installed_version == "1.1.1n-0+deb11u4"
        assert v.fixed_version == "1.1.1n-0+deb11u5"
        assert v.title == "OpenSSL buffer overflow"

    def test_parse_empty_results(self):
        vulns = TrivyTool.parse_output(SAMPLE_EMPTY_OUTPUT)
        assert len(vulns) == 0

    def test_parse_null_vulnerabilities(self):
        vulns = TrivyTool.parse_output(SAMPLE_NO_VULNS)
        assert len(vulns) == 0

    def test_parse_invalid_json(self):
        vulns = TrivyTool.parse_output("not json at all")
        assert len(vulns) == 0

    def test_parse_missing_fields(self):
        data = json.dumps({
            "Results": [{"Target": "test", "Vulnerabilities": [{"VulnerabilityID": "CVE-X"}]}]
        })
        vulns = TrivyTool.parse_output(data)
        assert len(vulns) == 1
        assert vulns[0].vuln_id == "CVE-X"
        assert vulns[0].pkg_name == ""
        assert vulns[0].severity == "info"

    def test_count_by_severity(self):
        vulns = TrivyTool.parse_output(SAMPLE_TRIVY_OUTPUT)
        counts = TrivyTool._count_by_severity(vulns)
        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1

    def test_severity_map_covers_all(self):
        for trivy_sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
            assert trivy_sev in SEVERITY_MAP


class TestTrivyToolAvailability:
    def test_not_available_when_no_binary(self):
        tool = TrivyTool()
        tool._binary = None
        assert tool.available is False

    @pytest.mark.asyncio
    async def test_scan_returns_error_when_unavailable(self):
        tool = TrivyTool()
        tool._binary = None
        result = await tool.scan_image("alpine:3.18")
        assert result.success is False
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_scan_fs_returns_error_when_unavailable(self):
        tool = TrivyTool()
        tool._binary = None
        result = await tool.scan_filesystem("/tmp")
        assert result.success is False

    @pytest.mark.asyncio
    async def test_scan_iac_returns_error_when_unavailable(self):
        tool = TrivyTool()
        tool._binary = None
        result = await tool.scan_iac("/tmp/terraform")
        assert result.success is False
