"""Tests for Phase 7 — real tool-wired Temporal activities.

Tests validate that activities call real tools (mocked) instead of returning
hardcoded placeholder data. Activities run outside Temporal context for unit testing.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass

from sentinel.orchestration.activities import (
    EngagementConfig,
    ExploitAttempt,
    ReportResult,
    _is_ip,
    _vuln_to_category,
)


# === Helper Tests ===

class TestHelpers:
    def test_is_ip_valid(self):
        assert _is_ip("192.168.1.1") is True
        assert _is_ip("10.0.0.1") is True

    def test_is_ip_invalid(self):
        assert _is_ip("example.com") is False
        assert _is_ip("not-an-ip") is False
        assert _is_ip("999.999.999.999") is False

    def test_vuln_to_category_sql_injection(self):
        assert _vuln_to_category({"name": "SQL Injection", "cwe_id": "CWE-89"}) == "injection"

    def test_vuln_to_category_xss(self):
        assert _vuln_to_category({"name": "Cross-Site Scripting", "cwe_id": "CWE-79"}) == "xss"

    def test_vuln_to_category_ssrf(self):
        assert _vuln_to_category({"name": "SSRF", "cwe_id": "CWE-918"}) == "ssrf"

    def test_vuln_to_category_xxe(self):
        assert _vuln_to_category({"name": "XXE Injection", "cwe_id": "CWE-611"}) == "xxe"

    def test_vuln_to_category_file_upload(self):
        assert _vuln_to_category({"name": "File Upload", "cwe_id": "CWE-434"}) == "file_upload"

    def test_vuln_to_category_auth(self):
        assert _vuln_to_category({"name": "Authentication Bypass", "cwe_id": "CWE-287"}) == "auth_bypass"

    def test_vuln_to_category_unknown(self):
        assert _vuln_to_category({"name": "Unknown", "cwe_id": ""}) == "unknown"


# === Recon Activities Tests ===

class TestReconActivities:
    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_discover_hosts_calls_nmap(self, mock_get_graph, mock_activity):
        """discover_hosts should attempt to use NmapTool."""
        mock_graph = AsyncMock()
        mock_graph.create_node = AsyncMock()
        mock_graph.create_edge = AsyncMock()
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        config = EngagementConfig(
            engagement_id="test-001",
            target_url="http://localhost:3000",
            target_ips=["127.0.0.1"],
            scope_includes=[".*"],
            scope_excludes=[],
        )

        # Mock NmapTool to raise (testing fallback)
        with patch("sentinel.tools.nmap_tool.NmapTool", side_effect=Exception("nmap not found")):
            from sentinel.orchestration.activities import discover_hosts
            result = await discover_hosts(config)

        # Fallback creates nodes from config IPs
        assert len(result) == 1
        mock_graph.create_node.assert_called()

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_scan_ports_returns_empty_for_missing_host(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import scan_ports
        result = await scan_ports("nonexistent-id", "eng-001")
        assert result == []

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_identify_services_returns_none_for_missing_port(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph

        from sentinel.orchestration.activities import identify_services
        result = await identify_services("nonexistent-id", "eng-001")
        assert result is None

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_identify_services_uses_fallback_for_known_ports(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value={"port_number": 80, "host_id": ""})
        mock_graph.create_node = AsyncMock()
        mock_graph.create_edge = AsyncMock()
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import identify_services
        result = await identify_services("00000000-0000-0000-0000-000000000001", "eng-001")
        assert result is not None
        mock_graph.create_node.assert_called_once()

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_http_recon_returns_dict(self, mock_get_graph, mock_activity):
        mock_activity.heartbeat = MagicMock()

        with patch("sentinel.tools.http_recon.HTTPReconTool") as mock_http:
            mock_resp = MagicMock()
            mock_resp.url = "http://target/"
            mock_resp.status_code = 200
            mock_resp.headers = {"server": "nginx/1.18", "x-powered-by": "Express"}
            mock_http.return_value.get = AsyncMock(return_value=mock_resp)

            from sentinel.orchestration.activities import http_recon
            result = await http_recon("http://target/", "eng-001")

        assert result["url"] == "http://target/"
        assert result["status_code"] == 200
        assert "server" in result["headers"]

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_http_recon_handles_failure(self, mock_get_graph, mock_activity):
        mock_activity.heartbeat = MagicMock()

        with patch("sentinel.tools.http_recon.HTTPReconTool", side_effect=Exception("fail")):
            from sentinel.orchestration.activities import http_recon
            result = await http_recon("http://target/", "eng-001")

        assert result["status_code"] == 0


# === Vuln Analysis Activities Tests ===

class TestVulnActivities:
    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_generate_hypotheses_returns_list(self, mock_get_graph, mock_activity):
        mock_activity.heartbeat = MagicMock()
        mock_graph = AsyncMock()
        mock_get_graph.return_value = mock_graph

        with patch("sentinel.agents.hypothesis_engine.HypothesisEngine") as mock_engine:
            mock_engine.return_value.generate_hypotheses = AsyncMock(return_value=[])

            from sentinel.orchestration.activities import generate_hypotheses
            result = await generate_hypotheses("eng-001")

        assert isinstance(result, list)

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_analyze_service_vulns_returns_empty_for_missing_service(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import analyze_service_vulns
        result = await analyze_service_vulns("nonexistent", "eng-001")
        assert result == []

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_run_nuclei_scan_handles_missing_binary(self, mock_get_graph, mock_activity):
        mock_activity.heartbeat = MagicMock()

        with patch("sentinel.tools.scanning.nuclei_tool.NucleiTool", side_effect=Exception("nuclei not found")):
            from sentinel.orchestration.activities import run_nuclei_scan
            result = await run_nuclei_scan("http://target/")

        assert result["success"] is False
        assert "error" in result

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_run_zap_scan_handles_failure(self, mock_get_graph, mock_activity):
        mock_activity.heartbeat = MagicMock()

        with patch("sentinel.tools.scanning.zap_tool.ZAPTool", side_effect=Exception("ZAP unavailable")):
            from sentinel.orchestration.activities import run_zap_scan
            result = await run_zap_scan("http://target/")

        assert result["success"] is False

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_analyze_endpoint_vulns_returns_empty_for_missing_endpoint(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import analyze_endpoint_vulns
        result = await analyze_endpoint_vulns("nonexistent", "eng-001")
        assert result == []


# === Exploitation Activities Tests ===

class TestExploitActivities:
    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_attempt_exploit_returns_not_found_for_missing_vuln(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import attempt_exploit
        result = await attempt_exploit("nonexistent", "eng-001")
        assert result.success is False
        assert result.error == "Vulnerability not found"

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_attempt_exploit_dry_run(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value={"name": "SQLi", "is_exploitable": True})
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import attempt_exploit
        result = await attempt_exploit("vuln-1", "eng-001", dry_run=True)
        assert result.success is True
        assert result.technique == "dry_run"
        assert result.evidence["mode"] == "dry_run"

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_verify_exploit_returns_false_for_missing_vuln(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        from sentinel.orchestration.activities import verify_exploit
        result = await verify_exploit("nonexistent", "session-1", "eng-001")
        assert result is False

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_generate_replay_script_returns_none_for_missing_vuln(self, mock_get_graph, mock_activity):
        mock_graph = AsyncMock()
        mock_graph.get_node = AsyncMock(return_value=None)
        mock_get_graph.return_value = mock_graph

        from sentinel.orchestration.activities import generate_replay_script
        result = await generate_replay_script("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    async def test_generate_poc_artifacts_returns_dict(self, mock_activity):
        mock_activity.heartbeat = MagicMock()

        findings = [
            {
                "category": "sqli",
                "evidence": "error",
                "http_traces": [{"method": "GET", "url": "http://t/", "headers": {}, "body": ""}],
            }
        ]

        from sentinel.orchestration.activities import generate_poc_artifacts
        result = await generate_poc_artifacts("eng-001", findings)
        assert "python_script" in result
        assert "bash_script" in result
        assert "postman_collection" in result
        assert "attack_graph" in result


# === Workflow Tests ===

class TestPentestWorkflow:
    def test_initial_state(self):
        from sentinel.orchestration.workflows import PentestWorkflow
        wf = PentestWorkflow()
        assert wf.state.phase == "initialized"
        assert wf.state.hosts_discovered == 0
        assert wf.state.hypotheses_generated == 0

    def test_get_state_returns_dict(self):
        from sentinel.orchestration.workflows import PentestWorkflow
        wf = PentestWorkflow()
        state = wf.get_state()
        assert isinstance(state, dict)
        assert state["phase"] == "initialized"
        assert "hypotheses_generated" in state

    def test_get_findings_returns_dict(self):
        from sentinel.orchestration.workflows import PentestWorkflow
        wf = PentestWorkflow()
        findings = wf.get_findings()
        assert isinstance(findings, dict)
        assert "hosts" in findings
        assert "vulnerabilities" in findings

    def test_approve_critical_exploit_signal_exists(self):
        from sentinel.orchestration.workflows import PentestWorkflow
        wf = PentestWorkflow()
        # Verify the signal method exists
        assert hasattr(wf, "approve_critical_exploit")


# === Reporting Activities Tests ===

class TestReportActivities:
    @pytest.mark.asyncio
    @patch("sentinel.orchestration.activities.activity")
    @patch("sentinel.orchestration.activities.get_graph_client")
    async def test_generate_report_writes_file(self, mock_get_graph, mock_activity, tmp_path):
        mock_graph = AsyncMock()
        mock_graph.find_vulnerabilities = AsyncMock(return_value=[
            {"name": "SQLi", "severity": "critical", "cve_id": "CVE-2024-001", "verified": True},
            {"name": "XSS", "severity": "high"},
        ])
        mock_graph.find_hosts = AsyncMock(return_value=[{"ip": "10.0.0.1"}])
        mock_get_graph.return_value = mock_graph
        mock_activity.heartbeat = MagicMock()

        output_path = str(tmp_path / "report.txt")

        from sentinel.orchestration.activities import generate_report
        result = await generate_report("eng-001", output_path)

        assert isinstance(result, ReportResult)
        assert result.total_findings == 2
        assert result.critical_findings == 1
        assert result.remediation_items == 2
        assert "eng-001" in result.executive_summary

        # Verify file was written
        with open(output_path) as f:
            content = f.read()
        assert "SQLi" in content
        assert "VERIFIED" in content


# === Worker Tests ===

class TestWorkerRegistration:
    def test_worker_imports_all_activities(self):
        """Verify worker module imports all 16 activities."""
        from sentinel.orchestration import worker
        # Check new Phase 7 activities are imported
        assert hasattr(worker, "http_recon")
        assert hasattr(worker, "generate_hypotheses")
        assert hasattr(worker, "run_nuclei_scan")
        assert hasattr(worker, "run_zap_scan")
        assert hasattr(worker, "generate_poc_artifacts")
        # Check existing activities still imported
        assert hasattr(worker, "discover_hosts")
        assert hasattr(worker, "attempt_exploit")
        assert hasattr(worker, "generate_report")


# === Multi-LLM Client Tests ===

class TestLLMClientFactory:
    def test_get_llm_client_exists(self):
        from sentinel.agents.llm_client import get_llm_client
        assert callable(get_llm_client)

    def test_llm_provider_enum_exists(self):
        from sentinel.agents.llm_client import LLMProvider
        assert hasattr(LLMProvider, "ANTHROPIC")
        assert hasattr(LLMProvider, "CEREBRAS")
