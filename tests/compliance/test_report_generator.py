"""Tests for compliance report generator."""

import pytest
from sentinel.compliance.report_generator import ComplianceReportGenerator, ComplianceReport


class TestComplianceReportGenerator:
    def setup_method(self):
        self.gen = ComplianceReportGenerator()

    def test_generate_basic(self):
        findings = [
            {"hypothesis_id": "h1", "category": "injection", "severity": "critical", "target_url": "/api/login"},
            {"hypothesis_id": "h2", "category": "xss", "severity": "high", "target_url": "/search"},
        ]
        report = self.gen.generate(findings, "eng-001")
        assert report.engagement_id == "eng-001"
        assert len(report.entries) == 2
        assert len(report.frameworks_covered) == 5  # all frameworks

    def test_generate_single_framework(self):
        findings = [
            {"hypothesis_id": "h1", "category": "injection", "severity": "critical", "target_url": "/api"},
        ]
        report = self.gen.generate(findings, "eng-002", frameworks=["pci_dss_v4"])
        assert len(report.frameworks_covered) == 1
        assert report.frameworks_covered[0] == "PCI DSS v4.0"

    def test_coverage_stats(self):
        findings = [{"hypothesis_id": "h1", "category": "injection", "severity": "critical", "target_url": "/api"}]
        report = self.gen.generate(findings, "eng-003")
        for fw_name, stats in report.coverage_stats.items():
            assert "tested" in stats
            assert "failed" in stats
            assert "coverage_pct" in stats
            assert "total_controls" in stats
            assert stats["coverage_pct"] >= 0
            assert stats["coverage_pct"] <= 100

    def test_empty_findings(self):
        report = self.gen.generate([], "eng-004")
        assert len(report.entries) == 0
        for fw_name, stats in report.coverage_stats.items():
            assert stats["tested"] == 0
            assert stats["failed"] == 0

    def test_control_summary_tracks_failures(self):
        findings = [
            {"hypothesis_id": "h1", "category": "injection", "severity": "critical", "target_url": "/api"},
        ]
        report = self.gen.generate(findings, "eng-005", frameworks=["pci_dss_v4"])
        pci_controls = report.control_summary.get("PCI DSS v4.0", {})
        assert len(pci_controls) > 0
        assert all(v == "FAIL" for v in pci_controls.values())

    def test_entry_has_controls(self):
        findings = [
            {"hypothesis_id": "h1", "category": "ssrf", "severity": "high", "target_url": "/proxy"},
        ]
        report = self.gen.generate(findings, "eng-006")
        assert len(report.entries) == 1
        entry = report.entries[0]
        assert entry.category == "ssrf"
        assert entry.severity == "high"
        assert len(entry.controls) > 0

    def test_unknown_category_maps_to_nothing(self):
        findings = [
            {"hypothesis_id": "h1", "category": "made_up_vuln", "severity": "low", "target_url": "/"},
        ]
        report = self.gen.generate(findings, "eng-007")
        assert len(report.entries) == 1
        assert len(report.entries[0].controls) == 0

    def test_multiple_findings_same_category(self):
        findings = [
            {"hypothesis_id": "h1", "category": "injection", "severity": "critical", "target_url": "/api/1"},
            {"hypothesis_id": "h2", "category": "injection", "severity": "high", "target_url": "/api/2"},
        ]
        report = self.gen.generate(findings, "eng-008", frameworks=["pci_dss_v4"])
        assert len(report.entries) == 2
        # Controls should be the same (both injection)
        pci_controls = report.control_summary.get("PCI DSS v4.0", {})
        # Still 3 unique controls (deduplicated)
        assert len(pci_controls) == 3

    def test_report_is_dataclass(self):
        report = self.gen.generate([], "eng-009")
        assert isinstance(report, ComplianceReport)
        assert isinstance(report.frameworks_covered, list)
        assert isinstance(report.entries, list)
        assert isinstance(report.control_summary, dict)
        assert isinstance(report.coverage_stats, dict)

    def test_finding_id_from_finding_id_key(self):
        findings = [
            {"finding_id": "f-123", "category": "xss", "severity": "medium", "target_url": "/page"},
        ]
        report = self.gen.generate(findings, "eng-010")
        assert report.entries[0].finding_id == "f-123"
