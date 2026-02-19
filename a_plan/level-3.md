# LEVEL 03: Compliance Report Generator

## Context
Sentinel base platform generates PDF pentest reports. This level adds compliance-framework mapping so findings auto-map to PCI DSS v4.0, SOC 2, ISO 27001, NIST 800-53, and OWASP controls. This is a sales multiplier — CISOs buy tools that speak compliance.

Research source: Block 10 (Compliance section).

## Why
Manual compliance mapping takes hours. Sentinel auto-tags every finding with the control IDs it validates/violates. Output: a compliance appendix that auditors can directly consume.

---

## Files to Create

### `src/sentinel/compliance/__init__.py`
```python
"""Compliance framework mappings and report generation."""
```

### `src/sentinel/compliance/framework_maps.py`
```python
"""
Static mapping: vulnerability category → compliance control IDs.

Covers: PCI DSS v4.0, SOC 2, ISO 27001, NIST 800-53, OWASP Top 10 2021.
"""

FRAMEWORKS = {
    "pci_dss_v4": {
        "name": "PCI DSS v4.0",
        "mappings": {
            "injection": ["6.2.4", "6.5.1", "11.4.1"],
            "xss": ["6.2.4", "6.5.7", "11.4.1"],
            "auth_bypass": ["2.2.7", "7.2.1", "8.3.1", "11.4.1"],
            "idor": ["7.2.2", "7.2.5", "11.4.1"],
            "ssrf": ["6.2.4", "11.4.1"],
            "xxe": ["6.2.4", "11.4.1"],
            "file_upload": ["6.2.4", "6.5.8"],
            "misconfig": ["2.2.1", "2.2.2", "6.3.1", "11.4.1"],
            "sensitive_data": ["3.4.1", "4.2.1", "6.5.3"],
            "broken_access": ["7.2.1", "7.2.2", "7.2.5"],
            "deserialization": ["6.2.4", "6.5.1"],
            "supply_chain": ["6.3.2", "6.5.1"],
        }
    },
    "soc2": {
        "name": "SOC 2 Type II",
        "mappings": {
            "injection": ["CC6.1", "CC7.1", "CC7.2"],
            "xss": ["CC6.1", "CC7.1"],
            "auth_bypass": ["CC6.1", "CC6.2", "CC6.3"],
            "idor": ["CC6.1", "CC6.3"],
            "ssrf": ["CC6.1", "CC6.6", "CC7.2"],
            "misconfig": ["CC6.1", "CC6.6", "CC7.1"],
            "sensitive_data": ["CC6.1", "CC6.5", "C1.1"],
            "broken_access": ["CC6.1", "CC6.2", "CC6.3"],
            "supply_chain": ["CC6.1", "CC7.1", "CC8.1"],
        }
    },
    "iso_27001": {
        "name": "ISO 27001:2022",
        "mappings": {
            "injection": ["A.8.26", "A.8.28", "A.8.29"],
            "xss": ["A.8.26", "A.8.28"],
            "auth_bypass": ["A.5.15", "A.8.5", "A.8.24"],
            "idor": ["A.5.15", "A.8.3"],
            "misconfig": ["A.8.9", "A.8.27"],
            "sensitive_data": ["A.5.33", "A.8.11", "A.8.24"],
            "supply_chain": ["A.5.21", "A.5.22", "A.8.30"],
        }
    },
    "nist_800_53": {
        "name": "NIST SP 800-53 Rev. 5",
        "mappings": {
            "injection": ["SI-10", "SI-16", "CA-8", "RA-5"],
            "xss": ["SI-10", "SC-18", "CA-8"],
            "auth_bypass": ["IA-2", "IA-5", "AC-7", "CA-8"],
            "idor": ["AC-3", "AC-6", "CA-8"],
            "ssrf": ["SC-7", "SI-10", "CA-8"],
            "misconfig": ["CM-6", "CM-7", "CA-8", "RA-5"],
            "sensitive_data": ["SC-8", "SC-28", "MP-5"],
            "supply_chain": ["SA-12", "SR-3", "SR-4", "RA-5"],
        }
    },
    "owasp_top10_2021": {
        "name": "OWASP Top 10 (2021)",
        "mappings": {
            "injection": ["A03:2021"],
            "xss": ["A03:2021"],
            "auth_bypass": ["A07:2021"],
            "idor": ["A01:2021"],
            "ssrf": ["A10:2021"],
            "xxe": ["A05:2021"],
            "misconfig": ["A05:2021"],
            "sensitive_data": ["A02:2021"],
            "broken_access": ["A01:2021"],
            "deserialization": ["A08:2021"],
            "supply_chain": ["A06:2021"],
        }
    },
}


def get_controls(vuln_category: str, frameworks: list[str] = None) -> dict[str, list[str]]:
    """
    Get compliance control IDs for a vulnerability category.
    
    Args:
        vuln_category: e.g. "injection", "xss", "auth_bypass"
        frameworks: list of framework keys to include, or None for all
    
    Returns:
        {"pci_dss_v4": ["6.2.4", ...], "soc2": ["CC6.1", ...], ...}
    """
    result = {}
    targets = frameworks or list(FRAMEWORKS.keys())
    for fw_key in targets:
        fw = FRAMEWORKS.get(fw_key)
        if fw:
            controls = fw["mappings"].get(vuln_category, [])
            if controls:
                result[fw["name"]] = controls
    return result
```

### `src/sentinel/compliance/report_generator.py`
```python
"""
Compliance Report Generator.

Takes a list of verified findings and generates a compliance appendix
that maps each finding to relevant framework controls.
"""
from dataclasses import dataclass, field
from sentinel.compliance.framework_maps import get_controls, FRAMEWORKS
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ComplianceFindingEntry:
    finding_id: str
    category: str
    severity: str
    target: str
    controls: dict[str, list[str]]  # framework_name → [control_ids]
    status: str = "FAIL"  # FAIL = vuln found, this control is not met


@dataclass 
class ComplianceReport:
    engagement_id: str
    frameworks_covered: list[str]
    entries: list[ComplianceFindingEntry]
    control_summary: dict  # framework → {control_id: "FAIL"/"PASS"}
    coverage_stats: dict   # framework → {tested: N, failed: N, coverage_pct: float}


class ComplianceReportGenerator:
    """Generate compliance appendix from verified findings."""
    
    def generate(
        self,
        findings: list[dict],
        engagement_id: str,
        frameworks: list[str] = None,
    ) -> ComplianceReport:
        """
        Map findings to compliance controls and generate report.
        
        Args:
            findings: list of verified finding dicts with "category", "severity", etc.
            engagement_id: engagement identifier
            frameworks: which frameworks to include (None = all)
        """
        fw_keys = frameworks or list(FRAMEWORKS.keys())
        entries = []
        control_tracker = {FRAMEWORKS[k]["name"]: {} for k in fw_keys if k in FRAMEWORKS}
        
        for finding in findings:
            category = finding.get("category", "")
            controls = get_controls(category, fw_keys)
            
            entry = ComplianceFindingEntry(
                finding_id=finding.get("hypothesis_id", finding.get("finding_id", "")),
                category=category,
                severity=finding.get("severity", ""),
                target=finding.get("target_url", ""),
                controls=controls,
            )
            entries.append(entry)
            
            # Track which controls failed
            for fw_name, ctrl_ids in controls.items():
                for ctrl in ctrl_ids:
                    control_tracker[fw_name][ctrl] = "FAIL"
        
        # Calculate coverage stats
        coverage = {}
        for fw_key in fw_keys:
            if fw_key not in FRAMEWORKS:
                continue
            fw_name = FRAMEWORKS[fw_key]["name"]
            all_controls = set()
            for ctrls in FRAMEWORKS[fw_key]["mappings"].values():
                all_controls.update(ctrls)
            
            tested = len(control_tracker.get(fw_name, {}))
            failed = sum(1 for v in control_tracker.get(fw_name, {}).values() if v == "FAIL")
            coverage[fw_name] = {
                "total_controls": len(all_controls),
                "tested": tested,
                "failed": failed,
                "coverage_pct": round(tested / len(all_controls) * 100, 1) if all_controls else 0,
            }
        
        return ComplianceReport(
            engagement_id=engagement_id,
            frameworks_covered=[FRAMEWORKS[k]["name"] for k in fw_keys if k in FRAMEWORKS],
            entries=entries,
            control_summary=control_tracker,
            coverage_stats=coverage,
        )
```

---

## Files to Modify

### `src/sentinel/reports/` — Add compliance section to existing PDF report
In the report generation module, after the findings section, add a compliance appendix.
Call `ComplianceReportGenerator.generate(findings, engagement_id)` and render the result.

---

## Tests

### `tests/compliance/test_framework_maps.py`
```python
import pytest
from sentinel.compliance.framework_maps import get_controls, FRAMEWORKS

class TestFrameworkMaps:
    def test_injection_has_pci(self):
        controls = get_controls("injection")
        assert "PCI DSS v4.0" in controls
        assert "6.2.4" in controls["PCI DSS v4.0"]
    
    def test_unknown_category_returns_empty(self):
        controls = get_controls("totally_fake_vuln")
        assert all(len(v) == 0 for v in controls.values()) or len(controls) == 0
    
    def test_filter_single_framework(self):
        controls = get_controls("xss", ["owasp_top10_2021"])
        assert len(controls) == 1
        assert "OWASP Top 10 (2021)" in controls
    
    def test_all_categories_covered(self):
        categories = ["injection", "xss", "auth_bypass", "idor", "ssrf", "misconfig"]
        for cat in categories:
            controls = get_controls(cat)
            assert len(controls) > 0, f"No controls mapped for {cat}"
```

### `tests/compliance/test_report_generator.py`
```python
import pytest
from sentinel.compliance.report_generator import ComplianceReportGenerator

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
    
    def test_coverage_stats(self):
        findings = [{"hypothesis_id": "h1", "category": "injection", "severity": "critical", "target_url": "/api"}]
        report = self.gen.generate(findings, "eng-002")
        for fw_name, stats in report.coverage_stats.items():
            assert "tested" in stats
            assert "failed" in stats
            assert "coverage_pct" in stats
    
    def test_empty_findings(self):
        report = self.gen.generate([], "eng-003")
        assert len(report.entries) == 0
```

---

## Acceptance Criteria
- [ ] `get_controls("injection")` returns control IDs for all 5 frameworks
- [ ] `ComplianceReportGenerator` maps findings to controls and calculates coverage
- [ ] Coverage stats show which % of each framework's controls were tested
- [ ] Control summary tracks FAIL/PASS per control per framework
- [ ] All tests pass