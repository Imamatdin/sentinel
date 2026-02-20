"""Tests for compliance framework maps."""

import pytest
from sentinel.compliance.framework_maps import get_controls, FRAMEWORKS


class TestFrameworkMaps:
    def test_injection_has_pci(self):
        controls = get_controls("injection")
        assert "PCI DSS v4.0" in controls
        assert "6.2.4" in controls["PCI DSS v4.0"]

    def test_injection_has_all_frameworks(self):
        controls = get_controls("injection")
        assert len(controls) >= 4  # PCI, SOC2, ISO, NIST, OWASP

    def test_unknown_category_returns_empty(self):
        controls = get_controls("totally_fake_vuln")
        assert len(controls) == 0

    def test_filter_single_framework(self):
        controls = get_controls("xss", ["owasp_top10_2021"])
        assert len(controls) == 1
        assert "OWASP Top 10 (2021)" in controls

    def test_filter_multiple_frameworks(self):
        controls = get_controls("injection", ["pci_dss_v4", "nist_800_53"])
        assert "PCI DSS v4.0" in controls
        assert "NIST SP 800-53 Rev. 5" in controls
        assert "SOC 2 Type II" not in controls

    def test_all_categories_covered(self):
        categories = ["injection", "xss", "auth_bypass", "idor", "ssrf", "misconfig"]
        for cat in categories:
            controls = get_controls(cat)
            assert len(controls) > 0, f"No controls mapped for {cat}"

    def test_supply_chain_has_controls(self):
        controls = get_controls("supply_chain")
        assert len(controls) >= 3  # PCI, SOC2, ISO, NIST, OWASP

    def test_xss_maps_to_owasp_a03(self):
        controls = get_controls("xss", ["owasp_top10_2021"])
        assert "A03:2021" in controls["OWASP Top 10 (2021)"]

    def test_idor_maps_to_owasp_a01(self):
        controls = get_controls("idor", ["owasp_top10_2021"])
        assert "A01:2021" in controls["OWASP Top 10 (2021)"]

    def test_all_frameworks_have_name(self):
        for key, fw in FRAMEWORKS.items():
            assert "name" in fw
            assert "mappings" in fw
            assert len(fw["mappings"]) > 0

    def test_invalid_framework_key_ignored(self):
        controls = get_controls("injection", ["nonexistent_framework"])
        assert len(controls) == 0
