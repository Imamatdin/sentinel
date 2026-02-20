"""
Static mapping: vulnerability category -> compliance control IDs.

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
        },
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
        },
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
        },
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
        },
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
        },
    },
}


def get_controls(
    vuln_category: str, frameworks: list[str] | None = None
) -> dict[str, list[str]]:
    """
    Get compliance control IDs for a vulnerability category.

    Args:
        vuln_category: e.g. "injection", "xss", "auth_bypass"
        frameworks: list of framework keys to include, or None for all

    Returns:
        {"PCI DSS v4.0": ["6.2.4", ...], "SOC 2 Type II": ["CC6.1", ...], ...}
    """
    result: dict[str, list[str]] = {}
    targets = frameworks or list(FRAMEWORKS.keys())
    for fw_key in targets:
        fw = FRAMEWORKS.get(fw_key)
        if fw:
            controls = fw["mappings"].get(vuln_category, [])
            if controls:
                result[fw["name"]] = controls
    return result
