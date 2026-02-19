"""MITREMapper -- Map attacks and defenses to MITRE ATT&CK framework."""

from dataclasses import dataclass
from typing import Any


@dataclass
class MITREMapping:
    """Mapping of an attack to MITRE ATT&CK technique and mitigation."""

    technique_id: str
    technique_name: str
    tactic: str
    mitigation_id: str
    mitigation_name: str


ATTACK_MAPPING: dict[str, MITREMapping] = {
    "sqli": MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", "M1030", "Network Segmentation"),
    "xss": MITREMapping("T1059.007", "JavaScript", "Execution", "M1021", "Restrict Web-Based Content"),
    "ssrf": MITREMapping("T1090", "Proxy", "Command and Control", "M1037", "Filter Network Traffic"),
    "cmd_injection": MITREMapping("T1059", "Command and Scripting Interpreter", "Execution", "M1038", "Execution Prevention"),
    "file_upload": MITREMapping("T1105", "Ingress Tool Transfer", "Command and Control", "M1031", "Network Intrusion Prevention"),
    "xxe": MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", "M1048", "Application Isolation"),
    "auth_bypass": MITREMapping("T1078", "Valid Accounts", "Defense Evasion", "M1032", "Multi-factor Authentication"),
    "idor": MITREMapping("T1078", "Valid Accounts", "Initial Access", "M1018", "User Account Management"),
    "brute_force": MITREMapping("T1110", "Brute Force", "Credential Access", "M1036", "Account Use Policies"),
    "data_exfil": MITREMapping("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "M1057", "Data Loss Prevention"),
}

# Default mapping for unknown categories
_DEFAULT_MAPPING = MITREMapping("T1190", "Unknown", "Unknown", "M1030", "Unknown")


class MITREMapper:
    """Maps attacks and defenses to the MITRE ATT&CK framework."""

    def map_attack(self, category: str) -> MITREMapping:
        """Map an attack category to its MITRE ATT&CK technique."""
        return ATTACK_MAPPING.get(category, _DEFAULT_MAPPING)

    def get_attack_coverage(self, findings: list[dict[str, Any]]) -> dict[str, Any]:
        """Calculate ATT&CK coverage from a list of findings.

        Returns:
            Dict with tactics_covered, techniques_used, and counts.
        """
        tactics_covered: set[str] = set()
        techniques_used: set[str] = set()

        for f in findings:
            mapping = self.map_attack(f.get("category", ""))
            tactics_covered.add(mapping.tactic)
            techniques_used.add(mapping.technique_id)

        return {
            "tactics_covered": sorted(tactics_covered),
            "techniques_used": sorted(techniques_used),
            "total_tactics": len(tactics_covered),
            "total_techniques": len(techniques_used),
        }
