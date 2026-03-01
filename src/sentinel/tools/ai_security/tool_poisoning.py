"""
Tool/MCP Poisoning Detector — Analyzes AI agent tool-use configurations for abuse.

Covers:
- LLM04 (OWASP): Data and Model Poisoning
- LLM08 (OWASP): Excessive Agency
- MCP tool poisoning: hidden instructions in tool descriptions
- Excessive agency: tools with overly broad permissions
- Tool shadowing: confusingly similar tool names

Based on Invariant Labs MCP research and Rich tool-use CVEs.
"""

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from sentinel.tools.base import ToolOutput
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class ToolPoisoningFinding:
    tool_name: str
    finding_type: str     # "hidden_instruction" | "excessive_scope" | "shadowing"
    severity: str
    description: str
    evidence: str
    recommendation: str
    owasp_id: str


# Patterns in tool descriptions that indicate embedded instructions
_SUSPICIOUS_PATTERNS = [
    (r"ignore\s+(previous|all|prior)\s+instructions", "instruction_override"),
    (r"(you\s+must|always|never)\s+\w+", "behavioral_directive"),
    (r"<\s*(system|assistant|hidden)\s*>", "xml_injection"),
    (r"\\u200[bcdef]", "zero_width_chars"),
    (r"<!--.*?-->", "html_comment_hiding"),
    (r"do\s+not\s+(tell|reveal|mention|show)", "concealment_directive"),
    (r"secretly|covertly|without\s+telling", "stealth_instruction"),
]

# Permissions that grant dangerous capabilities
_DANGEROUS_PERMISSIONS = {
    "file_system_write": "Can write arbitrary files",
    "network_unrestricted": "Has unrestricted network access",
    "shell_execute": "Can execute shell commands",
    "database_admin": "Has database admin privileges",
    "credential_access": "Can access stored credentials",
}

# Keywords in parameter descriptions that suggest injection-prone inputs
_SENSITIVE_PARAM_KEYWORDS = ["path", "url", "command", "query", "code"]

_LONG_DESCRIPTION_THRESHOLD = 2000
_SHADOWING_SIMILARITY_THRESHOLD = 0.8


class ToolPoisoningDetector:
    """Analyze tool/MCP configurations for poisoning and excessive agency."""

    name = "tool_poisoning_detect"
    description = "Detect tool poisoning and excessive agency in AI agent configurations"

    async def execute(self, tool_definitions: list[dict]) -> ToolOutput:
        """
        Analyze a set of tool definitions for security issues.

        Args:
            tool_definitions: List of tool definition dicts, each with
                name, description, parameters, and optional permissions.
        """
        findings: list[ToolPoisoningFinding] = []
        for tool_def in tool_definitions:
            findings.extend(self._check_hidden_instructions(tool_def))
            findings.extend(self._check_excessive_scope(tool_def))
            findings.extend(self._check_shadowing(tool_def, tool_definitions))

        finding_dicts = [
            {
                "tool_name": f.tool_name,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "owasp_id": f.owasp_id,
            }
            for f in findings
        ]

        return ToolOutput(
            tool_name=self.name,
            success=True,
            data={"findings": finding_dicts},
            metadata={
                "tools_analyzed": len(tool_definitions),
                "findings_count": len(findings),
            },
        )

    def _check_hidden_instructions(
        self, tool_def: dict
    ) -> list[ToolPoisoningFinding]:
        """Detect embedded instructions or injection payloads in tool descriptions."""
        findings: list[ToolPoisoningFinding] = []
        desc = tool_def.get("description", "")
        name = tool_def.get("name", "unknown")

        for pattern, pattern_type in _SUSPICIOUS_PATTERNS:
            if re.search(pattern, desc, re.IGNORECASE):
                findings.append(ToolPoisoningFinding(
                    tool_name=name,
                    finding_type="hidden_instruction",
                    severity="critical",
                    description=(
                        f"Tool description contains suspicious pattern: {pattern_type}"
                    ),
                    evidence=(
                        f"Pattern '{pattern}' matched in description of tool '{name}'"
                    ),
                    recommendation=(
                        "Review and sanitize tool description. "
                        "Remove any behavioral directives."
                    ),
                    owasp_id="LLM04",
                ))

        if len(desc) > _LONG_DESCRIPTION_THRESHOLD:
            findings.append(ToolPoisoningFinding(
                tool_name=name,
                finding_type="hidden_instruction",
                severity="medium",
                description=(
                    f"Tool description is unusually long ({len(desc)} chars). "
                    f"Long descriptions can hide injected instructions."
                ),
                evidence=f"Description length: {len(desc)} chars (threshold: {_LONG_DESCRIPTION_THRESHOLD})",
                recommendation="Audit the full description for hidden instructions.",
                owasp_id="LLM04",
            ))

        return findings

    def _check_excessive_scope(
        self, tool_def: dict
    ) -> list[ToolPoisoningFinding]:
        """Detect tools with dangerously broad permissions or unconstrained inputs."""
        findings: list[ToolPoisoningFinding] = []
        name = tool_def.get("name", "unknown")
        permissions = tool_def.get("permissions", [])
        params = tool_def.get("parameters", {})

        # Flag dangerous permissions
        for perm in permissions:
            if perm in _DANGEROUS_PERMISSIONS:
                findings.append(ToolPoisoningFinding(
                    tool_name=name,
                    finding_type="excessive_scope",
                    severity="high",
                    description=(
                        f"Tool has dangerous permission: {_DANGEROUS_PERMISSIONS[perm]}"
                    ),
                    evidence=f"Permission '{perm}' granted to tool '{name}'",
                    recommendation=(
                        f"Apply principle of least privilege. "
                        f"Restrict '{perm}' to specific paths/targets."
                    ),
                    owasp_id="LLM08",
                ))

        # Flag unconstrained string params for sensitive operations
        properties = params.get("properties", {})
        for param_name, param_def in properties.items():
            if not isinstance(param_def, dict):
                continue
            is_unconstrained_string = (
                param_def.get("type") == "string"
                and not param_def.get("enum")
                and not param_def.get("pattern")
            )
            if not is_unconstrained_string:
                continue
            param_desc = param_def.get("description", "").lower()
            if any(kw in param_desc for kw in _SENSITIVE_PARAM_KEYWORDS):
                findings.append(ToolPoisoningFinding(
                    tool_name=name,
                    finding_type="excessive_scope",
                    severity="medium",
                    description=(
                        f"Parameter '{param_name}' accepts unconstrained string "
                        f"for sensitive operation"
                    ),
                    evidence=(
                        f"Parameter '{param_name}' in tool '{name}': "
                        f"type=string, no enum/pattern constraint"
                    ),
                    recommendation=(
                        f"Add validation: enum, pattern regex, or "
                        f"allowlist for '{param_name}'."
                    ),
                    owasp_id="LLM08",
                ))

        return findings

    def _check_shadowing(
        self, tool_def: dict, all_tools: list[dict]
    ) -> list[ToolPoisoningFinding]:
        """Detect tools with confusingly similar names (potential shadowing attack)."""
        findings: list[ToolPoisoningFinding] = []
        name = tool_def.get("name", "")
        if not name:
            return findings

        for other in all_tools:
            other_name = other.get("name", "")
            if name == other_name:
                continue
            ratio = SequenceMatcher(None, name.lower(), other_name.lower()).ratio()
            if ratio > _SHADOWING_SIMILARITY_THRESHOLD:
                findings.append(ToolPoisoningFinding(
                    tool_name=name,
                    finding_type="shadowing",
                    severity="high",
                    description=(
                        f"Tool '{name}' has a suspiciously similar name to "
                        f"'{other_name}' (similarity: {ratio:.0%}). "
                        f"Possible tool shadowing attack."
                    ),
                    evidence=f"Name similarity: {name} <-> {other_name} = {ratio:.0%}",
                    recommendation=(
                        "Verify both tools are legitimate. "
                        "Remove duplicates or rename for clarity."
                    ),
                    owasp_id="LLM04",
                ))

        return findings
