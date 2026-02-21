"""
Trivy Tool — Container image and filesystem vulnerability scanning.

Wraps `trivy image --format json <image>` and `trivy fs --format json <path>`.
Parses JSON output into structured findings with severity mapping.
"""

import asyncio
import json
import shutil
from dataclasses import dataclass

from sentinel.tools.base import ToolOutput
from sentinel.core import get_logger

logger = get_logger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "info",
}


@dataclass
class TrivyVulnerability:
    vuln_id: str
    pkg_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    description: str
    target: str  # image layer or file path


class TrivyTool:
    """Wraps Trivy CLI for image, filesystem, and IaC scanning."""

    name = "trivy_scan"

    def __init__(self):
        self._binary = shutil.which("trivy")

    @property
    def available(self) -> bool:
        return self._binary is not None

    async def scan_image(self, image: str) -> ToolOutput:
        """Scan a container image for vulnerabilities."""
        return await self._run_scan(["image", "--format", "json", image], image)

    async def scan_filesystem(self, path: str) -> ToolOutput:
        """Scan a filesystem path (e.g., project dir) for vulnerabilities."""
        return await self._run_scan(["fs", "--format", "json", path], path)

    async def scan_iac(self, path: str) -> ToolOutput:
        """Scan Infrastructure as Code (Terraform, CloudFormation, etc.)."""
        return await self._run_scan(
            ["config", "--format", "json", path], path
        )

    async def _run_scan(
        self, args: list[str], target: str
    ) -> ToolOutput:
        if not self.available:
            return ToolOutput(
                tool_name=self.name,
                success=False,
                data={},
                raw_output="",
                error="Trivy binary not found in PATH",
            )

        cmd = [self._binary] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=300
            )
            raw = stdout.decode("utf-8", errors="replace")

            if proc.returncode != 0 and not raw.strip():
                return ToolOutput(
                    tool_name=self.name,
                    success=False,
                    data={},
                    raw_output=stderr.decode("utf-8", errors="replace"),
                    error=f"Trivy exited with code {proc.returncode}",
                )

            vulns = self.parse_output(raw)
            return ToolOutput(
                tool_name=self.name,
                success=True,
                data={
                    "target": target,
                    "vulnerabilities": [v.__dict__ for v in vulns],
                    "total_count": len(vulns),
                    "by_severity": self._count_by_severity(vulns),
                },
                raw_output=raw,
            )
        except asyncio.TimeoutError:
            return ToolOutput(
                tool_name=self.name,
                success=False,
                data={},
                raw_output="",
                error="Trivy scan timed out after 300s",
            )
        except Exception as e:
            return ToolOutput(
                tool_name=self.name,
                success=False,
                data={},
                raw_output="",
                error=f"Trivy scan failed: {e}",
            )

    @staticmethod
    def parse_output(raw_json: str) -> list[TrivyVulnerability]:
        """Parse Trivy JSON output into structured vulnerability list."""
        vulns: list[TrivyVulnerability] = []
        try:
            data = json.loads(raw_json)
        except json.JSONDecodeError:
            return vulns

        # Trivy JSON structure: {"Results": [{"Target": ..., "Vulnerabilities": [...]}]}
        results = data.get("Results") or []
        for result in results:
            target = result.get("Target", "unknown")
            for v in result.get("Vulnerabilities") or []:
                vulns.append(
                    TrivyVulnerability(
                        vuln_id=v.get("VulnerabilityID", ""),
                        pkg_name=v.get("PkgName", ""),
                        installed_version=v.get("InstalledVersion", ""),
                        fixed_version=v.get("FixedVersion", ""),
                        severity=SEVERITY_MAP.get(
                            v.get("Severity", "UNKNOWN"), "info"
                        ),
                        title=v.get("Title", ""),
                        description=v.get("Description", ""),
                        target=target,
                    )
                )
        return vulns

    @staticmethod
    def _count_by_severity(
        vulns: list[TrivyVulnerability],
    ) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts
