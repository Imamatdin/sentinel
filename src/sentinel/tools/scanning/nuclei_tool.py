"""
NucleiTool — Template-based vulnerability scanner.

Nuclei runs YAML templates against targets to detect known vulnerabilities.
This tool wraps the CLI and parses JSON output into structured findings.
"""
import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from sentinel.tools.base import ToolOutput
from sentinel.core.config import get_settings
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


class NucleiSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class NucleiResult:
    template_id: str
    name: str
    severity: NucleiSeverity
    matched_url: str
    matched_at: str
    description: str
    reference: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    curl_command: str = ""
    extracted_results: list[str] = field(default_factory=list)
    raw_response: str = ""


class NucleiTool:
    """
    Runs Nuclei scans against target URLs.

    Supports:
    - Full template scans (all templates)
    - Severity-filtered scans
    - Tag-filtered scans (e.g., cve, sqli, xss, ssrf)
    - Custom template paths
    - Rate limiting and concurrency control
    """

    name = "nuclei_scan"
    description = "Run Nuclei vulnerability scanner against target"

    def __init__(self):
        settings = get_settings()
        self.nuclei_binary = getattr(settings, "nuclei_path", "nuclei")
        self.templates_path = getattr(settings, "nuclei_templates", "")
        self.max_rate = 150
        self.concurrency = 25
        self.timeout = 10

    async def execute(
        self,
        target: str,
        severity: Optional[list[NucleiSeverity]] = None,
        tags: Optional[list[str]] = None,
        templates: Optional[list[str]] = None,
        exclude_tags: Optional[list[str]] = None,
        headless: bool = False,
    ) -> ToolOutput:
        """
        Run Nuclei scan.

        Args:
            target: URL or host to scan
            severity: Filter by severity levels
            tags: Filter by template tags (e.g., ["sqli", "xss", "ssrf"])
            templates: Specific template paths to use
            exclude_tags: Tags to exclude
            headless: Enable headless browser templates

        Returns:
            ToolResult with list of NucleiResult findings
        """
        cmd = [
            self.nuclei_binary,
            "-target", target,
            "-json-export", "/dev/stdout",
            "-silent",
            "-rate-limit", str(self.max_rate),
            "-concurrency", str(self.concurrency),
            "-timeout", str(self.timeout),
            "-no-color",
        ]

        if severity:
            cmd.extend(["-severity", ",".join(s.value for s in severity)])

        if tags:
            cmd.extend(["-tags", ",".join(tags)])

        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        elif self.templates_path:
            cmd.extend(["-t", self.templates_path])

        if exclude_tags:
            cmd.extend(["-exclude-tags", ",".join(exclude_tags)])

        if headless:
            cmd.append("-headless")

        logger.info(f"Running Nuclei scan: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 min max per scan
            )

            results = self._parse_output(stdout.decode())

            return ToolOutput(
                success=True,
                data={"findings": results},
                raw_output=stdout.decode(),
                tool_name=self.name,
                metadata={
                    "target": target,
                    "total_findings": len(results),
                    "by_severity": self._count_by_severity(results),
                }
            )
        except asyncio.TimeoutError:
            return ToolOutput(
                success=False,
                data={},
                error="Nuclei scan timed out after 300s",
                tool_name=self.name,
            )
        except Exception as e:
            logger.error(f"Nuclei scan failed: {e}")
            return ToolOutput(
                success=False,
                data={},
                error=str(e),
                tool_name=self.name,
            )

    def _parse_output(self, output: str) -> list[NucleiResult]:
        results = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append(NucleiResult(
                    template_id=data.get("template-id", ""),
                    name=data.get("info", {}).get("name", ""),
                    severity=NucleiSeverity(data.get("info", {}).get("severity", "info")),
                    matched_url=data.get("matched-at", ""),
                    matched_at=data.get("matched-at", ""),
                    description=data.get("info", {}).get("description", ""),
                    reference=data.get("info", {}).get("reference", []),
                    tags=data.get("info", {}).get("tags", []),
                    curl_command=data.get("curl-command", ""),
                    extracted_results=data.get("extracted-results", []),
                    raw_response=data.get("response", ""),
                ))
            except (json.JSONDecodeError, ValueError) as e:
                logger.warning(f"Failed to parse Nuclei output line: {e}")
        return results

    def _count_by_severity(self, results: list[NucleiResult]) -> dict[str, int]:
        counts = {}
        for r in results:
            counts[r.severity.value] = counts.get(r.severity.value, 0) + 1
        return counts
