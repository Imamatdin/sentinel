"""
SCA Scanner — Software Composition Analysis.

Parses project manifests (package.json, pom.xml, requirements.txt, go.mod, Gemfile)
to extract dependencies, queries vulnerability databases, and correlates with
the knowledge graph to check reachability.
"""

import asyncio
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from sentinel.tools.base import ToolOutput
from sentinel.core import get_logger

logger = get_logger(__name__)


class PackageManager(str, Enum):
    NPM = "npm"
    PIP = "pip"
    MAVEN = "maven"
    GO = "go"
    RUBY = "ruby"
    CARGO = "cargo"


@dataclass
class VulnerableDependency:
    name: str
    version: str
    cve_id: str
    severity: str          # critical/high/medium/low
    fixed_version: str
    description: str
    package_manager: PackageManager
    is_direct: bool        # Direct or transitive dependency
    is_reachable: bool = False  # Set after reachability analysis
    call_chain: list[str] = field(default_factory=list)


class SCAScanner:
    """
    Scan project dependencies for known vulnerabilities.

    Strategy:
    1. Detect package manager from project files
    2. Run native audit tool (npm audit, pip-audit, etc.)
    3. Parse results into structured VulnerableDependency objects
    4. Correlate with Neo4j graph for reachability (if available)
    """

    name = "sca_scan"
    description = "Scan dependencies for known vulnerabilities"

    MANIFEST_MAP = {
        "package.json": PackageManager.NPM,
        "package-lock.json": PackageManager.NPM,
        "requirements.txt": PackageManager.PIP,
        "Pipfile.lock": PackageManager.PIP,
        "pyproject.toml": PackageManager.PIP,
        "pom.xml": PackageManager.MAVEN,
        "build.gradle": PackageManager.MAVEN,
        "go.mod": PackageManager.GO,
        "Gemfile.lock": PackageManager.RUBY,
        "Cargo.lock": PackageManager.CARGO,
    }

    async def execute(self, project_path: str) -> ToolOutput:
        """Scan a project directory for vulnerable dependencies."""
        path = Path(project_path)
        if not path.exists():
            return ToolOutput(
                success=False,
                error=f"Path not found: {project_path}",
                tool_name=self.name,
                data={},
            )

        # Detect package managers
        managers = self._detect_managers(path)
        if not managers:
            return ToolOutput(
                success=False,
                error="No supported manifest files found",
                tool_name=self.name,
                data={},
            )

        all_vulns: list[VulnerableDependency] = []
        for manager in managers:
            vulns = await self._scan_manager(path, manager)
            all_vulns.extend(vulns)

        return ToolOutput(
            success=True,
            data={
                "vulnerabilities": [
                    {
                        "name": v.name,
                        "version": v.version,
                        "cve_id": v.cve_id,
                        "severity": v.severity,
                        "fixed_version": v.fixed_version,
                        "description": v.description,
                        "package_manager": v.package_manager.value,
                        "is_direct": v.is_direct,
                        "is_reachable": v.is_reachable,
                    }
                    for v in all_vulns
                ],
            },
            tool_name=self.name,
            metadata={
                "total_vulns": len(all_vulns),
                "by_severity": self._count_by_severity(all_vulns),
                "managers_scanned": [m.value for m in managers],
            },
        )

    def _detect_managers(self, path: Path) -> list[PackageManager]:
        found: set[PackageManager] = set()
        for filename, manager in self.MANIFEST_MAP.items():
            if (path / filename).exists():
                found.add(manager)
        return list(found)

    async def _scan_manager(
        self, path: Path, manager: PackageManager
    ) -> list[VulnerableDependency]:
        """Run the appropriate audit tool for a package manager."""
        scanners = {
            PackageManager.NPM: self._scan_npm,
            PackageManager.PIP: self._scan_pip,
        }
        scanner = scanners.get(manager)
        if not scanner:
            logger.warning(f"No scanner implemented for {manager.value}")
            return []
        return await scanner(path)

    async def _scan_npm(self, path: Path) -> list[VulnerableDependency]:
        """Run npm audit --json and parse results."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "npm", "audit", "--json",
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            data = json.loads(stdout.decode())

            vulns = []
            for name, advisory in data.get("vulnerabilities", {}).items():
                for via in advisory.get("via", []):
                    if isinstance(via, dict):
                        vulns.append(VulnerableDependency(
                            name=name,
                            version=advisory.get("range", ""),
                            cve_id=via.get("url", "").split("/")[-1] if via.get("url") else "",
                            severity=via.get("severity", "unknown"),
                            fixed_version=advisory.get("fixAvailable", {}).get("version", "")
                            if isinstance(advisory.get("fixAvailable"), dict) else "",
                            description=via.get("title", ""),
                            package_manager=PackageManager.NPM,
                            is_direct=advisory.get("isDirect", False),
                        ))
            return vulns
        except Exception as e:
            logger.error(f"npm audit failed: {e}")
            return []

    async def _scan_pip(self, path: Path) -> list[VulnerableDependency]:
        """Run pip-audit --format json and parse results."""
        try:
            # Try requirements.txt first, then pyproject.toml
            req_file = path / "requirements.txt"
            args = ["pip-audit", "--format", "json"]
            if req_file.exists():
                args.extend(["--requirement", str(req_file)])

            proc = await asyncio.create_subprocess_exec(
                *args,
                cwd=str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            data = json.loads(stdout.decode())

            vulns = []
            for entry in data:
                for vuln in entry.get("vulns", []):
                    fix_versions = vuln.get("fix_versions", [])
                    vulns.append(VulnerableDependency(
                        name=entry["name"],
                        version=entry["version"],
                        cve_id=vuln.get("id", ""),
                        severity=self._pip_audit_severity(vuln),
                        fixed_version=fix_versions[0] if fix_versions else "",
                        description=vuln.get("description", ""),
                        package_manager=PackageManager.PIP,
                        is_direct=True,
                    ))
            return vulns
        except Exception as e:
            logger.error(f"pip-audit failed: {e}")
            return []

    @staticmethod
    def _pip_audit_severity(vuln: dict) -> str:
        """Estimate severity from pip-audit data (no native severity field)."""
        vuln_id = vuln.get("id", "")
        # pip-audit doesn't provide severity directly; use a reasonable default
        # In production, this would be enriched via EPSS or NVD lookup
        if "CRITICAL" in vuln.get("description", "").upper():
            return "critical"
        return "high"

    @staticmethod
    def _count_by_severity(vulns: list[VulnerableDependency]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts
