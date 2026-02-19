# LEVEL 02: Supply Chain & Dependency Security Scanner

## Context
Sentinel base platform is complete. This level adds supply chain security: scan dependencies for known CVEs, check if vulnerable code paths are reachable, and detect dependency confusion/typosquatting attacks.

Research source: Block 12 (Supply Chain Security), Block 5 (Business Logic). Neupane et al. (USENIX Sec 2023) identified 13 confusion categories; their detectors flag 77% of issues missed by existing tools.

## Why
XBOW and Shannon don't do supply chain. This is a gap Sentinel fills. Every app has 100+ transitive dependencies. Static SCA flags everything; Sentinel confirms which ones are actually exploitable by correlating with the attack graph.

---

## Files to Create

### `src/sentinel/tools/supply_chain/__init__.py`
```python
"""Supply chain security tools — SCA, dependency confusion, container scanning."""
```

### `src/sentinel/tools/supply_chain/sca_scanner.py`
```python
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
from typing import Optional

from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

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
    call_chain: list[str] = field(default_factory=list)  # How app reaches vuln code


class SCAScanner(BaseTool):
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
    
    async def execute(self, project_path: str) -> ToolResult:
        """Scan a project directory for vulnerable dependencies."""
        path = Path(project_path)
        if not path.exists():
            return ToolResult(success=False, error=f"Path not found: {project_path}", tool_name=self.name)
        
        # Detect package managers
        managers = self._detect_managers(path)
        if not managers:
            return ToolResult(success=False, error="No supported manifest files found", tool_name=self.name)
        
        all_vulns = []
        for manager in managers:
            vulns = await self._scan_manager(path, manager)
            all_vulns.extend(vulns)
        
        return ToolResult(
            success=True,
            data=all_vulns,
            tool_name=self.name,
            metadata={
                "total_vulns": len(all_vulns),
                "by_severity": self._count_by_severity(all_vulns),
                "managers_scanned": [m.value for m in managers],
            }
        )
    
    def _detect_managers(self, path: Path) -> list[PackageManager]:
        found = set()
        for filename, manager in self.MANIFEST_MAP.items():
            if (path / filename).exists():
                found.add(manager)
        return list(found)
    
    async def _scan_manager(self, path: Path, manager: PackageManager) -> list[VulnerableDependency]:
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
                            fixed_version=advisory.get("fixAvailable", {}).get("version", ""),
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
            proc = await asyncio.create_subprocess_exec(
                "pip-audit", "--format", "json", "--requirement",
                str(path / "requirements.txt"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            data = json.loads(stdout.decode())
            
            vulns = []
            for entry in data:
                for vuln in entry.get("vulns", []):
                    vulns.append(VulnerableDependency(
                        name=entry["name"],
                        version=entry["version"],
                        cve_id=vuln.get("id", ""),
                        severity=vuln.get("fix_versions", [""])[0] if vuln.get("fix_versions") else "",
                        fixed_version=vuln.get("fix_versions", [""])[0] if vuln.get("fix_versions") else "",
                        description=vuln.get("description", ""),
                        package_manager=PackageManager.PIP,
                        is_direct=True,
                    ))
            return vulns
        except Exception as e:
            logger.error(f"pip-audit failed: {e}")
            return []
    
    def _count_by_severity(self, vulns: list[VulnerableDependency]) -> dict:
        counts = {}
        for v in vulns:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts
```

### `src/sentinel/tools/supply_chain/confusion_detector.py`
```python
"""
Dependency Confusion Detector.

Checks for:
1. Internal package names that exist on public registries (dependency confusion)
2. Typosquatting: packages with names similar to popular packages
3. Namespace confusion: @scope vs unscoped packages

Based on Neupane et al. (USENIX Sec 2023) — 13 confusion categories.
"""
import asyncio
import aiohttp
from dataclasses import dataclass
from difflib import SequenceMatcher
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)

POPULAR_PACKAGES = {
    "npm": ["express", "react", "lodash", "axios", "next", "vue", "webpack",
            "typescript", "eslint", "jest", "mocha", "mongoose", "sequelize"],
    "pip": ["requests", "flask", "django", "numpy", "pandas", "fastapi",
            "sqlalchemy", "celery", "boto3", "pytest", "scipy", "pillow"],
}


@dataclass
class ConfusionAlert:
    package_name: str
    alert_type: str      # "dependency_confusion" | "typosquatting" | "namespace"
    severity: str
    description: str
    similar_to: str = ""
    recommendation: str = ""


class ConfusionDetector(BaseTool):
    name = "confusion_detect"
    description = "Detect dependency confusion and typosquatting risks"
    
    async def execute(self, dependencies: list[dict], registry: str = "npm") -> ToolResult:
        """
        Check a list of dependencies for confusion risks.
        
        Args:
            dependencies: list of {"name": str, "version": str, "is_private": bool}
            registry: "npm" or "pip"
        """
        alerts = []
        
        for dep in dependencies:
            name = dep["name"]
            is_private = dep.get("is_private", False)
            
            # 1. Dependency confusion: private name exists on public registry
            if is_private:
                exists_public = await self._check_public_registry(name, registry)
                if exists_public:
                    alerts.append(ConfusionAlert(
                        package_name=name,
                        alert_type="dependency_confusion",
                        severity="critical",
                        description=f"Private package '{name}' has a public counterpart on {registry}. "
                                    f"An attacker could publish a malicious version.",
                        recommendation=f"Pin to private registry URL. Use .npmrc or pip --index-url to scope.",
                    ))
            
            # 2. Typosquatting: similar to popular packages
            typo = self._check_typosquatting(name, registry)
            if typo:
                alerts.append(typo)
        
        return ToolResult(
            success=True,
            data=alerts,
            tool_name=self.name,
            metadata={"total_alerts": len(alerts), "registry": registry},
        )
    
    async def _check_public_registry(self, name: str, registry: str) -> bool:
        """Check if package name exists on public registry."""
        try:
            if registry == "npm":
                url = f"https://registry.npmjs.org/{name}"
            elif registry == "pip":
                url = f"https://pypi.org/pypi/{name}/json"
            else:
                return False
            
            async with aiohttp.ClientSession() as session:
                async with session.head(url) as resp:
                    return resp.status == 200
        except Exception:
            return False
    
    def _check_typosquatting(self, name: str, registry: str) -> ConfusionAlert | None:
        """Check if package name is suspiciously similar to a popular package."""
        popular = POPULAR_PACKAGES.get(registry, [])
        for pop in popular:
            if name == pop:
                continue
            ratio = SequenceMatcher(None, name.lower(), pop.lower()).ratio()
            if ratio > 0.85 and name != pop:
                return ConfusionAlert(
                    package_name=name,
                    alert_type="typosquatting",
                    severity="high",
                    description=f"Package '{name}' is suspiciously similar to popular package '{pop}' "
                                f"(similarity: {ratio:.0%}). Possible typosquatting.",
                    similar_to=pop,
                    recommendation=f"Verify this is the intended package, not a malicious clone of '{pop}'.",
                )
        return None
```

---

## Files to Modify

### `src/sentinel/agents/hypothesis_engine.py`
Add new hypothesis category and rule:
```python
# In HypothesisCategory enum:
SUPPLY_CHAIN = "supply_chain"  # Vulnerable dependencies, confusion attacks

# In _load_hypothesis_rules(), add:
{
    "pattern": {"has_vulnerable_deps": True},
    "generates": [HypothesisCategory.SUPPLY_CHAIN],
    "confidence": HypothesisConfidence.HIGH,
},
```

### Neo4j: Add Dependency nodes
In the graph module, add support for:
```cypher
CREATE (d:Dependency {
    name: $name,
    version: $version,
    package_manager: $pm,
    cve_id: $cve,
    severity: $severity,
    is_reachable: $reachable,
    engagement_id: $eid
})
WITH d
MATCH (h:Host {engagement_id: $eid})
CREATE (h)-[:HAS_DEPENDENCY]->(d)
```

---

## Tests

### `tests/tools/supply_chain/test_sca_scanner.py`
```python
import pytest
from sentinel.tools.supply_chain.sca_scanner import SCAScanner, PackageManager

class TestSCAScanner:
    def setup_method(self):
        self.scanner = SCAScanner()
    
    def test_detect_npm(self, tmp_path):
        (tmp_path / "package.json").write_text("{}")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.NPM in managers
    
    def test_detect_pip(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("flask==2.0")
        managers = self.scanner._detect_managers(tmp_path)
        assert PackageManager.PIP in managers
    
    def test_detect_none(self, tmp_path):
        managers = self.scanner._detect_managers(tmp_path)
        assert managers == []
```

### `tests/tools/supply_chain/test_confusion_detector.py`
```python
import pytest
from sentinel.tools.supply_chain.confusion_detector import ConfusionDetector

class TestConfusionDetector:
    def setup_method(self):
        self.detector = ConfusionDetector()
    
    def test_typosquatting_detection(self):
        alert = self.detector._check_typosquatting("reqeusts", "pip")
        assert alert is not None
        assert alert.alert_type == "typosquatting"
        assert alert.similar_to == "requests"
    
    def test_no_false_positive_on_exact(self):
        alert = self.detector._check_typosquatting("requests", "pip")
        assert alert is None
    
    def test_no_alert_on_dissimilar(self):
        alert = self.detector._check_typosquatting("my-internal-lib", "pip")
        assert alert is None
```

---

## Acceptance Criteria
- [ ] SCAScanner detects package managers from project files
- [ ] npm audit JSON output is parsed into VulnerableDependency objects
- [ ] ConfusionDetector catches typosquatting (reqeusts → requests)
- [ ] ConfusionDetector catches dependency confusion (private name on public registry)
- [ ] Dependency nodes created in Neo4j with CVE links
- [ ] All tests pass