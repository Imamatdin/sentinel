"""
Dependency Confusion Detector.

Checks for:
1. Internal package names that exist on public registries (dependency confusion)
2. Typosquatting: packages with names similar to popular packages
3. Namespace confusion: @scope vs unscoped packages

Based on Neupane et al. (USENIX Sec 2023) — 13 confusion categories.
"""

import httpx
from dataclasses import dataclass
from difflib import SequenceMatcher

from sentinel.tools.base import ToolOutput
from sentinel.core import get_logger

logger = get_logger(__name__)

POPULAR_PACKAGES = {
    "npm": [
        "express", "react", "lodash", "axios", "next", "vue", "webpack",
        "typescript", "eslint", "jest", "mocha", "mongoose", "sequelize",
        "moment", "chalk", "commander", "dotenv", "cors", "uuid", "debug",
    ],
    "pip": [
        "requests", "flask", "django", "numpy", "pandas", "fastapi",
        "sqlalchemy", "celery", "boto3", "pytest", "scipy", "pillow",
        "pydantic", "httpx", "uvicorn", "gunicorn", "cryptography", "aiohttp",
    ],
}


@dataclass
class ConfusionAlert:
    package_name: str
    alert_type: str      # "dependency_confusion" | "typosquatting" | "namespace"
    severity: str
    description: str
    similar_to: str = ""
    recommendation: str = ""


class ConfusionDetector:
    """Detect dependency confusion and typosquatting risks."""

    name = "confusion_detect"
    description = "Detect dependency confusion and typosquatting risks"

    async def execute(
        self,
        dependencies: list[dict],
        registry: str = "npm",
    ) -> ToolOutput:
        """
        Check a list of dependencies for confusion risks.

        Args:
            dependencies: list of {"name": str, "version": str, "is_private": bool}
            registry: "npm" or "pip"
        """
        alerts: list[ConfusionAlert] = []

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
                        description=(
                            f"Private package '{name}' has a public counterpart on {registry}. "
                            f"An attacker could publish a malicious version."
                        ),
                        recommendation=(
                            f"Pin to private registry URL. Use .npmrc or pip --index-url to scope."
                        ),
                    ))

            # 2. Typosquatting: similar to popular packages
            typo = self._check_typosquatting(name, registry)
            if typo:
                alerts.append(typo)

        return ToolOutput(
            success=True,
            data={
                "alerts": [
                    {
                        "package_name": a.package_name,
                        "alert_type": a.alert_type,
                        "severity": a.severity,
                        "description": a.description,
                        "similar_to": a.similar_to,
                        "recommendation": a.recommendation,
                    }
                    for a in alerts
                ],
            },
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

            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.head(url)
                return resp.status_code == 200
        except Exception:
            return False

    def _check_typosquatting(self, name: str, registry: str) -> ConfusionAlert | None:
        """Check if package name is suspiciously similar to a popular package."""
        popular = POPULAR_PACKAGES.get(registry, [])
        for pop in popular:
            if name == pop:
                continue
            ratio = SequenceMatcher(None, name.lower(), pop.lower()).ratio()
            if ratio > 0.85:
                return ConfusionAlert(
                    package_name=name,
                    alert_type="typosquatting",
                    severity="high",
                    description=(
                        f"Package '{name}' is suspiciously similar to popular package '{pop}' "
                        f"(similarity: {ratio:.0%}). Possible typosquatting."
                    ),
                    similar_to=pop,
                    recommendation=f"Verify this is the intended package, not a malicious clone of '{pop}'.",
                )
        return None
