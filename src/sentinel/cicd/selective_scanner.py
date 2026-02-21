"""
Selective Scanner — Triggers re-testing of only affected hypothesis categories.

Given DiffRiskAssessments, determines which hypothesis categories need re-testing
and which endpoints are affected. Integrates with the HypothesisEngine to
generate targeted hypotheses rather than a full scan.
"""

from dataclasses import dataclass

from sentinel.cicd.diff_analyzer import DiffRiskAssessment
from sentinel.core import get_logger

logger = get_logger(__name__)

# Maps file path patterns to likely API endpoints
ROUTE_FILE_PATTERNS: dict[str, str] = {
    "routes": "/api",
    "views": "/",
    "controllers": "/api",
    "handlers": "/api",
    "endpoints": "/api",
}


@dataclass
class RetestTarget:
    """A specific target for selective re-testing."""
    hypothesis_categories: list[str]
    affected_endpoints: list[str]
    risk_score: float
    source_files: list[str]


class SelectiveScanner:
    """Determine what to re-test based on diff risk assessments."""

    def plan_retest(
        self, assessments: list[DiffRiskAssessment]
    ) -> RetestTarget | None:
        """Create a retest target from risk assessments.

        Returns None if risk is too low to warrant re-testing.
        """
        if not assessments:
            return None

        max_risk = max(a.risk_score for a in assessments)
        if max_risk < 0.3:
            logger.info(
                "skip_retest",
                reason="risk_too_low",
                max_risk=max_risk,
            )
            return None

        categories: set[str] = set()
        endpoints: set[str] = set()
        source_files: list[str] = []

        for a in assessments:
            if a.risk_score < 0.1:
                continue
            categories.update(a.hypotheses_to_rerun)
            source_files.append(a.file_path)

            # Try to infer endpoints from file paths
            for ep in self._infer_endpoints(a.file_path):
                endpoints.add(ep)

        if not categories:
            return None

        return RetestTarget(
            hypothesis_categories=sorted(categories),
            affected_endpoints=sorted(endpoints),
            risk_score=round(max_risk, 2),
            source_files=source_files,
        )

    def _infer_endpoints(self, file_path: str) -> list[str]:
        """Infer API endpoints from a file path.

        E.g., src/api/routes/users.py -> ["/api/users"]
        """
        endpoints: list[str] = []
        parts = file_path.replace("\\", "/").split("/")

        # Look for route-like directories
        for i, part in enumerate(parts):
            clean = part.replace(".py", "").replace(".ts", "").replace(".js", "")
            for pattern, prefix in ROUTE_FILE_PATTERNS.items():
                if pattern in part.lower() and i + 1 < len(parts):
                    # Next part is the resource
                    resource = parts[i + 1].replace(".py", "").replace(".ts", "").replace(".js", "")
                    endpoints.append(f"{prefix}/{resource}")

        # Also check the filename itself for resource names
        filename = parts[-1] if parts else ""
        clean_name = (
            filename.replace(".py", "")
            .replace(".ts", "")
            .replace(".js", "")
        )
        if clean_name and clean_name not in ("__init__", "index", "main", "app"):
            for pattern in ROUTE_FILE_PATTERNS:
                if pattern in "/".join(parts).lower():
                    endpoints.append(f"/api/{clean_name}")
                    break

        return endpoints
