"""
Auto Threat Modeling — Generates STRIDE threat models from code structure.

STRIDE categories:
  S -- Spoofing (auth bypass, session hijacking)
  T -- Tampering (injection, CSRF, parameter manipulation)
  R -- Repudiation (missing audit logs)
  I -- Information Disclosure (verbose errors, data exposure)
  D -- Denial of Service (resource exhaustion, ReDoS)
  E -- Elevation of Privilege (IDOR, privilege escalation)
"""

from dataclasses import dataclass
from enum import Enum

from sentinel.sast.ast_extractor import CodeStructure
from sentinel.core import get_logger

logger = get_logger(__name__)


class STRIDECategory(str, Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFO_DISCLOSURE = "info_disclosure"
    DENIAL_OF_SERVICE = "dos"
    ELEVATION = "elevation"


@dataclass
class TrustBoundary:
    name: str
    description: str
    entry_points: list[str]
    auth_required: bool


@dataclass
class ThreatEntry:
    stride_category: STRIDECategory
    target: str
    description: str
    likelihood: str   # high/medium/low
    impact: str
    mitigation_present: bool
    mitigation_description: str = ""
    dast_test_suggestion: str = ""


@dataclass
class ThreatModel:
    app_name: str
    components: list[dict]
    trust_boundaries: list[TrustBoundary]
    data_stores: list[dict]
    threats: list[ThreatEntry]
    summary: dict


class ThreatModelGenerator:
    """Generate STRIDE threat model from CodeStructure."""

    def generate(self, code: CodeStructure, app_name: str = "target") -> ThreatModel:
        """Generate threat model from extracted code structure."""
        components = self._identify_components(code)
        boundaries = self._identify_trust_boundaries(code)
        data_stores = self._identify_data_stores(code)
        threats = self._generate_threats(code, boundaries, data_stores)

        by_stride: dict[str, int] = {}
        by_likelihood: dict[str, int] = {}
        for t in threats:
            by_stride[t.stride_category.value] = by_stride.get(t.stride_category.value, 0) + 1
            by_likelihood[t.likelihood] = by_likelihood.get(t.likelihood, 0) + 1

        return ThreatModel(
            app_name=app_name,
            components=components,
            trust_boundaries=boundaries,
            data_stores=data_stores,
            threats=threats,
            summary={
                "total_threats": len(threats),
                "by_stride": by_stride,
                "by_likelihood": by_likelihood,
            },
        )

    def _identify_components(self, code: CodeStructure) -> list[dict]:
        """Identify application components from code structure."""
        components: list[dict] = []

        frameworks = {
            "flask": "Flask Web App",
            "django": "Django Web App",
            "fastapi": "FastAPI App",
            "express": "Express.js App",
        }
        seen_frameworks: set[str] = set()
        for imp in code.imports:
            for fw, label in frameworks.items():
                if fw in imp.lower() and fw not in seen_frameworks:
                    seen_frameworks.add(fw)
                    components.append({
                        "name": label,
                        "type": "web_framework",
                        "description": f"Detected {fw}",
                    })

        db_libs = {
            "sqlalchemy": "SQL Database",
            "sqlite3": "SQLite",
            "pymongo": "MongoDB",
            "redis": "Redis Cache",
            "psycopg": "PostgreSQL",
            "mysql": "MySQL",
        }
        seen_dbs: set[str] = set()
        for imp in code.imports:
            for lib, label in db_libs.items():
                if lib in imp.lower() and lib not in seen_dbs:
                    seen_dbs.add(lib)
                    components.append({
                        "name": label,
                        "type": "data_store",
                        "description": f"Via {lib}",
                    })

        for route in code.routes:
            components.append({
                "name": f"{route.http_method} {route.route_path}",
                "type": "endpoint",
                "description": f"Handler: {route.name} in {route.file_path}",
            })

        return components

    def _identify_trust_boundaries(self, code: CodeStructure) -> list[TrustBoundary]:
        """Identify trust boundaries from auth checks."""
        boundaries: list[TrustBoundary] = []

        auth_routes = [c for c in code.auth_checks if c["has_auth_decorator"]]
        unauth_routes = [c for c in code.auth_checks if not c["has_auth_decorator"]]

        if auth_routes:
            boundaries.append(TrustBoundary(
                name="Authentication Boundary",
                description="Routes requiring authentication",
                entry_points=[f"{c['method']} {c['route']}" for c in auth_routes],
                auth_required=True,
            ))

        if unauth_routes:
            boundaries.append(TrustBoundary(
                name="Public Boundary",
                description="Routes accessible without authentication",
                entry_points=[f"{c['method']} {c['route']}" for c in unauth_routes],
                auth_required=False,
            ))

        return boundaries

    def _identify_data_stores(self, code: CodeStructure) -> list[dict]:
        """Identify data stores and what they might contain."""
        stores: list[dict] = []
        db_indicators = ("sqlalchemy", "sqlite", "psycopg", "mysql", "pymongo")
        seen: set[str] = set()
        for imp in code.imports:
            if any(db in imp.lower() for db in db_indicators) and imp not in seen:
                seen.add(imp)
                stores.append({
                    "name": imp,
                    "type": "database",
                    "contains_pii": True,
                    "encrypted": False,
                })
        return stores

    def _generate_threats(
        self,
        code: CodeStructure,
        boundaries: list[TrustBoundary],
        data_stores: list[dict],
    ) -> list[ThreatEntry]:
        """Generate STRIDE threats from identified components."""
        threats: list[ThreatEntry] = []

        # SPOOFING: Routes without auth on state-changing methods
        for check in code.auth_checks:
            if not check["has_auth_decorator"] and check["method"] in (
                "POST", "PUT", "DELETE", "MULTI"
            ):
                threats.append(ThreatEntry(
                    stride_category=STRIDECategory.SPOOFING,
                    target=f"{check['method']} {check['route']}",
                    description="No auth on state-changing endpoint. Attacker can impersonate users.",
                    likelihood="high",
                    impact="high",
                    mitigation_present=False,
                    dast_test_suggestion=f"Test {check['route']} without auth headers",
                ))

        # TAMPERING: Unparameterized DB queries
        for q in code.db_queries:
            if not q.get("parameterized", True):
                threats.append(ThreatEntry(
                    stride_category=STRIDECategory.TAMPERING,
                    target=q.get("sink", q.get("file", "")),
                    description=f"SQL query built from user input without parameterization at line {q['line']}.",
                    likelihood="high",
                    impact="critical",
                    mitigation_present=False,
                    dast_test_suggestion=f"Test endpoint with SQLi payloads on {q.get('source', 'input')}",
                ))

        # TAMPERING: User input -> dangerous sinks
        for flow in code.data_flows:
            if not flow.is_sanitized and flow.sink_type in ("command", "deserialize"):
                threats.append(ThreatEntry(
                    stride_category=STRIDECategory.TAMPERING,
                    target=f"{flow.file_path}:{flow.line_sink}",
                    description=f"User input flows to {flow.sink_type} sink ({flow.sink}) without sanitization.",
                    likelihood="high",
                    impact="critical",
                    mitigation_present=False,
                    dast_test_suggestion=f"Test with {flow.sink_type} payloads",
                ))

        # INFO DISCLOSURE: PII in unencrypted data stores
        for store in data_stores:
            if store.get("contains_pii") and not store.get("encrypted"):
                threats.append(ThreatEntry(
                    stride_category=STRIDECategory.INFO_DISCLOSURE,
                    target=store["name"],
                    description="Data store likely contains PII without encryption at rest.",
                    likelihood="medium",
                    impact="high",
                    mitigation_present=False,
                    dast_test_suggestion="Check for data exposure via error messages and API responses",
                ))

        # ELEVATION: ID params without ownership checks (IDOR)
        id_params = {"id", "user_id", "uid", "account_id"}
        for route in code.routes:
            if id_params & set(route.params):
                threats.append(ThreatEntry(
                    stride_category=STRIDECategory.ELEVATION,
                    target=f"{route.http_method} {route.route_path}",
                    description=f"Route accepts ID parameter ({route.params}). Potential IDOR if no ownership check.",
                    likelihood="medium",
                    impact="high",
                    mitigation_present=False,
                    dast_test_suggestion="Test with different user's IDs (differential testing)",
                ))

        return threats

    def to_dast_hypotheses(self, model: ThreatModel) -> list[dict]:
        """Convert threat model entries to DAST hypothesis hints."""
        return [
            {
                "category": t.stride_category.value,
                "target": t.target,
                "test": t.dast_test_suggestion,
                "priority": 1.0 if t.likelihood == "high" else 0.6 if t.likelihood == "medium" else 0.3,
            }
            for t in model.threats
            if t.dast_test_suggestion
        ]
