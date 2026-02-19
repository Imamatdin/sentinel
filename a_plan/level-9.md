# LEVEL 09: Auto Threat Modeling from Code

## Context
Aardvark-style: ingest a repo, auto-generate a STRIDE threat model, then seed DAST hypotheses from it. SecureFlag ThreatCanvas does this CI-triggered. No published accuracy metrics exist — treat output as high-value hypotheses, not ground truth.

Research: Block 9 (Auto Threat Modeling from Code). Depends on L08 (AST extractor).

## Why
Manual threat modeling takes days. Auto-generating one from code gives a structured attack plan in minutes. Every route, every trust boundary, every data store becomes a node in the threat model. Sentinel uses this to prioritize what to test.

---

## Files to Create

### `src/sentinel/sast/threat_model.py`
```python
"""
Auto Threat Modeling — Generates STRIDE threat models from code structure.

STRIDE categories:
  S — Spoofing (auth bypass, session hijacking)
  T — Tampering (injection, CSRF, parameter manipulation)
  R — Repudiation (missing audit logs)
  I — Information Disclosure (verbose errors, data exposure)
  D — Denial of Service (resource exhaustion, ReDoS)
  E — Elevation of Privilege (IDOR, privilege escalation)
"""
from dataclasses import dataclass, field
from enum import Enum
from sentinel.sast.ast_extractor import CodeStructure, FunctionInfo
from sentinel.logging import get_logger

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
    entry_points: list[str]    # routes/endpoints that cross this boundary
    auth_required: bool


@dataclass 
class ThreatEntry:
    stride_category: STRIDECategory
    target: str                # component/route affected
    description: str
    likelihood: str            # high/medium/low
    impact: str
    mitigation_present: bool
    mitigation_description: str = ""
    dast_test_suggestion: str = ""


@dataclass
class ThreatModel:
    app_name: str
    components: list[dict]           # {name, type, description}
    trust_boundaries: list[TrustBoundary]
    data_stores: list[dict]          # {name, type, contains_pii, encrypted}
    threats: list[ThreatEntry]
    summary: dict                    # {total_threats, by_stride, by_likelihood}


class ThreatModelGenerator:
    """Generate STRIDE threat model from CodeStructure."""
    
    def generate(self, code: CodeStructure, app_name: str = "target") -> ThreatModel:
        """Generate threat model from extracted code structure."""
        components = self._identify_components(code)
        boundaries = self._identify_trust_boundaries(code)
        data_stores = self._identify_data_stores(code)
        threats = self._generate_threats(code, boundaries, data_stores)
        
        summary = {
            "total_threats": len(threats),
            "by_stride": {},
            "by_likelihood": {},
        }
        for t in threats:
            summary["by_stride"][t.stride_category.value] = summary["by_stride"].get(t.stride_category.value, 0) + 1
            summary["by_likelihood"][t.likelihood] = summary["by_likelihood"].get(t.likelihood, 0) + 1
        
        return ThreatModel(
            app_name=app_name,
            components=components,
            trust_boundaries=boundaries,
            data_stores=data_stores,
            threats=threats,
            summary=summary,
        )
    
    def _identify_components(self, code: CodeStructure) -> list[dict]:
        """Identify application components from code structure."""
        components = []
        
        # Web framework detection
        frameworks = {
            "flask": "Flask Web App",
            "django": "Django Web App",
            "fastapi": "FastAPI App",
            "express": "Express.js App",
        }
        for imp in code.imports:
            for fw, label in frameworks.items():
                if fw in imp.lower():
                    components.append({"name": label, "type": "web_framework", "description": f"Detected {fw}"})
                    break
        
        # Database detection
        db_libs = {"sqlalchemy": "SQL Database", "sqlite3": "SQLite", "pymongo": "MongoDB",
                    "redis": "Redis Cache", "psycopg": "PostgreSQL", "mysql": "MySQL"}
        for imp in code.imports:
            for lib, label in db_libs.items():
                if lib in imp.lower():
                    components.append({"name": label, "type": "data_store", "description": f"Via {lib}"})
        
        # API endpoints as components
        for route in code.routes:
            components.append({
                "name": f"{route.http_method} {route.route_path}",
                "type": "endpoint",
                "description": f"Handler: {route.name} in {route.file_path}",
            })
        
        return components
    
    def _identify_trust_boundaries(self, code: CodeStructure) -> list[TrustBoundary]:
        """Identify trust boundaries from auth checks."""
        boundaries = []
        
        # External → Authenticated boundary
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
        stores = []
        for imp in code.imports:
            if any(db in imp.lower() for db in ["sqlalchemy", "sqlite", "psycopg", "mysql", "pymongo"]):
                stores.append({
                    "name": imp,
                    "type": "database",
                    "contains_pii": True,   # Assume worst case
                    "encrypted": False,      # Assume worst case
                })
        return stores
    
    def _generate_threats(self, code: CodeStructure, boundaries: list[TrustBoundary],
                          data_stores: list[dict]) -> list[ThreatEntry]:
        """Generate STRIDE threats from identified components."""
        threats = []
        
        # SPOOFING: Routes without auth on state-changing methods
        for check in code.auth_checks:
            if not check["has_auth_decorator"] and check["method"] in ("POST", "PUT", "DELETE"):
                threats.append(ThreatEntry(
                    stride_category=STRIDECategory.SPOOFING,
                    target=f"{check['method']} {check['route']}",
                    description=f"No auth on state-changing endpoint. Attacker can impersonate users.",
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
        
        # TAMPERING: User input → dangerous sinks
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
        
        # INFO DISCLOSURE: Assume PII in data stores without encryption
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
        
        # ELEVATION: Look for IDOR patterns (ID params without ownership checks)
        for route in code.routes:
            if any(p in ["id", "user_id", "uid", "account_id"] for p in route.params):
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
```

---

## Tests

### `tests/sast/test_threat_model.py`
```python
import pytest
from sentinel.sast.threat_model import ThreatModelGenerator, STRIDECategory
from sentinel.sast.ast_extractor import CodeStructure, FunctionInfo, DataFlow

class TestThreatModelGenerator:
    def setup_method(self):
        self.gen = ThreatModelGenerator()
    
    def _make_code_structure(self):
        return CodeStructure(
            functions=[
                FunctionInfo("get_user", "app.py", 10, 20, ["id"], is_route_handler=True,
                            http_method="GET", route_path="/users"),
                FunctionInfo("delete_user", "app.py", 25, 35, ["id"], is_route_handler=True,
                            http_method="DELETE", route_path="/users/<id>"),
            ],
            data_flows=[
                DataFlow("request.args", "user_input", "cursor.execute", "sql",
                        "app.py", 12, 15, is_sanitized=False),
            ],
            imports=["flask", "sqlite3"],
            routes=[
                FunctionInfo("get_user", "app.py", 10, 20, ["id"], is_route_handler=True,
                            http_method="GET", route_path="/users"),
            ],
            db_queries=[{"file": "app.py", "sink": "cursor.execute", "line": 15,
                        "source": "request.args", "parameterized": False}],
            auth_checks=[
                {"function": "get_user", "route": "/users", "method": "GET",
                 "has_auth_decorator": False, "file": "app.py", "line": 10},
                {"function": "delete_user", "route": "/users/<id>", "method": "DELETE",
                 "has_auth_decorator": False, "file": "app.py", "line": 25},
            ],
            file_count=1, total_lines=40,
        )
    
    def test_generates_threats(self):
        model = self.gen.generate(self._make_code_structure())
        assert model.summary["total_threats"] > 0
    
    def test_detects_spoofing(self):
        model = self.gen.generate(self._make_code_structure())
        spoofing = [t for t in model.threats if t.stride_category == STRIDECategory.SPOOFING]
        assert len(spoofing) >= 1  # DELETE without auth
    
    def test_detects_tampering(self):
        model = self.gen.generate(self._make_code_structure())
        tampering = [t for t in model.threats if t.stride_category == STRIDECategory.TAMPERING]
        assert len(tampering) >= 1  # Unparameterized SQL
    
    def test_dast_hypotheses(self):
        model = self.gen.generate(self._make_code_structure())
        hypotheses = self.gen.to_dast_hypotheses(model)
        assert len(hypotheses) > 0
        assert all("test" in h for h in hypotheses)
```

---

## Acceptance Criteria
- [ ] ThreatModelGenerator produces STRIDE model from CodeStructure
- [ ] Spoofing threats generated for unauth state-changing routes
- [ ] Tampering threats generated for unparameterized queries
- [ ] Elevation threats generated for ID-param routes
- [ ] `to_dast_hypotheses()` converts threats into actionable test suggestions
- [ ] All tests pass