import pytest

from sentinel.sast.threat_model import ThreatModelGenerator, STRIDECategory
from sentinel.sast.ast_extractor import CodeStructure, FunctionInfo, DataFlow


def _make_code_structure() -> CodeStructure:
    return CodeStructure(
        functions=[
            FunctionInfo(
                "get_user", "app.py", 10, 20, ["id"],
                is_route_handler=True, http_method="GET", route_path="/users",
            ),
            FunctionInfo(
                "delete_user", "app.py", 25, 35, ["id"],
                is_route_handler=True, http_method="DELETE", route_path="/users/<id>",
            ),
        ],
        data_flows=[
            DataFlow(
                "request.args", "user_input", "cursor.execute", "sql",
                "app.py", 12, 15, is_sanitized=False,
            ),
        ],
        imports=["flask", "sqlite3"],
        routes=[
            FunctionInfo(
                "get_user", "app.py", 10, 20, ["id"],
                is_route_handler=True, http_method="GET", route_path="/users",
            ),
        ],
        db_queries=[{
            "file": "app.py", "sink": "cursor.execute", "line": 15,
            "source": "request.args", "parameterized": False,
        }],
        auth_checks=[
            {
                "function": "get_user", "route": "/users", "method": "GET",
                "has_auth_decorator": False, "file": "app.py", "line": 10,
            },
            {
                "function": "delete_user", "route": "/users/<id>", "method": "DELETE",
                "has_auth_decorator": False, "file": "app.py", "line": 25,
            },
        ],
        file_count=1,
        total_lines=40,
    )


class TestThreatModelGenerator:
    def setup_method(self):
        self.gen = ThreatModelGenerator()

    def test_generates_threats(self):
        model = self.gen.generate(_make_code_structure())
        assert model.summary["total_threats"] > 0

    def test_app_name(self):
        model = self.gen.generate(_make_code_structure(), app_name="myapp")
        assert model.app_name == "myapp"

    def test_detects_spoofing(self):
        model = self.gen.generate(_make_code_structure())
        spoofing = [t for t in model.threats if t.stride_category == STRIDECategory.SPOOFING]
        assert len(spoofing) >= 1  # DELETE without auth

    def test_detects_tampering(self):
        model = self.gen.generate(_make_code_structure())
        tampering = [t for t in model.threats if t.stride_category == STRIDECategory.TAMPERING]
        assert len(tampering) >= 1  # Unparameterized SQL

    def test_detects_info_disclosure(self):
        model = self.gen.generate(_make_code_structure())
        info = [t for t in model.threats if t.stride_category == STRIDECategory.INFO_DISCLOSURE]
        assert len(info) >= 1  # sqlite3 with PII

    def test_detects_elevation(self):
        model = self.gen.generate(_make_code_structure())
        elevation = [t for t in model.threats if t.stride_category == STRIDECategory.ELEVATION]
        assert len(elevation) >= 1  # route with 'id' param

    def test_trust_boundaries(self):
        model = self.gen.generate(_make_code_structure())
        assert len(model.trust_boundaries) >= 1
        public = [b for b in model.trust_boundaries if not b.auth_required]
        assert len(public) >= 1

    def test_components_detected(self):
        model = self.gen.generate(_make_code_structure())
        types = {c["type"] for c in model.components}
        assert "web_framework" in types
        assert "data_store" in types
        assert "endpoint" in types

    def test_data_stores_identified(self):
        model = self.gen.generate(_make_code_structure())
        assert len(model.data_stores) >= 1

    def test_dast_hypotheses(self):
        model = self.gen.generate(_make_code_structure())
        hypotheses = self.gen.to_dast_hypotheses(model)
        assert len(hypotheses) > 0
        assert all("test" in h for h in hypotheses)
        assert all("category" in h for h in hypotheses)
        assert all("priority" in h for h in hypotheses)

    def test_summary_counts(self):
        model = self.gen.generate(_make_code_structure())
        assert model.summary["total_threats"] == len(model.threats)
        total_by_stride = sum(model.summary["by_stride"].values())
        assert total_by_stride == model.summary["total_threats"]

    def test_empty_code_structure(self):
        empty = CodeStructure(
            functions=[], data_flows=[], imports=[], routes=[],
            db_queries=[], auth_checks=[], file_count=0, total_lines=0,
        )
        model = self.gen.generate(empty)
        assert model.summary["total_threats"] == 0
        assert model.threats == []

    def test_high_likelihood_priority(self):
        model = self.gen.generate(_make_code_structure())
        hypotheses = self.gen.to_dast_hypotheses(model)
        high_priority = [h for h in hypotheses if h["priority"] == 1.0]
        assert len(high_priority) >= 1
