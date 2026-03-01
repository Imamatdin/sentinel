import pytest

from sentinel.sast.dast_bridge import SASTtoDAST, TargetedHypothesis
from sentinel.sast.llm_analyzer import SASTFinding


class TestSASTtoDAST:
    def setup_method(self):
        self.bridge = SASTtoDAST()

    def test_sqli_finding_converts(self):
        finding = SASTFinding(
            vuln_type="sqli", confidence=0.9,
            file_path="app.py", line=12, function="get_users",
            description="SQLi in get_users",
            exploit_hint="Send GET to /api/users with id parameter",
            fix_suggestion="parameterize",
            cwe_id="CWE-89",
        )
        hypotheses = self.bridge.convert([finding], "http://target:8080")
        assert len(hypotheses) == 1
        assert hypotheses[0].test_category == "injection"
        assert hypotheses[0].method == "GET"

    def test_xss_finding_converts(self):
        finding = SASTFinding(
            vuln_type="xss", confidence=0.7,
            file_path="a.py", line=5, function="search",
            description="Reflected XSS",
            exploit_hint="GET /search with q param",
            fix_suggestion="escape output",
            cwe_id="CWE-79",
        )
        hypotheses = self.bridge.convert([finding], "http://target")
        assert len(hypotheses) == 1
        assert hypotheses[0].test_category == "xss"
        assert len(hypotheses[0].payload_hints) > 0

    def test_command_injection_converts(self):
        finding = SASTFinding(
            vuln_type="command_injection", confidence=0.85,
            file_path="a.py", line=1, function="run",
            description="cmd inj", exploit_hint="POST /exec",
            fix_suggestion="fix", cwe_id="CWE-78",
        )
        hypotheses = self.bridge.convert([finding], "http://target")
        assert len(hypotheses) == 1
        assert hypotheses[0].test_category == "command_injection"

    def test_unknown_type_skipped(self):
        finding = SASTFinding(
            vuln_type="unknown_thing", confidence=0.9,
            file_path="a.py", line=1, function="f",
            description="d", exploit_hint="e", fix_suggestion="f", cwe_id="",
        )
        hypotheses = self.bridge.convert([finding], "http://target")
        assert len(hypotheses) == 0

    def test_priority_boost(self):
        finding = SASTFinding(
            vuln_type="xss", confidence=0.8,
            file_path="a.py", line=1, function="f",
            description="d", exploit_hint="GET /search",
            fix_suggestion="f", cwe_id="CWE-79",
        )
        hypotheses = self.bridge.convert([finding], "http://target")
        assert hypotheses[0].priority == pytest.approx(0.8 * 1.5)

    def test_url_extraction_from_hint(self):
        finding = SASTFinding(
            vuln_type="sqli", confidence=0.9,
            file_path="a.py", line=1, function="f",
            description="d", exploit_hint="Send POST to /api/users",
            fix_suggestion="f", cwe_id="CWE-89",
        )
        hypotheses = self.bridge.convert([finding], "http://target:8080")
        assert hypotheses[0].target_url == "http://target:8080/api/users"
        assert hypotheses[0].method == "POST"

    def test_multiple_findings_sorted_by_priority(self):
        low = SASTFinding(
            vuln_type="xss", confidence=0.5,
            file_path="a.py", line=1, function="f",
            description="d", exploit_hint="e",
            fix_suggestion="f", cwe_id="CWE-79",
        )
        high = SASTFinding(
            vuln_type="sqli", confidence=0.95,
            file_path="b.py", line=10, function="g",
            description="d", exploit_hint="e",
            fix_suggestion="f", cwe_id="CWE-89",
        )
        hypotheses = self.bridge.convert([low, high], "http://target")
        assert len(hypotheses) == 2
        assert hypotheses[0].priority > hypotheses[1].priority

    def test_all_supported_types(self):
        for vuln_type in ["sqli", "xss", "command_injection", "ssrf", "path_traversal", "idor", "auth_bypass"]:
            finding = SASTFinding(
                vuln_type=vuln_type, confidence=0.8,
                file_path="a.py", line=1, function="f",
                description="d", exploit_hint="e",
                fix_suggestion="f", cwe_id="",
            )
            hypotheses = self.bridge.convert([finding], "http://target")
            assert len(hypotheses) == 1, f"Failed for {vuln_type}"
