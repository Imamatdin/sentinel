import pytest

from sentinel.sast.llm_analyzer import LLMCodeAnalyzer, SASTFinding


class TestLLMAnalyzerParsing:
    """Test LLM response parsing — no LLM calls needed."""

    def setup_method(self):
        self.analyzer = LLMCodeAnalyzer(llm_client=None)

    def test_parse_valid_json(self):
        response = (
            '{"findings": [{"vuln_type": "sqli", "confidence": 0.9, '
            '"file": "app.py", "line": 12, "function": "get_users", '
            '"description": "SQL injection", "exploit_hint": "Send id=1 OR 1=1", '
            '"fix_suggestion": "Use parameterized query", "cwe_id": "CWE-89"}]}'
        )
        findings = self.analyzer._parse_llm_response(response)
        assert len(findings) == 1
        assert findings[0].vuln_type == "sqli"
        assert findings[0].confidence == 0.9
        assert findings[0].cwe_id == "CWE-89"

    def test_parse_with_code_fences(self):
        response = (
            '```json\n{"findings": [{"vuln_type": "xss", "confidence": 0.7, '
            '"file": "a.py", "line": 1, "function": "f", "description": "d", '
            '"exploit_hint": "e", "fix_suggestion": "f", "cwe_id": "CWE-79"}]}\n```'
        )
        findings = self.analyzer._parse_llm_response(response)
        assert len(findings) == 1
        assert findings[0].vuln_type == "xss"

    def test_filter_low_confidence(self):
        response = (
            '{"findings": [{"vuln_type": "xss", "confidence": 0.3, '
            '"file": "a.py", "line": 1, "function": "f", "description": "d", '
            '"exploit_hint": "e", "fix_suggestion": "f", "cwe_id": "CWE-79"}]}'
        )
        findings = self.analyzer._parse_llm_response(response)
        assert len(findings) == 0

    def test_parse_threshold_exact(self):
        response = (
            '{"findings": [{"vuln_type": "xss", "confidence": 0.5, '
            '"file": "a.py", "line": 1, "function": "f", "description": "d", '
            '"exploit_hint": "e", "fix_suggestion": "f", "cwe_id": "CWE-79"}]}'
        )
        findings = self.analyzer._parse_llm_response(response)
        assert len(findings) == 1

    def test_parse_invalid_json(self):
        findings = self.analyzer._parse_llm_response("not json at all")
        assert findings == []

    def test_parse_empty_findings(self):
        findings = self.analyzer._parse_llm_response('{"findings": []}')
        assert findings == []

    def test_parse_list_format(self):
        response = (
            '[{"vuln_type": "sqli", "confidence": 0.8, "file": "a.py", "line": 1, '
            '"function": "f", "description": "d", "exploit_hint": "e", '
            '"fix_suggestion": "f", "cwe_id": "CWE-89"}]'
        )
        findings = self.analyzer._parse_llm_response(response)
        assert len(findings) == 1

    def test_deduplicate(self):
        f1 = SASTFinding("sqli", 0.9, "a.py", 10, "f", "d", "e", "f", "CWE-89")
        f2 = SASTFinding("sqli", 0.8, "a.py", 10, "f", "d2", "e2", "f2", "CWE-89")
        result = self.analyzer._deduplicate([f1, f2])
        assert len(result) == 1
        assert result[0].confidence == 0.9  # keeps first

    def test_deduplicate_different_lines(self):
        f1 = SASTFinding("sqli", 0.9, "a.py", 10, "f", "d", "e", "f", "CWE-89")
        f2 = SASTFinding("sqli", 0.8, "a.py", 20, "g", "d2", "e2", "f2", "CWE-89")
        result = self.analyzer._deduplicate([f1, f2])
        assert len(result) == 2

    def test_deduplicate_different_types(self):
        f1 = SASTFinding("sqli", 0.9, "a.py", 10, "f", "d", "e", "f", "CWE-89")
        f2 = SASTFinding("xss", 0.8, "a.py", 10, "f", "d2", "e2", "f2", "CWE-79")
        result = self.analyzer._deduplicate([f1, f2])
        assert len(result) == 2


class TestAuthCoverage:
    """Test auth coverage analysis (no LLM needed)."""

    def setup_method(self):
        self.analyzer = LLMCodeAnalyzer(llm_client=None)

    @pytest.mark.asyncio
    async def test_missing_auth_on_post(self):
        checks = [{
            "function": "create_user",
            "route": "/users",
            "method": "POST",
            "has_auth_decorator": False,
            "file": "app.py",
            "line": 10,
        }]
        findings = await self.analyzer._analyze_auth_coverage(checks)
        assert len(findings) == 1
        assert findings[0].vuln_type == "auth_bypass"
        assert findings[0].cwe_id == "CWE-862"

    @pytest.mark.asyncio
    async def test_auth_present_no_finding(self):
        checks = [{
            "function": "create_user",
            "route": "/users",
            "method": "POST",
            "has_auth_decorator": True,
            "file": "app.py",
            "line": 10,
        }]
        findings = await self.analyzer._analyze_auth_coverage(checks)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_get_without_auth_no_finding(self):
        checks = [{
            "function": "list_users",
            "route": "/users",
            "method": "GET",
            "has_auth_decorator": False,
            "file": "app.py",
            "line": 10,
        }]
        findings = await self.analyzer._analyze_auth_coverage(checks)
        assert len(findings) == 0  # GET without auth is common


class TestDBQueryAnalysis:
    """Test DB query analysis (no LLM needed)."""

    def setup_method(self):
        self.analyzer = LLMCodeAnalyzer(llm_client=None)

    @pytest.mark.asyncio
    async def test_unparameterized_query(self):
        queries = [{
            "file": "app.py",
            "sink": "cursor.execute",
            "line": 12,
            "source": "request.args",
            "parameterized": False,
        }]
        findings = await self.analyzer._analyze_db_queries(queries)
        assert len(findings) == 1
        assert findings[0].vuln_type == "sqli"
        assert findings[0].confidence == 0.8

    @pytest.mark.asyncio
    async def test_parameterized_query_safe(self):
        queries = [{
            "file": "app.py",
            "sink": "cursor.execute",
            "line": 12,
            "source": "request.args",
            "parameterized": True,
        }]
        findings = await self.analyzer._analyze_db_queries(queries)
        assert len(findings) == 0
