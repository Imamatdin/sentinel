# LEVEL 08: Hybrid SAST — LLM-Powered Static Analysis

## Context
Sentinel base platform does black-box DAST. This level adds white-box static analysis by combining AST/DFG extraction with LLM reasoning. IRIS (GPT-4 + taint analysis) found 55/120 real Java vulns vs CodeQL's 27 — ~2x recall. Aardvark achieves 92% recall on benchmark repos. Key: LLM reasons over structured code representations, not raw source.

Research: Block 9 (LLM-driven SAST, Hybrid Static/Dynamic Loop).

## Why
Static analysis finds bugs DAST misses (dead code paths, complex data flows). But traditional SAST has ~85% false discovery rate. LLM + AST reduces false positives by understanding intent, not just pattern matching. The hybrid loop: static flags → dynamic confirms → feedback improves static model.

---

## Files to Create

### `src/sentinel/sast/__init__.py`
```python
"""Static Application Security Testing — AST extraction, LLM analysis, taint tracking."""
```

### `src/sentinel/sast/ast_extractor.py`
```python
"""
AST/DFG Extractor — Parses source code into structured representations for LLM analysis.

Supports: Python (ast module), JavaScript (tree-sitter), Java (tree-sitter).
Extracts: function signatures, call graphs, data flow (source→sink), security-relevant patterns.
"""
import ast
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FunctionInfo:
    name: str
    file_path: str
    line_start: int
    line_end: int
    params: list[str]
    return_type: str = ""
    calls: list[str] = field(default_factory=list)       # functions this calls
    reads_from: list[str] = field(default_factory=list)   # variables/params read
    writes_to: list[str] = field(default_factory=list)    # variables/returns written
    decorators: list[str] = field(default_factory=list)
    is_route_handler: bool = False
    http_method: str = ""
    route_path: str = ""


@dataclass
class DataFlow:
    source: str          # e.g. "request.args['id']"
    source_type: str     # "user_input", "database", "file", "env"
    sink: str            # e.g. "cursor.execute(query)"
    sink_type: str       # "sql_query", "command_exec", "file_write", "response"
    file_path: str
    line_source: int
    line_sink: int
    intermediates: list[str] = field(default_factory=list)  # transformations applied
    is_sanitized: bool = False
    sanitizer: str = ""


@dataclass
class CodeStructure:
    """Structured representation of a codebase for LLM analysis."""
    functions: list[FunctionInfo]
    data_flows: list[DataFlow]
    imports: list[str]
    routes: list[FunctionInfo]      # HTTP route handlers
    db_queries: list[dict]          # {function, query_pattern, parameterized: bool}
    auth_checks: list[dict]         # {function, decorator_or_middleware, line}
    file_count: int
    total_lines: int


class PythonASTExtractor:
    """Extract security-relevant structure from Python source code."""
    
    DANGEROUS_SINKS = {
        "sql": ["execute", "executemany", "raw", "text", "query"],
        "command": ["system", "popen", "run", "call", "check_output", "Popen",
                     "exec", "eval", "compile"],
        "file": ["open", "read", "write", "readlines"],
        "response": ["render", "render_template", "render_template_string",
                      "jsonify", "Response", "make_response"],
        "deserialize": ["loads", "load", "unpickle", "yaml.load", "yaml.unsafe_load"],
    }
    
    USER_INPUT_SOURCES = [
        "request.args", "request.form", "request.json", "request.data",
        "request.files", "request.headers", "request.cookies",
        "request.GET", "request.POST", "request.body",
        "sys.argv", "input(", "os.environ",
    ]
    
    ROUTE_DECORATORS = [
        "route", "get", "post", "put", "delete", "patch",
        "api_view", "action", "app.route", "router.",
    ]
    
    AUTH_DECORATORS = [
        "login_required", "permission_required", "requires_auth",
        "jwt_required", "auth_required", "protected", "admin_only",
        "IsAuthenticated", "IsAdminUser", "has_permission",
    ]
    
    def extract_file(self, file_path: str) -> tuple[list[FunctionInfo], list[DataFlow]]:
        """Extract functions and data flows from a single Python file."""
        source = Path(file_path).read_text()
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            logger.warning(f"Parse error in {file_path}: {e}")
            return [], []
        
        functions = []
        data_flows = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info = self._extract_function(node, file_path, source)
                functions.append(func_info)
                
                # Track data flows within function
                flows = self._trace_data_flows(node, file_path, source)
                data_flows.extend(flows)
        
        return functions, data_flows
    
    def extract_project(self, project_path: str) -> CodeStructure:
        """Extract structure from entire project."""
        path = Path(project_path)
        all_functions = []
        all_flows = []
        all_imports = []
        file_count = 0
        total_lines = 0
        
        for py_file in path.rglob("*.py"):
            # Skip venv, node_modules, tests
            if any(skip in str(py_file) for skip in ["venv", "node_modules", ".git", "__pycache__"]):
                continue
            
            file_count += 1
            total_lines += sum(1 for _ in py_file.open())
            
            funcs, flows = self.extract_file(str(py_file))
            all_functions.extend(funcs)
            all_flows.extend(flows)
            
            # Extract imports
            try:
                tree = ast.parse(py_file.read_text())
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            all_imports.append(alias.name)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            all_imports.append(node.module)
            except SyntaxError:
                pass
        
        routes = [f for f in all_functions if f.is_route_handler]
        db_queries = self._find_db_queries(all_functions, all_flows)
        auth_checks = self._find_auth_checks(all_functions)
        
        return CodeStructure(
            functions=all_functions,
            data_flows=all_flows,
            imports=list(set(all_imports)),
            routes=routes,
            db_queries=db_queries,
            auth_checks=auth_checks,
            file_count=file_count,
            total_lines=total_lines,
        )
    
    def _extract_function(self, node, file_path: str, source: str) -> FunctionInfo:
        """Extract info from a function AST node."""
        params = [arg.arg for arg in node.args.args]
        decorators = []
        is_route = False
        http_method = ""
        route_path = ""
        
        for dec in node.decorator_list:
            dec_str = ast.dump(dec)
            dec_name = self._decorator_name(dec)
            decorators.append(dec_name)
            
            if any(rd in dec_name.lower() for rd in self.ROUTE_DECORATORS):
                is_route = True
                http_method = self._extract_http_method(dec)
                route_path = self._extract_route_path(dec)
        
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._call_name(child)
                if call_name:
                    calls.append(call_name)
        
        return FunctionInfo(
            name=node.name,
            file_path=file_path,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            params=params,
            calls=calls,
            decorators=decorators,
            is_route_handler=is_route,
            http_method=http_method,
            route_path=route_path,
        )
    
    def _trace_data_flows(self, func_node, file_path: str, source: str) -> list[DataFlow]:
        """Trace user input → dangerous sink flows within a function."""
        flows = []
        source_lines = source.split("\n")
        
        for child in ast.walk(func_node):
            if isinstance(child, ast.Call):
                call_name = self._call_name(child)
                if not call_name:
                    continue
                
                # Check if this is a dangerous sink
                sink_type = None
                for stype, sinks in self.DANGEROUS_SINKS.items():
                    if any(s in call_name for s in sinks):
                        sink_type = stype
                        break
                
                if sink_type:
                    # Check if any argument traces back to user input
                    for arg in ast.walk(child):
                        if isinstance(arg, ast.Attribute):
                            attr_str = self._attribute_string(arg)
                            if any(src in attr_str for src in self.USER_INPUT_SOURCES):
                                flows.append(DataFlow(
                                    source=attr_str,
                                    source_type="user_input",
                                    sink=call_name,
                                    sink_type=sink_type,
                                    file_path=file_path,
                                    line_source=arg.lineno,
                                    line_sink=child.lineno,
                                ))
        return flows
    
    def _decorator_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._attribute_string(node)
        elif isinstance(node, ast.Call):
            return self._decorator_name(node.func)
        return ""
    
    def _call_name(self, node) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._attribute_string(node.func)
        return ""
    
    def _attribute_string(self, node) -> str:
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    
    def _extract_http_method(self, dec) -> str:
        name = self._decorator_name(dec).lower()
        for method in ["get", "post", "put", "delete", "patch"]:
            if method in name:
                return method.upper()
        # Check for methods= kwarg
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "methods":
                    return "MULTI"
        return "GET"
    
    def _extract_route_path(self, dec) -> str:
        if isinstance(dec, ast.Call) and dec.args:
            if isinstance(dec.args[0], ast.Constant):
                return str(dec.args[0].value)
        return ""
    
    def _find_db_queries(self, functions, flows) -> list[dict]:
        results = []
        for flow in flows:
            if flow.sink_type == "sql":
                results.append({
                    "file": flow.file_path,
                    "sink": flow.sink,
                    "line": flow.line_sink,
                    "source": flow.source,
                    "parameterized": False,  # Assume unsafe; LLM will verify
                })
        return results
    
    def _find_auth_checks(self, functions) -> list[dict]:
        results = []
        for func in functions:
            has_auth = any(
                any(ad in dec for ad in self.AUTH_DECORATORS)
                for dec in func.decorators
            )
            if func.is_route_handler:
                results.append({
                    "function": func.name,
                    "route": func.route_path,
                    "method": func.http_method,
                    "has_auth_decorator": has_auth,
                    "file": func.file_path,
                    "line": func.line_start,
                })
        return results
```

### `src/sentinel/sast/llm_analyzer.py`
```python
"""
LLM-Powered Code Analyzer — Sends structured code representations to LLM for vulnerability detection.

Strategy:
1. AST extractor produces CodeStructure
2. This module chunks it into LLM-digestible pieces
3. Sends each chunk with a security-focused system prompt
4. Parses LLM responses into structured findings
5. Deduplicates and ranks by confidence
"""
from dataclasses import dataclass, field
from sentinel.sast.ast_extractor import CodeStructure, DataFlow, FunctionInfo
from sentinel.llm.model_router import ModelRouter, TaskType
from sentinel.logging import get_logger

logger = get_logger(__name__)

ANALYSIS_SYSTEM_PROMPT = """You are a security code reviewer. You will receive structured code analysis data including:
- Function signatures with their parameters, decorators, and call graphs
- Data flow traces from user input sources to dangerous sinks
- Route handlers with their auth decorators (or lack thereof)
- Database query patterns

For each potential vulnerability, respond in JSON:
{
  "findings": [
    {
      "vuln_type": "sqli|xss|idor|command_injection|path_traversal|ssrf|auth_bypass|insecure_deser",
      "confidence": 0.0-1.0,
      "file": "path/to/file.py",
      "line": 42,
      "function": "function_name",
      "description": "Brief explanation of the vulnerability",
      "exploit_hint": "How this could be exploited",
      "fix_suggestion": "How to fix this",
      "cwe_id": "CWE-89"
    }
  ]
}

Rules:
- Only report findings with confidence >= 0.5
- Unsanitized user input → SQL query = HIGH confidence
- Route handler without auth decorator = MEDIUM confidence (might have middleware auth)
- eval/exec with any dynamic input = HIGH confidence
- Flag missing parameterized queries specifically
"""


@dataclass
class SASTFinding:
    vuln_type: str
    confidence: float
    file_path: str
    line: int
    function: str
    description: str
    exploit_hint: str
    fix_suggestion: str
    cwe_id: str
    source: str = "sast_llm"
    verified_by_dast: bool = False


class LLMCodeAnalyzer:
    """Analyze code structure with LLM for vulnerability detection."""
    
    def __init__(self, llm_client, router: ModelRouter = None):
        self.llm = llm_client
        self.router = router or ModelRouter()
    
    async def analyze(self, code_structure: CodeStructure) -> list[SASTFinding]:
        """Run full LLM-powered analysis on extracted code structure."""
        findings = []
        
        # 1. Analyze data flows (highest signal)
        if code_structure.data_flows:
            flow_findings = await self._analyze_data_flows(code_structure.data_flows)
            findings.extend(flow_findings)
        
        # 2. Analyze route auth coverage
        if code_structure.auth_checks:
            auth_findings = await self._analyze_auth_coverage(code_structure.auth_checks)
            findings.extend(auth_findings)
        
        # 3. Analyze DB query patterns
        if code_structure.db_queries:
            db_findings = await self._analyze_db_queries(code_structure.db_queries)
            findings.extend(db_findings)
        
        # 4. Deep analysis: send function code to LLM for complex patterns
        complex_findings = await self._deep_function_analysis(code_structure.functions)
        findings.extend(complex_findings)
        
        # Deduplicate
        findings = self._deduplicate(findings)
        
        return sorted(findings, key=lambda f: f.confidence, reverse=True)
    
    async def _analyze_data_flows(self, flows: list[DataFlow]) -> list[SASTFinding]:
        """Analyze traced data flows with LLM."""
        findings = []
        
        # Group flows by file for batching
        by_file = {}
        for flow in flows:
            by_file.setdefault(flow.file_path, []).append(flow)
        
        for file_path, file_flows in by_file.items():
            flow_desc = "\n".join([
                f"  Line {f.line_source}: {f.source} ({f.source_type}) → "
                f"Line {f.line_sink}: {f.sink} ({f.sink_type}) "
                f"{'[SANITIZED by ' + f.sanitizer + ']' if f.is_sanitized else '[UNSANITIZED]'}"
                for f in file_flows
            ])
            
            prompt = f"Analyze these data flows in {file_path}:\n{flow_desc}\n\nReturn JSON findings."
            
            model = self.router.route(TaskType.CODE_ANALYSIS)
            response = await self.llm.complete(
                prompt,
                system=ANALYSIS_SYSTEM_PROMPT,
                model=model.model_id,
                provider=model.provider,
            )
            
            parsed = self._parse_llm_response(response)
            findings.extend(parsed)
        
        return findings
    
    async def _analyze_auth_coverage(self, auth_checks: list[dict]) -> list[SASTFinding]:
        """Find routes missing auth decorators."""
        findings = []
        for check in auth_checks:
            if not check["has_auth_decorator"] and check["method"] in ("POST", "PUT", "DELETE", "MULTI"):
                findings.append(SASTFinding(
                    vuln_type="auth_bypass",
                    confidence=0.6,  # Medium — might have middleware auth
                    file_path=check["file"],
                    line=check["line"],
                    function=check["function"],
                    description=f"Route handler '{check['function']}' ({check['method']} {check['route']}) "
                                f"has no auth decorator. If no middleware auth exists, this is an auth bypass.",
                    exploit_hint=f"Send {check['method']} to {check['route']} without auth headers",
                    fix_suggestion=f"Add @login_required or equivalent auth decorator",
                    cwe_id="CWE-862",
                ))
        return findings
    
    async def _analyze_db_queries(self, queries: list[dict]) -> list[SASTFinding]:
        """Find unparameterized DB queries."""
        findings = []
        for q in queries:
            if not q.get("parameterized", True):
                findings.append(SASTFinding(
                    vuln_type="sqli",
                    confidence=0.8,
                    file_path=q["file"],
                    line=q["line"],
                    function=q.get("function", ""),
                    description=f"Database query at line {q['line']} uses input from {q['source']} "
                                f"without parameterization. Likely SQL injection.",
                    exploit_hint=f"Send SQL payload via {q['source']}",
                    fix_suggestion="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_input,))",
                    cwe_id="CWE-89",
                ))
        return findings
    
    async def _deep_function_analysis(self, functions: list[FunctionInfo]) -> list[SASTFinding]:
        """Send complex functions to LLM for deeper analysis (batched)."""
        # Only analyze route handlers and functions that call dangerous sinks
        interesting = [
            f for f in functions
            if f.is_route_handler or any(
                any(s in c for s in ["execute", "eval", "exec", "system", "popen"])
                for c in f.calls
            )
        ]
        
        if not interesting:
            return []
        
        # Batch into chunks of 10 functions
        findings = []
        for i in range(0, len(interesting), 10):
            batch = interesting[i:i+10]
            desc = "\n\n".join([
                f"Function: {f.name}\n"
                f"  File: {f.file_path}:{f.line_start}-{f.line_end}\n"
                f"  Params: {f.params}\n"
                f"  Decorators: {f.decorators}\n"
                f"  Calls: {f.calls}\n"
                f"  Route: {f.http_method} {f.route_path}" if f.is_route_handler else ""
                for f in batch
            ])
            
            model = self.router.route(TaskType.CODE_ANALYSIS)
            response = await self.llm.complete(
                f"Analyze these functions for security vulnerabilities:\n\n{desc}\n\nReturn JSON findings.",
                system=ANALYSIS_SYSTEM_PROMPT,
                model=model.model_id,
                provider=model.provider,
            )
            
            parsed = self._parse_llm_response(response)
            findings.extend(parsed)
        
        return findings
    
    def _parse_llm_response(self, response: str) -> list[SASTFinding]:
        """Parse LLM JSON response into SASTFinding objects."""
        import json
        try:
            # Strip markdown code fences if present
            clean = response.strip()
            if clean.startswith("```"):
                clean = clean.split("\n", 1)[1]
                clean = clean.rsplit("```", 1)[0]
            
            data = json.loads(clean)
            findings_data = data if isinstance(data, list) else data.get("findings", [])
            
            return [
                SASTFinding(
                    vuln_type=f.get("vuln_type", "unknown"),
                    confidence=float(f.get("confidence", 0.5)),
                    file_path=f.get("file", ""),
                    line=int(f.get("line", 0)),
                    function=f.get("function", ""),
                    description=f.get("description", ""),
                    exploit_hint=f.get("exploit_hint", ""),
                    fix_suggestion=f.get("fix_suggestion", ""),
                    cwe_id=f.get("cwe_id", ""),
                )
                for f in findings_data
                if float(f.get("confidence", 0)) >= 0.5
            ]
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM SAST response: {e}")
            return []
    
    def _deduplicate(self, findings: list[SASTFinding]) -> list[SASTFinding]:
        """Remove duplicate findings (same file+line+type)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line, f.vuln_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
```

### `src/sentinel/sast/dast_bridge.py`
```python
"""
SAST→DAST Bridge — Converts static findings into targeted DAST hypotheses.

The hybrid loop:
1. SAST finds "unsanitized input to SQL query at /api/users line 42"
2. Bridge creates a targeted VulnHypothesis: "Test /api/users for SQLi on 'id' param"
3. VulnAgent runs the DAST test
4. If confirmed: high-confidence finding. If not: lower SAST confidence for that pattern.
"""
from dataclasses import dataclass
from sentinel.sast.llm_analyzer import SASTFinding
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TargetedHypothesis:
    """A DAST hypothesis generated from a SAST finding."""
    source_finding: SASTFinding
    target_url: str
    method: str
    parameter: str
    test_category: str    # maps to VulnHypothesis category
    payload_hints: list[str]
    priority: float


class SASTtoDAST:
    """Convert SAST findings into targeted DAST test hypotheses."""
    
    VULN_TO_DAST = {
        "sqli": {"category": "injection", "payloads": ["' OR '1'='1", "1; SELECT", "admin'--"]},
        "xss": {"category": "xss", "payloads": ["<script>alert(1)</script>", "{{7*7}}"]},
        "command_injection": {"category": "command_injection", "payloads": ["; ls", "| id", "$(whoami)"]},
        "ssrf": {"category": "ssrf", "payloads": ["http://169.254.169.254/", "http://localhost:"]},
        "path_traversal": {"category": "path_traversal", "payloads": ["../../../etc/passwd"]},
        "idor": {"category": "idor", "payloads": []},  # Needs differential testing
        "auth_bypass": {"category": "auth_bypass", "payloads": []},
    }
    
    def convert(self, findings: list[SASTFinding], base_url: str) -> list[TargetedHypothesis]:
        """Convert SAST findings to targeted DAST hypotheses."""
        hypotheses = []
        
        for finding in findings:
            mapping = self.VULN_TO_DAST.get(finding.vuln_type)
            if not mapping:
                continue
            
            # Build target URL from route info
            target = self._build_target(finding, base_url)
            if not target:
                continue
            
            hypotheses.append(TargetedHypothesis(
                source_finding=finding,
                target_url=target["url"],
                method=target["method"],
                parameter=target["param"],
                test_category=mapping["category"],
                payload_hints=mapping["payloads"],
                priority=finding.confidence * 1.5,  # Boost priority for SAST-informed tests
            ))
        
        return sorted(hypotheses, key=lambda h: h.priority, reverse=True)
    
    def _build_target(self, finding: SASTFinding, base_url: str) -> dict | None:
        """Extract target URL, method, and parameter from SAST finding context."""
        # Use exploit_hint to infer target details
        result = {"url": base_url, "method": "GET", "param": ""}
        
        if finding.exploit_hint:
            hint = finding.exploit_hint.lower()
            for method in ["post", "put", "delete", "get"]:
                if method in hint:
                    result["method"] = method.upper()
                    break
            
            # Try to extract route path from function metadata
            # This is a best-effort extraction
            if "/" in finding.exploit_hint:
                parts = finding.exploit_hint.split()
                for part in parts:
                    if part.startswith("/"):
                        result["url"] = base_url.rstrip("/") + part
                        break
        
        return result
```

---

## Files to Modify

### `src/sentinel/agents/hypothesis_engine.py`
Add SAST-informed hypothesis source:
```python
# New method:
async def generate_from_sast(self, sast_findings: list, base_url: str) -> list[VulnHypothesis]:
    """Generate hypotheses from SAST findings (higher priority than pattern-based)."""
    bridge = SASTtoDAST()
    targeted = bridge.convert(sast_findings, base_url)
    
    hypotheses = []
    for t in targeted:
        h = VulnHypothesis(
            category=t.test_category,
            target_url=t.target_url,
            confidence=min(t.priority, 1.0),
            source="sast",
            # ... fill other fields
        )
        hypotheses.append(h)
    return hypotheses
```

---

## Tests

### `tests/sast/test_ast_extractor.py`
```python
import pytest
import tempfile
from pathlib import Path
from sentinel.sast.ast_extractor import PythonASTExtractor

SAMPLE_FLASK_APP = '''
from flask import Flask, request
import sqlite3

app = Flask(__name__)

@app.route("/users", methods=["GET"])
def get_users():
    user_id = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchall()

@app.route("/admin", methods=["POST"])
@login_required
def admin_panel():
    return "admin"

@app.route("/public")
def public_page():
    return "hello"
'''

class TestPythonASTExtractor:
    def setup_method(self):
        self.extractor = PythonASTExtractor()
    
    def test_extract_functions(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_FLASK_APP)
            f.flush()
            funcs, flows = self.extractor.extract_file(f.name)
        
        assert len(funcs) == 3
        route_funcs = [f for f in funcs if f.is_route_handler]
        assert len(route_funcs) == 3
    
    def test_detect_sql_data_flow(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_FLASK_APP)
            f.flush()
            funcs, flows = self.extractor.extract_file(f.name)
        
        sql_flows = [f for f in flows if f.sink_type == "sql"]
        # Should detect request.args → cursor.execute flow
        assert len(sql_flows) >= 1
    
    def test_detect_missing_auth(self):
        with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False) as f:
            f.write(SAMPLE_FLASK_APP)
            f.flush()
            funcs, _ = self.extractor.extract_file(f.name)
        
        # get_users has no auth decorator
        get_users = next(f for f in funcs if f.name == "get_users")
        assert not any("login_required" in d for d in get_users.decorators)
```

### `tests/sast/test_llm_analyzer.py`
```python
import pytest
from sentinel.sast.llm_analyzer import LLMCodeAnalyzer

class TestLLMAnalyzer:
    def test_parse_valid_json(self):
        analyzer = LLMCodeAnalyzer(llm_client=None)
        response = '{"findings": [{"vuln_type": "sqli", "confidence": 0.9, "file": "app.py", "line": 12, "function": "get_users", "description": "SQL injection", "exploit_hint": "Send id=1 OR 1=1", "fix_suggestion": "Use parameterized query", "cwe_id": "CWE-89"}]}'
        findings = analyzer._parse_llm_response(response)
        assert len(findings) == 1
        assert findings[0].vuln_type == "sqli"
        assert findings[0].confidence == 0.9
    
    def test_parse_with_code_fences(self):
        analyzer = LLMCodeAnalyzer(llm_client=None)
        response = '```json\n{"findings": [{"vuln_type": "xss", "confidence": 0.7, "file": "a.py", "line": 1, "function": "f", "description": "d", "exploit_hint": "e", "fix_suggestion": "f", "cwe_id": "CWE-79"}]}\n```'
        findings = analyzer._parse_llm_response(response)
        assert len(findings) == 1
    
    def test_filter_low_confidence(self):
        analyzer = LLMCodeAnalyzer(llm_client=None)
        response = '{"findings": [{"vuln_type": "xss", "confidence": 0.3, "file": "a.py", "line": 1, "function": "f", "description": "d", "exploit_hint": "e", "fix_suggestion": "f", "cwe_id": "CWE-79"}]}'
        findings = analyzer._parse_llm_response(response)
        assert len(findings) == 0  # Below 0.5 threshold
    
    def test_deduplicate(self):
        analyzer = LLMCodeAnalyzer(llm_client=None)
        from sentinel.sast.llm_analyzer import SASTFinding
        f1 = SASTFinding("sqli", 0.9, "a.py", 10, "f", "d", "e", "f", "CWE-89")
        f2 = SASTFinding("sqli", 0.8, "a.py", 10, "f", "d2", "e2", "f2", "CWE-89")
        result = analyzer._deduplicate([f1, f2])
        assert len(result) == 1
```

### `tests/sast/test_dast_bridge.py`
```python
import pytest
from sentinel.sast.dast_bridge import SASTtoDAST
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
            description="d", exploit_hint="GET /search", fix_suggestion="f", cwe_id="CWE-79",
        )
        hypotheses = self.bridge.convert([finding], "http://target")
        assert hypotheses[0].priority == 0.8 * 1.5  # Boosted
```

---

## Acceptance Criteria
- [ ] PythonASTExtractor parses Flask/Django apps and extracts functions, routes, data flows
- [ ] Data flow tracing detects request.args → cursor.execute paths
- [ ] Missing auth decorators on route handlers are flagged
- [ ] LLMCodeAnalyzer sends structured data to LLM and parses JSON responses
- [ ] SASTtoDAST bridge converts SAST findings into targeted DAST hypotheses
- [ ] Hybrid loop: SAST finding → targeted DAST test → confirmed or lowered confidence
- [ ] All tests pass