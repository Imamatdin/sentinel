"""
LLM-Powered Code Analyzer — Sends structured code representations to LLM for vulnerability detection.

Strategy:
1. AST extractor produces CodeStructure
2. This module chunks it into LLM-digestible pieces
3. Sends each chunk with a security-focused system prompt
4. Parses LLM responses into structured findings
5. Deduplicates and ranks by confidence
"""

import json
from dataclasses import dataclass
from typing import Any

from sentinel.sast.ast_extractor import CodeStructure, DataFlow, FunctionInfo
from sentinel.llm.model_router import ModelRouter, TaskType
from sentinel.core import get_logger

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
- Unsanitized user input -> SQL query = HIGH confidence
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

    def __init__(self, llm_client: Any, router: ModelRouter | None = None):
        self.llm = llm_client
        self.router = router or ModelRouter()

    async def analyze(self, code_structure: CodeStructure) -> list[SASTFinding]:
        """Run full LLM-powered analysis on extracted code structure."""
        findings: list[SASTFinding] = []

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
        findings: list[SASTFinding] = []

        by_file: dict[str, list[DataFlow]] = {}
        for flow in flows:
            by_file.setdefault(flow.file_path, []).append(flow)

        for file_path, file_flows in by_file.items():
            flow_desc = "\n".join([
                f"  Line {f.line_source}: {f.source} ({f.source_type}) -> "
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
        findings: list[SASTFinding] = []
        for check in auth_checks:
            if not check["has_auth_decorator"] and check["method"] in (
                "POST", "PUT", "DELETE", "MULTI"
            ):
                findings.append(SASTFinding(
                    vuln_type="auth_bypass",
                    confidence=0.6,
                    file_path=check["file"],
                    line=check["line"],
                    function=check["function"],
                    description=(
                        f"Route handler '{check['function']}' ({check['method']} {check['route']}) "
                        f"has no auth decorator. If no middleware auth exists, this is an auth bypass."
                    ),
                    exploit_hint=f"Send {check['method']} to {check['route']} without auth headers",
                    fix_suggestion="Add @login_required or equivalent auth decorator",
                    cwe_id="CWE-862",
                ))
        return findings

    async def _analyze_db_queries(self, queries: list[dict]) -> list[SASTFinding]:
        """Find unparameterized DB queries."""
        findings: list[SASTFinding] = []
        for q in queries:
            if not q.get("parameterized", True):
                findings.append(SASTFinding(
                    vuln_type="sqli",
                    confidence=0.8,
                    file_path=q["file"],
                    line=q["line"],
                    function=q.get("function", ""),
                    description=(
                        f"Database query at line {q['line']} uses input from {q['source']} "
                        f"without parameterization. Likely SQL injection."
                    ),
                    exploit_hint=f"Send SQL payload via {q['source']}",
                    fix_suggestion="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_input,))",
                    cwe_id="CWE-89",
                ))
        return findings

    async def _deep_function_analysis(self, functions: list[FunctionInfo]) -> list[SASTFinding]:
        """Send complex functions to LLM for deeper analysis (batched)."""
        interesting = [
            f for f in functions
            if f.is_route_handler or any(
                any(s in c for s in ["execute", "eval", "exec", "system", "popen"])
                for c in f.calls
            )
        ]

        if not interesting:
            return []

        findings: list[SASTFinding] = []
        for i in range(0, len(interesting), 10):
            batch = interesting[i:i + 10]
            desc = "\n\n".join([
                f"Function: {f.name}\n"
                f"  File: {f.file_path}:{f.line_start}-{f.line_end}\n"
                f"  Params: {f.params}\n"
                f"  Decorators: {f.decorators}\n"
                f"  Calls: {f.calls}\n"
                + (f"  Route: {f.http_method} {f.route_path}" if f.is_route_handler else "")
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
        try:
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
        seen: set[tuple[str, int, str]] = set()
        unique: list[SASTFinding] = []
        for f in findings:
            key = (f.file_path, f.line, f.vuln_type)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
