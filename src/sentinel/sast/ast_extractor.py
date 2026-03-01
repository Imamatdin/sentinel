"""
AST/DFG Extractor — Parses source code into structured representations for LLM analysis.

Supports: Python (ast module).
Extracts: function signatures, call graphs, data flow (source->sink), security-relevant patterns.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class FunctionInfo:
    name: str
    file_path: str
    line_start: int
    line_end: int
    params: list[str]
    return_type: str = ""
    calls: list[str] = field(default_factory=list)
    reads_from: list[str] = field(default_factory=list)
    writes_to: list[str] = field(default_factory=list)
    decorators: list[str] = field(default_factory=list)
    is_route_handler: bool = False
    http_method: str = ""
    route_path: str = ""


@dataclass
class DataFlow:
    source: str           # e.g. "request.args['id']"
    source_type: str      # "user_input", "database", "file", "env"
    sink: str             # e.g. "cursor.execute(query)"
    sink_type: str        # "sql_query", "command_exec", "file_write", "response"
    file_path: str
    line_source: int
    line_sink: int
    intermediates: list[str] = field(default_factory=list)
    is_sanitized: bool = False
    sanitizer: str = ""


@dataclass
class CodeStructure:
    """Structured representation of a codebase for LLM analysis."""
    functions: list[FunctionInfo]
    data_flows: list[DataFlow]
    imports: list[str]
    routes: list[FunctionInfo]
    db_queries: list[dict]
    auth_checks: list[dict]
    file_count: int
    total_lines: int


class PythonASTExtractor:
    """Extract security-relevant structure from Python source code."""

    DANGEROUS_SINKS = {
        "sql": ["execute", "executemany", "raw", "text"],
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
        source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError as e:
            logger.warning(f"Parse error in {file_path}: {e}")
            return [], []

        functions: list[FunctionInfo] = []
        data_flows: list[DataFlow] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_info = self._extract_function(node, file_path)
                functions.append(func_info)

                flows = self._trace_data_flows(node, file_path)
                data_flows.extend(flows)

        return functions, data_flows

    def extract_project(self, project_path: str) -> CodeStructure:
        """Extract structure from entire project."""
        path = Path(project_path)
        all_functions: list[FunctionInfo] = []
        all_flows: list[DataFlow] = []
        all_imports: list[str] = []
        file_count = 0
        total_lines = 0

        skip_dirs = {"venv", ".venv", "node_modules", ".git", "__pycache__", ".tox", "env"}
        for py_file in path.rglob("*.py"):
            if skip_dirs & set(py_file.relative_to(path).parts):
                continue

            file_count += 1
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            total_lines += content.count("\n") + 1

            funcs, flows = self.extract_file(str(py_file))
            all_functions.extend(funcs)
            all_flows.extend(flows)

            try:
                tree = ast.parse(content)
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
        db_queries = self._find_db_queries(all_flows)
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

    def _extract_function(self, node: ast.AST, file_path: str) -> FunctionInfo:
        """Extract info from a function AST node."""
        params = [arg.arg for arg in node.args.args]
        decorators: list[str] = []
        is_route = False
        http_method = ""
        route_path = ""

        for dec in node.decorator_list:
            dec_name = self._decorator_name(dec)
            decorators.append(dec_name)

            if any(rd in dec_name.lower() for rd in self.ROUTE_DECORATORS):
                is_route = True
                http_method = self._extract_http_method(dec)
                route_path = self._extract_route_path(dec)

        calls: list[str] = []
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

    def _trace_data_flows(self, func_node: ast.AST, file_path: str) -> list[DataFlow]:
        """Trace user input -> dangerous sink flows within a function.

        Two-pass approach:
        1. Collect tainted variables (assigned from user input sources)
        2. Check if tainted variables or direct user input reach dangerous sinks
        """
        flows: list[DataFlow] = []

        # Pass 1: build taint map {variable_name: (source_string, line)}
        tainted: dict[str, tuple[str, int]] = {}
        for child in ast.walk(func_node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    var_name = self._target_name(target)
                    if var_name:
                        source_str = self._find_user_input_in_node(child.value)
                        if source_str:
                            tainted[var_name] = (source_str, child.lineno)

        # Pass 2: check sinks for tainted variables or direct user input
        for child in ast.walk(func_node):
            if not isinstance(child, ast.Call):
                continue
            call_name = self._call_name(child)
            if not call_name:
                continue

            sink_type = None
            for stype, sinks in self.DANGEROUS_SINKS.items():
                if any(s in call_name for s in sinks):
                    sink_type = stype
                    break

            if not sink_type:
                continue

            # Check direct user input in call args
            direct_source = self._find_user_input_in_node(child)
            if direct_source:
                flows.append(DataFlow(
                    source=direct_source,
                    source_type="user_input",
                    sink=call_name,
                    sink_type=sink_type,
                    file_path=file_path,
                    line_source=child.lineno,
                    line_sink=child.lineno,
                ))
                continue

            # Check tainted variables used in call args (including f-strings)
            for name_node in self._find_names_in_node(child):
                if name_node in tainted:
                    source_str, source_line = tainted[name_node]
                    flows.append(DataFlow(
                        source=source_str,
                        source_type="user_input",
                        sink=call_name,
                        sink_type=sink_type,
                        file_path=file_path,
                        line_source=source_line,
                        line_sink=child.lineno,
                        intermediates=[name_node],
                    ))
                    break  # one flow per sink call

        return flows

    def _find_user_input_in_node(self, node: ast.AST) -> str | None:
        """Check if any sub-expression references a user input source."""
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                attr_str = self._attribute_string(child)
                if any(src in attr_str for src in self.USER_INPUT_SOURCES):
                    return attr_str
        return None

    def _find_names_in_node(self, node: ast.AST) -> set[str]:
        """Collect all Name references inside a node (including f-strings)."""
        names: set[str] = set()
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                names.add(child.id)
        return names

    def _target_name(self, node: ast.AST) -> str | None:
        """Get the variable name from an assignment target."""
        if isinstance(node, ast.Name):
            return node.id
        return None

    def _decorator_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._attribute_string(node)
        elif isinstance(node, ast.Call):
            return self._decorator_name(node.func)
        return ""

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._attribute_string(node.func)
        return ""

    def _attribute_string(self, node: ast.AST) -> str:
        parts: list[str] = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))

    def _extract_http_method(self, dec: ast.AST) -> str:
        name = self._decorator_name(dec).lower()
        for method in ["get", "post", "put", "delete", "patch"]:
            if method in name:
                return method.upper()
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "methods":
                    return "MULTI"
        return "GET"

    def _extract_route_path(self, dec: ast.AST) -> str:
        if isinstance(dec, ast.Call) and dec.args:
            if isinstance(dec.args[0], ast.Constant):
                return str(dec.args[0].value)
        return ""

    def _find_db_queries(self, flows: list[DataFlow]) -> list[dict]:
        results: list[dict] = []
        for flow in flows:
            if flow.sink_type == "sql":
                results.append({
                    "file": flow.file_path,
                    "sink": flow.sink,
                    "line": flow.line_sink,
                    "source": flow.source,
                    "parameterized": False,
                })
        return results

    def _find_auth_checks(self, functions: list[FunctionInfo]) -> list[dict]:
        results: list[dict] = []
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
