import tempfile
from pathlib import Path

import pytest

from sentinel.sast.ast_extractor import PythonASTExtractor


SAMPLE_FLASK_APP = '''\
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

SAMPLE_DANGEROUS_CODE = '''\
import os, subprocess

def run_cmd(user_input):
    os.system(user_input)

def safe_func():
    return 42

def eval_input(data):
    return eval(data)
'''

SAMPLE_SYNTAX_ERROR = '''\
def broken(
    pass  # missing closing paren
'''


class TestPythonASTExtractor:
    def setup_method(self):
        self.extractor = PythonASTExtractor()

    def _write_temp(self, content: str) -> str:
        f = tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False, encoding="utf-8")
        f.write(content)
        f.flush()
        f.close()
        return f.name

    def test_extract_functions(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, flows = self.extractor.extract_file(path)

        assert len(funcs) == 3
        route_funcs = [f for f in funcs if f.is_route_handler]
        assert len(route_funcs) == 3

    def test_function_names(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, _ = self.extractor.extract_file(path)

        names = {f.name for f in funcs}
        assert names == {"get_users", "admin_panel", "public_page"}

    def test_detect_sql_data_flow(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, flows = self.extractor.extract_file(path)

        sql_flows = [f for f in flows if f.sink_type == "sql"]
        assert len(sql_flows) >= 1
        assert sql_flows[0].source_type == "user_input"

    def test_detect_missing_auth(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, _ = self.extractor.extract_file(path)

        get_users = next(f for f in funcs if f.name == "get_users")
        assert not any("login_required" in d for d in get_users.decorators)

    def test_detect_auth_present(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, _ = self.extractor.extract_file(path)

        admin = next(f for f in funcs if f.name == "admin_panel")
        assert any("login_required" in d for d in admin.decorators)

    def test_route_method_detection(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, _ = self.extractor.extract_file(path)

        admin = next(f for f in funcs if f.name == "admin_panel")
        assert admin.http_method == "MULTI"  # methods=["POST"]

    def test_route_path_extraction(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, _ = self.extractor.extract_file(path)

        get_users = next(f for f in funcs if f.name == "get_users")
        assert get_users.route_path == "/users"

    def test_call_graph(self):
        path = self._write_temp(SAMPLE_FLASK_APP)
        funcs, _ = self.extractor.extract_file(path)

        get_users = next(f for f in funcs if f.name == "get_users")
        assert any("execute" in c for c in get_users.calls)

    def test_dangerous_sinks_detected(self):
        path = self._write_temp(SAMPLE_DANGEROUS_CODE)
        funcs, _ = self.extractor.extract_file(path)

        run_cmd = next(f for f in funcs if f.name == "run_cmd")
        assert any("system" in c for c in run_cmd.calls)

        eval_func = next(f for f in funcs if f.name == "eval_input")
        assert any("eval" in c for c in eval_func.calls)

    def test_syntax_error_handled(self):
        path = self._write_temp(SAMPLE_SYNTAX_ERROR)
        funcs, flows = self.extractor.extract_file(path)
        assert funcs == []
        assert flows == []

    def test_extract_project(self, tmp_path):
        (tmp_path / "app.py").write_text(SAMPLE_FLASK_APP, encoding="utf-8")
        (tmp_path / "utils.py").write_text(SAMPLE_DANGEROUS_CODE, encoding="utf-8")

        structure = self.extractor.extract_project(str(tmp_path))

        assert structure.file_count == 2
        assert len(structure.functions) == 6  # 3 + 3
        assert len(structure.routes) == 3
        assert structure.total_lines > 0

    def test_project_auth_checks(self, tmp_path):
        (tmp_path / "app.py").write_text(SAMPLE_FLASK_APP, encoding="utf-8")

        structure = self.extractor.extract_project(str(tmp_path))

        assert len(structure.auth_checks) == 3
        no_auth = [c for c in structure.auth_checks if not c["has_auth_decorator"]]
        assert len(no_auth) == 2  # get_users, public_page

    def test_project_db_queries(self, tmp_path):
        (tmp_path / "app.py").write_text(SAMPLE_FLASK_APP, encoding="utf-8")

        structure = self.extractor.extract_project(str(tmp_path))

        assert len(structure.db_queries) >= 1
        assert structure.db_queries[0]["parameterized"] is False

    def test_skips_venv(self, tmp_path):
        venv_dir = tmp_path / "venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "module.py").write_text(SAMPLE_FLASK_APP, encoding="utf-8")
        (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")

        structure = self.extractor.extract_project(str(tmp_path))
        assert structure.file_count == 1  # only main.py

    def test_imports_extracted(self, tmp_path):
        (tmp_path / "app.py").write_text(SAMPLE_FLASK_APP, encoding="utf-8")
        structure = self.extractor.extract_project(str(tmp_path))
        assert "sqlite3" in structure.imports
