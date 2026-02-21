"""Tests for diff analyzer."""

import pytest
from sentinel.cicd.diff_analyzer import DiffAnalyzer, DiffRiskAssessment


AUTH_DIFF = """
diff --git a/src/auth/login.py b/src/auth/login.py
+++ b/src/auth/login.py
+def login(username, password):
+    token = create_jwt(username)
+    session.set("auth_token", token)
+    return token
"""

SQL_DIFF = """
diff --git a/src/db/queries.py b/src/db/queries.py
+++ b/src/db/queries.py
+def get_user(user_id):
+    return execute(f"SELECT * FROM users WHERE id = {user_id}")
"""

COMMAND_DIFF = """
diff --git a/src/utils/runner.py b/src/utils/runner.py
+++ b/src/utils/runner.py
+import subprocess
+def run_scan(target):
+    subprocess.call(["nmap", target])
"""

README_DIFF = """
diff --git a/README.md b/README.md
+++ b/README.md
+# Updated documentation
+This is a README change.
"""

CSS_DIFF = """
diff --git a/src/styles/main.css b/src/styles/main.css
+++ b/src/styles/main.css
+body { background: #fff; }
"""

API_ROUTE_DIFF = """
diff --git a/src/api/routes/users.py b/src/api/routes/users.py
+++ b/src/api/routes/users.py
+@router.post("/users")
+def create_user(data):
+    return save_user(data)
"""

DEPENDENCY_DIFF = """
diff --git a/requirements.txt b/requirements.txt
+++ b/requirements.txt
+flask==3.0.0
+requests==2.31.0
"""

MULTI_FILE_DIFF = """
diff --git a/src/auth/middleware.py b/src/auth/middleware.py
+++ b/src/auth/middleware.py
+def check_auth(request):
+    token = request.headers.get("Authorization")
+    return validate_token(token)
diff --git a/README.md b/README.md
+++ b/README.md
+Updated docs
diff --git a/src/db/models.py b/src/db/models.py
+++ b/src/db/models.py
+class User:
+    pass
"""

CRYPTO_DIFF = """
diff --git a/src/security/crypto.py b/src/security/crypto.py
+++ b/src/security/crypto.py
+from cryptography.fernet import Fernet
+def encrypt_data(data, key):
+    return Fernet(key).encrypt(data)
"""

EMPTY_DIFF = ""


class TestDiffAnalyzer:
    def setup_method(self):
        self.analyzer = DiffAnalyzer()

    def test_auth_change_high_risk(self):
        """Auth file changes should score HIGH risk."""
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score >= 0.8
        assert "auth_change" in assessments[0].risk_factors

    def test_sql_change_high_risk(self):
        assessments = self.analyzer.analyze_diff(SQL_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score >= 0.8
        assert "sql_modification" in assessments[0].risk_factors

    def test_command_execution_high_risk(self):
        assessments = self.analyzer.analyze_diff(COMMAND_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score >= 0.8
        assert "command_execution" in assessments[0].risk_factors

    def test_readme_low_risk(self):
        assessments = self.analyzer.analyze_diff(README_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score < 0.3

    def test_css_low_risk(self):
        assessments = self.analyzer.analyze_diff(CSS_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score < 0.3

    def test_api_route_medium_risk(self):
        assessments = self.analyzer.analyze_diff(API_ROUTE_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score >= 0.4

    def test_dependency_update_medium_risk(self):
        assessments = self.analyzer.analyze_diff(DEPENDENCY_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score >= 0.4
        assert "dependency_update" in assessments[0].risk_factors

    def test_crypto_change_high_risk(self):
        assessments = self.analyzer.analyze_diff(CRYPTO_DIFF)
        assert len(assessments) == 1
        assert assessments[0].risk_score >= 0.8
        assert "crypto_change" in assessments[0].risk_factors

    def test_multi_file_diff(self):
        assessments = self.analyzer.analyze_diff(MULTI_FILE_DIFF)
        assert len(assessments) == 3
        # Should be sorted by risk descending
        assert assessments[0].risk_score >= assessments[-1].risk_score

    def test_empty_diff(self):
        assessments = self.analyzer.analyze_diff(EMPTY_DIFF)
        assert len(assessments) == 0

    def test_auth_maps_to_auth_bypass_hypothesis(self):
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        assert "auth_bypass" in assessments[0].hypotheses_to_rerun

    def test_sql_maps_to_injection_hypothesis(self):
        assessments = self.analyzer.analyze_diff(SQL_DIFF)
        assert "injection" in assessments[0].hypotheses_to_rerun

    def test_changed_lines_count(self):
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        assert assessments[0].changed_lines > 0

    def test_assessment_has_file_path(self):
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        assert "login.py" in assessments[0].file_path


class TestRetestPlan:
    def setup_method(self):
        self.analyzer = DiffAnalyzer()

    def test_high_risk_should_retest(self):
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert plan["should_retest"] is True

    def test_low_risk_should_not_retest(self):
        assessments = self.analyzer.analyze_diff(README_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert plan["should_retest"] is False

    def test_plan_has_categories(self):
        assessments = self.analyzer.analyze_diff(SQL_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert "injection" in plan["hypothesis_categories"]

    def test_plan_has_affected_files(self):
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert len(plan["affected_files"]) > 0

    def test_plan_aggregates_multiple_files(self):
        assessments = self.analyzer.analyze_diff(MULTI_FILE_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert plan["file_count"] == 3
        assert plan["total_changed_lines"] > 0

    def test_plan_max_risk_score(self):
        assessments = self.analyzer.analyze_diff(AUTH_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert plan["max_risk_score"] >= 0.8

    def test_empty_assessments(self):
        plan = self.analyzer.get_retest_plan([])
        assert plan["should_retest"] is False
        assert plan["total_changed_lines"] == 0

    def test_dependency_maps_to_supply_chain(self):
        assessments = self.analyzer.analyze_diff(DEPENDENCY_DIFF)
        plan = self.analyzer.get_retest_plan(assessments)
        assert "supply_chain" in plan["hypothesis_categories"]
