"""Tests for selective scanner."""

import pytest
from sentinel.cicd.diff_analyzer import DiffRiskAssessment
from sentinel.cicd.selective_scanner import SelectiveScanner, RetestTarget


class TestSelectiveScanner:
    def setup_method(self):
        self.scanner = SelectiveScanner()

    def test_high_risk_returns_target(self):
        assessments = [
            DiffRiskAssessment(
                file_path="src/auth/login.py",
                risk_score=0.9,
                risk_factors=["auth_change"],
                changed_lines=10,
                hypotheses_to_rerun=["auth_bypass", "broken_access"],
            )
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is not None
        assert "auth_bypass" in target.hypothesis_categories

    def test_low_risk_returns_none(self):
        assessments = [
            DiffRiskAssessment(
                file_path="README.md",
                risk_score=0.05,
                risk_factors=[],
                changed_lines=2,
                hypotheses_to_rerun=[],
            )
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is None

    def test_empty_assessments_returns_none(self):
        target = self.scanner.plan_retest([])
        assert target is None

    def test_target_has_categories(self):
        assessments = [
            DiffRiskAssessment(
                file_path="src/db/queries.py",
                risk_score=0.85,
                risk_factors=["sql_modification"],
                changed_lines=5,
                hypotheses_to_rerun=["injection"],
            )
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is not None
        assert target.hypothesis_categories == ["injection"]

    def test_target_aggregates_categories(self):
        assessments = [
            DiffRiskAssessment(
                file_path="src/auth/login.py",
                risk_score=0.9,
                risk_factors=["auth_change"],
                changed_lines=10,
                hypotheses_to_rerun=["auth_bypass"],
            ),
            DiffRiskAssessment(
                file_path="src/db/queries.py",
                risk_score=0.85,
                risk_factors=["sql_modification"],
                changed_lines=5,
                hypotheses_to_rerun=["injection"],
            ),
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is not None
        assert "auth_bypass" in target.hypothesis_categories
        assert "injection" in target.hypothesis_categories

    def test_target_source_files(self):
        assessments = [
            DiffRiskAssessment(
                file_path="src/auth/login.py",
                risk_score=0.9,
                risk_factors=["auth_change"],
                changed_lines=10,
                hypotheses_to_rerun=["auth_bypass"],
            ),
        ]
        target = self.scanner.plan_retest(assessments)
        assert "src/auth/login.py" in target.source_files

    def test_target_risk_score(self):
        assessments = [
            DiffRiskAssessment(
                file_path="src/auth/login.py",
                risk_score=0.9,
                risk_factors=["auth_change"],
                changed_lines=10,
                hypotheses_to_rerun=["auth_bypass"],
            ),
        ]
        target = self.scanner.plan_retest(assessments)
        assert target.risk_score == 0.9

    def test_infer_endpoints_from_routes(self):
        assessments = [
            DiffRiskAssessment(
                file_path="src/api/routes/users.py",
                risk_score=0.6,
                risk_factors=["api_route_change"],
                changed_lines=5,
                hypotheses_to_rerun=["injection", "xss"],
            ),
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is not None
        assert len(target.affected_endpoints) > 0

    def test_borderline_risk_threshold(self):
        """Risk score exactly at 0.3 should trigger retest."""
        assessments = [
            DiffRiskAssessment(
                file_path="src/config.yaml",
                risk_score=0.3,
                risk_factors=["config_change"],
                changed_lines=3,
                hypotheses_to_rerun=["misconfig"],
            ),
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is not None

    def test_just_below_threshold(self):
        """Risk score at 0.29 should not trigger retest."""
        assessments = [
            DiffRiskAssessment(
                file_path="src/config.yaml",
                risk_score=0.29,
                risk_factors=["config_change"],
                changed_lines=3,
                hypotheses_to_rerun=["misconfig"],
            ),
        ]
        target = self.scanner.plan_retest(assessments)
        assert target is None
