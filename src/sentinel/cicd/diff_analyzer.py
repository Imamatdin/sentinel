"""
Diff Analyzer — Parses git diffs and assigns risk scores.

Risk tiers:
  HIGH (0.8-1.0): auth, crypto, SQL, command execution, input validation
  MEDIUM (0.4-0.7): API routes, new endpoints, dependency updates
  LOW (0.0-0.3): UI, comments, tests, docs
"""

import asyncio
import re
from dataclasses import dataclass, field

from sentinel.core import get_logger

logger = get_logger(__name__)


# (pattern, risk_factor_name, base_score)
HIGH_RISK_PATTERNS: list[tuple[str, str, float]] = [
    (r"auth|login|session|token|jwt|oauth", "auth_change", 0.9),
    (r"password|credential|secret|key|api_key", "credential_handling", 0.95),
    (r"SELECT|INSERT|UPDATE|DELETE|query|execute", "sql_modification", 0.85),
    (r"exec|eval|system|subprocess|shell", "command_execution", 0.9),
    (r"sanitize|escape|validate|filter", "input_validation", 0.8),
    (r"middleware|interceptor|guard|policy", "access_control", 0.85),
    (r"crypto|encrypt|decrypt|hash|hmac|sign|verify", "crypto_change", 0.85),
]

MEDIUM_RISK_PATTERNS: list[tuple[str, str, float]] = [
    (r"@(app|router)\.(get|post|put|delete|patch)", "api_route_change", 0.6),
    (r"def\s+(get|post|put|delete|patch)_", "endpoint_handler", 0.55),
    (r"requirements\.txt|package\.json|Gemfile|go\.mod|pom\.xml", "dependency_update", 0.5),
    (r"Dockerfile|docker-compose|\.env", "infra_change", 0.5),
    (r"\.yaml|\.yml", "config_change", 0.4),
]

LOW_RISK_FILE_PATTERNS: list[str] = [
    r"\.md$",
    r"\.rst$",
    r"test_.*\.py$",
    r"tests/",
    r"docs/",
    r"\.css$",
    r"\.scss$",
    r"\.html$",
    r"__pycache__",
    r"\.gitignore$",
]

# Files that look low-risk by extension but are actually meaningful
EXCLUDE_FROM_LOW_RISK: list[str] = [
    r"requirements.*\.txt$",
    r"Gemfile",
    r"Dockerfile",
]

# Risk factor -> hypothesis categories to re-test
RISK_TO_HYPOTHESES: dict[str, list[str]] = {
    "auth_change": ["auth_bypass", "broken_access", "idor"],
    "credential_handling": ["auth_bypass", "sensitive_data"],
    "sql_modification": ["injection"],
    "command_execution": ["injection"],
    "input_validation": ["injection", "xss", "ssrf"],
    "access_control": ["auth_bypass", "broken_access", "idor"],
    "crypto_change": ["sensitive_data", "auth_bypass"],
    "api_route_change": ["injection", "xss", "auth_bypass", "idor"],
    "endpoint_handler": ["injection", "xss", "auth_bypass"],
    "dependency_update": ["supply_chain"],
    "infra_change": ["misconfig"],
    "config_change": ["misconfig"],
}


@dataclass
class DiffRiskAssessment:
    file_path: str
    risk_score: float  # 0.0-1.0
    risk_factors: list[str]
    changed_lines: int
    hypotheses_to_rerun: list[str]


class DiffAnalyzer:
    """Analyze git diffs and assign risk scores for selective re-testing."""

    def analyze_diff(self, diff_text: str) -> list[DiffRiskAssessment]:
        """Parse a unified diff and return risk assessments per file."""
        files = self._parse_diff_files(diff_text)
        assessments: list[DiffRiskAssessment] = []

        for file_path, added_lines in files.items():
            assessment = self._assess_file(file_path, added_lines)
            assessments.append(assessment)

        # Sort by risk score descending
        assessments.sort(key=lambda a: a.risk_score, reverse=True)
        return assessments

    def analyze_commit(
        self, repo_path: str, commit_sha: str
    ) -> list[DiffRiskAssessment]:
        """Analyze a specific commit in a git repo."""
        try:
            result = asyncio.get_event_loop().run_until_complete(
                self._run_git_diff(repo_path, commit_sha)
            )
            return self.analyze_diff(result)
        except RuntimeError:
            # No event loop — run synchronously
            import subprocess

            proc = subprocess.run(
                ["git", "diff", f"{commit_sha}^..{commit_sha}"],
                capture_output=True,
                text=True,
                cwd=repo_path,
            )
            return self.analyze_diff(proc.stdout)

    async def _run_git_diff(
        self, repo_path: str, commit_sha: str
    ) -> str:
        proc = await asyncio.create_subprocess_exec(
            "git", "diff", f"{commit_sha}^..{commit_sha}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_path,
        )
        stdout, _ = await proc.communicate()
        return stdout.decode("utf-8", errors="replace")

    def get_retest_plan(
        self, assessments: list[DiffRiskAssessment]
    ) -> dict:
        """Aggregate assessments into a retest plan."""
        categories: set[str] = set()
        affected_files: list[str] = []
        max_risk = 0.0
        total_changed = 0

        for a in assessments:
            categories.update(a.hypotheses_to_rerun)
            if a.risk_score > 0.1:
                affected_files.append(a.file_path)
            max_risk = max(max_risk, a.risk_score)
            total_changed += a.changed_lines

        return {
            "should_retest": max_risk >= 0.3,
            "max_risk_score": round(max_risk, 2),
            "hypothesis_categories": sorted(categories),
            "affected_files": affected_files,
            "total_changed_lines": total_changed,
            "file_count": len(assessments),
        }

    def _parse_diff_files(
        self, diff_text: str
    ) -> dict[str, list[str]]:
        """Parse unified diff into {file_path: [added_lines]}."""
        files: dict[str, list[str]] = {}
        current_file = None

        for line in diff_text.splitlines():
            if line.startswith("diff --git"):
                # Extract b/ path
                parts = line.split(" b/")
                if len(parts) >= 2:
                    current_file = parts[-1]
                    files[current_file] = []
            elif line.startswith("+++ b/"):
                current_file = line[6:]
                if current_file not in files:
                    files[current_file] = []
            elif line.startswith("+") and not line.startswith("+++"):
                if current_file:
                    files[current_file].append(line[1:])

        return files

    def _assess_file(
        self, file_path: str, added_lines: list[str]
    ) -> DiffRiskAssessment:
        """Assess risk for a single changed file."""
        risk_factors: list[str] = []
        max_score = 0.0

        # Check if file is low-risk by path
        is_excluded = any(
            re.search(p, file_path) for p in EXCLUDE_FROM_LOW_RISK
        )
        is_low_risk = not is_excluded and any(
            re.search(p, file_path) for p in LOW_RISK_FILE_PATTERNS
        )

        content = "\n".join(added_lines)
        combined = file_path + "\n" + content

        # Check high-risk patterns against both file path and content
        for pattern, factor, score in HIGH_RISK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                if factor not in risk_factors:
                    risk_factors.append(factor)
                    max_score = max(max_score, score)

        # Check medium-risk patterns
        for pattern, factor, score in MEDIUM_RISK_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                if factor not in risk_factors:
                    risk_factors.append(factor)
                    max_score = max(max_score, score)

        # Dampen score for low-risk files
        if is_low_risk and max_score > 0:
            max_score *= 0.3

        # If no patterns matched, assign a small base score
        if max_score == 0:
            max_score = 0.05 if not is_low_risk else 0.01

        # Collect hypotheses to rerun
        hypotheses: set[str] = set()
        for factor in risk_factors:
            hypotheses.update(RISK_TO_HYPOTHESES.get(factor, []))

        return DiffRiskAssessment(
            file_path=file_path,
            risk_score=round(max_score, 2),
            risk_factors=risk_factors,
            changed_lines=len(added_lines),
            hypotheses_to_rerun=sorted(hypotheses),
        )
