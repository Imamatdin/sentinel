# LEVEL 06: Change-Based Diff Testing (CI/CD Integration)

## Context
Instead of full re-scans, analyze git diffs to selectively re-test only changed code. Google's VP classifier achieves 80% recall / 98% precision on risky commits. This enables "test on every commit" workflows.

Research: Block 9 (Change-Based/Diff Testing), Aardvark continuous commit monitoring pattern.

## Files to Create

### `src/sentinel/cicd/__init__.py`
```python
"""CI/CD integration — diff analysis, webhook handlers, selective re-testing."""
```

### `src/sentinel/cicd/diff_analyzer.py`
Parses git diffs and assigns risk scores:
- **HIGH risk**: changes to auth/login files, middleware, access control, crypto, SQL queries, input validation
- **MEDIUM risk**: API route changes, new endpoints, dependency updates
- **LOW risk**: UI-only changes, comments, tests, docs

Key signatures:
```python
@dataclass
class DiffRiskAssessment:
    file_path: str
    risk_score: float  # 0.0-1.0
    risk_factors: list[str]  # ["auth_change", "new_endpoint", "sql_modification"]
    changed_lines: int
    hypotheses_to_rerun: list[str]  # hypothesis categories to re-test

class DiffAnalyzer:
    def analyze_diff(self, diff_text: str) -> list[DiffRiskAssessment]: ...
    def analyze_commit(self, repo_path: str, commit_sha: str) -> list[DiffRiskAssessment]: ...
    def get_retest_plan(self, assessments: list[DiffRiskAssessment]) -> dict: ...
```

Risk scoring rules:
```python
HIGH_RISK_PATTERNS = [
    (r"auth|login|session|token|jwt|oauth", "auth_change", 0.9),
    (r"password|credential|secret|key|api_key", "credential_handling", 0.95),
    (r"SELECT|INSERT|UPDATE|DELETE|query|execute", "sql_modification", 0.85),
    (r"exec|eval|system|subprocess|shell", "command_execution", 0.9),
    (r"sanitize|escape|validate|filter", "input_validation", 0.8),
    (r"middleware|interceptor|guard|policy", "access_control", 0.85),
]
```

### `src/sentinel/cicd/webhook_handler.py`
FastAPI endpoint that receives GitHub/GitLab webhooks:
```python
@router.post("/api/v1/webhook/github")
async def github_push(request: Request):
    # 1. Verify webhook signature
    # 2. Extract commits from payload
    # 3. Run DiffAnalyzer on each commit
    # 4. If risk > threshold: trigger selective re-test via Temporal workflow
    # 5. Return assessment summary
```

### `src/sentinel/cicd/selective_scanner.py`
Given a DiffRiskAssessment, triggers only the relevant hypothesis categories:
- Auth file changed → re-run AUTH_BYPASS, BROKEN_ACCESS hypotheses
- SQL query changed → re-run INJECTION hypotheses
- New endpoint added → run full hypothesis generation for that endpoint only

## Tests
- Test risk scoring: auth file change → HIGH risk
- Test risk scoring: README change → LOW risk
- Test retest plan generation: SQL change maps to INJECTION hypotheses
- Test webhook signature verification

## Acceptance Criteria
- [ ] DiffAnalyzer correctly scores auth/SQL/command changes as HIGH risk
- [ ] Selective scanner only re-tests affected hypothesis categories
- [ ] GitHub webhook endpoint receives and processes push events
- [ ] Changes correlate with existing knowledge graph endpoints
- [ ] All tests pass