# LEVEL 31: Public Benchmark Harness

  

## Context


Sentinel needs a transparent, reproducible benchmark suite to prove its capabilities against competitors. This includes intentionally vulnerable applications (test targets), ground-truth vulnerability databases, negative controls (known clean apps), automated scoring, and a public leaderboard.

  

Research: Block 10 (Benchmarking — XBOW 85% on HackerOne, CyberSecEval methodology, negative controls to prevent false-positive inflation, CVE-to-ground-truth mapping, time-bounded scoring).

  

## Why

XBOW published benchmarks and took the market. Sentinel needs the same credibility. Transparent benchmarks attract researchers, build trust, and create a flywheel: community contributes challenges, Sentinel improves, benchmarks prove improvement. The harness also enables CI/CD regression testing — every PR runs against the benchmark.

  

---

  

## Files to Create

  

### `src/sentinel/benchmark/__init__.py`

```python

"""Benchmark harness — test targets, ground truth, scoring, leaderboard."""

```

  

### `src/sentinel/benchmark/targets.py`

```python

"""

Benchmark Targets — Intentionally vulnerable applications for testing.

  

Each target:

- Docker Compose definition for reproducible deployment

- Ground truth: exact list of vulnerabilities with evidence

- Difficulty rating

- Domain tags (web, api, network, ai)

- Negative controls: known-clean endpoints that should NOT flag

  

Target registry supports both built-in targets (DVWA, Juice Shop, etc.)

and community-contributed challenges.

"""

from dataclasses import dataclass, field

from enum import Enum

from sentinel.logging import get_logger

  

logger = get_logger(__name__)

  
  

class Difficulty(str, Enum):

    EASY = "easy"

    MEDIUM = "medium"

    HARD = "hard"

    EXPERT = "expert"

  
  

@dataclass

class GroundTruthVuln:

    vuln_id: str

    category: str           # sqli, xss, ssrf, idor, auth_bypass, etc.

    severity: str           # critical, high, medium, low

    location: str           # URL path or endpoint

    parameter: str          # Vulnerable parameter

    description: str

    evidence: str           # What proves the vuln exists (expected response pattern)

    cwe_id: str

    cvss_score: float = 0.0

  
  

@dataclass

class NegativeControl:

    endpoint: str

    description: str        # Why this should NOT flag

    expected_result: str    # "clean" — any finding here is a false positive

  
  

@dataclass

class BenchmarkTarget:

    target_id: str

    name: str

    description: str

    difficulty: Difficulty

    domains: list[str]      # ["web", "api", "network", "ai"]

    docker_compose: str     # Docker Compose YAML to deploy the target

    base_url: str           # URL after deployment (e.g., http://localhost:8080)

    ground_truth: list[GroundTruthVuln]

    negative_controls: list[NegativeControl]

    setup_time_seconds: int

    teardown_script: str = "docker compose down"

  
  

# Built-in targets

BUILTIN_TARGETS: list[BenchmarkTarget] = [

    BenchmarkTarget(

        target_id="juice-shop",

        name="OWASP Juice Shop",

        description="Deliberately insecure web application covering OWASP Top 10",

        difficulty=Difficulty.MEDIUM,

        domains=["web", "api"],

        docker_compose=(

            "version: '3'\n"

            "services:\n"

            "  juice-shop:\n"

            "    image: bkimminich/juice-shop:latest\n"

            "    ports:\n"

            "      - '3000:3000'\n"

        ),

        base_url="http://localhost:3000",

        ground_truth=[

            GroundTruthVuln("js-sqli-1", "sqli", "high", "/rest/products/search",

                            "q", "SQL injection in product search",

                            "Returns all products with ' OR 1=1--", "CWE-89", 8.6),

            GroundTruthVuln("js-xss-1", "xss", "medium", "/api/Users",

                            "email", "Stored XSS in user registration",

                            "Script executes in admin panel", "CWE-79", 6.1),

            GroundTruthVuln("js-idor-1", "idor", "high", "/api/BasketItems/{id}",

                            "id", "IDOR: access other users' basket items",

                            "Returns items belonging to different user", "CWE-639", 7.5),

            GroundTruthVuln("js-auth-1", "auth_bypass", "critical", "/rest/user/login",

                            "email", "Authentication bypass via SQL injection",

                            "Login as admin without password", "CWE-287", 9.8),

        ],

        negative_controls=[

            NegativeControl("/", "Static homepage should not flag"),

            NegativeControl("/api/SecurityQuestions", "Public endpoint, not a vuln"),

        ],

        setup_time_seconds=30,

    ),

    BenchmarkTarget(

        target_id="dvwa",

        name="Damn Vulnerable Web Application",

        description="Classic PHP vulnerable app with configurable difficulty",

        difficulty=Difficulty.EASY,

        domains=["web"],

        docker_compose=(

            "version: '3'\n"

            "services:\n"

            "  dvwa:\n"

            "    image: vulnerables/web-dvwa:latest\n"

            "    ports:\n"

            "      - '8080:80'\n"

        ),

        base_url="http://localhost:8080",

        ground_truth=[

            GroundTruthVuln("dvwa-sqli-1", "sqli", "high", "/vulnerabilities/sqli/",

                            "id", "SQL injection in user ID lookup",

                            "Returns database contents", "CWE-89", 8.6),

            GroundTruthVuln("dvwa-xss-r", "xss", "medium", "/vulnerabilities/xss_r/",

                            "name", "Reflected XSS in name parameter",

                            "Script reflected in response", "CWE-79", 6.1),

            GroundTruthVuln("dvwa-cmd-1", "command", "critical", "/vulnerabilities/exec/",

                            "ip", "OS command injection",

                            "Executes arbitrary commands", "CWE-78", 9.8),

            GroundTruthVuln("dvwa-fi-1", "path_traversal", "high", "/vulnerabilities/fi/",

                            "page", "Local file inclusion",

                            "Reads /etc/passwd", "CWE-22", 7.5),

        ],

        negative_controls=[

            NegativeControl("/login.php", "Login page is expected functionality"),

            NegativeControl("/about.php", "Static info page"),

        ],

        setup_time_seconds=20,

    ),

    BenchmarkTarget(

        target_id="custom-api-v1",

        name="Sentinel Custom API Challenge",

        description="Custom REST API with business logic vulns, SSRF, and auth issues",

        difficulty=Difficulty.HARD,

        domains=["api"],

        docker_compose=(

            "version: '3'\n"

            "services:\n"

            "  api:\n"

            "    build: ./benchmark/custom-api\n"

            "    ports:\n"

            "      - '5000:5000'\n"

        ),

        base_url="http://localhost:5000",

        ground_truth=[

            GroundTruthVuln("api-ssrf-1", "ssrf", "critical", "/api/fetch-url",

                            "url", "SSRF via URL fetcher endpoint",

                            "Fetches internal metadata endpoint", "CWE-918", 9.1),

            GroundTruthVuln("api-bola-1", "idor", "high", "/api/users/{id}/profile",

                            "id", "BOLA: access any user's profile",

                            "Returns other user data with changed ID", "CWE-639", 7.5),

            GroundTruthVuln("api-massassign", "mass_assignment", "high", "/api/users/register",

                            "role", "Mass assignment allows role escalation",

                            "Set role=admin in registration", "CWE-915", 8.1),

        ],

        negative_controls=[

            NegativeControl("/api/health", "Health check endpoint"),

            NegativeControl("/api/docs", "API documentation"),

        ],

        setup_time_seconds=45,

    ),

]

  
  

class TargetRegistry:

    """Manage benchmark targets."""

  

    def __init__(self):

        self.targets: dict[str, BenchmarkTarget] = {}

        for t in BUILTIN_TARGETS:

            self.targets[t.target_id] = t

  

    def register(self, target: BenchmarkTarget):

        self.targets[target.target_id] = target

  

    def get(self, target_id: str) -> BenchmarkTarget | None:

        return self.targets.get(target_id)

  

    def list_targets(self, difficulty: Difficulty = None, domain: str = None) -> list[BenchmarkTarget]:

        results = list(self.targets.values())

        if difficulty:

            results = [t for t in results if t.difficulty == difficulty]

        if domain:

            results = [t for t in results if domain in t.domains]

        return results

```

  

### `src/sentinel/benchmark/scorer.py`

```python

"""

Benchmark Scorer — Compare scan findings against ground truth.

  

Metrics:

- True Positives (TP): findings that match ground truth vulns

- False Positives (FP): findings on negative controls or non-existent vulns

- False Negatives (FN): ground truth vulns not found

- Precision: TP / (TP + FP)

- Recall: TP / (TP + FN)

- F1: 2 × P × R / (P + R)

- Time to first finding

- Total scan time

  

Matching: A finding matches ground truth if category + location + parameter all match.

"""

from dataclasses import dataclass, field

from datetime import datetime

from sentinel.benchmark.targets import BenchmarkTarget, GroundTruthVuln, NegativeControl

from sentinel.logging import get_logger

  

logger = get_logger(__name__)

  
  

@dataclass

class Finding:

    category: str

    location: str        # URL path

    parameter: str

    severity: str

    evidence: str

    timestamp: datetime = None

  
  

@dataclass

class MatchResult:

    ground_truth_id: str

    finding: Finding

    match_quality: str   # "exact", "partial", "category_only"

  
  

@dataclass

class BenchmarkScore:

    target_id: str

    true_positives: int

    false_positives: int

    false_negatives: int

    precision: float

    recall: float

    f1: float

    false_positive_rate: float   # FP on negative controls

    total_findings: int

    total_ground_truth: int

    scan_time_seconds: float

    time_to_first_finding_seconds: float

    matches: list[MatchResult]

    missed_vulns: list[str]      # Ground truth IDs not found

    false_positive_details: list[str]

  
  

class BenchmarkScorer:

    """Score scan results against benchmark ground truth."""

  

    def score(

        self,

        target: BenchmarkTarget,

        findings: list[Finding],

        scan_time_seconds: float = 0,

    ) -> BenchmarkScore:

        """Score a set of findings against a benchmark target."""

        matches = []

        matched_gt_ids = set()

        false_positives = []

  

        # Match findings to ground truth

        for finding in findings:

            best_match = self._find_match(finding, target.ground_truth, matched_gt_ids)

            if best_match:

                matches.append(best_match)

                matched_gt_ids.add(best_match.ground_truth_id)

            else:

                # Check if it's a false positive on negative controls

                is_negative = self._is_negative_control(finding, target.negative_controls)

                if is_negative:

                    false_positives.append(f"FP on negative control: {finding.location}")

                else:

                    false_positives.append(f"Unknown finding: {finding.category} at {finding.location}")

  

        tp = len(matches)

        fp = len(false_positives)

        fn = len(target.ground_truth) - tp

        total = len(findings)

  

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0

        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

  

        # False positive rate on negative controls specifically

        neg_fps = sum(1 for fp_str in false_positives if "negative control" in fp_str)

        fp_rate = neg_fps / max(len(target.negative_controls), 1)

  

        missed = [gt.vuln_id for gt in target.ground_truth if gt.vuln_id not in matched_gt_ids]

  

        # Time to first finding

        ttff = 0.0

        if findings and findings[0].timestamp:

            ttff = scan_time_seconds * 0.1  # Approximate

  

        return BenchmarkScore(

            target_id=target.target_id,

            true_positives=tp, false_positives=fp, false_negatives=fn,

            precision=round(precision, 4), recall=round(recall, 4), f1=round(f1, 4),

            false_positive_rate=round(fp_rate, 4),

            total_findings=total,

            total_ground_truth=len(target.ground_truth),

            scan_time_seconds=scan_time_seconds,

            time_to_first_finding_seconds=ttff,

            matches=matches, missed_vulns=missed,

            false_positive_details=false_positives,

        )

  

    def _find_match(self, finding: Finding, ground_truth: list[GroundTruthVuln],

                     already_matched: set) -> MatchResult | None:

        """Find the best ground truth match for a finding."""

        for gt in ground_truth:

            if gt.vuln_id in already_matched:

                continue

  

            # Exact match: category + location + parameter

            if (finding.category == gt.category and

                self._path_matches(finding.location, gt.location) and

                finding.parameter == gt.parameter):

                return MatchResult(gt.vuln_id, finding, "exact")

  

            # Partial match: category + location

            if (finding.category == gt.category and

                self._path_matches(finding.location, gt.location)):

                return MatchResult(gt.vuln_id, finding, "partial")

  

            # Category-only match (weakest)

            if finding.category == gt.category:

                return MatchResult(gt.vuln_id, finding, "category_only")

  

        return None

  

    def _path_matches(self, finding_path: str, gt_path: str) -> bool:

        """Check if paths match, accounting for path parameters."""

        import re

        # Replace {param} in ground truth with regex

        pattern = re.sub(r'\{[^}]+\}', r'[^/]+', gt_path)

        return bool(re.search(pattern, finding_path))

  

    def _is_negative_control(self, finding: Finding, controls: list[NegativeControl]) -> bool:

        """Check if a finding hits a negative control endpoint."""

        for nc in controls:

            if nc.endpoint in finding.location:

                return True

        return False

```

  

### `src/sentinel/benchmark/runner.py`

```python

"""

Benchmark Runner — Orchestrate full benchmark runs.

  

Flow:

1. Deploy target (Docker Compose up)

2. Wait for target to be healthy

3. Run Sentinel scan against target

4. Collect findings

5. Score against ground truth

6. Teardown target

7. Aggregate scores across all targets

"""

import time

from dataclasses import dataclass, field

from sentinel.benchmark.targets import TargetRegistry, BenchmarkTarget, Difficulty

from sentinel.benchmark.scorer import BenchmarkScorer, BenchmarkScore, Finding

from sentinel.logging import get_logger

  

logger = get_logger(__name__)

  
  

@dataclass

class BenchmarkRun:

    run_id: str

    runner_name: str       # "sentinel-v1.0", "competitor-x", etc.

    timestamp: str

    scores: list[BenchmarkScore]

    aggregate: dict = field(default_factory=dict)

  
  

class BenchmarkRunner:

    """Run benchmarks against targets and aggregate results."""

  

    def __init__(self, registry: TargetRegistry = None):

        self.registry = registry or TargetRegistry()

        self.scorer = BenchmarkScorer()

  

    async def run_single(

        self,

        target_id: str,

        scanner_fn=None,

    ) -> BenchmarkScore:

        """Run benchmark against a single target."""

        target = self.registry.get(target_id)

        if not target:

            raise ValueError(f"Unknown target: {target_id}")

  

        logger.info(f"Benchmark: deploying {target.name}...")

        # In production: docker compose up

        # await self._deploy(target)

  

        logger.info(f"Benchmark: scanning {target.name}...")

        start = time.time()

  

        if scanner_fn:

            findings = await scanner_fn(target.base_url)

        else:

            findings = []  # No scanner provided

  

        scan_time = time.time() - start

  

        # Score

        score = self.scorer.score(target, findings, scan_time)

  

        logger.info(f"Benchmark: {target.name} — P={score.precision:.1%} R={score.recall:.1%} F1={score.f1:.1%}")

  

        # Teardown

        # await self._teardown(target)

  

        return score

  

    async def run_suite(

        self,

        difficulty: Difficulty = None,

        domain: str = None,

        scanner_fn=None,

        run_id: str = "default",

        runner_name: str = "sentinel",

    ) -> BenchmarkRun:

        """Run full benchmark suite and aggregate."""

        targets = self.registry.list_targets(difficulty=difficulty, domain=domain)

        scores = []

  

        for target in targets:

            try:

                score = await self.run_single(target.target_id, scanner_fn)

                scores.append(score)

            except Exception as e:

                logger.error(f"Benchmark failed for {target.name}: {e}")

  

        aggregate = self._aggregate(scores)

  

        return BenchmarkRun(

            run_id=run_id, runner_name=runner_name,

            timestamp=str(time.time()),

            scores=scores, aggregate=aggregate,

        )

  

    def _aggregate(self, scores: list[BenchmarkScore]) -> dict:

        """Compute aggregate metrics across all targets."""

        if not scores:

            return {}

  

        total_tp = sum(s.true_positives for s in scores)

        total_fp = sum(s.false_positives for s in scores)

        total_fn = sum(s.false_negatives for s in scores)

  

        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0

        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0

        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

  

        return {

            "total_targets": len(scores),

            "total_ground_truth": sum(s.total_ground_truth for s in scores),

            "total_true_positives": total_tp,

            "total_false_positives": total_fp,

            "total_false_negatives": total_fn,

            "aggregate_precision": round(precision, 4),

            "aggregate_recall": round(recall, 4),

            "aggregate_f1": round(f1, 4),

            "avg_scan_time": round(sum(s.scan_time_seconds for s in scores) / len(scores), 2),

            "avg_false_positive_rate": round(

                sum(s.false_positive_rate for s in scores) / len(scores), 4),

        }

```

  

---

  

## Tests

  

### `tests/benchmark/test_targets.py`

```python

import pytest

from sentinel.benchmark.targets import TargetRegistry, Difficulty, BUILTIN_TARGETS

  

class TestTargetRegistry:

    def test_builtin_targets_loaded(self):

        reg = TargetRegistry()

        assert len(reg.targets) >= 3

  

    def test_get_target(self):

        reg = TargetRegistry()

        target = reg.get("juice-shop")

        assert target is not None

        assert target.name == "OWASP Juice Shop"

  

    def test_ground_truth_exists(self):

        reg = TargetRegistry()

        for t in reg.list_targets():

            assert len(t.ground_truth) > 0, f"{t.name} has no ground truth"

  

    def test_negative_controls_exist(self):

        reg = TargetRegistry()

        for t in reg.list_targets():

            assert len(t.negative_controls) > 0, f"{t.name} has no negative controls"

  

    def test_filter_by_difficulty(self):

        reg = TargetRegistry()

        easy = reg.list_targets(difficulty=Difficulty.EASY)

        assert all(t.difficulty == Difficulty.EASY for t in easy)

  

    def test_filter_by_domain(self):

        reg = TargetRegistry()

        api = reg.list_targets(domain="api")

        assert all("api" in t.domains for t in api)

  

    def test_all_vulns_have_cwe(self):

        for t in BUILTIN_TARGETS:

            for v in t.ground_truth:

                assert v.cwe_id.startswith("CWE-"), f"{v.vuln_id} missing CWE"

```

  

### `tests/benchmark/test_scorer.py`

```python

import pytest

from sentinel.benchmark.scorer import BenchmarkScorer, Finding

from sentinel.benchmark.targets import TargetRegistry

  

class TestBenchmarkScorer:

    def setup_method(self):

        self.scorer = BenchmarkScorer()

        self.target = TargetRegistry().get("juice-shop")

  

    def test_perfect_score(self):

        findings = [

            Finding("sqli", "/rest/products/search", "q", "high", "union select"),

            Finding("xss", "/api/Users", "email", "medium", "script tag"),

            Finding("idor", "/api/BasketItems/5", "id", "high", "other user data"),

            Finding("auth_bypass", "/rest/user/login", "email", "critical", "admin login"),

        ]

        score = self.scorer.score(self.target, findings)

        assert score.recall == 1.0

        assert score.true_positives == 4

        assert score.false_negatives == 0

  

    def test_zero_findings(self):

        score = self.scorer.score(self.target, [])

        assert score.recall == 0.0

        assert score.false_negatives == len(self.target.ground_truth)

  

    def test_false_positive_on_negative_control(self):

        findings = [

            Finding("xss", "/", "page", "low", "false alarm"),

        ]

        score = self.scorer.score(self.target, findings)

        assert score.false_positives >= 1

        assert score.false_positive_rate > 0

  

    def test_partial_match(self):

        findings = [

            Finding("sqli", "/rest/products/search", "other_param", "high", "union"),

        ]

        score = self.scorer.score(self.target, findings)

        assert score.true_positives >= 1  # Partial match on category+location

  

    def test_path_parameter_matching(self):

        assert self.scorer._path_matches("/api/BasketItems/42", "/api/BasketItems/{id}")

        assert not self.scorer._path_matches("/api/Users/42", "/api/BasketItems/{id}")

```

  

### `tests/benchmark/test_runner.py`

```python

import pytest

from sentinel.benchmark.runner import BenchmarkRunner

from sentinel.benchmark.scorer import Finding

  

class TestBenchmarkRunner:

    @pytest.mark.asyncio

    async def test_run_single_no_scanner(self):

        runner = BenchmarkRunner()

        score = await runner.run_single("dvwa")

        assert score.target_id == "dvwa"

        assert score.recall == 0.0  # No scanner provided

  

    @pytest.mark.asyncio

    async def test_run_single_with_scanner(self):

        async def mock_scanner(url):

            return [

                Finding("sqli", "/vulnerabilities/sqli/", "id", "high", "union"),

                Finding("command", "/vulnerabilities/exec/", "ip", "critical", "cmd"),

            ]

        runner = BenchmarkRunner()

        score = await runner.run_single("dvwa", scanner_fn=mock_scanner)

        assert score.true_positives >= 2

  

    @pytest.mark.asyncio

    async def test_run_suite(self):

        runner = BenchmarkRunner()

        run = await runner.run_suite(run_id="test-1", runner_name="test")

        assert run.run_id == "test-1"

        assert len(run.scores) >= 3

        assert "aggregate_f1" in run.aggregate

  

    def test_aggregate_empty(self):

        runner = BenchmarkRunner()

        agg = runner._aggregate([])

        assert agg == {}

```

  

---

  

## Acceptance Criteria

- [ ] TargetRegistry ships 3+ built-in targets (Juice Shop, DVWA, Custom API)

- [ ] Each target has ground truth vulns with CWE IDs and evidence patterns

- [ ] Each target has negative controls (known-clean endpoints)

- [ ] Scorer matches findings to ground truth by category + location + parameter

- [ ] Path parameter matching works (/api/items/42 matches /api/items/{id})

- [ ] Precision, recall, F1 computed correctly

- [ ] False positive rate tracked separately for negative controls

- [ ] Perfect findings → recall=1.0; no findings → recall=0.0

- [ ] Runner orchestrates deploy → scan → score → teardown

- [ ] Suite aggregates metrics across all targets

- [ ] Community targets can be registered via TargetRegistry.register()

- [ ] All tests pass