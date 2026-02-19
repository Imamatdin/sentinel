# PHASE 11: Benchmark Harness

## Context

Paste after PHASE_10.md. This is the validation layer — proves Sentinel actually works. Without benchmarks, every phase is untested claims. This harness runs Sentinel against known-vulnerable apps and measures detection rate, exploit success, false positives, time-to-chain, and compares against baseline tools.

## What This Phase Builds

1. **BenchmarkRunner** — Orchestrates full pentest runs against target apps, collects metrics
2. **GroundTruth** — Known vulnerability databases for each target app (what SHOULD be found)
3. **MetricsCollector** — Tracks detection rate, exploit rate, false positives, timing, coverage
4. **BenchmarkReporter** — Generates comparison reports (Sentinel vs ground truth vs baseline tools)
5. **RegressionTracker** — Compares benchmark runs over time, flags regressions
6. **CLI** — `sentinel benchmark run`, `sentinel benchmark report`, `sentinel benchmark compare`

## Target Applications

### Tier 1 (MVP — must pass)

- **OWASP Juice Shop** — Modern Node.js/Angular app, 100+ challenges mapped to OWASP Top 10
- Ground truth: ~95 known vulnerabilities across SQLi, XSS, IDOR, SSRF, XXE, auth bypass, etc.

### Tier 2 (Stretch)

- **DVWA** (Damn Vulnerable Web App) — Classic PHP app, well-documented vulns at multiple difficulty levels
- **WebGoat** — OWASP teaching app, lesson-based vulnerabilities

### Tier 3 (Advanced — future)

- **GOAD** (Game of Active Directory) — AD environment, lateral movement, privilege escalation
- **HackTheBox/TryHackMe retired machines** — Real-world complexity

---

## Directory Structure

```
src/sentinel/benchmark/
├── __init__.py
├── runner.py              # BenchmarkRunner — orchestrates runs
├── ground_truth.py        # Ground truth databases per target
├── metrics.py             # MetricsCollector — tracks all measurements
├── reporter.py            # BenchmarkReporter — generates reports
├── regression.py          # RegressionTracker — compares across runs
├── targets/
│   ├── __init__.py
│   ├── juice_shop.py      # Juice Shop ground truth + setup
│   ├── dvwa.py            # DVWA ground truth + setup
│   └── webgoat.py         # WebGoat ground truth + setup
└── cli.py                 # CLI commands

tests/benchmark/
├── test_runner.py
├── test_metrics.py
├── test_ground_truth.py
└── test_regression.py
```

---

## File-by-File Implementation

### 1. `src/sentinel/benchmark/__init__.py`

```python
"""Sentinel Benchmark Harness — measures detection and exploitation accuracy."""
```

### 2. `src/sentinel/benchmark/targets/juice_shop.py`

```python
"""
Juice Shop ground truth — known vulnerabilities with metadata.

Source: https://pwning.owasp-juice.shop/companion-guide/latest/appendix/solutions.html
Each entry maps to a Juice Shop challenge with:
- category (OWASP mapping)
- severity
- endpoint/parameter
- technique required
- difficulty (1-6 stars)
"""
from dataclasses import dataclass


@dataclass
class KnownVuln:
    id: str
    name: str
    category: str           # sqli, xss, idor, ssrf, auth_bypass, etc.
    owasp: str              # A01:2021, A02:2021, etc.
    severity: str           # critical, high, medium, low
    endpoint: str           # URL path
    parameter: str | None   # Vulnerable parameter
    technique: str          # Brief description of exploitation technique
    difficulty: int         # 1-6 stars
    requires_auth: bool     # Whether auth is needed to reach it


JUICE_SHOP_GROUND_TRUTH: list[KnownVuln] = [
    # === A01:2021 — Broken Access Control ===
    KnownVuln(
        id="js-bac-001",
        name="View Another User's Basket",
        category="idor",
        owasp="A01:2021",
        severity="high",
        endpoint="/rest/basket/{id}",
        parameter="id",
        technique="Change basket ID in API call to access other users' baskets",
        difficulty=2,
        requires_auth=True,
    ),
    KnownVuln(
        id="js-bac-002",
        name="Admin Section Access",
        category="auth_bypass",
        owasp="A01:2021",
        severity="critical",
        endpoint="/#/administration",
        parameter=None,
        technique="Access admin panel without admin role by direct URL navigation",
        difficulty=2,
        requires_auth=True,
    ),
    KnownVuln(
        id="js-bac-003",
        name="Forged Feedback",
        category="idor",
        owasp="A01:2021",
        severity="medium",
        endpoint="/api/Feedbacks/",
        parameter="UserId",
        technique="Post feedback as another user by changing UserId in request body",
        difficulty=3,
        requires_auth=True,
    ),
    KnownVuln(
        id="js-bac-004",
        name="View Another User's Shopping Basket",
        category="idor",
        owasp="A01:2021",
        severity="high",
        endpoint="/rest/basket/{id}",
        parameter="id",
        technique="IDOR on basket endpoint to view other users' data",
        difficulty=2,
        requires_auth=True,
    ),
    KnownVuln(
        id="js-bac-005",
        name="Manipulate Basket via PUT",
        category="idor",
        owasp="A01:2021",
        severity="high",
        endpoint="/api/BasketItems/{id}",
        parameter="id",
        technique="Modify other users' basket items via direct API call",
        difficulty=3,
        requires_auth=True,
    ),

    # === A02:2021 — Cryptographic Failures ===
    KnownVuln(
        id="js-crypto-001",
        name="Confidential Document Access",
        category="info_disclosure",
        owasp="A02:2021",
        severity="high",
        endpoint="/ftp/",
        parameter=None,
        technique="Access exposed FTP directory containing sensitive files",
        difficulty=1,
        requires_auth=False,
    ),
    KnownVuln(
        id="js-crypto-002",
        name="Exposed Metrics Endpoint",
        category="info_disclosure",
        owasp="A02:2021",
        severity="medium",
        endpoint="/metrics",
        parameter=None,
        technique="Access Prometheus metrics endpoint leaking internal data",
        difficulty=1,
        requires_auth=False,
    ),

    # === A03:2021 — Injection ===
    KnownVuln(
        id="js-sqli-001",
        name="Login Admin via SQLi",
        category="sqli",
        owasp="A03:2021",
        severity="critical",
        endpoint="/rest/user/login",
        parameter="email",
        technique="SQL injection in login form: ' OR 1=1--",
        difficulty=2,
        requires_auth=False,
    ),
    KnownVuln(
        id="js-sqli-002",
        name="Search SQLi",
        category="sqli",
        owasp="A03:2021",
        severity="high",
        endpoint="/rest/products/search",
        parameter="q",
        technique="SQL injection in product search parameter",
        difficulty=3,
        requires_auth=False,
    ),
    KnownVuln(
        id="js-xss-001",
        name="DOM XSS via Search",
        category="xss",
        owasp="A03:2021",
        severity="high",
        endpoint="/#/search",
        parameter="q",
        technique="Reflected XSS in search results via iframe injection",
        difficulty=1,
        requires_auth=False,
    ),
    KnownVuln(
        id="js-xss-002",
        name="Stored XSS via Feedback",
        category="xss",
        owasp="A03:2021",
        severity="high",
        endpoint="/api/Feedbacks/",
        parameter="comment",
        technique="Stored XSS in feedback comment rendered on admin page",
        difficulty=3,
        requires_auth=True,
    ),
    KnownVuln(
        id="js-xss-003",
        name="Reflected XSS via Track Order",
        category="xss",
        owasp="A03:2021",
        severity="medium",
        endpoint="/#/track-result",
        parameter="id",
        technique="Reflected XSS in order tracking result page",
        difficulty=2,
        requires_auth=False,
    ),

    # === A05:2021 — Security Misconfiguration ===
    KnownVuln(
        id="js-misconfig-001",
        name="Error Handling Information Leak",
        category="info_disclosure",
        owasp="A05:2021",
        severity="medium",
        endpoint="/api/",
        parameter=None,
        technique="Verbose error messages revealing stack traces and internal paths",
        difficulty=1,
        requires_auth=False,
    ),
    KnownVuln(
        id="js-misconfig-002",
        name="Deprecated B2B Interface",
        category="xxe",
        owasp="A05:2021",
        severity="critical",
        endpoint="/file-upload",
        parameter="file",
        technique="XXE via file upload in deprecated B2B interface accepting XML",
        difficulty=4,
        requires_auth=True,
    ),

    # === A07:2021 — Identification & Auth Failures ===
    KnownVuln(
        id="js-auth-001",
        name="Password Strength Bypass",
        category="auth_bypass",
        owasp="A07:2021",
        severity="medium",
        endpoint="/rest/user/login",
        parameter="password",
        technique="Brute force with common passwords on known accounts",
        difficulty=2,
        requires_auth=False,
    ),
    KnownVuln(
        id="js-auth-002",
        name="JWT Token Forgery",
        category="auth_bypass",
        owasp="A07:2021",
        severity="critical",
        endpoint="/rest/user/login",
        parameter="Authorization",
        technique="Forge JWT with none algorithm or weak secret",
        difficulty=5,
        requires_auth=False,
    ),

    # === A09:2021 — Security Logging & Monitoring Failures ===
    KnownVuln(
        id="js-log-001",
        name="Access Log File",
        category="info_disclosure",
        owasp="A09:2021",
        severity="medium",
        endpoint="/support/logs",
        parameter=None,
        technique="Direct access to application log files",
        difficulty=2,
        requires_auth=False,
    ),

    # === A10:2021 — SSRF ===
    KnownVuln(
        id="js-ssrf-001",
        name="SSRF via Profile Image URL",
        category="ssrf",
        owasp="A10:2021",
        severity="high",
        endpoint="/profile/image/url",
        parameter="imageUrl",
        technique="SSRF by providing internal URL as profile image source",
        difficulty=4,
        requires_auth=True,
    ),
]


def get_juice_shop_ground_truth() -> list[KnownVuln]:
    """Return all known Juice Shop vulnerabilities."""
    return JUICE_SHOP_GROUND_TRUTH


def get_by_category(category: str) -> list[KnownVuln]:
    return [v for v in JUICE_SHOP_GROUND_TRUTH if v.category == category]


def get_by_owasp(owasp: str) -> list[KnownVuln]:
    return [v for v in JUICE_SHOP_GROUND_TRUTH if v.owasp == owasp]


def get_by_max_difficulty(max_difficulty: int) -> list[KnownVuln]:
    return [v for v in JUICE_SHOP_GROUND_TRUTH if v.difficulty <= max_difficulty]
```

### 3. `src/sentinel/benchmark/metrics.py`

```python
"""
MetricsCollector — tracks all benchmark measurements during a run.

Metrics:
- Detection rate: found / ground_truth_total
- Exploit rate: exploited / found
- False positive rate: false_positives / total_reported
- Time to first finding
- Time to first exploit
- Total run time
- Coverage by OWASP category
- Coverage by severity
- Attack chain depth distribution
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from sentinel.benchmark.targets.juice_shop import KnownVuln


@dataclass
class FindingMatch:
    """A match between a Sentinel finding and a ground truth vulnerability."""
    ground_truth_id: str
    finding_id: str
    category: str
    severity: str
    matched_by: str  # "exact_endpoint", "category_param", "fuzzy"
    verified: bool
    exploited: bool
    time_to_detect_seconds: float


@dataclass
class FalsePositive:
    """A Sentinel finding that doesn't match any ground truth."""
    finding_id: str
    category: str
    severity: str
    endpoint: str
    reason: str  # Why it's considered false positive


@dataclass
class BenchmarkMetrics:
    """Complete metrics for a benchmark run."""

    # Identity
    run_id: str = ""
    target: str = ""
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Ground truth
    ground_truth_total: int = 0
    ground_truth_by_category: dict[str, int] = field(default_factory=dict)
    ground_truth_by_severity: dict[str, int] = field(default_factory=dict)

    # Matches
    matches: list[FindingMatch] = field(default_factory=list)
    false_positives: list[FalsePositive] = field(default_factory=list)
    missed: list[str] = field(default_factory=list)  # Ground truth IDs not found

    # Timing
    time_to_first_finding_seconds: Optional[float] = None
    time_to_first_exploit_seconds: Optional[float] = None
    total_duration_seconds: float = 0.0

    # Chain metrics
    max_chain_depth: int = 0
    avg_chain_depth: float = 0.0
    chains_found: int = 0

    # LLM usage
    total_llm_calls: int = 0
    total_llm_tokens: int = 0
    total_llm_cost_usd: float = 0.0

    @property
    def detection_rate(self) -> float:
        """Percentage of ground truth vulns detected."""
        if self.ground_truth_total == 0:
            return 0.0
        return len(self.matches) / self.ground_truth_total

    @property
    def exploit_rate(self) -> float:
        """Percentage of detected vulns successfully exploited."""
        if not self.matches:
            return 0.0
        exploited = sum(1 for m in self.matches if m.exploited)
        return exploited / len(self.matches)

    @property
    def verification_rate(self) -> float:
        """Percentage of detected vulns verified (proof-by-exploitation)."""
        if not self.matches:
            return 0.0
        verified = sum(1 for m in self.matches if m.verified)
        return verified / len(self.matches)

    @property
    def false_positive_rate(self) -> float:
        """False positives / total reported findings."""
        total_reported = len(self.matches) + len(self.false_positives)
        if total_reported == 0:
            return 0.0
        return len(self.false_positives) / total_reported

    @property
    def precision(self) -> float:
        """True positives / (true positives + false positives)."""
        tp = len(self.matches)
        fp = len(self.false_positives)
        if tp + fp == 0:
            return 0.0
        return tp / (tp + fp)

    @property
    def recall(self) -> float:
        """Same as detection_rate: true positives / total ground truth."""
        return self.detection_rate

    @property
    def f1_score(self) -> float:
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    def coverage_by_owasp(self) -> dict[str, float]:
        """Detection rate per OWASP category."""
        coverage = {}
        matched_ids = {m.ground_truth_id for m in self.matches}
        # Need ground truth list to compute — caller passes it
        return coverage

    def summary_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "target": self.target,
            "duration_seconds": self.total_duration_seconds,
            "ground_truth_total": self.ground_truth_total,
            "detected": len(self.matches),
            "exploited": sum(1 for m in self.matches if m.exploited),
            "verified": sum(1 for m in self.matches if m.verified),
            "false_positives": len(self.false_positives),
            "missed": len(self.missed),
            "detection_rate": round(self.detection_rate * 100, 1),
            "exploit_rate": round(self.exploit_rate * 100, 1),
            "verification_rate": round(self.verification_rate * 100, 1),
            "false_positive_rate": round(self.false_positive_rate * 100, 1),
            "precision": round(self.precision * 100, 1),
            "recall": round(self.recall * 100, 1),
            "f1_score": round(self.f1_score * 100, 1),
            "time_to_first_finding": self.time_to_first_finding_seconds,
            "time_to_first_exploit": self.time_to_first_exploit_seconds,
            "chains_found": self.chains_found,
            "max_chain_depth": self.max_chain_depth,
            "llm_calls": self.total_llm_calls,
            "llm_tokens": self.total_llm_tokens,
            "llm_cost_usd": round(self.total_llm_cost_usd, 4),
        }
```

### 4. `src/sentinel/benchmark/runner.py`

```python
"""
BenchmarkRunner — Orchestrates a full pentest run against a target app,
collects findings, matches against ground truth, computes metrics.

Usage:
    runner = BenchmarkRunner(target="juice-shop", config={...})
    metrics = await runner.run()
    print(metrics.summary_dict())
"""
import time
import uuid
from datetime import datetime
from typing import Optional

from sentinel.benchmark.metrics import BenchmarkMetrics, FindingMatch, FalsePositive
from sentinel.benchmark.targets.juice_shop import (
    KnownVuln,
    get_juice_shop_ground_truth,
)
from sentinel.logging import get_logger

logger = get_logger(__name__)


class BenchmarkRunner:
    """
    Runs Sentinel against a target, matches findings to ground truth,
    and produces BenchmarkMetrics.
    """

    def __init__(
        self,
        target: str = "juice-shop",
        target_url: str = "http://localhost:3001",
        max_difficulty: int = 6,
        categories: Optional[list[str]] = None,
        timeout_seconds: int = 1800,  # 30 min default
    ):
        self.target = target
        self.target_url = target_url
        self.max_difficulty = max_difficulty
        self.categories = categories
        self.timeout_seconds = timeout_seconds
        self.run_id = str(uuid.uuid4())[:8]
        self.ground_truth = self._load_ground_truth()

    def _load_ground_truth(self) -> list[KnownVuln]:
        """Load ground truth for the target, filtered by difficulty and category."""
        if self.target == "juice-shop":
            gt = get_juice_shop_ground_truth()
        else:
            raise ValueError(f"Unknown target: {self.target}. Supported: juice-shop")

        gt = [v for v in gt if v.difficulty <= self.max_difficulty]
        if self.categories:
            gt = [v for v in gt if v.category in self.categories]

        return gt

    async def run(self) -> BenchmarkMetrics:
        """
        Execute full benchmark:
        1. Start Sentinel engagement against target
        2. Wait for completion or timeout
        3. Collect findings
        4. Match findings against ground truth
        5. Compute metrics
        """
        metrics = BenchmarkMetrics(
            run_id=self.run_id,
            target=self.target,
            started_at=datetime.utcnow(),
            ground_truth_total=len(self.ground_truth),
        )

        # Compute ground truth breakdowns
        for vuln in self.ground_truth:
            metrics.ground_truth_by_category[vuln.category] = (
                metrics.ground_truth_by_category.get(vuln.category, 0) + 1
            )
            metrics.ground_truth_by_severity[vuln.severity] = (
                metrics.ground_truth_by_severity.get(vuln.severity, 0) + 1
            )

        start_time = time.monotonic()

        try:
            # Step 1: Create and start engagement via API
            engagement_id = await self._start_engagement()
            logger.info(f"Benchmark {self.run_id}: engagement {engagement_id} started")

            # Step 2: Wait for completion
            findings = await self._wait_and_collect(engagement_id, start_time)
            logger.info(f"Benchmark {self.run_id}: collected {len(findings)} findings")

            # Step 3: Match findings against ground truth
            self._match_findings(findings, metrics, start_time)

            # Step 4: Identify missed vulns
            matched_gt_ids = {m.ground_truth_id for m in metrics.matches}
            metrics.missed = [v.id for v in self.ground_truth if v.id not in matched_gt_ids]

            # Step 5: Collect chain metrics
            chains = await self._collect_chains(engagement_id)
            if chains:
                metrics.chains_found = len(chains)
                depths = [c.get("total_depth", 0) for c in chains]
                metrics.max_chain_depth = max(depths) if depths else 0
                metrics.avg_chain_depth = sum(depths) / len(depths) if depths else 0

        except Exception as e:
            logger.error(f"Benchmark {self.run_id} failed: {e}")

        metrics.completed_at = datetime.utcnow()
        metrics.total_duration_seconds = time.monotonic() - start_time

        return metrics

    async def _start_engagement(self) -> str:
        """Create and start a Sentinel engagement via the API."""
        from sentinel.benchmark._api_helpers import create_engagement, start_engagement

        engagement = await create_engagement(
            target_url=self.target_url,
            config={
                "require_approval": False,  # Full auto for benchmarks
                "scan_depth": 3,
                "excluded_paths": [],
            },
        )
        await start_engagement(engagement["id"])
        return engagement["id"]

    async def _wait_and_collect(self, engagement_id: str, start_time: float) -> list[dict]:
        """Poll engagement status until complete or timeout, then collect findings."""
        import asyncio
        from sentinel.benchmark._api_helpers import get_engagement_status, get_findings

        while time.monotonic() - start_time < self.timeout_seconds:
            status = await get_engagement_status(engagement_id)

            if status in ("complete", "failed"):
                break

            await asyncio.sleep(5)

        return await get_findings(engagement_id)

    def _match_findings(
        self, findings: list[dict], metrics: BenchmarkMetrics, start_time: float
    ):
        """
        Match Sentinel findings against ground truth.
        
        Matching strategy (in order of strictness):
        6. Exact: same endpoint + same category
        7. Category + param: same category + same parameter name
        8. Category only: same category (weaker match)
        """
        matched_gt_ids: set[str] = set()
        first_finding_time = None
        first_exploit_time = None

        for finding in findings:
            f_endpoint = finding.get("target_url", "")
            f_category = finding.get("category", "")
            f_param = finding.get("target_param", "")
            f_time = finding.get("detected_at_offset_seconds", 0)

            best_match: Optional[KnownVuln] = None
            match_type = ""

            for vuln in self.ground_truth:
                if vuln.id in matched_gt_ids:
                    continue

                # Exact: endpoint contains known path + same category
                if vuln.category == f_category and vuln.endpoint in f_endpoint:
                    best_match = vuln
                    match_type = "exact_endpoint"
                    break

                # Category + param
                if (
                    vuln.category == f_category
                    and vuln.parameter
                    and vuln.parameter == f_param
                ):
                    best_match = vuln
                    match_type = "category_param"

                # Category only (weakest)
                if vuln.category == f_category and not best_match:
                    best_match = vuln
                    match_type = "fuzzy"

            if best_match:
                matched_gt_ids.add(best_match.id)
                metrics.matches.append(
                    FindingMatch(
                        ground_truth_id=best_match.id,
                        finding_id=finding.get("id", ""),
                        category=f_category,
                        severity=finding.get("severity", "info"),
                        matched_by=match_type,
                        verified=finding.get("verified", False),
                        exploited=finding.get("exploited", False),
                        time_to_detect_seconds=f_time,
                    )
                )

                if first_finding_time is None:
                    first_finding_time = f_time
                if finding.get("exploited") and first_exploit_time is None:
                    first_exploit_time = f_time
            else:
                metrics.false_positives.append(
                    FalsePositive(
                        finding_id=finding.get("id", ""),
                        category=f_category,
                        severity=finding.get("severity", "info"),
                        endpoint=f_endpoint,
                        reason="No matching ground truth vulnerability",
                    )
                )

        metrics.time_to_first_finding_seconds = first_finding_time
        metrics.time_to_first_exploit_seconds = first_exploit_time

    async def _collect_chains(self, engagement_id: str) -> list[dict]:
        """Collect attack chains from the engagement."""
        from sentinel.benchmark._api_helpers import get_chains

        try:
            return await get_chains(engagement_id)
        except Exception:
            return []
```

### 5. `src/sentinel/benchmark/_api_helpers.py`

```python
"""
Internal API helpers for benchmark runner.
Thin wrappers around Sentinel REST API calls.
"""
import aiohttp

API_BASE = "http://localhost:8000"


async def create_engagement(target_url: str, config: dict) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{API_BASE}/api/engagements",
            json={"target_url": target_url, "config": config},
        ) as resp:
            return await resp.json()


async def start_engagement(engagement_id: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{API_BASE}/api/engagements/{engagement_id}/start"
        ) as resp:
            return await resp.json()


async def get_engagement_status(engagement_id: str) -> str:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{API_BASE}/api/engagements/{engagement_id}"
        ) as resp:
            data = await resp.json()
            return data.get("status", "unknown")


async def get_findings(engagement_id: str) -> list[dict]:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{API_BASE}/api/findings?engagement_id={engagement_id}"
        ) as resp:
            return await resp.json()


async def get_chains(engagement_id: str) -> list[dict]:
    async with aiohttp.ClientSession() as session:
        async with session.get(
            f"{API_BASE}/api/engagements/{engagement_id}/chains"
        ) as resp:
            return await resp.json()
```

### 6. `src/sentinel/benchmark/reporter.py`

```python
"""
BenchmarkReporter — Generates human-readable benchmark reports.

Outputs:
- Terminal summary (colored, tabular)
- JSON (machine-readable, for CI/CD)
- Markdown (for docs/README)
"""
import json
from sentinel.benchmark.metrics import BenchmarkMetrics


class BenchmarkReporter:

    @staticmethod
    def to_terminal(metrics: BenchmarkMetrics) -> str:
        """Terminal-formatted summary with ASCII bars."""
        s = metrics.summary_dict()
        lines = [
            "=" * 60,
            f"  SENTINEL BENCHMARK — {s['target']}",
            f"  Run: {s['run_id']}  Duration: {s['duration_seconds']:.0f}s",
            "=" * 60,
            "",
            f"  Detection Rate:     {_bar(s['detection_rate'])} {s['detection_rate']}%  ({s['detected']}/{s['ground_truth_total']})",
            f"  Exploit Rate:       {_bar(s['exploit_rate'])} {s['exploit_rate']}%  ({s['exploited']}/{s['detected']})",
            f"  Verification Rate:  {_bar(s['verification_rate'])} {s['verification_rate']}%  ({s['verified']}/{s['detected']})",
            f"  False Positive Rate:{_bar(s['false_positive_rate'], inverse=True)} {s['false_positive_rate']}%  ({s['false_positives']})",
            "",
            f"  Precision: {s['precision']}%   Recall: {s['recall']}%   F1: {s['f1_score']}%",
            "",
            f"  Time to first finding:  {_fmt_time(s['time_to_first_finding'])}",
            f"  Time to first exploit:  {_fmt_time(s['time_to_first_exploit'])}",
            f"  Attack chains found:    {s['chains_found']}",
            f"  Max chain depth:        {s['max_chain_depth']}",
            "",
            f"  LLM calls: {s['llm_calls']}  Tokens: {s['llm_tokens']}  Cost: ${s['llm_cost_usd']}",
            "",
            f"  Missed ({len(metrics.missed)}):",
        ]

        for mid in metrics.missed[:10]:
            lines.append(f"    - {mid}")
        if len(metrics.missed) > 10:
            lines.append(f"    ... and {len(metrics.missed) - 10} more")

        lines.append("=" * 60)
        return "\n".join(lines)

    @staticmethod
    def to_json(metrics: BenchmarkMetrics) -> str:
        """Machine-readable JSON output."""
        data = metrics.summary_dict()
        data["matches"] = [
            {
                "ground_truth_id": m.ground_truth_id,
                "finding_id": m.finding_id,
                "matched_by": m.matched_by,
                "verified": m.verified,
                "exploited": m.exploited,
            }
            for m in metrics.matches
        ]
        data["false_positives_detail"] = [
            {
                "finding_id": fp.finding_id,
                "category": fp.category,
                "endpoint": fp.endpoint,
            }
            for fp in metrics.false_positives
        ]
        data["missed_ids"] = metrics.missed
        return json.dumps(data, indent=2)

    @staticmethod
    def to_markdown(metrics: BenchmarkMetrics) -> str:
        """Markdown report for docs/README."""
        s = metrics.summary_dict()
        lines = [
            f"# Sentinel Benchmark: {s['target']}",
            "",
            f"Run `{s['run_id']}` — {s['duration_seconds']:.0f}s",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Detection Rate | {s['detection_rate']}% ({s['detected']}/{s['ground_truth_total']}) |",
            f"| Exploit Rate | {s['exploit_rate']}% |",
            f"| Verification Rate | {s['verification_rate']}% |",
            f"| False Positive Rate | {s['false_positive_rate']}% |",
            f"| Precision | {s['precision']}% |",
            f"| Recall | {s['recall']}% |",
            f"| F1 Score | {s['f1_score']}% |",
            f"| Time to First Finding | {_fmt_time(s['time_to_first_finding'])} |",
            f"| Time to First Exploit | {_fmt_time(s['time_to_first_exploit'])} |",
            f"| Attack Chains | {s['chains_found']} (max depth {s['max_chain_depth']}) |",
            f"| LLM Cost | ${s['llm_cost_usd']} |",
        ]
        return "\n".join(lines)


def _bar(pct: float, width: int = 20, inverse: bool = False) -> str:
    """ASCII progress bar."""
    filled = int(pct / 100 * width)
    if inverse:
        filled = width - filled
    return f"[{'█' * filled}{'░' * (width - filled)}]"


def _fmt_time(seconds) -> str:
    if seconds is None:
        return "N/A"
    if seconds < 60:
        return f"{seconds:.1f}s"
    return f"{seconds / 60:.1f}m"
```

### 7. `src/sentinel/benchmark/regression.py`

```python
"""
RegressionTracker — Compares benchmark runs over time.

Stores results in PostgreSQL, detects regressions.
A regression = detection_rate dropped by >5% or false_positive_rate increased by >5%.
"""
import json
from datetime import datetime
from typing import Optional

from sentinel.benchmark.metrics import BenchmarkMetrics
from sentinel.logging import get_logger

logger = get_logger(__name__)


class RegressionTracker:

    def __init__(self, db_url: str):
        self.db_url = db_url

    async def save_run(self, metrics: BenchmarkMetrics):
        """Save benchmark run to database."""
        import asyncpg

        conn = await asyncpg.connect(self.db_url)
        try:
            await conn.execute(
                """
                INSERT INTO benchmark_runs (run_id, target, metrics_json, created_at)
                VALUES ($1, $2, $3, $4)
                """,
                metrics.run_id,
                metrics.target,
                json.dumps(metrics.summary_dict()),
                datetime.utcnow(),
            )
        finally:
            await conn.close()

    async def get_previous_run(self, target: str) -> Optional[dict]:
        """Get the most recent benchmark run for a target."""
        import asyncpg

        conn = await asyncpg.connect(self.db_url)
        try:
            row = await conn.fetchrow(
                """
                SELECT metrics_json FROM benchmark_runs
                WHERE target = $1
                ORDER BY created_at DESC
                LIMIT 1 OFFSET 1
                """,
                target,
            )
            return json.loads(row["metrics_json"]) if row else None
        finally:
            await conn.close()

    async def check_regression(self, metrics: BenchmarkMetrics) -> list[str]:
        """
        Compare current run against previous. Return list of regression warnings.
        """
        previous = await self.get_previous_run(metrics.target)
        if not previous:
            return []

        warnings = []
        current = metrics.summary_dict()

        # Detection rate regression
        det_delta = current["detection_rate"] - previous["detection_rate"]
        if det_delta < -5:
            warnings.append(
                f"REGRESSION: Detection rate dropped {abs(det_delta):.1f}% "
                f"({previous['detection_rate']}% → {current['detection_rate']}%)"
            )

        # False positive rate regression
        fp_delta = current["false_positive_rate"] - previous["false_positive_rate"]
        if fp_delta > 5:
            warnings.append(
                f"REGRESSION: False positive rate increased {fp_delta:.1f}% "
                f"({previous['false_positive_rate']}% → {current['false_positive_rate']}%)"
            )

        # Exploit rate regression
        exp_delta = current["exploit_rate"] - previous["exploit_rate"]
        if exp_delta < -10:
            warnings.append(
                f"REGRESSION: Exploit rate dropped {abs(exp_delta):.1f}% "
                f"({previous['exploit_rate']}% → {current['exploit_rate']}%)"
            )

        # Time regression (>50% slower)
        if previous.get("duration_seconds") and current["duration_seconds"]:
            time_ratio = current["duration_seconds"] / previous["duration_seconds"]
            if time_ratio > 1.5:
                warnings.append(
                    f"REGRESSION: Run time increased {(time_ratio - 1) * 100:.0f}% "
                    f"({previous['duration_seconds']:.0f}s → {current['duration_seconds']:.0f}s)"
                )

        return warnings
```

### 8. `src/sentinel/benchmark/cli.py`

```python
"""
Benchmark CLI — run, report, compare benchmark results.

Usage:
    sentinel benchmark run --target juice-shop --max-difficulty 3
    sentinel benchmark report --run-id abc123
    sentinel benchmark compare --run1 abc123 --run2 def456
    sentinel benchmark history --target juice-shop
"""
import asyncio
import click

from sentinel.benchmark.runner import BenchmarkRunner
from sentinel.benchmark.reporter import BenchmarkReporter
from sentinel.benchmark.regression import RegressionTracker
from sentinel.config import get_config


@click.group()
def benchmark():
    """Sentinel Benchmark Harness."""
    pass


@benchmark.command()
@click.option("--target", default="juice-shop", help="Target app name")
@click.option("--target-url", default="http://localhost:3001", help="Target URL")
@click.option("--max-difficulty", default=6, type=int, help="Max vuln difficulty (1-6)")
@click.option("--categories", default=None, help="Comma-separated categories to test")
@click.option("--timeout", default=1800, type=int, help="Timeout in seconds")
@click.option("--format", "fmt", default="terminal", type=click.Choice(["terminal", "json", "markdown"]))
def run(target, target_url, max_difficulty, categories, timeout, fmt):
    """Run a full benchmark against a target application."""
    cats = categories.split(",") if categories else None

    runner = BenchmarkRunner(
        target=target,
        target_url=target_url,
        max_difficulty=max_difficulty,
        categories=cats,
        timeout_seconds=timeout,
    )

    metrics = asyncio.run(runner.run())

    # Output
    if fmt == "terminal":
        click.echo(BenchmarkReporter.to_terminal(metrics))
    elif fmt == "json":
        click.echo(BenchmarkReporter.to_json(metrics))
    elif fmt == "markdown":
        click.echo(BenchmarkReporter.to_markdown(metrics))

    # Save and check regression
    config = get_config()
    db_url = config.get("database_url")
    if db_url:
        tracker = RegressionTracker(db_url)
        asyncio.run(tracker.save_run(metrics))
        warnings = asyncio.run(tracker.check_regression(metrics))
        for w in warnings:
            click.echo(click.style(f"⚠ {w}", fg="red"))


@benchmark.command()
@click.option("--target", default="juice-shop", help="Target to show history for")
@click.option("--limit", default=10, type=int, help="Number of runs to show")
def history(target, limit):
    """Show benchmark history for a target."""
    import asyncpg
    config = get_config()
    db_url = config.get("database_url")

    async def _fetch():
        conn = await asyncpg.connect(db_url)
        rows = await conn.fetch(
            """
            SELECT run_id, metrics_json, created_at FROM benchmark_runs
            WHERE target = $1 ORDER BY created_at DESC LIMIT $2
            """,
            target, limit,
        )
        await conn.close()
        return rows

    rows = asyncio.run(_fetch())
    for row in rows:
        import json
        m = json.loads(row["metrics_json"])
        click.echo(
            f"{row['created_at'].strftime('%Y-%m-%d %H:%M')} | "
            f"{row['run_id']} | "
            f"Det: {m['detection_rate']}% | "
            f"Exp: {m['exploit_rate']}% | "
            f"FP: {m['false_positive_rate']}% | "
            f"F1: {m['f1_score']}% | "
            f"{m['duration_seconds']:.0f}s"
        )
```

---

## Database Migration

Add to `infra/init-db.sql`:

```sql
-- ============================================================
-- Benchmark runs (Phase 11)
-- ============================================================
CREATE TABLE IF NOT EXISTS benchmark_runs (
    id SERIAL PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    metrics_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_benchmark_target ON benchmark_runs(target, created_at DESC);
```

---

## Tests

### `tests/benchmark/test_metrics.py`

```python
import pytest
from sentinel.benchmark.metrics import BenchmarkMetrics, FindingMatch, FalsePositive


class TestBenchmarkMetrics:
    def test_detection_rate(self):
        m = BenchmarkMetrics(ground_truth_total=20)
        m.matches = [FindingMatch("gt1", "f1", "sqli", "high", "exact_endpoint", True, True, 10.0)] * 15
        assert m.detection_rate == 0.75

    def test_false_positive_rate(self):
        m = BenchmarkMetrics(ground_truth_total=10)
        m.matches = [FindingMatch("gt1", "f1", "sqli", "high", "exact_endpoint", True, True, 5.0)] * 8
        m.false_positives = [FalsePositive("fp1", "xss", "medium", "/test", "no match")] * 2
        assert m.false_positive_rate == 0.2

    def test_f1_score(self):
        m = BenchmarkMetrics(ground_truth_total=10)
        m.matches = [FindingMatch("gt1", "f1", "sqli", "high", "exact_endpoint", True, True, 5.0)] * 8
        assert m.precision == 1.0  # No false positives
        assert m.recall == 0.8
        assert round(m.f1_score, 4) == 0.8889

    def test_zero_findings(self):
        m = BenchmarkMetrics(ground_truth_total=10)
        assert m.detection_rate == 0.0
        assert m.false_positive_rate == 0.0
        assert m.f1_score == 0.0

    def test_summary_dict(self):
        m = BenchmarkMetrics(run_id="test", target="juice-shop", ground_truth_total=5)
        s = m.summary_dict()
        assert s["run_id"] == "test"
        assert s["target"] == "juice-shop"
        assert "detection_rate" in s
```

### `tests/benchmark/test_ground_truth.py`

```python
from sentinel.benchmark.targets.juice_shop import (
    get_juice_shop_ground_truth,
    get_by_category,
    get_by_owasp,
    get_by_max_difficulty,
)


class TestJuiceShopGroundTruth:
    def test_has_vulns(self):
        gt = get_juice_shop_ground_truth()
        assert len(gt) > 10

    def test_all_have_required_fields(self):
        for v in get_juice_shop_ground_truth():
            assert v.id
            assert v.category
            assert v.owasp
            assert v.severity in ("critical", "high", "medium", "low")
            assert v.endpoint
            assert 1 <= v.difficulty <= 6

    def test_filter_by_category(self):
        sqli = get_by_category("sqli")
        assert all(v.category == "sqli" for v in sqli)
        assert len(sqli) >= 2

    def test_filter_by_owasp(self):
        a03 = get_by_owasp("A03:2021")
        assert all(v.owasp == "A03:2021" for v in a03)

    def test_filter_by_difficulty(self):
        easy = get_by_max_difficulty(2)
        assert all(v.difficulty <= 2 for v in easy)
        assert len(easy) < len(get_juice_shop_ground_truth())

    def test_unique_ids(self):
        gt = get_juice_shop_ground_truth()
        ids = [v.id for v in gt]
        assert len(ids) == len(set(ids))
```

---

## Acceptance Criteria

- [ ] BenchmarkRunner executes full run against Juice Shop
- [ ] Ground truth has 15+ known Juice Shop vulns with complete metadata
- [ ] Finding matching works at three levels (exact, category+param, fuzzy)
- [ ] Metrics compute correctly: detection rate, exploit rate, FP rate, precision, recall, F1
- [ ] Terminal, JSON, and Markdown report outputs are formatted correctly
- [ ] Regression tracker saves runs and detects regressions (>5% detection drop, >5% FP increase)
- [ ] CLI commands work: `sentinel benchmark run`, `sentinel benchmark history`
- [ ] All tests pass
- [ ] Benchmark run completes within 30 minutes against Juice Shop