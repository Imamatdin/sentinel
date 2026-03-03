"""
Benchmark Targets -- Intentionally vulnerable applications for testing.

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

from sentinel.core import get_logger

logger = get_logger(__name__)


class Difficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    EXPERT = "expert"


@dataclass
class GroundTruthVuln:
    vuln_id: str
    category: str  # sqli, xss, ssrf, idor, auth_bypass, etc.
    severity: str  # critical, high, medium, low
    location: str  # URL path or endpoint
    parameter: str  # Vulnerable parameter
    description: str
    evidence: str  # What proves the vuln exists
    cwe_id: str
    cvss_score: float = 0.0


@dataclass
class NegativeControl:
    endpoint: str
    description: str  # Why this should NOT flag
    expected_result: str = "clean"


@dataclass
class BenchmarkTarget:
    target_id: str
    name: str
    description: str
    difficulty: Difficulty
    domains: list[str]
    docker_compose: str
    base_url: str
    ground_truth: list[GroundTruthVuln]
    negative_controls: list[NegativeControl]
    setup_time_seconds: int
    teardown_script: str = "docker compose down"


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
            "  juice-shop:\n"
            "    image: bkimminich/juice-shop:latest\n"
            "    ports:\n"
            "      - '3000:3000'\n"
        ),
        base_url="http://localhost:3000",
        ground_truth=[
            GroundTruthVuln(
                "js-sqli-1", "sqli", "high", "/rest/products/search",
                "q", "SQL injection in product search",
                "Returns all products with ' OR 1=1--", "CWE-89", 8.6,
            ),
            GroundTruthVuln(
                "js-xss-1", "xss", "medium", "/api/Users",
                "email", "Stored XSS in user registration",
                "Script executes in admin panel", "CWE-79", 6.1,
            ),
            GroundTruthVuln(
                "js-idor-1", "idor", "high", "/api/BasketItems/{id}",
                "id", "IDOR: access other users' basket items",
                "Returns items belonging to different user", "CWE-639", 7.5,
            ),
            GroundTruthVuln(
                "js-auth-1", "auth_bypass", "critical", "/rest/user/login",
                "email", "Authentication bypass via SQL injection",
                "Login as admin without password", "CWE-287", 9.8,
            ),
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
            "  dvwa:\n"
            "    image: vulnerables/web-dvwa:latest\n"
            "    ports:\n"
            "      - '8080:80'\n"
        ),
        base_url="http://localhost:8080",
        ground_truth=[
            GroundTruthVuln(
                "dvwa-sqli-1", "sqli", "high", "/vulnerabilities/sqli/",
                "id", "SQL injection in user ID lookup",
                "Returns database contents", "CWE-89", 8.6,
            ),
            GroundTruthVuln(
                "dvwa-xss-r", "xss", "medium", "/vulnerabilities/xss_r/",
                "name", "Reflected XSS in name parameter",
                "Script reflected in response", "CWE-79", 6.1,
            ),
            GroundTruthVuln(
                "dvwa-cmd-1", "command", "critical", "/vulnerabilities/exec/",
                "ip", "OS command injection",
                "Executes arbitrary commands", "CWE-78", 9.8,
            ),
            GroundTruthVuln(
                "dvwa-fi-1", "path_traversal", "high", "/vulnerabilities/fi/",
                "page", "Local file inclusion",
                "Reads /etc/passwd", "CWE-22", 7.5,
            ),
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
            "  api:\n"
            "    build: ./benchmark/custom-api\n"
            "    ports:\n"
            "      - '5000:5000'\n"
        ),
        base_url="http://localhost:5000",
        ground_truth=[
            GroundTruthVuln(
                "api-ssrf-1", "ssrf", "critical", "/api/fetch-url",
                "url", "SSRF via URL fetcher endpoint",
                "Fetches internal metadata endpoint", "CWE-918", 9.1,
            ),
            GroundTruthVuln(
                "api-bola-1", "idor", "high", "/api/users/{id}/profile",
                "id", "BOLA: access any user's profile",
                "Returns other user data with changed ID", "CWE-639", 7.5,
            ),
            GroundTruthVuln(
                "api-massassign", "mass_assignment", "high", "/api/users/register",
                "role", "Mass assignment allows role escalation",
                "Set role=admin in registration", "CWE-915", 8.1,
            ),
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

    def list_targets(
        self, difficulty: Difficulty | None = None, domain: str | None = None
    ) -> list[BenchmarkTarget]:
        results = list(self.targets.values())
        if difficulty:
            results = [t for t in results if t.difficulty == difficulty]
        if domain:
            results = [t for t in results if domain in t.domains]
        return results
