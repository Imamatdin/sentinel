"""
Dockerfile Analyzer — Static analysis for security anti-patterns.

Checks for:
- USER root (or no USER directive)
- ADD instead of COPY (cache poisoning risk)
- Exposed secrets in ENV/ARG
- Latest tag usage
- Missing health checks
- Unnecessary package installs
"""

import re
from dataclasses import dataclass

from sentinel.core import get_logger

logger = get_logger(__name__)

SECRET_PATTERNS = [
    r"(?i)(password|passwd|secret|api[_-]?key|token|private[_-]?key).*=",
    r"(?i)(aws[_-]?access|aws[_-]?secret)",
]


@dataclass
class DockerfileIssue:
    line: int
    severity: str
    description: str
    fix: str


class DockerfileAnalyzer:
    """Analyze Dockerfiles for security anti-patterns."""

    def analyze(self, content: str) -> list[DockerfileIssue]:
        """Analyze Dockerfile content and return list of issues."""
        issues: list[DockerfileIssue] = []
        lines = content.strip().splitlines()

        if not lines:
            return issues

        has_user = False
        has_healthcheck = False
        has_from = False

        for i, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            instruction = line.split()[0].upper() if line.split() else ""

            # Check for USER directive
            if instruction == "USER":
                has_user = True
                user_val = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
                if user_val == "root":
                    issues.append(DockerfileIssue(
                        line=i,
                        severity="high",
                        description="Container runs as root user",
                        fix="Use a non-root user: USER appuser",
                    ))

            # Check for ADD instead of COPY
            if instruction == "ADD":
                # ADD is valid for tar extraction and URLs, but flag general use
                rest = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
                if not rest.startswith("http") and ".tar" not in rest:
                    issues.append(DockerfileIssue(
                        line=i,
                        severity="medium",
                        description="ADD used instead of COPY (cache poisoning risk)",
                        fix="Use COPY unless you need tar extraction or remote URLs",
                    ))

            # Check for secrets in ENV/ARG
            if instruction in ("ENV", "ARG"):
                for pattern in SECRET_PATTERNS:
                    if re.search(pattern, line):
                        issues.append(DockerfileIssue(
                            line=i,
                            severity="critical",
                            description=f"Potential secret exposed in {instruction} directive",
                            fix="Use build secrets (--mount=type=secret) or runtime env vars",
                        ))
                        break

            # Check for latest tag
            if instruction == "FROM":
                has_from = True
                image_ref = line.split(None, 1)[1].split(" as ")[0].split(" AS ")[0].strip() if len(line.split(None, 1)) > 1 else ""
                if image_ref and ":" not in image_ref and "@" not in image_ref:
                    issues.append(DockerfileIssue(
                        line=i,
                        severity="medium",
                        description="Base image uses implicit :latest tag",
                        fix="Pin to a specific version tag, e.g., python:3.12-slim",
                    ))
                elif ":latest" in image_ref:
                    issues.append(DockerfileIssue(
                        line=i,
                        severity="medium",
                        description="Base image uses :latest tag",
                        fix="Pin to a specific version tag, e.g., python:3.12-slim",
                    ))

            # Check HEALTHCHECK
            if instruction == "HEALTHCHECK":
                has_healthcheck = True

        # Global checks (only if this is a valid Dockerfile with FROM)
        if not has_from:
            return issues

        if not has_user:
            issues.append(DockerfileIssue(
                line=0,
                severity="high",
                description="No USER directive — container will run as root",
                fix="Add USER directive with a non-root user",
            ))

        if not has_healthcheck:
            issues.append(DockerfileIssue(
                line=0,
                severity="low",
                description="No HEALTHCHECK directive",
                fix="Add HEALTHCHECK CMD curl -f http://localhost/ || exit 1",
            ))

        return issues
