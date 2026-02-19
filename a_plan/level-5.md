# LEVEL 05: Container & Kubernetes Security Scanner

## Context
Adds container image scanning (Trivy CLI wrapper) and Kubernetes misconfiguration detection (kube-bench). Covers base image CVEs, Dockerfile anti-patterns, and K8s RBAC/network policy issues.

Research: Block 12 (Container & Orchestration Security), Block 5.

## Files to Create

### `src/sentinel/tools/infra/__init__.py`
```python
"""Infrastructure security tools — containers, K8s, cloud."""
```

### `src/sentinel/tools/infra/trivy_tool.py`
Wraps `trivy image --format json <image>` and `trivy fs --format json <path>`.
- Parse JSON output into structured findings
- Map severity levels to Sentinel's severity enum
- Support scanning: container images, filesystem (Dockerfile), and IaC (Terraform, CloudFormation)

Key function signatures:
```python
class TrivyTool(BaseTool):
    name = "trivy_scan"
    async def scan_image(self, image: str) -> ToolResult: ...
    async def scan_filesystem(self, path: str) -> ToolResult: ...
    async def scan_iac(self, path: str) -> ToolResult: ...
```

### `src/sentinel/tools/infra/dockerfile_analyzer.py`
Static analysis of Dockerfile for security anti-patterns:
- `USER root` (or no USER directive)
- `ADD` instead of `COPY` (cache poisoning risk)
- Exposed secrets in ENV/ARG
- Latest tag usage
- Missing health checks
- Unnecessary package installs

Returns list of `DockerfileIssue(line, severity, description, fix)`.

### `src/sentinel/tools/infra/kube_scanner.py`
Wraps `kube-bench run --json` for CIS Kubernetes Benchmark checks.
- Also does static analysis of K8s manifests (YAML) for: privileged containers, hostNetwork, missing resource limits, missing NetworkPolicy, exposed etcd, open kube-dashboard.

## Tests
- Test Trivy JSON output parsing with sample fixtures
- Test Dockerfile analyzer catches `USER root`, `ADD *`, no health check
- Test K8s manifest scanner catches privileged: true, hostNetwork: true

## Acceptance Criteria
- [ ] TrivyTool parses real Trivy JSON output
- [ ] DockerfileAnalyzer catches top 6 anti-patterns
- [ ] KubeScanner catches CIS benchmark violations from manifests
- [ ] Findings flow into Neo4j as InfraFinding nodes
- [ ] All tests pass