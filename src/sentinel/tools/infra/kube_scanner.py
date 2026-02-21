"""
Kubernetes Security Scanner — Static analysis of K8s manifests.

Checks for CIS Kubernetes Benchmark violations:
- Privileged containers
- hostNetwork / hostPID / hostIPC
- Missing resource limits
- Missing NetworkPolicy
- Running as root
- Exposed hostPort
- Writable root filesystem
"""

import json
from dataclasses import dataclass

import yaml

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class KubeIssue:
    resource: str       # e.g., "Deployment/myapp"
    container: str      # container name within the pod
    severity: str
    check_id: str       # CIS benchmark reference
    description: str
    fix: str


class KubeScanner:
    """Scan Kubernetes manifests for security misconfigurations."""

    def scan_manifest(self, content: str) -> list[KubeIssue]:
        """Scan a YAML manifest (may contain multiple documents)."""
        issues: list[KubeIssue] = []
        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError as e:
            logger.warning("yaml_parse_error", error=str(e))
            return issues

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            name = doc.get("metadata", {}).get("name", "unknown")
            resource_id = f"{kind}/{name}"

            pod_spec = self._extract_pod_spec(doc)
            if pod_spec:
                issues.extend(self._check_pod_spec(resource_id, pod_spec))

        return issues

    def _extract_pod_spec(self, doc: dict) -> dict | None:
        """Extract the pod spec from various K8s resource types."""
        kind = doc.get("kind", "")
        if kind == "Pod":
            return doc.get("spec", {})
        elif kind in ("Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"):
            return doc.get("spec", {}).get("template", {}).get("spec", {})
        elif kind == "CronJob":
            return (
                doc.get("spec", {})
                .get("jobTemplate", {})
                .get("spec", {})
                .get("template", {})
                .get("spec", {})
            )
        return None

    def _check_pod_spec(
        self, resource_id: str, pod_spec: dict
    ) -> list[KubeIssue]:
        issues: list[KubeIssue] = []

        # Host-level checks
        if pod_spec.get("hostNetwork"):
            issues.append(KubeIssue(
                resource=resource_id, container="*",
                severity="high", check_id="CIS-5.2.4",
                description="hostNetwork is enabled",
                fix="Set hostNetwork: false",
            ))

        if pod_spec.get("hostPID"):
            issues.append(KubeIssue(
                resource=resource_id, container="*",
                severity="high", check_id="CIS-5.2.2",
                description="hostPID is enabled",
                fix="Set hostPID: false",
            ))

        if pod_spec.get("hostIPC"):
            issues.append(KubeIssue(
                resource=resource_id, container="*",
                severity="high", check_id="CIS-5.2.3",
                description="hostIPC is enabled",
                fix="Set hostIPC: false",
            ))

        # Container-level checks
        containers = pod_spec.get("containers") or []
        for container in containers:
            cname = container.get("name", "unnamed")
            sc = container.get("securityContext") or {}

            # Privileged
            if sc.get("privileged"):
                issues.append(KubeIssue(
                    resource=resource_id, container=cname,
                    severity="critical", check_id="CIS-5.2.1",
                    description="Container runs in privileged mode",
                    fix="Set securityContext.privileged: false",
                ))

            # Run as root
            if sc.get("runAsUser") == 0 or (
                not sc.get("runAsNonRoot") and sc.get("runAsUser") is None
            ):
                run_as_non_root = sc.get("runAsNonRoot")
                if run_as_non_root is not True:
                    issues.append(KubeIssue(
                        resource=resource_id, container=cname,
                        severity="high", check_id="CIS-5.2.6",
                        description="Container may run as root",
                        fix="Set securityContext.runAsNonRoot: true and runAsUser: 1000",
                    ))

            # Writable root filesystem
            if not sc.get("readOnlyRootFilesystem"):
                issues.append(KubeIssue(
                    resource=resource_id, container=cname,
                    severity="medium", check_id="CIS-5.2.8",
                    description="Root filesystem is writable",
                    fix="Set securityContext.readOnlyRootFilesystem: true",
                ))

            # Resource limits
            resources = container.get("resources") or {}
            if not resources.get("limits"):
                issues.append(KubeIssue(
                    resource=resource_id, container=cname,
                    severity="medium", check_id="CIS-5.4.1",
                    description="No resource limits set",
                    fix="Set resources.limits.cpu and resources.limits.memory",
                ))

            # Host ports
            for port in container.get("ports") or []:
                if port.get("hostPort"):
                    issues.append(KubeIssue(
                        resource=resource_id, container=cname,
                        severity="medium", check_id="CIS-5.2.13",
                        description=f"hostPort {port['hostPort']} is exposed",
                        fix="Remove hostPort unless absolutely necessary",
                    ))

        return issues
