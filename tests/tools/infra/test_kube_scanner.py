"""Tests for Kubernetes security scanner."""

import pytest
from sentinel.tools.infra.kube_scanner import KubeScanner, KubeIssue


SECURE_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
          privileged: false
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
"""

INSECURE_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          privileged: true
          runAsUser: 0
        ports:
        - containerPort: 8080
          hostPort: 8080
"""

PRIVILEGED_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod
spec:
  containers:
  - name: main
    image: alpine
    securityContext:
      privileged: true
"""

MINIMAL_POD = """
apiVersion: v1
kind: Pod
metadata:
  name: minimal
spec:
  containers:
  - name: app
    image: myapp:1.0
"""

MULTI_CONTAINER = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: multi
spec:
  template:
    spec:
      containers:
      - name: web
        image: nginx
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
        resources:
          limits:
            cpu: "100m"
            memory: "128Mi"
      - name: sidecar
        image: envoy
        securityContext:
          privileged: true
"""

MULTI_DOC = """
apiVersion: v1
kind: Pod
metadata:
  name: pod1
spec:
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
---
apiVersion: v1
kind: Pod
metadata:
  name: pod2
spec:
  hostNetwork: true
  containers:
  - name: app
    image: myapp:1.0
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
"""

STATEFULSET = """
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: db
spec:
  template:
    spec:
      containers:
      - name: postgres
        image: postgres:15
        securityContext:
          privileged: true
"""

CRONJOB = """
apiVersion: batch/v1
kind: CronJob
metadata:
  name: backup
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: backup:1.0
            securityContext:
              runAsNonRoot: true
              readOnlyRootFilesystem: true
            resources:
              limits:
                cpu: "100m"
                memory: "128Mi"
"""


class TestKubeScanner:
    def setup_method(self):
        self.scanner = KubeScanner()

    def test_secure_deployment_minimal_issues(self):
        issues = self.scanner.scan_manifest(SECURE_DEPLOYMENT)
        # Secure deployment should have no issues
        assert len(issues) == 0

    def test_privileged_container(self):
        issues = self.scanner.scan_manifest(PRIVILEGED_POD)
        priv = [i for i in issues if i.check_id == "CIS-5.2.1"]
        assert len(priv) == 1
        assert priv[0].severity == "critical"

    def test_host_network(self):
        issues = self.scanner.scan_manifest(INSECURE_DEPLOYMENT)
        net = [i for i in issues if i.check_id == "CIS-5.2.4"]
        assert len(net) == 1
        assert net[0].severity == "high"

    def test_host_pid(self):
        issues = self.scanner.scan_manifest(INSECURE_DEPLOYMENT)
        pid = [i for i in issues if i.check_id == "CIS-5.2.2"]
        assert len(pid) == 1

    def test_host_port(self):
        issues = self.scanner.scan_manifest(INSECURE_DEPLOYMENT)
        hp = [i for i in issues if i.check_id == "CIS-5.2.13"]
        assert len(hp) == 1

    def test_run_as_root(self):
        issues = self.scanner.scan_manifest(INSECURE_DEPLOYMENT)
        root = [i for i in issues if i.check_id == "CIS-5.2.6"]
        assert len(root) == 1

    def test_no_resource_limits(self):
        issues = self.scanner.scan_manifest(MINIMAL_POD)
        limits = [i for i in issues if i.check_id == "CIS-5.4.1"]
        assert len(limits) == 1

    def test_writable_root_fs(self):
        issues = self.scanner.scan_manifest(MINIMAL_POD)
        fs = [i for i in issues if i.check_id == "CIS-5.2.8"]
        assert len(fs) == 1

    def test_minimal_pod_many_issues(self):
        """A pod with no security context should flag multiple issues."""
        issues = self.scanner.scan_manifest(MINIMAL_POD)
        # run as root, writable FS, no limits
        assert len(issues) >= 3

    def test_multi_container_flags_only_insecure(self):
        issues = self.scanner.scan_manifest(MULTI_CONTAINER)
        priv = [i for i in issues if i.check_id == "CIS-5.2.1"]
        assert len(priv) == 1
        assert priv[0].container == "sidecar"

    def test_multi_document_yaml(self):
        issues = self.scanner.scan_manifest(MULTI_DOC)
        net = [i for i in issues if i.check_id == "CIS-5.2.4"]
        assert len(net) == 1
        assert "pod2" in net[0].resource

    def test_statefulset_support(self):
        issues = self.scanner.scan_manifest(STATEFULSET)
        priv = [i for i in issues if i.check_id == "CIS-5.2.1"]
        assert len(priv) == 1

    def test_cronjob_support(self):
        issues = self.scanner.scan_manifest(CRONJOB)
        # Secure cronjob — should have no issues
        assert len(issues) == 0

    def test_invalid_yaml(self):
        issues = self.scanner.scan_manifest("not: [valid yaml: {{")
        assert len(issues) == 0

    def test_empty_manifest(self):
        issues = self.scanner.scan_manifest("")
        assert len(issues) == 0

    def test_non_workload_kind(self):
        manifest = """
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  ports:
  - port: 80
"""
        issues = self.scanner.scan_manifest(manifest)
        assert len(issues) == 0

    def test_issue_has_resource_name(self):
        issues = self.scanner.scan_manifest(PRIVILEGED_POD)
        assert any("priv-pod" in i.resource for i in issues)

    def test_issue_has_container_name(self):
        issues = self.scanner.scan_manifest(PRIVILEGED_POD)
        priv = [i for i in issues if i.check_id == "CIS-5.2.1"]
        assert priv[0].container == "main"

    def test_host_ipc(self):
        manifest = """
apiVersion: v1
kind: Pod
metadata:
  name: ipc-pod
spec:
  hostIPC: true
  containers:
  - name: app
    image: myapp
    securityContext:
      runAsNonRoot: true
      readOnlyRootFilesystem: true
    resources:
      limits:
        cpu: "100m"
        memory: "128Mi"
"""
        issues = self.scanner.scan_manifest(manifest)
        ipc = [i for i in issues if i.check_id == "CIS-5.2.3"]
        assert len(ipc) == 1
