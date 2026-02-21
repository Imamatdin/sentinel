"""Tests for Dockerfile analyzer."""

import pytest
from sentinel.tools.infra.dockerfile_analyzer import DockerfileAnalyzer, DockerfileIssue


class TestDockerfileAnalyzer:
    def setup_method(self):
        self.analyzer = DockerfileAnalyzer()

    def test_secure_dockerfile_minimal_issues(self):
        """A well-written Dockerfile should only flag HEALTHCHECK if missing."""
        content = """
FROM python:3.12-slim
COPY . /app
RUN pip install --no-cache-dir -r /app/requirements.txt
USER appuser
HEALTHCHECK CMD curl -f http://localhost:8000/ || exit 1
CMD ["python", "app.py"]
"""
        issues = self.analyzer.analyze(content)
        assert len(issues) == 0

    def test_user_root(self):
        content = """
FROM python:3.12-slim
USER root
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
"""
        issues = self.analyzer.analyze(content)
        root_issues = [i for i in issues if "runs as root" in i.description]
        assert len(root_issues) == 1
        assert root_issues[0].severity == "high"

    def test_no_user_directive(self):
        content = """
FROM python:3.12-slim
COPY . /app
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
"""
        issues = self.analyzer.analyze(content)
        no_user = [i for i in issues if "No USER directive" in i.description]
        assert len(no_user) == 1
        assert no_user[0].severity == "high"

    def test_add_instead_of_copy(self):
        content = """
FROM python:3.12-slim
ADD . /app
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        add_issues = [i for i in issues if "ADD used instead of COPY" in i.description]
        assert len(add_issues) == 1
        assert add_issues[0].severity == "medium"

    def test_add_with_tar_is_ok(self):
        content = """
FROM python:3.12-slim
ADD archive.tar.gz /app
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        add_issues = [i for i in issues if "ADD used instead of COPY" in i.description]
        assert len(add_issues) == 0

    def test_add_with_url_is_ok(self):
        content = """
FROM python:3.12-slim
ADD https://example.com/file.txt /app/
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        add_issues = [i for i in issues if "ADD used instead of COPY" in i.description]
        assert len(add_issues) == 0

    def test_secret_in_env(self):
        content = """
FROM python:3.12-slim
ENV API_KEY=sk-12345
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        secret_issues = [i for i in issues if "secret" in i.description.lower()]
        assert len(secret_issues) == 1
        assert secret_issues[0].severity == "critical"

    def test_secret_in_arg(self):
        content = """
FROM python:3.12-slim
ARG PASSWORD=mypassword
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        secret_issues = [i for i in issues if "secret" in i.description.lower()]
        assert len(secret_issues) == 1

    def test_latest_tag_implicit(self):
        content = """
FROM python
COPY . /app
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        tag_issues = [i for i in issues if "latest" in i.description.lower()]
        assert len(tag_issues) == 1

    def test_latest_tag_explicit(self):
        content = """
FROM python:latest
COPY . /app
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        tag_issues = [i for i in issues if "latest" in i.description.lower()]
        assert len(tag_issues) == 1

    def test_pinned_tag_ok(self):
        content = """
FROM python:3.12-slim
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
"""
        issues = self.analyzer.analyze(content)
        tag_issues = [i for i in issues if "latest" in i.description.lower()]
        assert len(tag_issues) == 0

    def test_no_healthcheck(self):
        content = """
FROM python:3.12-slim
COPY . /app
USER appuser
CMD ["python", "app.py"]
"""
        issues = self.analyzer.analyze(content)
        hc_issues = [i for i in issues if "HEALTHCHECK" in i.description]
        assert len(hc_issues) == 1
        assert hc_issues[0].severity == "low"

    def test_with_healthcheck(self):
        content = """
FROM python:3.12-slim
COPY . /app
USER appuser
HEALTHCHECK --interval=30s CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
"""
        issues = self.analyzer.analyze(content)
        hc_issues = [i for i in issues if "HEALTHCHECK" in i.description]
        assert len(hc_issues) == 0

    def test_multiple_issues(self):
        """A terrible Dockerfile should flag many issues."""
        content = """
FROM python
ADD . /app
ENV SECRET_KEY=abc123
CMD ["python", "app.py"]
"""
        issues = self.analyzer.analyze(content)
        # Should catch: latest tag, ADD, secret, no USER, no HEALTHCHECK
        assert len(issues) == 5

    def test_empty_dockerfile(self):
        issues = self.analyzer.analyze("")
        assert len(issues) == 0

    def test_comments_ignored(self):
        content = """
# This is a comment
FROM python:3.12-slim
# ADD . /app  <- this is commented
COPY . /app
USER appuser
HEALTHCHECK CMD true
"""
        issues = self.analyzer.analyze(content)
        add_issues = [i for i in issues if "ADD" in i.description]
        assert len(add_issues) == 0

    def test_issue_has_line_number(self):
        content = """FROM python:latest
COPY . /app
USER appuser
HEALTHCHECK CMD true
"""
        issues = self.analyzer.analyze(content)
        tag_issues = [i for i in issues if "latest" in i.description.lower()]
        assert len(tag_issues) == 1
        assert tag_issues[0].line == 1

    def test_aws_secret_detection(self):
        content = """
FROM python:3.12-slim
ENV AWS_SECRET_ACCESS_KEY=AKIA1234567890
USER appuser
HEALTHCHECK CMD true
"""
        issues = self.analyzer.analyze(content)
        secret_issues = [i for i in issues if "secret" in i.description.lower()]
        assert len(secret_issues) == 1
