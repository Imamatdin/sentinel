"""Tests for webhook handler."""

import hashlib
import hmac
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinel.cicd.webhook_handler import router, verify_github_signature


def create_test_app(webhook_secret: str = "") -> FastAPI:
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    app.state.webhook_secret = webhook_secret
    return app


GITHUB_PUSH_PAYLOAD = {
    "ref": "refs/heads/main",
    "repository": {"full_name": "org/repo"},
    "commits": [
        {
            "id": "abc123",
            "message": "Update auth middleware",
            "modified": ["src/auth/middleware.py"],
            "added": [],
            "removed": [],
        }
    ],
}

GITHUB_PUSH_SQL = {
    "ref": "refs/heads/main",
    "repository": {"full_name": "org/repo"},
    "commits": [
        {
            "id": "def456",
            "message": "Fix SQL query in users",
            "modified": ["src/db/queries.py"],
            "added": [],
            "removed": [],
        }
    ],
}

GITHUB_PUSH_DOCS = {
    "ref": "refs/heads/main",
    "repository": {"full_name": "org/repo"},
    "commits": [
        {
            "id": "ghi789",
            "message": "Update README",
            "modified": ["README.md"],
            "added": [],
            "removed": [],
        }
    ],
}

GITHUB_PUSH_MULTI = {
    "ref": "refs/heads/main",
    "repository": {"full_name": "org/repo"},
    "commits": [
        {
            "id": "abc123",
            "message": "Auth and SQL changes",
            "modified": ["src/auth/login.py", "src/db/queries.py"],
            "added": ["src/api/routes/payments.py"],
            "removed": [],
        }
    ],
}


class TestGithubSignatureVerification:
    def test_valid_signature(self):
        secret = "test-secret"
        payload = b'{"test": true}'
        sig = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        assert verify_github_signature(payload, sig, secret) is True

    def test_invalid_signature(self):
        assert verify_github_signature(b"data", "sha256=invalid", "secret") is False

    def test_missing_signature(self):
        assert verify_github_signature(b"data", "", "secret") is False

    def test_wrong_prefix(self):
        assert verify_github_signature(b"data", "sha1=abc", "secret") is False


class TestWebhookEndpoint:
    def test_auth_change_triggers_retest(self):
        app = create_test_app()
        client = TestClient(app)
        resp = client.post("/api/v1/webhook/github", json=GITHUB_PUSH_PAYLOAD)
        assert resp.status_code == 200
        data = resp.json()
        assert data["commits_analyzed"] == 1
        plan = data["retest_plan"]
        assert plan["should_retest"] is True
        assert plan["max_risk_score"] >= 0.8

    def test_sql_change_maps_to_injection(self):
        app = create_test_app()
        client = TestClient(app)
        resp = client.post("/api/v1/webhook/github", json=GITHUB_PUSH_SQL)
        assert resp.status_code == 200
        data = resp.json()
        target = data.get("retest_target")
        assert target is not None
        assert "injection" in target["categories"]

    def test_docs_change_no_retest(self):
        app = create_test_app()
        client = TestClient(app)
        resp = client.post("/api/v1/webhook/github", json=GITHUB_PUSH_DOCS)
        assert resp.status_code == 200
        data = resp.json()
        assert data["retest_plan"]["should_retest"] is False
        assert data["retest_target"] is None

    def test_multi_file_commit(self):
        app = create_test_app()
        client = TestClient(app)
        resp = client.post("/api/v1/webhook/github", json=GITHUB_PUSH_MULTI)
        assert resp.status_code == 200
        data = resp.json()
        plan = data["retest_plan"]
        assert plan["should_retest"] is True
        assert len(plan["hypothesis_categories"]) > 1

    def test_signature_verification_rejects_bad_sig(self):
        app = create_test_app(webhook_secret="my-secret")
        client = TestClient(app)
        resp = client.post(
            "/api/v1/webhook/github",
            content=json.dumps(GITHUB_PUSH_PAYLOAD).encode(),
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": "sha256=invalid",
            },
        )
        assert resp.status_code == 401

    def test_signature_verification_accepts_good_sig(self):
        secret = "my-secret"
        payload = json.dumps(GITHUB_PUSH_PAYLOAD).encode()
        sig = "sha256=" + hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        app = create_test_app(webhook_secret=secret)
        client = TestClient(app)
        resp = client.post(
            "/api/v1/webhook/github",
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Hub-Signature-256": sig,
            },
        )
        assert resp.status_code == 200

    def test_returns_repo_name(self):
        app = create_test_app()
        client = TestClient(app)
        resp = client.post("/api/v1/webhook/github", json=GITHUB_PUSH_PAYLOAD)
        assert resp.json()["repo"] == "org/repo"

    def test_returns_ref(self):
        app = create_test_app()
        client = TestClient(app)
        resp = client.post("/api/v1/webhook/github", json=GITHUB_PUSH_PAYLOAD)
        assert resp.json()["ref"] == "refs/heads/main"

    def test_empty_commits(self):
        app = create_test_app()
        client = TestClient(app)
        payload = {
            "ref": "refs/heads/main",
            "repository": {"full_name": "org/repo"},
            "commits": [],
        }
        resp = client.post("/api/v1/webhook/github", json=payload)
        assert resp.status_code == 200
        assert resp.json()["commits_analyzed"] == 0
