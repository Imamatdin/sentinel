"""
Webhook Handler — Receives GitHub/GitLab push events and triggers selective re-testing.

Verifies HMAC-SHA256 signature, extracts commits, runs DiffAnalyzer,
and returns risk assessment.
"""

import hashlib
import hmac
from typing import Any

from fastapi import APIRouter, Request, HTTPException

from sentinel.cicd.diff_analyzer import DiffAnalyzer
from sentinel.cicd.selective_scanner import SelectiveScanner
from sentinel.core import get_logger

logger = get_logger(__name__)

router = APIRouter()


def verify_github_signature(
    payload: bytes, signature: str, secret: str
) -> bool:
    """Verify GitHub webhook HMAC-SHA256 signature."""
    if not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    received = signature[7:]  # strip "sha256="
    return hmac.compare_digest(expected, received)


@router.post("/webhook/github")
async def github_push(request: Request) -> dict[str, Any]:
    """Handle GitHub push webhook.

    1. Verify webhook signature (if secret configured)
    2. Extract commits and diffs from payload
    3. Run DiffAnalyzer on patch content
    4. Return risk assessment and retest plan
    """
    body = await request.body()

    # Signature verification (optional — only if secret is configured)
    webhook_secret = getattr(request.app.state, "webhook_secret", "")
    if webhook_secret:
        sig = request.headers.get("X-Hub-Signature-256", "")
        if not verify_github_signature(body, sig, webhook_secret):
            raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    # Extract push event data
    commits = payload.get("commits", [])
    repo_name = payload.get("repository", {}).get("full_name", "unknown")
    ref = payload.get("ref", "")

    analyzer = DiffAnalyzer()
    scanner = SelectiveScanner()

    all_assessments = []
    for commit in commits:
        # GitHub sends patch URLs but not inline diffs.
        # Use the commit message and file lists as a lightweight signal.
        # For full diff analysis, would need to fetch from GitHub API.
        modified = commit.get("modified", [])
        added = commit.get("added", [])
        removed = commit.get("removed", [])

        # Build a synthetic diff from file lists
        all_files = modified + added
        if all_files:
            diff_lines = []
            for f in all_files:
                diff_lines.append(f"diff --git a/{f} b/{f}")
                diff_lines.append(f"+++ b/{f}")
                # Include commit message as "added content" for risk scanning
                diff_lines.append(f"+{commit.get('message', '')}")
            synthetic_diff = "\n".join(diff_lines)
            assessments = analyzer.analyze_diff(synthetic_diff)
            all_assessments.extend(assessments)

    retest_plan = analyzer.get_retest_plan(all_assessments)
    retest_target = scanner.plan_retest(all_assessments)

    logger.info(
        "webhook_processed",
        repo=repo_name,
        ref=ref,
        commits=len(commits),
        max_risk=retest_plan.get("max_risk_score", 0),
        should_retest=retest_plan.get("should_retest", False),
    )

    return {
        "repo": repo_name,
        "ref": ref,
        "commits_analyzed": len(commits),
        "retest_plan": retest_plan,
        "retest_target": {
            "categories": retest_target.hypothesis_categories,
            "endpoints": retest_target.affected_endpoints,
            "risk_score": retest_target.risk_score,
        }
        if retest_target
        else None,
    }
