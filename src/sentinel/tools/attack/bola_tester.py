"""
BOLA/IDOR Differential Tester.

Strategy:
1. Authenticate as User A, collect resource IDs (orders, profiles, etc.)
2. Authenticate as User B (different role/tenant)
3. Try accessing User A's resources as User B
4. Compare responses: if User B gets User A's data -> BOLA confirmed

This is the "gold standard" for IDOR testing -- requires two valid sessions.
"""

import aiohttp
from dataclasses import dataclass

from sentinel.tools.base import ToolOutput
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class BOLATestCase:
    endpoint: str
    method: str
    resource_id: str
    owner_user: str        # User who owns the resource
    attacker_user: str     # User trying to access it


@dataclass
class BOLAFinding:
    endpoint: str
    method: str
    resource_id: str
    owner: str
    attacker: str
    owner_status: int
    attacker_status: int
    data_leaked: bool
    response_similarity: float  # 0.0-1.0 how similar attacker response is to owner's
    severity: str = "critical"


class BOLATester:
    name = "bola_test"
    description = "Test for Broken Object Level Authorization (IDOR)"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def execute(
        self,
        test_cases: list[BOLATestCase],
        owner_session: dict,     # {"headers": {"Authorization": "Bearer ..."}}
        attacker_session: dict,
    ) -> ToolOutput:
        """Run BOLA differential tests."""
        findings: list[BOLAFinding] = []

        for tc in test_cases:
            finding = await self._test_single(tc, owner_session, attacker_session)
            if finding:
                findings.append(finding)

        return ToolOutput(
            tool_name=self.name,
            success=True,
            data={
                "findings": [
                    {
                        "endpoint": f.endpoint,
                        "method": f.method,
                        "resource_id": f.resource_id,
                        "owner": f.owner,
                        "attacker": f.attacker,
                        "owner_status": f.owner_status,
                        "attacker_status": f.attacker_status,
                        "data_leaked": f.data_leaked,
                        "response_similarity": f.response_similarity,
                        "severity": f.severity,
                    }
                    for f in findings
                ],
            },
            metadata={
                "total_tests": len(test_cases),
                "bola_confirmed": len(findings),
            },
        )

    async def _test_single(
        self, tc: BOLATestCase, owner_session: dict, attacker_session: dict
    ) -> BOLAFinding | None:
        """Test a single endpoint for BOLA."""
        try:
            async with aiohttp.ClientSession() as session:
                # Step 1: Get owner's response (baseline)
                owner_resp = await self._make_request(
                    session, tc.method, tc.endpoint, owner_session.get("headers", {})
                )

                if owner_resp["status"] >= 400:
                    return None  # Owner can't access their own resource -- skip

                # Step 2: Try same request as attacker
                attacker_resp = await self._make_request(
                    session, tc.method, tc.endpoint, attacker_session.get("headers", {})
                )

                # Step 3: Analyze
                if attacker_resp["status"] < 400:
                    # Attacker got a 2xx/3xx -- potential BOLA
                    similarity = self._compare_responses(
                        owner_resp["body"], attacker_resp["body"]
                    )

                    if similarity > 0.5:  # Attacker sees similar data to owner
                        return BOLAFinding(
                            endpoint=tc.endpoint,
                            method=tc.method,
                            resource_id=tc.resource_id,
                            owner=tc.owner_user,
                            attacker=tc.attacker_user,
                            owner_status=owner_resp["status"],
                            attacker_status=attacker_resp["status"],
                            data_leaked=True,
                            response_similarity=similarity,
                        )

                return None
        except Exception as e:
            logger.error(f"BOLA test failed for {tc.endpoint}: {e}")
            return None

    async def _make_request(
        self, session: aiohttp.ClientSession, method: str, url: str, headers: dict
    ) -> dict:
        async with session.request(
            method, url, headers=headers,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
        ) as resp:
            body = await resp.text()
            return {"status": resp.status, "body": body, "headers": dict(resp.headers)}

    def _compare_responses(self, body_a: str, body_b: str) -> float:
        """Compare two response bodies for similarity (0.0-1.0)."""
        if not body_a or not body_b:
            return 0.0
        if body_a == body_b:
            return 1.0

        # Jaccard similarity on tokens
        tokens_a = set(body_a.split())
        tokens_b = set(body_b.split())
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)
