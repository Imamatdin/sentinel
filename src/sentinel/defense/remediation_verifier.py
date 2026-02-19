"""RemediationVerifier -- Post-fix verification.

After exploit:
1. Suggest specific remediation
2. (Optional) Apply fix
3. Re-run exploit
4. Verify fix worked
"""

from typing import Any, Callable, Awaitable

from sentinel.core import get_logger

logger = get_logger(__name__)


class RemediationVerifier:
    """Autonomous blue hardening verification.

    For each exploited finding:
    1. Re-run the exact exploit that succeeded
    2. Confirm it now fails (fix verified)
    3. Log result for defense effectiveness scoring
    """

    async def verify_remediation(
        self,
        finding: dict[str, Any],
        replay_tool: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Re-run exploit after fix and verify it's blocked.

        Args:
            finding: The original finding dict with exploit details.
            replay_tool: Async callable that replays the exploit and returns result dict
                         with at least a 'success' key.

        Returns:
            Dict with finding_id, fix_verified, original_severity, retest_result.
        """
        try:
            result = await replay_tool(finding)
        except Exception as exc:
            logger.warning("replay_failed", finding_id=finding.get("hypothesis_id"), error=str(exc))
            return {
                "finding_id": finding.get("hypothesis_id"),
                "fix_verified": False,
                "original_severity": finding.get("severity"),
                "retest_result": "ERROR",
                "error": str(exc),
            }

        return {
            "finding_id": finding.get("hypothesis_id"),
            "fix_verified": not result.get("success", True),
            "original_severity": finding.get("severity"),
            "retest_result": "BLOCKED" if not result.get("success") else "STILL_VULNERABLE",
        }

    async def bulk_verify(
        self,
        findings: list[dict[str, Any]],
        replay_tool: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
    ) -> dict[str, Any]:
        """Verify remediation for all findings.

        Returns:
            Aggregate stats with total, verified_fixed, still_vulnerable, fix_rate, details.
        """
        results: list[dict[str, Any]] = []
        for finding in findings:
            result = await self.verify_remediation(finding, replay_tool)
            results.append(result)

        verified = sum(1 for r in results if r.get("fix_verified"))
        return {
            "total": len(results),
            "verified_fixed": verified,
            "still_vulnerable": len(results) - verified,
            "fix_rate": verified / max(len(results), 1),
            "details": results,
        }
