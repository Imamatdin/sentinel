"""
EPSS Client — Fetches exploit prediction scores from FIRST.org API.

API: https://api.first.org/data/v1/epss
Returns probability (0-1) and percentile for each CVE.
Cache results for 24h (scores update daily).
"""

import httpx
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from sentinel.core import get_logger

logger = get_logger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_TTL = timedelta(hours=24)


@dataclass
class EPSSScore:
    cve_id: str
    epss: float        # 0.0-1.0 probability of exploitation in 30 days
    percentile: float   # 0.0-1.0 rank among all CVEs
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class EPSSClient:
    """Fetch and cache EPSS scores from FIRST.org API."""

    def __init__(self) -> None:
        self._cache: dict[str, EPSSScore] = {}

    async def get_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a single CVE."""
        # Check memory cache
        cached = self._cache.get(cve_id)
        if cached and (datetime.now(timezone.utc) - cached.fetched_at) < CACHE_TTL:
            return cached

        # Fetch from API
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(EPSS_API, params={"cve": cve_id})
                if resp.status_code != 200:
                    logger.warning(f"EPSS API returned {resp.status_code} for {cve_id}")
                    return None
                data = resp.json()

            results = data.get("data", [])
            if not results:
                return None

            entry = results[0]
            score = EPSSScore(
                cve_id=entry["cve"],
                epss=float(entry["epss"]),
                percentile=float(entry["percentile"]),
            )
            self._cache[cve_id] = score
            return score

        except Exception as e:
            logger.error(f"EPSS fetch failed for {cve_id}: {e}")
            return None

    async def get_scores_bulk(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for multiple CVEs in one call (API supports comma-separated)."""
        if not cve_ids:
            return {}

        # Return cached scores where available, fetch missing ones
        results: dict[str, EPSSScore] = {}
        to_fetch: list[str] = []

        for cve_id in cve_ids:
            cached = self._cache.get(cve_id)
            if cached and (datetime.now(timezone.utc) - cached.fetched_at) < CACHE_TTL:
                results[cve_id] = cached
            else:
                to_fetch.append(cve_id)

        if not to_fetch:
            return results

        # API accepts up to ~100 CVEs per request
        for chunk in _chunks(to_fetch, 100):
            try:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    resp = await client.get(EPSS_API, params={"cve": ",".join(chunk)})
                    if resp.status_code != 200:
                        logger.warning(f"EPSS bulk API returned {resp.status_code}")
                        continue
                    data = resp.json()

                for entry in data.get("data", []):
                    score = EPSSScore(
                        cve_id=entry["cve"],
                        epss=float(entry["epss"]),
                        percentile=float(entry["percentile"]),
                    )
                    self._cache[score.cve_id] = score
                    results[score.cve_id] = score

            except Exception as e:
                logger.error(f"EPSS bulk fetch failed: {e}")

        return results


def _chunks(lst: list, n: int):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]
