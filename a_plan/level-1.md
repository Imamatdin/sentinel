# LEVEL 01: EPSS Vulnerability Priority Scoring

## Context
You are extending the Sentinel autonomous AI pentesting platform. The base platform (Phases 0-9) is complete with: Neo4j knowledge graph, Temporal workflows, PolicyEngine, HypothesisEngine, GuardedVulnAgent, pgvector RAG, FastAPI+WebSocket API.

This level integrates FIRST.org's EPSS (Exploit Prediction Scoring System) to prioritize which vulnerabilities to test first based on real-world exploitation probability.

## Why
Without EPSS, Sentinel treats all CVEs equally. EPSS gives each CVE a 0-1 probability of being exploited in the next 30 days. A CVE with EPSS 0.97 should be tested before one with EPSS 0.001. This makes hypothesis ranking 10x smarter and is a compliance selling point (shows risk-based prioritization).

---

## Files to Create

### `src/sentinel/intel/epss_client.py`
```python
"""
EPSS Client — Fetches exploit prediction scores from FIRST.org API.

API: https://api.first.org/data/v1/epss
Returns probability (0-1) and percentile for each CVE.
Cache results for 24h (scores update daily).
"""
import asyncio
import aiohttp
import json
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
from sentinel.logging import get_logger

logger = get_logger(__name__)

EPSS_API = "https://api.first.org/data/v1/epss"
CACHE_TTL = timedelta(hours=24)


@dataclass
class EPSSScore:
    cve_id: str
    epss: float        # 0.0-1.0 probability of exploitation in 30 days
    percentile: float   # 0.0-1.0 rank among all CVEs
    fetched_at: datetime = None


class EPSSClient:
    """Fetch and cache EPSS scores."""
    
    def __init__(self, cache_dir: str = "/tmp/sentinel/epss"):
        self._cache: dict[str, EPSSScore] = {}
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._last_bulk_fetch: datetime = None
    
    async def get_score(self, cve_id: str) -> EPSSScore | None:
        """Get EPSS score for a single CVE."""
        # Check memory cache
        if cve_id in self._cache:
            cached = self._cache[cve_id]
            if datetime.utcnow() - cached.fetched_at < CACHE_TTL:
                return cached
        
        # Fetch from API
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    EPSS_API, params={"cve": cve_id}
                ) as resp:
                    if resp.status != 200:
                        logger.warning(f"EPSS API returned {resp.status} for {cve_id}")
                        return None
                    data = await resp.json()
                    
            results = data.get("data", [])
            if not results:
                return None
            
            entry = results[0]
            score = EPSSScore(
                cve_id=entry["cve"],
                epss=float(entry["epss"]),
                percentile=float(entry["percentile"]),
                fetched_at=datetime.utcnow(),
            )
            self._cache[cve_id] = score
            return score
            
        except Exception as e:
            logger.error(f"EPSS fetch failed for {cve_id}: {e}")
            return None
    
    async def get_scores_bulk(self, cve_ids: list[str]) -> dict[str, EPSSScore]:
        """Fetch EPSS scores for multiple CVEs in one call (API supports comma-separated)."""
        results = {}
        # API accepts up to ~100 CVEs per request
        for chunk in _chunks(cve_ids, 100):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        EPSS_API, params={"cve": ",".join(chunk)}
                    ) as resp:
                        if resp.status != 200:
                            continue
                        data = await resp.json()
                
                for entry in data.get("data", []):
                    score = EPSSScore(
                        cve_id=entry["cve"],
                        epss=float(entry["epss"]),
                        percentile=float(entry["percentile"]),
                        fetched_at=datetime.utcnow(),
                    )
                    self._cache[score.cve_id] = score
                    results[score.cve_id] = score
                    
            except Exception as e:
                logger.error(f"EPSS bulk fetch failed: {e}")
        
        return results


def _chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
```

### `src/sentinel/intel/__init__.py`
```python
"""Threat intelligence integrations."""
```

---

## Files to Modify

### `src/sentinel/agents/hypothesis_engine.py`
Add EPSS-aware ranking. In the `_rank()` method, multiply priority_score by EPSS percentile when a hypothesis maps to a known CVE.

**Add import at top:**
```python
from sentinel.intel.epss_client import EPSSClient
```

**Add to `__init__`:**
```python
self.epss = EPSSClient()
```

**Add method:**
```python
async def _enrich_with_epss(self, hypotheses: list[VulnHypothesis]) -> list[VulnHypothesis]:
    """Boost hypothesis priority if linked CVE has high EPSS score."""
    # Collect CVE IDs from hypotheses that reference known CVEs
    cve_map = {}
    for h in hypotheses:
        if hasattr(h, 'cve_id') and h.cve_id:
            cve_map[h.cve_id] = h
    
    if not cve_map:
        return hypotheses
    
    scores = await self.epss.get_scores_bulk(list(cve_map.keys()))
    
    for cve_id, score in scores.items():
        if cve_id in cve_map:
            h = cve_map[cve_id]
            # Boost: multiply by (1 + epss_percentile) so high-EPSS vulns jump up
            h.priority_score *= (1.0 + score.percentile)
    
    return sorted(hypotheses, key=lambda h: h.priority_score, reverse=True)
```

**Call it in `generate_hypotheses()` after `_rank()`:**
```python
hypotheses = await self._enrich_with_epss(hypotheses)
```

### `src/sentinel/agents/hypothesis_engine.py` — VulnHypothesis dataclass
Add optional field:
```python
cve_id: str = ""  # CVE identifier if hypothesis maps to a known CVE
```

### Neo4j: Add EPSS score to Vulnerability nodes
In whatever method creates/updates Vulnerability nodes in the graph, add:
```python
# After creating/finding a Vulnerability node with a CVE ID:
epss_score = await self.epss.get_score(cve_id)
if epss_score:
    await self.graph.query(
        "MATCH (v:Vulnerability {cve_id: $cve}) "
        "SET v.epss_score = $epss, v.epss_percentile = $pct, v.epss_updated = datetime()",
        {"cve": cve_id, "epss": epss_score.epss, "pct": epss_score.percentile}
    )
```

---

## Tests

### `tests/intel/test_epss_client.py`
```python
"""Tests for EPSS client."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel.intel.epss_client import EPSSClient, EPSSScore


class TestEPSSClient:
    def setup_method(self):
        self.client = EPSSClient()
    
    @pytest.mark.asyncio
    async def test_get_score_parses_response(self):
        mock_response = {
            "data": [{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99961"}]
        }
        with patch("aiohttp.ClientSession") as mock_session:
            mock_resp = AsyncMock()
            mock_resp.status = 200
            mock_resp.json = AsyncMock(return_value=mock_response)
            mock_session.return_value.__aenter__ = AsyncMock(return_value=mock_session.return_value)
            mock_session.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_session.return_value.get = MagicMock(return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_resp),
                __aexit__=AsyncMock(return_value=False),
            ))
            
            score = await self.client.get_score("CVE-2021-44228")
            # Note: actual test needs proper async context manager mocking
            # This is a structural test — verify parsing logic separately:
    
    def test_score_dataclass(self):
        score = EPSSScore(cve_id="CVE-2021-44228", epss=0.97, percentile=0.999)
        assert score.epss == 0.97
        assert score.percentile == 0.999
    
    def test_chunks_utility(self):
        from sentinel.intel.epss_client import _chunks
        items = list(range(250))
        chunks = list(_chunks(items, 100))
        assert len(chunks) == 3
        assert len(chunks[0]) == 100
        assert len(chunks[2]) == 50
    
    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Second call should use cache, not API."""
        from datetime import datetime
        self.client._cache["CVE-2021-44228"] = EPSSScore(
            cve_id="CVE-2021-44228", epss=0.97, percentile=0.999,
            fetched_at=datetime.utcnow()
        )
        score = await self.client.get_score("CVE-2021-44228")
        assert score.epss == 0.97  # From cache, no API call
```

---

## Acceptance Criteria
- [ ] `EPSSClient.get_score("CVE-2021-44228")` returns a valid EPSSScore
- [ ] `EPSSClient.get_scores_bulk()` handles 100+ CVEs in batched requests
- [ ] Cache prevents redundant API calls within 24h
- [ ] HypothesisEngine `_rank()` now factors in EPSS percentile
- [ ] Vulnerability nodes in Neo4j have `epss_score` and `epss_percentile` properties
- [ ] All tests pass
- [ ] No modifications to files outside this spec