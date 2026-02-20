"""Tests for EPSS client."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta, timezone
from sentinel.intel.epss_client import EPSSClient, EPSSScore, _chunks


class TestEPSSScore:
    def test_score_dataclass(self):
        score = EPSSScore(cve_id="CVE-2021-44228", epss=0.97, percentile=0.999)
        assert score.cve_id == "CVE-2021-44228"
        assert score.epss == 0.97
        assert score.percentile == 0.999
        assert score.fetched_at is not None

    def test_score_defaults(self):
        score = EPSSScore(cve_id="CVE-2023-0001", epss=0.5, percentile=0.5)
        assert isinstance(score.fetched_at, datetime)


class TestChunksUtility:
    def test_chunks_splits_evenly(self):
        items = list(range(200))
        chunks = list(_chunks(items, 100))
        assert len(chunks) == 2
        assert len(chunks[0]) == 100
        assert len(chunks[1]) == 100

    def test_chunks_handles_remainder(self):
        items = list(range(250))
        chunks = list(_chunks(items, 100))
        assert len(chunks) == 3
        assert len(chunks[0]) == 100
        assert len(chunks[2]) == 50

    def test_chunks_empty_list(self):
        chunks = list(_chunks([], 100))
        assert chunks == []

    def test_chunks_smaller_than_n(self):
        items = list(range(5))
        chunks = list(_chunks(items, 100))
        assert len(chunks) == 1
        assert len(chunks[0]) == 5


class TestEPSSClient:
    def setup_method(self):
        self.client = EPSSClient()

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Second call should use cache, not API."""
        self.client._cache["CVE-2021-44228"] = EPSSScore(
            cve_id="CVE-2021-44228",
            epss=0.97,
            percentile=0.999,
            fetched_at=datetime.now(timezone.utc),
        )
        score = await self.client.get_score("CVE-2021-44228")
        assert score is not None
        assert score.epss == 0.97
        assert score.percentile == 0.999

    @pytest.mark.asyncio
    async def test_cache_expiry(self):
        """Stale cache should be ignored."""
        self.client._cache["CVE-2021-44228"] = EPSSScore(
            cve_id="CVE-2021-44228",
            epss=0.5,
            percentile=0.5,
            fetched_at=datetime.now(timezone.utc) - timedelta(hours=25),
        )
        # With expired cache and no mock API, should return None (API unreachable in test)
        with patch("sentinel.intel.epss_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": [{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99961"}]
            }
            mock_client.get = AsyncMock(return_value=mock_resp)

            score = await self.client.get_score("CVE-2021-44228")
            assert score is not None
            assert score.epss == pytest.approx(0.97565)
            assert score.percentile == pytest.approx(0.99961)

    @pytest.mark.asyncio
    async def test_get_score_api_success(self):
        """Should parse API response correctly."""
        with patch("sentinel.intel.epss_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": [{"cve": "CVE-2023-1234", "epss": "0.42", "percentile": "0.88"}]
            }
            mock_client.get = AsyncMock(return_value=mock_resp)

            score = await self.client.get_score("CVE-2023-1234")
            assert score is not None
            assert score.cve_id == "CVE-2023-1234"
            assert score.epss == pytest.approx(0.42)
            assert score.percentile == pytest.approx(0.88)
            # Should be cached now
            assert "CVE-2023-1234" in self.client._cache

    @pytest.mark.asyncio
    async def test_get_score_api_404(self):
        """Should return None on API error."""
        with patch("sentinel.intel.epss_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_client.get = AsyncMock(return_value=mock_resp)

            score = await self.client.get_score("CVE-9999-0000")
            assert score is None

    @pytest.mark.asyncio
    async def test_get_score_empty_data(self):
        """Should return None when API returns no data."""
        with patch("sentinel.intel.epss_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"data": []}
            mock_client.get = AsyncMock(return_value=mock_resp)

            score = await self.client.get_score("CVE-0000-0000")
            assert score is None

    @pytest.mark.asyncio
    async def test_get_score_network_error(self):
        """Should return None on network error."""
        with patch("sentinel.intel.epss_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
            mock_client.get = AsyncMock(side_effect=Exception("Connection refused"))

            score = await self.client.get_score("CVE-2021-44228")
            assert score is None

    @pytest.mark.asyncio
    async def test_get_scores_bulk_with_cache(self):
        """Bulk fetch should use cache for already-fetched CVEs."""
        self.client._cache["CVE-2021-44228"] = EPSSScore(
            cve_id="CVE-2021-44228",
            epss=0.97,
            percentile=0.999,
            fetched_at=datetime.now(timezone.utc),
        )

        with patch("sentinel.intel.epss_client.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": [{"cve": "CVE-2023-5678", "epss": "0.1", "percentile": "0.3"}]
            }
            mock_client.get = AsyncMock(return_value=mock_resp)

            scores = await self.client.get_scores_bulk(["CVE-2021-44228", "CVE-2023-5678"])
            assert "CVE-2021-44228" in scores
            assert scores["CVE-2021-44228"].epss == 0.97  # From cache
            assert "CVE-2023-5678" in scores
            assert scores["CVE-2023-5678"].epss == pytest.approx(0.1)  # From API

    @pytest.mark.asyncio
    async def test_get_scores_bulk_empty_list(self):
        """Bulk fetch with empty list should return empty dict."""
        result = await self.client.get_scores_bulk([])
        assert result == {}

    @pytest.mark.asyncio
    async def test_get_scores_bulk_all_cached(self):
        """When all CVEs are cached, no API call should be made."""
        self.client._cache["CVE-A"] = EPSSScore(
            cve_id="CVE-A", epss=0.1, percentile=0.2,
            fetched_at=datetime.now(timezone.utc),
        )
        self.client._cache["CVE-B"] = EPSSScore(
            cve_id="CVE-B", epss=0.3, percentile=0.4,
            fetched_at=datetime.now(timezone.utc),
        )

        # No mock needed since all cached
        scores = await self.client.get_scores_bulk(["CVE-A", "CVE-B"])
        assert len(scores) == 2
        assert scores["CVE-A"].epss == 0.1
        assert scores["CVE-B"].epss == 0.3
