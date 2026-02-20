"""Tests for EPSS integration with HypothesisEngine."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from sentinel.agents.hypothesis_engine import (
    HypothesisEngine,
    VulnHypothesis,
    HypothesisCategory,
    HypothesisConfidence,
)
from sentinel.intel.epss_client import EPSSScore


class TestHypothesisEPSSIntegration:
    def _make_hypothesis(self, cve_id: str = "", priority: float = 0.5, category=HypothesisCategory.INJECTION):
        return VulnHypothesis(
            id="test-id",
            category=category,
            confidence=HypothesisConfidence.MEDIUM,
            target_url="http://localhost:3000/api",
            target_param="q",
            description="Test hypothesis",
            rationale="Test",
            test_plan=["step1"],
            required_tools=["nuclei_scan"],
            expected_evidence="error",
            risk_level="HIGH",
            priority_score=priority,
            cve_id=cve_id,
        )

    @pytest.mark.asyncio
    async def test_enrich_boosts_high_epss(self):
        """Hypotheses with high-EPSS CVEs should get priority boost."""
        mock_graph = AsyncMock()
        engine = HypothesisEngine(mock_graph)

        h1 = self._make_hypothesis(cve_id="CVE-2021-44228", priority=0.5)
        h2 = self._make_hypothesis(cve_id="", priority=0.6)

        with patch.object(engine.epss, "get_scores_bulk", new_callable=AsyncMock) as mock_bulk:
            mock_bulk.return_value = {
                "CVE-2021-44228": EPSSScore(cve_id="CVE-2021-44228", epss=0.975, percentile=0.999)
            }

            result = await engine._enrich_with_epss([h1, h2])

            # h1 should be boosted: 0.5 * (1 + 0.999) = ~0.9995
            assert result[0].cve_id == "CVE-2021-44228"
            assert result[0].priority_score == pytest.approx(0.5 * (1 + 0.999))
            # h2 should remain unchanged
            assert result[1].priority_score == 0.6

    @pytest.mark.asyncio
    async def test_enrich_no_cve_ids(self):
        """Without CVE IDs, enrichment is a no-op."""
        mock_graph = AsyncMock()
        engine = HypothesisEngine(mock_graph)

        h1 = self._make_hypothesis(priority=0.5)
        h2 = self._make_hypothesis(priority=0.6)

        result = await engine._enrich_with_epss([h1, h2])
        # Should return in same order, unchanged
        assert result[0].priority_score == 0.5
        assert result[1].priority_score == 0.6

    @pytest.mark.asyncio
    async def test_enrich_handles_api_failure(self):
        """If EPSS API fails, enrichment should not crash."""
        mock_graph = AsyncMock()
        engine = HypothesisEngine(mock_graph)

        h1 = self._make_hypothesis(cve_id="CVE-2021-44228", priority=0.5)

        with patch.object(engine.epss, "get_scores_bulk", new_callable=AsyncMock) as mock_bulk:
            mock_bulk.side_effect = Exception("Network error")

            result = await engine._enrich_with_epss([h1])
            # Should return unchanged
            assert result[0].priority_score == 0.5

    @pytest.mark.asyncio
    async def test_enrich_reorders_by_epss(self):
        """Low-priority hypothesis with high EPSS should jump above high-priority without EPSS."""
        mock_graph = AsyncMock()
        engine = HypothesisEngine(mock_graph)

        h_low = self._make_hypothesis(cve_id="CVE-HIGH-EPSS", priority=0.3)
        h_high = self._make_hypothesis(cve_id="", priority=0.5)

        with patch.object(engine.epss, "get_scores_bulk", new_callable=AsyncMock) as mock_bulk:
            mock_bulk.return_value = {
                "CVE-HIGH-EPSS": EPSSScore(cve_id="CVE-HIGH-EPSS", epss=0.95, percentile=0.99)
            }

            result = await engine._enrich_with_epss([h_low, h_high])

            # h_low boosted: 0.3 * (1 + 0.99) = 0.597 > h_high 0.5
            assert result[0].cve_id == "CVE-HIGH-EPSS"
            assert result[0].priority_score > result[1].priority_score

    def test_hypothesis_has_cve_id_field(self):
        """VulnHypothesis should have cve_id field."""
        h = self._make_hypothesis(cve_id="CVE-2023-1234")
        assert h.cve_id == "CVE-2023-1234"

    def test_hypothesis_cve_id_default_empty(self):
        """cve_id should default to empty string."""
        h = self._make_hypothesis()
        assert h.cve_id == ""

    def test_engine_has_epss_client(self):
        """HypothesisEngine should have an EPSS client."""
        mock_graph = AsyncMock()
        engine = HypothesisEngine(mock_graph)
        from sentinel.intel.epss_client import EPSSClient
        assert isinstance(engine.epss, EPSSClient)
