"""Tests for Knowledge Graph Risk Analytics."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.graph.analytics import GraphAnalytics, AttackPath, RiskAnalysisResult


class TestAttackPath:
    def test_dataclass_fields(self):
        path = AttackPath(
            source="host_1", target="db_1", hops=3,
            nodes=["host_1", "svc_1", "endpoint_1", "db_1"],
            edges=["HAS_PORT", "RUNS_SERVICE", "CONNECTS_TO"],
            probability=0.7, risk_score=8.5,
        )
        assert path.hops == 3
        assert len(path.nodes) == 4
        assert len(path.edges) == 3
        assert path.source == "host_1"
        assert path.target == "db_1"

    def test_risk_formula_concept(self):
        """Verify risk scoring logic: EPSS x severity x reachability."""
        epss = 0.9
        severity = 9.0 / 10.0
        distance = 2
        reachability = 1.0 / (distance + 1)
        risk = epss * severity * reachability
        assert 0.2 < risk < 0.4


class TestGraphAnalytics:
    def setup_method(self):
        self.mock_client = AsyncMock()
        self.analytics = GraphAnalytics(self.mock_client)

    @pytest.mark.asyncio
    async def test_detect_crown_jewels(self):
        """Crown jewel detection queries for critical assets."""
        self.mock_client.query.return_value = [
            {"id": "db-node-1"},
            {"id": "admin-node-2"},
        ]
        result = await self.analytics._detect_crown_jewels("eng-1")
        assert len(result) == 2
        assert "db-node-1" in result
        self.mock_client.query.assert_called_once()

    @pytest.mark.asyncio
    async def test_find_attack_paths_with_explicit_targets(self):
        """Attack paths query uses explicit crown jewel IDs."""
        self.mock_client.query.return_value = [
            {
                "node_ids": ["host-1", "svc-1", "db-1"],
                "edge_types": ["HAS_PORT", "CONNECTS_TO"],
                "hops": 2,
            }
        ]
        paths = await self.analytics._find_attack_paths("eng-1", ["db-1"])
        assert len(paths) == 1
        assert paths[0].target == "db-1"
        assert paths[0].hops == 2

    @pytest.mark.asyncio
    async def test_find_attack_paths_empty_when_no_crown_jewels(self):
        """No paths returned if no crown jewels detected."""
        # First call: _detect_crown_jewels returns empty
        self.mock_client.query.return_value = []
        paths = await self.analytics._find_attack_paths("eng-1", [])
        assert paths == []

    @pytest.mark.asyncio
    async def test_summary_stats(self):
        """Summary stats aggregates node counts by type."""
        self.mock_client.query.side_effect = [
            # First call: node type counts
            [{"type": "Host", "cnt": 5}, {"type": "Vulnerability", "cnt": 12}],
            # Second call: path count
            [{"total_paths": 3}],
        ]
        stats = await self.analytics._summary_stats("eng-1")
        assert stats["Host"] == 5
        assert stats["Vulnerability"] == 12
        assert stats["total_attack_paths"] == 3

    @pytest.mark.asyncio
    async def test_full_analysis_calls_all_stages(self):
        """Full analysis orchestrates project -> algorithms -> drop."""
        self.mock_client.query.return_value = []
        result = await self.analytics.full_analysis("eng-1")
        assert isinstance(result, RiskAnalysisResult)
        assert result.engagement_id == "eng-1"
        # Should have called query multiple times (project, pagerank, betweenness,
        # louvain, detect_crown_jewels, risk_scores, summary_stats x2, drop)
        assert self.mock_client.query.call_count >= 7

    @pytest.mark.asyncio
    async def test_drop_projection_swallows_errors(self):
        """Drop projection does not raise on failure."""
        self.mock_client.query.side_effect = Exception("not found")
        # Should not raise
        await self.analytics._drop_projection("nonexistent_graph")
