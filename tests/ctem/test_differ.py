"""Tests for CTEM Diff Engine."""

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock

from sentinel.ctem.snapshot import GraphSnapshot, SnapshotCapture
from sentinel.ctem.differ import CTEMDiffer


def _make_snapshot(sid, nodes, edges, metrics=None):
    return GraphSnapshot(
        snapshot_id=sid,
        engagement_id="eng-1",
        timestamp=datetime.now(timezone.utc),
        nodes=nodes,
        edges=edges,
        metrics=metrics or {"total_vulns": len(nodes)},
    )


class TestGraphSnapshot:
    def test_roundtrip_json(self):
        snap = _make_snapshot(
            "s1",
            {"a": {"type": "Host", "properties": {"ip": "10.0.0.1"}}},
            [{"source": "a", "target": "b", "type": "HAS_PORT", "properties": {}}],
            {"total_vulns": 5, "total_nodes": 2},
        )
        json_str = snap.to_json()
        restored = GraphSnapshot.from_json(json_str)
        assert restored.snapshot_id == "s1"
        assert restored.nodes["a"]["type"] == "Host"
        assert len(restored.edges) == 1
        assert restored.metrics["total_vulns"] == 5


class TestSnapshotCapture:
    @pytest.mark.asyncio
    async def test_capture_exports_nodes_and_edges(self):
        mock_client = AsyncMock()
        mock_client.query.side_effect = [
            # _export_nodes
            [
                {"id": "h1", "type": "Host", "props": {"ip": "10.0.0.1", "engagement_id": "eng-1"}},
                {"id": "v1", "type": "Vulnerability", "props": {"severity": "high", "engagement_id": "eng-1"}},
            ],
            # _export_edges
            [
                {"source": "h1", "target": "v1", "rel_type": "HAS_VULNERABILITY", "props": {}},
            ],
        ]
        capture = SnapshotCapture(mock_client)
        snap = await capture.capture("eng-1")
        assert len(snap.nodes) == 2
        assert len(snap.edges) == 1
        assert snap.metrics["total_vulns"] == 1
        assert snap.metrics["unique_hosts"] == 1
        # engagement_id stripped from properties
        assert "engagement_id" not in snap.nodes["h1"]["properties"]


class TestCTEMDiffer:
    def test_new_node_detected(self):
        old = _make_snapshot("s1", {"a": {"type": "Host", "properties": {}}}, [])
        new = _make_snapshot("s2", {
            "a": {"type": "Host", "properties": {}},
            "b": {"type": "Vulnerability", "properties": {"severity": "high"}},
        }, [])
        diff = CTEMDiffer().diff(old, new)
        assert len(diff.new_nodes) == 1
        assert diff.new_nodes[0]["id"] == "b"

    def test_removed_node_detected(self):
        old = _make_snapshot("s1", {
            "a": {"type": "Host", "properties": {}},
            "b": {"type": "Vulnerability", "properties": {}},
        }, [])
        new = _make_snapshot("s2", {"a": {"type": "Host", "properties": {}}}, [])
        diff = CTEMDiffer().diff(old, new)
        assert len(diff.removed_nodes) == 1
        assert diff.removed_nodes[0]["id"] == "b"

    def test_persistent_nodes_tracked(self):
        old = _make_snapshot("s1", {
            "a": {"type": "Host", "properties": {}},
            "b": {"type": "Service", "properties": {}},
        }, [])
        new = _make_snapshot("s2", {
            "a": {"type": "Host", "properties": {}},
            "b": {"type": "Service", "properties": {}},
        }, [])
        diff = CTEMDiffer().diff(old, new)
        assert len(diff.persistent_nodes) == 2
        assert set(diff.persistent_nodes) == {"a", "b"}

    def test_regression_detected(self):
        differ = CTEMDiffer()
        s1 = _make_snapshot("s1", {
            "a": {"type": "Host", "properties": {}},
            "v1": {"type": "Vulnerability", "properties": {}},
        }, [])
        s2 = _make_snapshot("s2", {"a": {"type": "Host", "properties": {}}}, [])
        differ.diff(s1, s2)  # v1 removed, tracked in history

        s3 = _make_snapshot("s3", {
            "a": {"type": "Host", "properties": {}},
            "v1": {"type": "Vulnerability", "properties": {}},
        }, [])
        diff = differ.diff(s2, s3)  # v1 back!
        assert len(diff.regression_nodes) == 1
        assert diff.regression_nodes[0]["regression"] is True
        assert "previously_removed_at" in diff.regression_nodes[0]

    def test_edge_diff(self):
        old = _make_snapshot("s1", {"a": {}, "b": {}}, [
            {"source": "a", "target": "b", "type": "HAS_PORT", "properties": {}},
        ])
        new = _make_snapshot("s2", {"a": {}, "b": {}, "c": {}}, [
            {"source": "a", "target": "b", "type": "HAS_PORT", "properties": {}},
            {"source": "b", "target": "c", "type": "RUNS_SERVICE", "properties": {}},
        ])
        diff = CTEMDiffer().diff(old, new)
        assert len(diff.new_edges) == 1
        assert diff.new_edges[0]["type"] == "RUNS_SERVICE"
        assert len(diff.removed_edges) == 0

    def test_metric_deltas(self):
        old = _make_snapshot("s1", {}, [], {"total_vulns": 10, "total_nodes": 20})
        new = _make_snapshot("s2", {}, [], {"total_vulns": 7, "total_nodes": 18})
        diff = CTEMDiffer().diff(old, new)
        assert diff.metric_deltas["total_vulns"]["delta"] == -3
        assert diff.metric_deltas["total_nodes"]["delta"] == -2

    def test_summary_resolved(self):
        old = _make_snapshot("s1", {}, [], {"total_vulns": 10})
        new = _make_snapshot("s2", {}, [], {"total_vulns": 7})
        diff = CTEMDiffer().diff(old, new)
        assert "3" in diff.summary
        assert "resolved" in diff.summary.lower()

    def test_summary_no_changes(self):
        s = _make_snapshot("s1", {"a": {"type": "Host", "properties": {}}}, [])
        diff = CTEMDiffer().diff(s, s)
        assert "unchanged" in diff.summary.lower() or "no significant" in diff.summary.lower()
