# LEVEL 17: CTEM Diff Engine (Continuous Threat Exposure Management)

## Context
Run Sentinel against the same target over time. This level snapshots the attack graph after each run and diffs across runs to show: new attack paths, closed paths, regressions (re-introduced vulns), and fix verification. Implements the Gartner CTEM cycle: Scope→Discover→Prioritize→Validate→Mobilize.

Research: Block 4 (CTEM diffing, NodeZero tracking metrics). Simple ID-based diff is O(V+E).

**Requires:** L16 (Graph Analytics) for risk scores and attack paths.

## Why
Single-shot pentests are snapshots. CTEM shows progress over time. CISOs need: "Last month we had 12 attack paths to the DB, now we have 4." NodeZero does exactly this. Essential for enterprise recurring engagements.

---

## Files to Create

### `src/sentinel/ctem/__init__.py`
```python
"""Continuous Threat Exposure Management — snapshots, diffing, trend tracking."""
```

### `src/sentinel/ctem/snapshot.py`
```python
"""
Attack Graph Snapshot.

Captures the full state of the knowledge graph at a point in time:
- All nodes (Host, Service, Endpoint, Vulnerability, Finding) with properties
- All edges (relationships) with types
- Computed metrics (risk scores, attack path count, etc.)

Snapshots are stored in Postgres (JSONB) for efficient diffing.
"""
import json
from dataclasses import dataclass, field
from datetime import datetime
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class GraphSnapshot:
    snapshot_id: str
    engagement_id: str
    timestamp: datetime
    nodes: dict[str, dict]       # node_id → {type, properties}
    edges: list[dict]            # [{source, target, type, properties}]
    metrics: dict                # {total_vulns, critical_count, attack_paths, etc.}
    
    def to_json(self) -> str:
        return json.dumps({
            "snapshot_id": self.snapshot_id,
            "engagement_id": self.engagement_id,
            "timestamp": self.timestamp.isoformat(),
            "nodes": self.nodes,
            "edges": self.edges,
            "metrics": self.metrics,
        })
    
    @classmethod
    def from_json(cls, data: str) -> "GraphSnapshot":
        d = json.loads(data)
        return cls(
            snapshot_id=d["snapshot_id"],
            engagement_id=d["engagement_id"],
            timestamp=datetime.fromisoformat(d["timestamp"]),
            nodes=d["nodes"],
            edges=d["edges"],
            metrics=d["metrics"],
        )


class SnapshotCapture:
    """Capture a snapshot of the current knowledge graph state."""
    
    def __init__(self, neo4j_driver, pg_pool=None):
        self.neo4j = neo4j_driver
        self.pg_pool = pg_pool  # For persistent snapshot storage
    
    async def capture(self, engagement_id: str) -> GraphSnapshot:
        """Capture current graph state as a snapshot."""
        import uuid
        
        nodes = await self._export_nodes(engagement_id)
        edges = await self._export_edges(engagement_id)
        metrics = await self._compute_metrics(engagement_id, nodes, edges)
        
        snapshot = GraphSnapshot(
            snapshot_id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            timestamp=datetime.utcnow(),
            nodes=nodes,
            edges=edges,
            metrics=metrics,
        )
        
        # Persist to Postgres
        if self.pg_pool:
            await self._store(snapshot)
        
        logger.info(
            f"Snapshot {snapshot.snapshot_id}: "
            f"{len(nodes)} nodes, {len(edges)} edges, "
            f"{metrics.get('total_vulns', 0)} vulns"
        )
        return snapshot
    
    async def _export_nodes(self, engagement_id: str) -> dict[str, dict]:
        """Export all nodes for this engagement."""
        query = """
        MATCH (n {engagement_id: $eid})
        RETURN n.id AS id, labels(n)[0] AS type, properties(n) AS props
        """
        nodes = {}
        async with self.neo4j.session() as session:
            result = await session.run(query, {"eid": engagement_id})
            async for record in result:
                node_id = record["id"]
                props = dict(record["props"])
                props.pop("engagement_id", None)  # Don't duplicate
                nodes[node_id] = {"type": record["type"], "properties": props}
        return nodes
    
    async def _export_edges(self, engagement_id: str) -> list[dict]:
        """Export all edges for this engagement."""
        query = """
        MATCH (a {engagement_id: $eid})-[r]->(b {engagement_id: $eid})
        RETURN a.id AS source, b.id AS target, type(r) AS rel_type,
               properties(r) AS props
        """
        edges = []
        async with self.neo4j.session() as session:
            result = await session.run(query, {"eid": engagement_id})
            async for record in result:
                edges.append({
                    "source": record["source"],
                    "target": record["target"],
                    "type": record["rel_type"],
                    "properties": dict(record["props"]) if record["props"] else {},
                })
        return edges
    
    async def _compute_metrics(self, eid: str, nodes: dict, edges: list) -> dict:
        """Compute summary metrics for the snapshot."""
        vuln_nodes = [n for n in nodes.values() if n["type"] in ("Vulnerability", "Finding")]
        severity_counts = {}
        for v in vuln_nodes:
            sev = v["properties"].get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        
        return {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "total_vulns": len(vuln_nodes),
            "by_severity": severity_counts,
            "unique_hosts": sum(1 for n in nodes.values() if n["type"] == "Host"),
            "unique_endpoints": sum(1 for n in nodes.values() if n["type"] == "Endpoint"),
        }
    
    async def _store(self, snapshot: GraphSnapshot):
        """Store snapshot in Postgres."""
        async with self.pg_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO ctem_snapshots (id, engagement_id, timestamp, data)
                   VALUES ($1, $2, $3, $4)""",
                snapshot.snapshot_id, snapshot.engagement_id,
                snapshot.timestamp, snapshot.to_json(),
            )
    
    async def load_latest(self, engagement_id: str, n: int = 2) -> list[GraphSnapshot]:
        """Load the N most recent snapshots for an engagement."""
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT data FROM ctem_snapshots
                   WHERE engagement_id = $1
                   ORDER BY timestamp DESC LIMIT $2""",
                engagement_id, n,
            )
            return [GraphSnapshot.from_json(row["data"]) for row in rows]
```

### `src/sentinel/ctem/differ.py`
```python
"""
CTEM Diff Engine — Compares two snapshots to show changes.

Outputs:
- New nodes/edges (appeared since last scan)
- Removed nodes/edges (fixed/closed)
- Persistent nodes (still present)
- Regressions (was removed, now back — flagged with regression:true)
- Metric deltas (vuln count change, severity shifts, path count change)
"""
from dataclasses import dataclass, field
from sentinel.ctem.snapshot import GraphSnapshot
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DiffResult:
    old_snapshot_id: str
    new_snapshot_id: str
    engagement_id: str
    
    new_nodes: list[dict]         # Appeared since last scan
    removed_nodes: list[dict]     # Fixed/closed since last scan
    persistent_nodes: list[str]   # Still present (node IDs)
    regression_nodes: list[dict]  # Were removed, now back
    
    new_edges: list[dict]
    removed_edges: list[dict]
    
    metric_deltas: dict           # {metric_name: {old: X, new: Y, delta: Z}}
    
    summary: str                  # Human-readable summary


class CTEMDiffer:
    """Diff two attack graph snapshots."""
    
    def __init__(self, regression_history: dict = None):
        # Track node IDs that were previously removed (for regression detection)
        self._removal_history = regression_history or {}
    
    def diff(self, old: GraphSnapshot, new: GraphSnapshot) -> DiffResult:
        """Compare two snapshots and produce a diff."""
        old_node_ids = set(old.nodes.keys())
        new_node_ids = set(new.nodes.keys())
        
        # Node diff
        added_ids = new_node_ids - old_node_ids
        removed_ids = old_node_ids - new_node_ids
        persistent_ids = old_node_ids & new_node_ids
        
        new_nodes = [
            {"id": nid, **new.nodes[nid]}
            for nid in added_ids
        ]
        removed_nodes = [
            {"id": nid, **old.nodes[nid]}
            for nid in removed_ids
        ]
        
        # Regression detection
        regressions = []
        for nid in added_ids:
            if nid in self._removal_history:
                node_data = {"id": nid, **new.nodes[nid], "regression": True}
                node_data["previously_removed_at"] = self._removal_history[nid]
                regressions.append(node_data)
        
        # Update removal history
        for nid in removed_ids:
            self._removal_history[nid] = new.timestamp.isoformat()
        
        # Edge diff
        old_edge_set = self._edge_set(old.edges)
        new_edge_set = self._edge_set(new.edges)
        
        new_edges = [e for e in new.edges if self._edge_key(e) in (new_edge_set - old_edge_set)]
        removed_edges = [e for e in old.edges if self._edge_key(e) in (old_edge_set - new_edge_set)]
        
        # Metric deltas
        deltas = {}
        all_metric_keys = set(old.metrics.keys()) | set(new.metrics.keys())
        for key in all_metric_keys:
            old_val = old.metrics.get(key, 0)
            new_val = new.metrics.get(key, 0)
            if isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
                deltas[key] = {"old": old_val, "new": new_val, "delta": new_val - old_val}
        
        # Summary
        summary = self._generate_summary(
            new_nodes, removed_nodes, regressions, deltas
        )
        
        result = DiffResult(
            old_snapshot_id=old.snapshot_id,
            new_snapshot_id=new.snapshot_id,
            engagement_id=new.engagement_id,
            new_nodes=new_nodes,
            removed_nodes=removed_nodes,
            persistent_nodes=list(persistent_ids),
            regression_nodes=regressions,
            new_edges=new_edges,
            removed_edges=removed_edges,
            metric_deltas=deltas,
            summary=summary,
        )
        
        logger.info(
            f"CTEM diff: +{len(new_nodes)} nodes, -{len(removed_nodes)} nodes, "
            f"{len(regressions)} regressions"
        )
        return result
    
    def _edge_set(self, edges: list[dict]) -> set:
        return {self._edge_key(e) for e in edges}
    
    def _edge_key(self, edge: dict) -> str:
        return f"{edge['source']}--{edge['type']}-->{edge['target']}"
    
    def _generate_summary(self, new_nodes, removed_nodes, regressions, deltas) -> str:
        parts = []
        
        vuln_delta = deltas.get("total_vulns", {})
        if vuln_delta:
            d = vuln_delta["delta"]
            if d > 0:
                parts.append(f"⚠ {d} new vulnerabilities discovered.")
            elif d < 0:
                parts.append(f"✅ {abs(d)} vulnerabilities resolved.")
            else:
                parts.append(f"Vulnerability count unchanged ({vuln_delta['new']}).")
        
        if regressions:
            parts.append(f"🔴 {len(regressions)} REGRESSIONS — previously fixed vulnerabilities have returned.")
        
        new_vulns = [n for n in new_nodes if n.get("type") in ("Vulnerability", "Finding")]
        if new_vulns:
            critical = sum(1 for n in new_vulns if n.get("properties", {}).get("severity") == "critical")
            if critical:
                parts.append(f"🚨 {critical} new CRITICAL vulnerabilities.")
        
        removed_vulns = [n for n in removed_nodes if n.get("type") in ("Vulnerability", "Finding")]
        if removed_vulns:
            parts.append(f"Fixed: {len(removed_vulns)} vulnerabilities no longer present.")
        
        return " ".join(parts) if parts else "No significant changes detected."
```

---

## Database Migration
```sql
CREATE TABLE ctem_snapshots (
    id UUID PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL
);
CREATE INDEX idx_ctem_engagement ON ctem_snapshots(engagement_id, timestamp DESC);
```

## API Endpoints
```python
@app.post("/api/v1/engagements/{eid}/snapshot")
async def capture_snapshot(eid: str): ...

@app.get("/api/v1/engagements/{eid}/diff")
async def get_diff(eid: str): ...  # Diffs latest 2 snapshots

@app.get("/api/v1/engagements/{eid}/trend")
async def get_trend(eid: str, count: int = 10): ...  # Metric trend over N snapshots
```

## Tests

### `tests/ctem/test_differ.py`
```python
import pytest
from datetime import datetime
from sentinel.ctem.snapshot import GraphSnapshot
from sentinel.ctem.differ import CTEMDiffer

class TestCTEMDiffer:
    def _make_snapshot(self, sid, nodes, edges, metrics=None):
        return GraphSnapshot(
            snapshot_id=sid, engagement_id="eng-1",
            timestamp=datetime.utcnow(),
            nodes=nodes, edges=edges,
            metrics=metrics or {"total_vulns": len(nodes)},
        )
    
    def test_new_node_detected(self):
        old = self._make_snapshot("s1", {"a": {"type": "Host", "properties": {}}}, [])
        new = self._make_snapshot("s2", {
            "a": {"type": "Host", "properties": {}},
            "b": {"type": "Vulnerability", "properties": {"severity": "high"}},
        }, [])
        diff = CTEMDiffer().diff(old, new)
        assert len(diff.new_nodes) == 1
        assert diff.new_nodes[0]["id"] == "b"
    
    def test_removed_node_detected(self):
        old = self._make_snapshot("s1", {
            "a": {"type": "Host", "properties": {}},
            "b": {"type": "Vulnerability", "properties": {}},
        }, [])
        new = self._make_snapshot("s2", {"a": {"type": "Host", "properties": {}}}, [])
        diff = CTEMDiffer().diff(old, new)
        assert len(diff.removed_nodes) == 1
        assert diff.removed_nodes[0]["id"] == "b"
    
    def test_regression_detected(self):
        differ = CTEMDiffer()
        s1 = self._make_snapshot("s1", {"a": {}, "v1": {"type": "Vulnerability", "properties": {}}}, [])
        s2 = self._make_snapshot("s2", {"a": {}}, [])
        differ.diff(s1, s2)  # v1 removed, tracked in history
        
        s3 = self._make_snapshot("s3", {"a": {}, "v1": {"type": "Vulnerability", "properties": {}}}, [])
        diff = differ.diff(s2, s3)  # v1 back!
        assert len(diff.regression_nodes) == 1
        assert diff.regression_nodes[0]["regression"] is True
    
    def test_metric_deltas(self):
        old = self._make_snapshot("s1", {}, [], {"total_vulns": 10})
        new = self._make_snapshot("s2", {}, [], {"total_vulns": 7})
        diff = CTEMDiffer().diff(old, new)
        assert diff.metric_deltas["total_vulns"]["delta"] == -3
    
    def test_summary_text(self):
        old = self._make_snapshot("s1", {}, [], {"total_vulns": 10})
        new = self._make_snapshot("s2", {}, [], {"total_vulns": 7})
        diff = CTEMDiffer().diff(old, new)
        assert "resolved" in diff.summary.lower() or "3" in diff.summary
```

---

## Acceptance Criteria
- [ ] Snapshots capture full graph state (nodes, edges, metrics)
- [ ] Snapshots stored in Postgres JSONB
- [ ] Differ detects new, removed, and persistent nodes/edges
- [ ] Regressions flagged when previously-removed vulns reappear
- [ ] Metric deltas calculated (vuln count change, severity shifts)
- [ ] Human-readable summary generated
- [ ] All tests pass