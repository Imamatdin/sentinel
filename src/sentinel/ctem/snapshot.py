"""
Attack Graph Snapshot.

Captures the full state of the knowledge graph at a point in time:
- All nodes (Host, Service, Endpoint, Vulnerability) with properties
- All edges (relationships) with types
- Computed metrics (risk scores, attack path count, etc.)

Snapshots are stored in Postgres (JSONB) for efficient diffing.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinel.core import get_logger
from sentinel.graph.neo4j_client import Neo4jClient

logger = get_logger(__name__)


@dataclass
class GraphSnapshot:
    snapshot_id: str
    engagement_id: str
    timestamp: datetime
    nodes: dict[str, dict[str, Any]]   # node_id -> {type, properties}
    edges: list[dict[str, Any]]        # [{source, target, type, properties}]
    metrics: dict[str, Any]            # {total_vulns, critical_count, etc.}

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

    def __init__(self, graph_client: Neo4jClient, pg_pool: Any = None):
        self.client = graph_client
        self.pg_pool = pg_pool

    async def capture(self, engagement_id: str) -> GraphSnapshot:
        """Capture current graph state as a snapshot."""
        nodes = await self._export_nodes(engagement_id)
        edges = await self._export_edges(engagement_id)
        metrics = self._compute_metrics(nodes, edges)

        snapshot = GraphSnapshot(
            snapshot_id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            timestamp=datetime.now(timezone.utc),
            nodes=nodes,
            edges=edges,
            metrics=metrics,
        )

        if self.pg_pool:
            await self._store(snapshot)

        logger.info(
            "snapshot_captured",
            snapshot_id=snapshot.snapshot_id,
            node_count=len(nodes),
            edge_count=len(edges),
            vuln_count=metrics.get("total_vulns", 0),
        )
        return snapshot

    async def _export_nodes(self, engagement_id: str) -> dict[str, dict[str, Any]]:
        """Export all nodes for this engagement from Neo4j."""
        records = await self.client.query(
            """
            MATCH (n {engagement_id: $eid})
            RETURN n.id AS id, labels(n)[0] AS type, properties(n) AS props
            """,
            {"eid": engagement_id},
        )
        nodes: dict[str, dict[str, Any]] = {}
        for record in records:
            node_id = record.get("id", "")
            props = dict(record.get("props", {}))
            props.pop("engagement_id", None)
            nodes[node_id] = {"type": record.get("type", ""), "properties": props}
        return nodes

    async def _export_edges(self, engagement_id: str) -> list[dict[str, Any]]:
        """Export all edges for this engagement from Neo4j."""
        records = await self.client.query(
            """
            MATCH (a {engagement_id: $eid})-[r]->(b {engagement_id: $eid})
            RETURN a.id AS source, b.id AS target, type(r) AS rel_type,
                   properties(r) AS props
            """,
            {"eid": engagement_id},
        )
        edges: list[dict[str, Any]] = []
        for record in records:
            edges.append({
                "source": record.get("source", ""),
                "target": record.get("target", ""),
                "type": record.get("rel_type", ""),
                "properties": dict(record.get("props", {})) if record.get("props") else {},
            })
        return edges

    def _compute_metrics(
        self, nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Compute summary metrics from exported nodes and edges."""
        vuln_nodes = [
            n for n in nodes.values()
            if n["type"] in ("Vulnerability", "Finding")
        ]
        severity_counts: dict[str, int] = {}
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

    async def _store(self, snapshot: GraphSnapshot) -> None:
        """Store snapshot in Postgres."""
        async with self.pg_pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO ctem_snapshots (id, engagement_id, timestamp, data)
                   VALUES ($1, $2, $3, $4)""",
                snapshot.snapshot_id,
                snapshot.engagement_id,
                snapshot.timestamp,
                snapshot.to_json(),
            )

    async def load_latest(
        self, engagement_id: str, n: int = 2
    ) -> list[GraphSnapshot]:
        """Load the N most recent snapshots for an engagement."""
        async with self.pg_pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT data FROM ctem_snapshots
                   WHERE engagement_id = $1
                   ORDER BY timestamp DESC LIMIT $2""",
                engagement_id,
                n,
            )
            return [GraphSnapshot.from_json(row["data"]) for row in rows]
