"""
CTEM Diff Engine -- Compares two snapshots to show changes.

Outputs:
- New nodes/edges (appeared since last scan)
- Removed nodes/edges (fixed/closed)
- Persistent nodes (still present)
- Regressions (was removed, now back -- flagged with regression:true)
- Metric deltas (vuln count change, severity shifts, path count change)
"""

from dataclasses import dataclass, field
from typing import Any

from sentinel.ctem.snapshot import GraphSnapshot
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class DiffResult:
    old_snapshot_id: str
    new_snapshot_id: str
    engagement_id: str

    new_nodes: list[dict[str, Any]]
    removed_nodes: list[dict[str, Any]]
    persistent_nodes: list[str]
    regression_nodes: list[dict[str, Any]]

    new_edges: list[dict[str, Any]]
    removed_edges: list[dict[str, Any]]

    metric_deltas: dict[str, dict[str, Any]]

    summary: str


class CTEMDiffer:
    """Diff two attack graph snapshots."""

    def __init__(self, regression_history: dict[str, str] | None = None):
        self._removal_history: dict[str, str] = regression_history or {}

    def diff(self, old: GraphSnapshot, new: GraphSnapshot) -> DiffResult:
        """Compare two snapshots and produce a diff."""
        old_node_ids = set(old.nodes.keys())
        new_node_ids = set(new.nodes.keys())

        added_ids = new_node_ids - old_node_ids
        removed_ids = old_node_ids - new_node_ids
        persistent_ids = old_node_ids & new_node_ids

        new_nodes = [{"id": nid, **new.nodes[nid]} for nid in added_ids]
        removed_nodes = [{"id": nid, **old.nodes[nid]} for nid in removed_ids]

        # Regression detection: node was previously removed, now reappearing
        regressions: list[dict[str, Any]] = []
        for nid in added_ids:
            if nid in self._removal_history:
                node_data = {
                    "id": nid,
                    **new.nodes[nid],
                    "regression": True,
                    "previously_removed_at": self._removal_history[nid],
                }
                regressions.append(node_data)

        # Update removal history with newly removed nodes
        for nid in removed_ids:
            self._removal_history[nid] = new.timestamp.isoformat()

        # Edge diff
        old_edge_set = self._edge_set(old.edges)
        new_edge_set = self._edge_set(new.edges)
        added_edge_keys = new_edge_set - old_edge_set
        removed_edge_keys = old_edge_set - new_edge_set

        new_edges = [e for e in new.edges if self._edge_key(e) in added_edge_keys]
        removed_edges = [e for e in old.edges if self._edge_key(e) in removed_edge_keys]

        # Metric deltas
        deltas: dict[str, dict[str, Any]] = {}
        all_metric_keys = set(old.metrics.keys()) | set(new.metrics.keys())
        for key in all_metric_keys:
            old_val = old.metrics.get(key, 0)
            new_val = new.metrics.get(key, 0)
            if isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
                deltas[key] = {
                    "old": old_val,
                    "new": new_val,
                    "delta": new_val - old_val,
                }

        summary = self._generate_summary(new_nodes, removed_nodes, regressions, deltas)

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
            "ctem_diff",
            new_nodes=len(new_nodes),
            removed_nodes=len(removed_nodes),
            regressions=len(regressions),
        )
        return result

    def _edge_set(self, edges: list[dict[str, Any]]) -> set[str]:
        return {self._edge_key(e) for e in edges}

    def _edge_key(self, edge: dict[str, Any]) -> str:
        return f"{edge['source']}--{edge['type']}-->{edge['target']}"

    def _generate_summary(
        self,
        new_nodes: list[dict[str, Any]],
        removed_nodes: list[dict[str, Any]],
        regressions: list[dict[str, Any]],
        deltas: dict[str, dict[str, Any]],
    ) -> str:
        parts: list[str] = []

        vuln_delta = deltas.get("total_vulns")
        if vuln_delta:
            d = vuln_delta["delta"]
            if d > 0:
                parts.append(f"{d} new vulnerabilities discovered.")
            elif d < 0:
                parts.append(f"{abs(d)} vulnerabilities resolved.")
            else:
                parts.append(f"Vulnerability count unchanged ({vuln_delta['new']}).")

        if regressions:
            parts.append(
                f"{len(regressions)} REGRESSIONS -- previously fixed vulnerabilities have returned."
            )

        new_vulns = [
            n for n in new_nodes
            if n.get("type") in ("Vulnerability", "Finding")
        ]
        if new_vulns:
            critical = sum(
                1 for n in new_vulns
                if n.get("properties", {}).get("severity") == "critical"
            )
            if critical:
                parts.append(f"{critical} new CRITICAL vulnerabilities.")

        removed_vulns = [
            n for n in removed_nodes
            if n.get("type") in ("Vulnerability", "Finding")
        ]
        if removed_vulns:
            parts.append(f"Fixed: {len(removed_vulns)} vulnerabilities no longer present.")

        return " ".join(parts) if parts else "No significant changes detected."
