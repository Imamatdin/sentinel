"""Async Neo4j client for Sentinel knowledge graph."""

from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from neo4j import AsyncGraphDatabase, AsyncDriver, AsyncSession
from neo4j.exceptions import ServiceUnavailable, AuthError

from sentinel.core import get_logger, get_settings, GraphError
from sentinel.graph.models import (
    BaseNode,
    BaseEdge,
    NodeType,
    EdgeType,
    GraphSnapshot,
)

logger = get_logger(__name__)


class Neo4jClient:
    """Async Neo4j client with connection pooling."""

    def __init__(self):
        self.settings = get_settings()
        self._driver: AsyncDriver | None = None

    async def connect(self) -> None:
        """Establish connection to Neo4j."""
        try:
            self._driver = AsyncGraphDatabase.driver(
                self.settings.neo4j_uri,
                auth=(
                    self.settings.neo4j_user,
                    self.settings.neo4j_password.get_secret_value(),
                ),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=60,
            )
            await self._driver.verify_connectivity()
            logger.info("Connected to Neo4j", uri=self.settings.neo4j_uri)
        except AuthError as e:
            raise GraphError(f"Neo4j authentication failed: {e}")
        except ServiceUnavailable as e:
            raise GraphError(f"Neo4j service unavailable: {e}")

    async def disconnect(self) -> None:
        """Close Neo4j connection."""
        if self._driver:
            await self._driver.close()
            self._driver = None
            logger.info("Disconnected from Neo4j")

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get a Neo4j session."""
        if not self._driver:
            await self.connect()
        async with self._driver.session() as session:
            yield session

    async def setup_schema(self) -> None:
        """Create indexes and constraints."""
        async with self.session() as session:
            constraints = [
                "CREATE CONSTRAINT host_id IF NOT EXISTS FOR (h:Host) REQUIRE h.id IS UNIQUE",
                "CREATE CONSTRAINT port_id IF NOT EXISTS FOR (p:Port) REQUIRE p.id IS UNIQUE",
                "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.id IS UNIQUE",
                "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
                "CREATE CONSTRAINT cred_id IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
                "CREATE CONSTRAINT session_id IF NOT EXISTS FOR (s:Session) REQUIRE s.id IS UNIQUE",
                "CREATE CONSTRAINT endpoint_id IF NOT EXISTS FOR (e:Endpoint) REQUIRE e.id IS UNIQUE",
                "CREATE CONSTRAINT asset_id IF NOT EXISTS FOR (a:CriticalAsset) REQUIRE a.id IS UNIQUE",
            ]

            indexes = [
                "CREATE INDEX host_ip IF NOT EXISTS FOR (h:Host) ON (h.ip_address)",
                "CREATE INDEX vuln_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id)",
                "CREATE INDEX vuln_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
                "CREATE INDEX cred_username IF NOT EXISTS FOR (c:Credential) ON (c.username)",
            ]

            for query in constraints + indexes:
                try:
                    await session.run(query)
                except Exception as e:
                    logger.debug(f"Schema element may exist: {e}")

            logger.info("Neo4j schema setup complete")

    # === Node Operations ===

    async def create_node(self, node: BaseNode) -> str:
        """Create a node in the graph."""
        query = f"""
        CREATE (n:{node.node_type.value} $props)
        RETURN n.id as id
        """
        async with self.session() as session:
            result = await session.run(query, props=node.to_neo4j_properties())
            record = await result.single()
            logger.debug("Created node", node_type=node.node_type.value, id=str(node.id))
            return record["id"]

    async def get_node(self, node_id: str, node_type: NodeType) -> dict[str, Any] | None:
        """Get a node by ID."""
        query = f"""
        MATCH (n:{node_type.value} {{id: $id}})
        RETURN n
        """
        async with self.session() as session:
            result = await session.run(query, id=node_id)
            record = await result.single()
            return dict(record["n"]) if record else None

    async def update_node(self, node_id: str, node_type: NodeType, updates: dict[str, Any]) -> bool:
        """Update node properties."""
        set_clause = ", ".join([f"n.{k} = ${k}" for k in updates.keys()])
        query = f"""
        MATCH (n:{node_type.value} {{id: $id}})
        SET {set_clause}, n.updated_at = datetime()
        RETURN n.id as id
        """
        async with self.session() as session:
            result = await session.run(query, id=node_id, **updates)
            record = await result.single()
            return record is not None

    async def delete_node(self, node_id: str, node_type: NodeType) -> bool:
        """Delete a node and its relationships."""
        query = f"""
        MATCH (n:{node_type.value} {{id: $id}})
        DETACH DELETE n
        RETURN count(n) as deleted
        """
        async with self.session() as session:
            result = await session.run(query, id=node_id)
            record = await result.single()
            return record["deleted"] > 0

    # === Edge Operations ===

    async def create_edge(
        self,
        source_id: str,
        source_type: NodeType,
        target_id: str,
        target_type: NodeType,
        edge: BaseEdge,
    ) -> str:
        """Create an edge between two nodes."""
        query = f"""
        MATCH (a:{source_type.value} {{id: $source_id}})
        MATCH (b:{target_type.value} {{id: $target_id}})
        CREATE (a)-[r:{edge.edge_type.value} $props]->(b)
        RETURN r.id as id
        """
        async with self.session() as session:
            result = await session.run(
                query,
                source_id=source_id,
                target_id=target_id,
                props=edge.to_neo4j_properties(),
            )
            record = await result.single()
            return record["id"]

    # === Query Operations ===

    async def find_hosts(
        self,
        engagement_id: str | None = None,
        is_compromised: bool | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Find hosts matching criteria."""
        conditions = []
        params = {"limit": limit}

        if engagement_id:
            conditions.append("h.engagement_id = $engagement_id")
            params["engagement_id"] = engagement_id
        if is_compromised is not None:
            conditions.append("h.is_compromised = $is_compromised")
            params["is_compromised"] = is_compromised

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
        MATCH (h:Host)
        {where_clause}
        RETURN h
        ORDER BY h.created_at DESC
        LIMIT $limit
        """
        async with self.session() as session:
            result = await session.run(query, **params)
            records = await result.data()
            return [dict(r["h"]) for r in records]

    async def find_vulnerabilities(
        self,
        host_id: str | None = None,
        severity: str | None = None,
        is_exploitable: bool | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Find vulnerabilities matching criteria."""
        conditions = []
        params = {"limit": limit}

        match_clause = "MATCH (v:Vulnerability)"
        if host_id:
            match_clause = """
            MATCH (h:Host {id: $host_id})-[:HAS_PORT]->(:Port)-[:RUNS_SERVICE]->(:Service)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            """
            params["host_id"] = host_id

        if severity:
            conditions.append("v.severity = $severity")
            params["severity"] = severity
        if is_exploitable is not None:
            conditions.append("v.is_exploitable = $is_exploitable")
            params["is_exploitable"] = is_exploitable

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
        {match_clause}
        {where_clause}
        RETURN DISTINCT v
        ORDER BY v.cvss_score DESC
        LIMIT $limit
        """
        async with self.session() as session:
            result = await session.run(query, **params)
            records = await result.data()
            return [dict(r["v"]) for r in records]

    # === Attack Path Computation ===

    async def find_shortest_path(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
    ) -> dict[str, Any] | None:
        """Find shortest attack path between two nodes."""
        query = f"""
        MATCH path = shortestPath(
            (source {{id: $source_id}})-[*1..{max_depth}]->(target {{id: $target_id}})
        )
        RETURN path,
               length(path) as depth,
               [r IN relationships(path) | type(r)] as edge_types,
               [n IN nodes(path) | {{id: n.id, type: labels(n)[0], name: coalesce(n.hostname, n.ip_address, n.name, n.url, 'unknown')}}] as nodes
        """
        async with self.session() as session:
            result = await session.run(
                query,
                source_id=source_id,
                target_id=target_id,
            )
            record = await result.single()
            if not record:
                return None
            return {
                "depth": record["depth"],
                "edge_types": record["edge_types"],
                "nodes": record["nodes"],
            }

    async def find_all_paths_to_asset(
        self,
        target_id: str,
        max_depth: int = 6,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Find all attack paths to a critical asset."""
        query = f"""
        MATCH path = (entry:Host)-[*1..{max_depth}]->(target:CriticalAsset {{id: $target_id}})
        WHERE NOT (entry)<-[]-()
        RETURN path,
               length(path) as depth,
               [n IN nodes(path) | {{id: n.id, type: labels(n)[0]}}] as nodes,
               reduce(w = 0.0, r IN relationships(path) | w + coalesce(r.weight, 1.0)) as total_weight
        ORDER BY total_weight ASC
        LIMIT $limit
        """
        async with self.session() as session:
            result = await session.run(
                query,
                target_id=target_id,
                limit=limit,
            )
            records = await result.data()
            return records

    async def compute_choke_points(
        self,
        engagement_id: str,
        min_path_count: int = 3,
    ) -> list[dict[str, Any]]:
        """Find choke points where multiple attack paths converge."""
        query = """
        MATCH path = (entry:Host)-[*1..6]->(target:CriticalAsset)
        WHERE entry.engagement_id = $engagement_id
        UNWIND nodes(path)[1..-1] as node
        WITH node, count(DISTINCT path) as path_count,
             collect(DISTINCT target.id) as targets_reached
        WHERE path_count >= $min_path_count
        RETURN node.id as id,
               labels(node)[0] as type,
               coalesce(node.hostname, node.ip_address, node.name, 'unknown') as label,
               path_count,
               size(targets_reached) as critical_assets_reachable,
               path_count * size(targets_reached) as choke_point_score
        ORDER BY choke_point_score DESC
        LIMIT 20
        """
        async with self.session() as session:
            result = await session.run(
                query,
                engagement_id=engagement_id,
                min_path_count=min_path_count,
            )
            records = await result.data()
            return records

    async def compute_blast_radius(self, node_id: str, max_depth: int = 4) -> dict[str, Any]:
        """Compute what can be reached if this node is compromised."""
        query = f"""
        MATCH path = (source {{id: $node_id}})-[*1..{max_depth}]->(target)
        WITH collect(DISTINCT target) as reachable
        RETURN size(reachable) as total_reachable,
               size([n IN reachable WHERE 'CriticalAsset' IN labels(n)]) as critical_assets,
               size([n IN reachable WHERE 'Host' IN labels(n) AND n.is_domain_controller]) as domain_controllers,
               size([n IN reachable WHERE 'Credential' IN labels(n) AND n.is_admin]) as admin_credentials
        """
        async with self.session() as session:
            result = await session.run(query, node_id=node_id)
            record = await result.single()
            return dict(record) if record else {}

    # === Snapshot Operations ===

    async def create_snapshot(self, engagement_id: str) -> GraphSnapshot:
        """Create a point-in-time snapshot of the graph."""
        async with self.session() as session:
            counts_query = """
            MATCH (n {engagement_id: $eid})
            WITH labels(n)[0] as label, count(n) as cnt
            RETURN collect({label: label, count: cnt}) as counts
            """
            result = await session.run(counts_query, eid=engagement_id)
            record = await result.single()
            counts = {c["label"]: c["count"] for c in record["counts"]}

            nodes_query = """
            MATCH (n {engagement_id: $eid})
            RETURN collect(n.id) as ids
            """
            result = await session.run(nodes_query, eid=engagement_id)
            record = await result.single()
            node_ids = record["ids"]

            choke_points = await self.compute_choke_points(engagement_id)

            return GraphSnapshot(
                engagement_id=engagement_id,
                host_count=counts.get("Host", 0),
                vulnerability_count=counts.get("Vulnerability", 0),
                credential_count=counts.get("Credential", 0),
                session_count=counts.get("Session", 0),
                critical_assets_at_risk=counts.get("CriticalAsset", 0),
                choke_points=[cp["id"] for cp in choke_points[:10]],
                node_ids=node_ids,
            )

    async def diff_snapshots(
        self,
        old_snapshot: GraphSnapshot,
        new_snapshot: GraphSnapshot,
    ) -> dict[str, Any]:
        """Compare two snapshots for CTEM diff."""
        old_nodes = set(str(n) for n in old_snapshot.node_ids)
        new_nodes = set(str(n) for n in new_snapshot.node_ids)

        return {
            "new_nodes": list(new_nodes - old_nodes),
            "removed_nodes": list(old_nodes - new_nodes),
            "host_delta": new_snapshot.host_count - old_snapshot.host_count,
            "vulnerability_delta": new_snapshot.vulnerability_count - old_snapshot.vulnerability_count,
            "credential_delta": new_snapshot.credential_count - old_snapshot.credential_count,
        }

    async def clear_engagement(self, engagement_id: str) -> int:
        """Delete all nodes for an engagement."""
        query = """
        MATCH (n {engagement_id: $eid})
        DETACH DELETE n
        RETURN count(n) as deleted
        """
        async with self.session() as session:
            result = await session.run(query, eid=engagement_id)
            record = await result.single()
            deleted = record["deleted"]
            logger.info("Cleared engagement", engagement_id=engagement_id, deleted=deleted)
            return deleted


# === Singleton ===

_client: Neo4jClient | None = None


async def get_graph_client() -> Neo4jClient:
    """Get or create the Neo4j client singleton."""
    global _client
    if _client is None:
        _client = Neo4jClient()
        await _client.connect()
        await _client.setup_schema()
    return _client


async def close_graph_client() -> None:
    """Close the Neo4j client."""
    global _client
    if _client:
        await _client.disconnect()
        _client = None
