"""
GraphRAG -- Combines Neo4j knowledge graph traversal with vector retrieval.

For multi-hop queries ("What attack chains exist from exposed service X
to crown jewel Y through known vulnerabilities?"), naive vector search fails.
GraphRAG:
1. Extract entities from query
2. Find those entities in Neo4j
3. Traverse relationships to find connected context
4. Use that context to filter/enhance vector search
"""

from dataclasses import dataclass

from sentinel.rag.vector_store import VectorStore, SearchResult
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class GraphContext:
    entities: list[dict]          # Matched nodes from Neo4j
    relationships: list[dict]     # Edges connecting entities
    subgraph_text: str            # Natural language summary of graph context


class GraphRAG:
    """Combine graph traversal with vector retrieval."""

    def __init__(self, neo4j_client, vector_store: VectorStore, embedding_manager):
        self.graph = neo4j_client
        self.vectors = vector_store
        self.embeddings = embedding_manager

    async def search(
        self,
        query: str,
        engagement_id: str = "",
        top_k: int = 10,
    ) -> list[SearchResult]:
        """GraphRAG search:
        1. Extract tech/vuln entities from query
        2. Find related nodes in Neo4j
        3. Build context from graph relationships
        4. Enhance vector search with graph context
        """
        # Step 1: Extract key entities from query
        entities = self._extract_entities(query)

        # Step 2: Find in Neo4j
        graph_context = await self._get_graph_context(entities, engagement_id)

        # Step 3: Enhance query with graph context
        enhanced_query = f"{query}\n\nGraph context: {graph_context.subgraph_text}"

        # Step 4: Vector search with enhanced query
        embedding = await self.embeddings.embed_text(enhanced_query)
        results = await self.vectors.search(embedding, top_k=top_k)

        return results

    def _extract_entities(self, query: str) -> list[str]:
        """Simple entity extraction from query (upgrade to NER later)."""
        known_terms: dict[str, list[str]] = {
            "tech": [
                "django", "flask", "express", "spring", "react", "nginx",
                "apache", "postgresql", "mongodb", "redis", "docker", "k8s",
            ],
            "vuln": [
                "sqli", "xss", "idor", "ssrf", "rce", "lfi", "xxe",
                "deserialization", "csrf", "bola", "injection",
            ],
            "tool": ["nmap", "nuclei", "zap", "sqlmap", "burp", "ffuf"],
        }

        entities: list[str] = []
        query_lower = query.lower()
        for _category, terms in known_terms.items():
            for term in terms:
                if term in query_lower:
                    entities.append(term)

        return entities

    async def _get_graph_context(
        self, entities: list[str], engagement_id: str
    ) -> GraphContext:
        """Query Neo4j for context around extracted entities."""
        if not entities:
            return GraphContext([], [], "No graph entities found.")

        cypher = """
        MATCH (n)
        WHERE toLower(n.name) IN $entities
           OR toLower(n.service_name) IN $entities
           OR toLower(n.vuln_type) IN $entities
        OPTIONAL MATCH (n)-[r]-(m)
        RETURN n, type(r) as rel_type, m
        LIMIT 50
        """

        try:
            results = await self.graph.query(cypher, {"entities": entities})

            nodes: list[dict] = []
            rels: list[dict] = []
            for record in results:
                if record.get("n"):
                    nodes.append(dict(record["n"]))
                if record.get("rel_type") and record.get("m"):
                    rels.append({
                        "from": str(record.get("n", {}).get("name", "")),
                        "type": record["rel_type"],
                        "to": str(record.get("m", {}).get("name", "")),
                    })

            # Build natural language summary
            summary_parts: list[str] = []
            for node in nodes[:10]:
                summary_parts.append(
                    f"Found: {node.get('name', 'unknown')} (labels: {node.get('labels', [])})"
                )
            for rel in rels[:10]:
                summary_parts.append(
                    f"  {rel['from']} --[{rel['type']}]--> {rel['to']}"
                )

            return GraphContext(
                entities=nodes,
                relationships=rels,
                subgraph_text="\n".join(summary_parts) or "No matching graph data.",
            )
        except Exception as e:
            logger.error(f"GraphRAG Neo4j query failed: {e}")
            return GraphContext([], [], f"Graph query error: {e}")
