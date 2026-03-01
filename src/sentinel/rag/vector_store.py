"""
pgvector Store -- Manages vector storage and retrieval in PostgreSQL.

Tables:
  knowledge_chunks: chunk_id, text, embedding (vector), metadata (jsonb), created_at

Indexes:
  HNSW on embedding column for approximate nearest neighbor search
  GIN on metadata for filtering by tech_stack, vuln_type, etc.
"""

import json
from dataclasses import dataclass

from sentinel.logging_config import get_logger

logger = get_logger(__name__)

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id SERIAL PRIMARY KEY,
    chunk_id TEXT UNIQUE NOT NULL,
    text TEXT NOT NULL,
    embedding vector(1536),
    metadata JSONB DEFAULT '{}',
    engagement_id TEXT,
    vuln_type TEXT,
    tech_stack TEXT[],
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chunks_embedding
    ON knowledge_chunks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 32, ef_construction = 128);

CREATE INDEX IF NOT EXISTS idx_chunks_metadata
    ON knowledge_chunks USING gin (metadata);

CREATE INDEX IF NOT EXISTS idx_chunks_vuln_type
    ON knowledge_chunks (vuln_type);

CREATE INDEX IF NOT EXISTS idx_chunks_tech_stack
    ON knowledge_chunks USING gin (tech_stack);
"""


@dataclass
class SearchResult:
    chunk_id: str
    text: str
    metadata: dict
    similarity: float


class VectorStore:
    """pgvector-backed vector store for security knowledge."""

    def __init__(self, pool):
        """Args:
            pool: asyncpg connection pool to PostgreSQL with pgvector extension
        """
        self.pool = pool

    async def initialize(self):
        """Create tables and indexes."""
        async with self.pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
        logger.info("Vector store initialized")

    async def upsert(
        self,
        chunk_id: str,
        text: str,
        embedding: list[float],
        metadata: dict | None = None,
        engagement_id: str = "",
        vuln_type: str = "",
        tech_stack: list[str] | None = None,
    ):
        """Insert or update a knowledge chunk."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO knowledge_chunks (chunk_id, text, embedding, metadata,
                                              engagement_id, vuln_type, tech_stack)
                VALUES ($1, $2, $3::vector, $4, $5, $6, $7)
                ON CONFLICT (chunk_id)
                DO UPDATE SET text = $2, embedding = $3::vector, metadata = $4
                """,
                chunk_id, text, str(embedding), json.dumps(metadata or {}),
                engagement_id, vuln_type, tech_stack or [],
            )

    async def search(
        self,
        query_embedding: list[float],
        top_k: int = 10,
        vuln_type: str | None = None,
        tech_stack: str | None = None,
        min_similarity: float = 0.5,
    ) -> list[SearchResult]:
        """Semantic search with optional metadata filtering.

        Uses cosine similarity via pgvector.
        """
        filters: list[str] = []
        params: list = [str(query_embedding), top_k]
        param_idx = 3

        if vuln_type:
            filters.append(f"vuln_type = ${param_idx}")
            params.append(vuln_type)
            param_idx += 1

        if tech_stack:
            filters.append(f"${param_idx} = ANY(tech_stack)")
            params.append(tech_stack)
            param_idx += 1

        where_clause = "WHERE " + " AND ".join(filters) if filters else ""

        query = f"""
            SELECT chunk_id, text, metadata,
                   1 - (embedding <=> $1::vector) AS similarity
            FROM knowledge_chunks
            {where_clause}
            ORDER BY embedding <=> $1::vector
            LIMIT $2
        """

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)

        return [
            SearchResult(
                chunk_id=row["chunk_id"],
                text=row["text"],
                metadata=(
                    json.loads(row["metadata"])
                    if isinstance(row["metadata"], str)
                    else row["metadata"]
                ),
                similarity=float(row["similarity"]),
            )
            for row in rows
            if float(row["similarity"]) >= min_similarity
        ]

    async def hybrid_search(
        self,
        query_embedding: list[float],
        keyword_query: str,
        top_k: int = 10,
    ) -> list[SearchResult]:
        """Hybrid search: combine vector similarity with keyword matching.

        Uses Reciprocal Rank Fusion (RRF) to merge results.
        """
        # Vector search
        vector_results = await self.search(query_embedding, top_k=top_k * 2)

        # Keyword search (simple ILIKE; upgrade to tsvector for production)
        async with self.pool.acquire() as conn:
            keyword_rows = await conn.fetch(
                """
                SELECT chunk_id, text, metadata, 0.5 AS similarity
                FROM knowledge_chunks
                WHERE text ILIKE $1
                LIMIT $2
                """,
                f"%{keyword_query}%", top_k * 2,
            )

        keyword_results = [
            SearchResult(
                r["chunk_id"],
                r["text"],
                (
                    json.loads(r["metadata"])
                    if isinstance(r["metadata"], str)
                    else r["metadata"]
                ),
                float(r["similarity"]),
            )
            for r in keyword_rows
        ]

        return self._rrf_merge(vector_results, keyword_results, top_k)

    def _rrf_merge(
        self,
        list_a: list[SearchResult],
        list_b: list[SearchResult],
        top_k: int,
        k: int = 60,
    ) -> list[SearchResult]:
        """Reciprocal Rank Fusion to merge two ranked lists."""
        scores: dict[str, float] = {}
        items: dict[str, SearchResult] = {}

        for rank, item in enumerate(list_a):
            scores[item.chunk_id] = scores.get(item.chunk_id, 0) + 1.0 / (k + rank + 1)
            items[item.chunk_id] = item

        for rank, item in enumerate(list_b):
            scores[item.chunk_id] = scores.get(item.chunk_id, 0) + 1.0 / (k + rank + 1)
            items[item.chunk_id] = item

        sorted_ids = sorted(scores, key=scores.get, reverse=True)[:top_k]
        return [items[cid] for cid in sorted_ids if cid in items]
