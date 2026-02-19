"""EmbeddingStore -- pgvector-backed vector store for security knowledge.

Stores embeddings of:
- Vulnerability patterns (description + evidence + remediation)
- Exploit payloads (what worked, what didn't, against what tech)
- Attack chains (multi-step sequences)
- Defense patterns (what blocked what)

Used for RAG retrieval before LLM decisions.
"""

import json
from dataclasses import dataclass, field
from typing import Any

import asyncpg

from sentinel.core import get_logger, get_settings

logger = get_logger(__name__)


@dataclass
class EmbeddingRecord:
    """A single embedded security pattern."""

    id: str
    content: str  # The text that was embedded
    embedding: list[float]  # The vector (1536-dim for OpenAI)
    category: str  # "vulnerability", "exploit", "defense", "chain"
    metadata: dict[str, Any] = field(default_factory=dict)
    engagement_id: str = ""
    confidence: float = 0.5  # 0.0-1.0, updated across engagements
    success_count: int = 0
    failure_count: int = 0


class EmbeddingStore:
    """pgvector-backed store for security pattern embeddings.

    Schema creates:
    - sentinel_embeddings table with vector(1536) column
    - HNSW index for fast cosine similarity search
    """

    def __init__(self):
        self.pool: asyncpg.Pool | None = None

    def _get_dsn(self) -> str:
        """Get raw asyncpg DSN (strip SQLAlchemy prefix if present)."""
        settings = get_settings()
        dsn = settings.postgres_dsn
        # SQLAlchemy uses 'postgresql+asyncpg://', raw asyncpg needs 'postgresql://'
        return dsn.replace("postgresql+asyncpg://", "postgresql://")

    async def initialize(self) -> None:
        """Create connection pool and ensure schema exists."""
        dsn = self._get_dsn()
        self.pool = await asyncpg.create_pool(dsn, min_size=2, max_size=10)

        async with self.pool.acquire() as conn:
            # Enable pgvector extension
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")

            # Create embeddings table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS sentinel_embeddings (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    embedding vector(1536),
                    category TEXT NOT NULL,
                    metadata JSONB DEFAULT '{}',
                    engagement_id TEXT,
                    confidence FLOAT DEFAULT 0.5,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """)

            # HNSW index for fast cosine similarity search
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_embeddings_hnsw
                ON sentinel_embeddings
                USING hnsw (embedding vector_cosine_ops)
                WITH (m = 16, ef_construction = 64)
            """)

            # Category index for filtered search
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_embeddings_category
                ON sentinel_embeddings (category)
            """)

        logger.info("EmbeddingStore initialized")

    async def store(self, record: EmbeddingRecord) -> None:
        """Store or update an embedding record."""
        if not self.pool:
            raise RuntimeError("EmbeddingStore not initialized")

        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO sentinel_embeddings
                    (id, content, embedding, category, metadata,
                     engagement_id, confidence, success_count, failure_count)
                VALUES ($1, $2, $3::vector, $4, $5::jsonb, $6, $7, $8, $9)
                ON CONFLICT (id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    confidence = EXCLUDED.confidence,
                    success_count = EXCLUDED.success_count,
                    failure_count = EXCLUDED.failure_count,
                    updated_at = NOW()
                """,
                record.id,
                record.content,
                str(record.embedding),
                record.category,
                json.dumps(record.metadata),
                record.engagement_id,
                record.confidence,
                record.success_count,
                record.failure_count,
            )

    async def search(
        self,
        query_embedding: list[float],
        category: str | None = None,
        limit: int = 10,
        min_confidence: float = 0.0,
    ) -> list[EmbeddingRecord]:
        """Search for similar patterns using cosine similarity."""
        if not self.pool:
            raise RuntimeError("EmbeddingStore not initialized")

        async with self.pool.acquire() as conn:
            embedding_str = str(query_embedding)

            if category:
                rows = await conn.fetch(
                    """
                    SELECT *, 1 - (embedding <=> $1::vector) as similarity
                    FROM sentinel_embeddings
                    WHERE category = $2 AND confidence >= $3
                    ORDER BY embedding <=> $1::vector
                    LIMIT $4
                    """,
                    embedding_str,
                    category,
                    min_confidence,
                    limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT *, 1 - (embedding <=> $1::vector) as similarity
                    FROM sentinel_embeddings
                    WHERE confidence >= $2
                    ORDER BY embedding <=> $1::vector
                    LIMIT $3
                    """,
                    embedding_str,
                    min_confidence,
                    limit,
                )

            return [
                EmbeddingRecord(
                    id=row["id"],
                    content=row["content"],
                    embedding=[],  # Don't return full vector for performance
                    category=row["category"],
                    metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else (row["metadata"] or {}),
                    engagement_id=row["engagement_id"] or "",
                    confidence=row["confidence"],
                    success_count=row["success_count"],
                    failure_count=row["failure_count"],
                )
                for row in rows
            ]

    async def update_confidence(self, record_id: str, success: bool) -> None:
        """Update confidence score based on exploit success/failure."""
        if not self.pool:
            raise RuntimeError("EmbeddingStore not initialized")

        async with self.pool.acquire() as conn:
            if success:
                await conn.execute(
                    """
                    UPDATE sentinel_embeddings
                    SET success_count = success_count + 1,
                        confidence = (success_count + 1.0) / (success_count + failure_count + 1.0),
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    record_id,
                )
            else:
                await conn.execute(
                    """
                    UPDATE sentinel_embeddings
                    SET failure_count = failure_count + 1,
                        confidence = success_count::float / (success_count + failure_count + 1.0),
                        updated_at = NOW()
                    WHERE id = $1
                    """,
                    record_id,
                )

    async def delete(self, record_id: str) -> None:
        """Delete an embedding record."""
        if not self.pool:
            raise RuntimeError("EmbeddingStore not initialized")

        async with self.pool.acquire() as conn:
            await conn.execute("DELETE FROM sentinel_embeddings WHERE id = $1", record_id)

    async def count(self, category: str | None = None) -> int:
        """Count records, optionally filtered by category."""
        if not self.pool:
            raise RuntimeError("EmbeddingStore not initialized")

        async with self.pool.acquire() as conn:
            if category:
                row = await conn.fetchrow(
                    "SELECT COUNT(*) as cnt FROM sentinel_embeddings WHERE category = $1",
                    category,
                )
            else:
                row = await conn.fetchrow("SELECT COUNT(*) as cnt FROM sentinel_embeddings")
            return row["cnt"] if row else 0

    async def close(self) -> None:
        """Close connection pool."""
        if self.pool:
            await self.pool.close()
            self.pool = None
