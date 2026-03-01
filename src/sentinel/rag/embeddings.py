"""
Embedding Manager -- Generates and manages vector embeddings for security knowledge.

Strategy:
- Use OpenAI text-embedding-3-small for general text (cheap, good enough)
- Chunk size: 500-1000 tokens with 10-20% overlap
- Store in pgvector with HNSW index for fast retrieval
"""

import hashlib
from dataclasses import dataclass

from sentinel.logging_config import get_logger

logger = get_logger(__name__)

CHUNK_SIZE = 800       # tokens (approx 4 chars per token)
CHUNK_OVERLAP = 80     # 10% overlap
EMBEDDING_DIM = 1536   # text-embedding-3-small dimension


@dataclass
class EmbeddedChunk:
    chunk_id: str
    text: str
    embedding: list[float]
    metadata: dict         # {engagement_id, vuln_type, tech_stack, source}


class EmbeddingManager:
    """Generate and manage embeddings for security knowledge."""

    def __init__(self, openai_client=None):
        self.client = openai_client

    async def embed_text(self, text: str) -> list[float]:
        """Generate embedding for a single text."""
        if self.client is None:
            raise RuntimeError("OpenAI client required for embeddings")

        response = await self.client.embeddings.create(
            model="text-embedding-3-small",
            input=text,
        )
        return response.data[0].embedding

    async def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Generate embeddings for multiple texts (batched API call)."""
        if not texts:
            return []

        response = await self.client.embeddings.create(
            model="text-embedding-3-small",
            input=texts,
        )
        return [d.embedding for d in response.data]

    def chunk_text(self, text: str, metadata: dict | None = None) -> list[dict]:
        """Split text into overlapping chunks for embedding."""
        metadata = metadata or {}
        chars_per_chunk = CHUNK_SIZE * 4
        overlap_chars = CHUNK_OVERLAP * 4

        chunks: list[dict] = []
        start = 0
        while start < len(text):
            end = start + chars_per_chunk
            chunk_text = text[start:end]

            if chunk_text.strip():
                chunk_id = hashlib.sha256(
                    f"{metadata.get('source', '')}:{start}".encode()
                ).hexdigest()[:16]

                chunks.append({
                    "chunk_id": chunk_id,
                    "text": chunk_text,
                    "metadata": {**metadata, "char_start": start, "char_end": end},
                })

            start = end - overlap_chars

        return chunks
