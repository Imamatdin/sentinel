"""
Knowledge Ingestor -- Processes engagement results into the RAG knowledge base.

After each engagement:
1. Extract key findings, techniques, payloads
2. Anonymize (strip IPs, hostnames, paths)
3. Chunk and embed
4. Store in pgvector with metadata tags
"""

import re

from sentinel.rag.embeddings import EmbeddingManager
from sentinel.rag.vector_store import VectorStore
from sentinel.logging_config import get_logger

logger = get_logger(__name__)

# Patterns to anonymize
ANONYMIZE_PATTERNS = [
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", "[IP]"),
    (r"https?://[^\s]+", "[URL]"),
    (r"/home/[^\s/]+", "/home/[USER]"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[EMAIL]"),
    (r"Bearer [A-Za-z0-9\-._~+/]+=*", "Bearer [TOKEN]"),
    (r"[A-Fa-f0-9]{32,}", "[HASH]"),
]


class KnowledgeIngestor:
    """Ingest engagement results into RAG knowledge base."""

    def __init__(self, embedding_manager: EmbeddingManager, vector_store: VectorStore):
        self.embeddings = embedding_manager
        self.store = vector_store

    async def ingest_finding(self, finding: dict, engagement_id: str):
        """Ingest a single verified finding into the knowledge base."""
        text = self._finding_to_text(finding)
        text = self._anonymize(text)

        chunks = self.embeddings.chunk_text(text, metadata={
            "engagement_id": engagement_id,
            "vuln_type": finding.get("category", ""),
            "source": "finding",
        })

        texts = [c["text"] for c in chunks]
        embeddings = await self.embeddings.embed_batch(texts)

        for chunk, embedding in zip(chunks, embeddings):
            await self.store.upsert(
                chunk_id=chunk["chunk_id"],
                text=chunk["text"],
                embedding=embedding,
                metadata=chunk["metadata"],
                engagement_id=engagement_id,
                vuln_type=finding.get("category", ""),
                tech_stack=finding.get("tech_stack", []),
            )

        logger.info(
            f"Ingested finding {finding.get('finding_id', 'unknown')} as {len(chunks)} chunks"
        )

    async def ingest_engagement_summary(self, summary: dict, engagement_id: str):
        """Ingest full engagement summary (techniques, outcomes, lessons)."""
        text = self._summary_to_text(summary)
        text = self._anonymize(text)

        chunks = self.embeddings.chunk_text(text, metadata={
            "engagement_id": engagement_id,
            "source": "engagement_summary",
        })

        texts = [c["text"] for c in chunks]
        if texts:
            embeddings = await self.embeddings.embed_batch(texts)
            for chunk, embedding in zip(chunks, embeddings):
                await self.store.upsert(
                    chunk_id=chunk["chunk_id"],
                    text=chunk["text"],
                    embedding=embedding,
                    metadata=chunk["metadata"],
                    engagement_id=engagement_id,
                )

    def _finding_to_text(self, finding: dict) -> str:
        parts = [
            f"Vulnerability: {finding.get('category', 'unknown')}",
            f"Severity: {finding.get('severity', '')}",
            f"Target: {finding.get('target_url', '')}",
            f"Description: {finding.get('description', '')}",
            f"Technique: {finding.get('technique', '')}",
            f"Payload: {finding.get('payload', '')}",
            f"Response: {finding.get('response_excerpt', '')}",
            f"Verified: {finding.get('verified', False)}",
            f"Tech stack: {', '.join(finding.get('tech_stack', []))}",
        ]
        return "\n".join(p for p in parts if p.split(": ", 1)[-1])

    def _summary_to_text(self, summary: dict) -> str:
        parts = [
            f"Engagement summary for {summary.get('target', 'unknown')}",
            f"Tech stack: {', '.join(summary.get('tech_stack', []))}",
            f"Total findings: {summary.get('total_findings', 0)}",
            f"Critical: {summary.get('critical', 0)}",
            f"Techniques used: {', '.join(summary.get('techniques', []))}",
            f"Lessons: {summary.get('lessons', '')}",
        ]
        return "\n".join(parts)

    def _anonymize(self, text: str) -> str:
        """Strip PII and sensitive details before storing."""
        for pattern, replacement in ANONYMIZE_PATTERNS:
            text = re.sub(pattern, replacement, text)
        return text
