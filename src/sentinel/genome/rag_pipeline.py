"""RAGPipeline -- Retrieval-Augmented Generation for security decisions.

Before any LLM decision, retrieve relevant past patterns:
- "We've seen this tech stack before, here's what worked"
- "This payload was effective against similar endpoints"
- "This defense blocked previous attempts, try alternative"
"""

from typing import Any

from sentinel.core import get_logger
from sentinel.genome.embedding_store import EmbeddingStore, EmbeddingRecord

logger = get_logger(__name__)


class RAGPipeline:
    """Adds RAG context to LLM prompts for grounded security decisions.

    Flow:
    1. Take input context (target info, current hypothesis, tech stack)
    2. Generate embedding of input
    3. Search pgvector for similar past patterns
    4. Inject relevant patterns into LLM prompt
    5. Return grounded LLM response
    """

    def __init__(
        self,
        embedding_store: EmbeddingStore,
        embedding_client: Any | None = None,
    ):
        self.store = embedding_store
        self._embedding_client = embedding_client

    @property
    def embedding_client(self) -> Any:
        """Lazy-load embedding client."""
        if self._embedding_client is None:
            from sentinel.agents.llm_client import get_embedding_client
            self._embedding_client = get_embedding_client()
        return self._embedding_client

    async def generate_embedding(self, text: str) -> list[float]:
        """Generate embedding vector from text."""
        return await self.embedding_client.embed(text)

    async def retrieve_context(
        self,
        query: str,
        category: str | None = None,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Retrieve relevant past patterns for a given query."""
        embedding = await self.generate_embedding(query)
        results = await self.store.search(
            query_embedding=embedding,
            category=category,
            limit=limit,
            min_confidence=0.3,
        )
        return [
            {
                "content": r.content,
                "category": r.category,
                "confidence": r.confidence,
                "metadata": r.metadata,
                "success_rate": r.success_count / max(r.success_count + r.failure_count, 1),
            }
            for r in results
        ]

    async def grounded_completion(
        self,
        prompt: str,
        context_query: str,
        category: str | None = None,
    ) -> str:
        """LLM completion with RAG-grounded context.

        Injects relevant past patterns into the prompt before sending to LLM.
        """
        # Retrieve relevant context
        context = await self.retrieve_context(context_query, category)

        if context:
            context_str = "\n\n".join([
                f"[Past Pattern | Confidence: {c['confidence']:.0%} | "
                f"Success Rate: {c['success_rate']:.0%}]\n{c['content']}"
                for c in context
            ])
            grounded_prompt = (
                f"You have access to relevant patterns from past engagements:\n\n"
                f"{context_str}\n\n---\n\n{prompt}\n\n"
                f"Use the past patterns to inform your decision, "
                f"but validate against the current context."
            )
        else:
            grounded_prompt = prompt

        from sentinel.agents.llm_client import get_llm_client, LLMMessage
        llm = get_llm_client()
        response = await llm.complete(
            messages=[LLMMessage(role="user", content=grounded_prompt)],
        )
        return response.content

    async def embed_finding(self, finding: dict[str, Any], engagement_id: str) -> None:
        """Embed a verified finding for future retrieval."""
        content = (
            f"Vulnerability: {finding.get('category', 'unknown')}\n"
            f"Target: {finding.get('target_url', '')}\n"
            f"Severity: {finding.get('severity', 'unknown')}\n"
            f"Evidence: {finding.get('evidence', '')}\n"
            f"Remediation: {finding.get('remediation', '')}"
        )

        embedding = await self.generate_embedding(content)

        record = EmbeddingRecord(
            id=f"{engagement_id}:{finding.get('hypothesis_id', 'unknown')}",
            content=content,
            embedding=embedding,
            category="vulnerability",
            metadata={
                "category": finding.get("category"),
                "severity": finding.get("severity"),
                "target_url": finding.get("target_url"),
                "mitre_technique": finding.get("mitre_technique", ""),
            },
            engagement_id=engagement_id,
            confidence=0.5,
            success_count=1 if finding.get("verified") else 0,
            failure_count=0 if finding.get("verified") else 1,
        )

        await self.store.store(record)
        logger.debug("Embedded finding", record_id=record.id, category=record.category)

    async def embed_exploit(
        self,
        exploit_data: dict[str, Any],
        engagement_id: str,
        success: bool,
    ) -> None:
        """Embed an exploit attempt result for future retrieval."""
        content = (
            f"Exploit: {exploit_data.get('technique', 'unknown')}\n"
            f"Target: {exploit_data.get('target_url', '')}\n"
            f"Payload: {exploit_data.get('payload', '')}\n"
            f"Result: {'success' if success else 'failure'}\n"
            f"Tech Stack: {exploit_data.get('tech_stack', '')}"
        )

        embedding = await self.generate_embedding(content)

        record = EmbeddingRecord(
            id=f"{engagement_id}:exploit:{exploit_data.get('vuln_id', 'unknown')}",
            content=content,
            embedding=embedding,
            category="exploit",
            metadata={
                "technique": exploit_data.get("technique"),
                "tech_stack": exploit_data.get("tech_stack"),
                "success": success,
            },
            engagement_id=engagement_id,
            confidence=0.8 if success else 0.2,
            success_count=1 if success else 0,
            failure_count=0 if success else 1,
        )

        await self.store.store(record)
