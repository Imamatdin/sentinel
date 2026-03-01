"""
HyDE -- Hypothetical Document Embeddings.

Instead of embedding the raw query, ask the LLM to generate a hypothetical
document that would answer the query, then embed THAT. Gets 10-20% better
recall than naive query embedding (Gao et al., 2022).
"""

from sentinel.logging_config import get_logger

logger = get_logger(__name__)

HYDE_SYSTEM_PROMPT = """You are a penetration testing knowledge base.
Given a security query, generate a detailed hypothetical document that would
perfectly answer this query. Include specific technical details, tool names,
payload examples, and exploitation steps. Write as if this is an entry in a
pentest knowledge base."""


class HyDEGenerator:
    """Generate hypothetical documents for improved retrieval."""

    def __init__(self, llm_client, router=None):
        self.llm = llm_client
        self.router = router

    async def generate_hypothetical(self, query: str) -> str:
        """Generate a hypothetical document that would answer the query.

        Example:
          Query: "How to test Django IDOR on user profile endpoints"
          HyDE output: "To test for IDOR on Django user profile endpoints,
                        first authenticate as user A and note the profile URL
                        /api/users/42/. Then authenticate as user B and request
                        /api/users/42/. If user B receives user A's data..."
        """
        from sentinel.agents.llm_client import LLMMessage

        messages = [
            LLMMessage(
                role="user",
                content=(
                    f"Query: {query}\n\n"
                    "Generate a detailed hypothetical pentest knowledge base entry "
                    "that answers this query:"
                ),
            ),
        ]

        response = await self.llm.complete(
            messages, system=HYDE_SYSTEM_PROMPT,
        )

        return response
