import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.rag.hyde import HyDEGenerator, HYDE_SYSTEM_PROMPT


class TestHyDEGenerator:
    def test_system_prompt_exists(self):
        assert "penetration testing" in HYDE_SYSTEM_PROMPT.lower()

    @pytest.mark.asyncio
    async def test_generate_hypothetical(self):
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(
            return_value="To test IDOR on Django, authenticate as user A..."
        )

        hyde = HyDEGenerator(llm_client=mock_llm)
        result = await hyde.generate_hypothetical("How to test Django IDOR")

        assert "IDOR" in result
        mock_llm.complete.assert_called_once()
        # Verify system prompt was passed
        call_kwargs = mock_llm.complete.call_args
        assert call_kwargs.kwargs.get("system") == HYDE_SYSTEM_PROMPT

    @pytest.mark.asyncio
    async def test_generate_passes_query_in_message(self):
        mock_llm = MagicMock()
        mock_llm.complete = AsyncMock(return_value="hypothetical doc")

        hyde = HyDEGenerator(llm_client=mock_llm)
        await hyde.generate_hypothetical("test SSRF on AWS")

        messages = mock_llm.complete.call_args.args[0]
        assert any("SSRF" in m.content for m in messages)
