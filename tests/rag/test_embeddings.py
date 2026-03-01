import pytest

from sentinel.rag.embeddings import EmbeddingManager, CHUNK_SIZE, CHUNK_OVERLAP


class TestEmbeddingManager:
    def setup_method(self):
        self.mgr = EmbeddingManager()

    def test_chunk_text_produces_multiple_chunks(self):
        text = "A" * 10000
        chunks = self.mgr.chunk_text(text, {"source": "test"})
        assert len(chunks) > 1
        assert all("chunk_id" in c for c in chunks)
        assert all("text" in c for c in chunks)
        assert all("metadata" in c for c in chunks)

    def test_chunk_text_overlap(self):
        text = "A" * 10000
        chunks = self.mgr.chunk_text(text, {"source": "test"})
        if len(chunks) > 1:
            # Second chunk starts before first chunk ends
            assert chunks[0]["metadata"]["char_end"] > chunks[1]["metadata"]["char_start"]

    def test_chunk_empty_text(self):
        chunks = self.mgr.chunk_text("", {})
        assert len(chunks) == 0

    def test_chunk_whitespace_only(self):
        chunks = self.mgr.chunk_text("   \n\t  ", {})
        assert len(chunks) == 0

    def test_chunk_small_text_single_chunk(self):
        chunks = self.mgr.chunk_text("Hello world", {"source": "test"})
        assert len(chunks) == 1
        assert chunks[0]["text"] == "Hello world"

    def test_chunk_ids_are_unique(self):
        text = "X" * 20000
        chunks = self.mgr.chunk_text(text, {"source": "test"})
        ids = [c["chunk_id"] for c in chunks]
        assert len(ids) == len(set(ids))

    def test_chunk_metadata_preserved(self):
        chunks = self.mgr.chunk_text("test text", {"source": "finding", "vuln_type": "sqli"})
        assert chunks[0]["metadata"]["source"] == "finding"
        assert chunks[0]["metadata"]["vuln_type"] == "sqli"

    def test_chunk_has_char_positions(self):
        text = "A" * 10000
        chunks = self.mgr.chunk_text(text, {"source": "test"})
        for c in chunks:
            assert "char_start" in c["metadata"]
            assert "char_end" in c["metadata"]
            assert c["metadata"]["char_start"] < c["metadata"]["char_end"]

    @pytest.mark.asyncio
    async def test_embed_text_requires_client(self):
        with pytest.raises(RuntimeError, match="OpenAI client required"):
            await self.mgr.embed_text("test")

    @pytest.mark.asyncio
    async def test_embed_batch_empty(self):
        result = await self.mgr.embed_batch([])
        assert result == []
