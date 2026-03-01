import pytest

from sentinel.rag.vector_store import VectorStore, SearchResult, SCHEMA_SQL


class TestVectorStoreRRF:
    def setup_method(self):
        self.store = VectorStore(pool=None)

    def test_rrf_merge_shared_item_ranks_highest(self):
        a = [
            SearchResult("c1", "text1", {}, 0.9),
            SearchResult("c2", "text2", {}, 0.8),
        ]
        b = [
            SearchResult("c2", "text2", {}, 0.7),
            SearchResult("c3", "text3", {}, 0.6),
        ]
        merged = self.store._rrf_merge(a, b, top_k=3)
        # c2 appears in both lists, should rank highest
        assert merged[0].chunk_id == "c2"

    def test_rrf_merge_respects_top_k(self):
        a = [SearchResult(f"a{i}", f"text{i}", {}, 0.9 - i * 0.1) for i in range(5)]
        b = [SearchResult(f"b{i}", f"text{i}", {}, 0.8 - i * 0.1) for i in range(5)]
        merged = self.store._rrf_merge(a, b, top_k=3)
        assert len(merged) == 3

    def test_rrf_merge_empty_lists(self):
        merged = self.store._rrf_merge([], [], top_k=5)
        assert merged == []

    def test_rrf_merge_one_empty(self):
        a = [SearchResult("c1", "text1", {}, 0.9)]
        merged = self.store._rrf_merge(a, [], top_k=5)
        assert len(merged) == 1
        assert merged[0].chunk_id == "c1"

    def test_rrf_merge_all_same(self):
        """When both lists have the same items, deduplication works."""
        items = [SearchResult("c1", "t1", {}, 0.9), SearchResult("c2", "t2", {}, 0.8)]
        merged = self.store._rrf_merge(items, items, top_k=5)
        assert len(merged) == 2


class TestSchemaSQL:
    def test_schema_creates_table(self):
        assert "CREATE TABLE IF NOT EXISTS knowledge_chunks" in SCHEMA_SQL

    def test_schema_creates_hnsw_index(self):
        assert "hnsw" in SCHEMA_SQL.lower()

    def test_schema_creates_gin_index(self):
        assert "gin" in SCHEMA_SQL.lower()

    def test_schema_creates_vector_extension(self):
        assert "CREATE EXTENSION IF NOT EXISTS vector" in SCHEMA_SQL


class TestSearchResult:
    def test_dataclass(self):
        r = SearchResult("chunk1", "some text", {"key": "val"}, 0.95)
        assert r.chunk_id == "chunk1"
        assert r.similarity == 0.95
