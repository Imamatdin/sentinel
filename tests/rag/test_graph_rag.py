import pytest
from unittest.mock import AsyncMock, MagicMock

from sentinel.rag.graph_rag import GraphRAG, GraphContext
from sentinel.rag.vector_store import VectorStore, SearchResult


class TestGraphRAGEntityExtraction:
    def setup_method(self):
        self.rag = GraphRAG(
            neo4j_client=MagicMock(),
            vector_store=MagicMock(),
            embedding_manager=MagicMock(),
        )

    def test_extract_tech_entities(self):
        entities = self.rag._extract_entities("How to attack django with postgresql")
        assert "django" in entities
        assert "postgresql" in entities

    def test_extract_vuln_entities(self):
        entities = self.rag._extract_entities("test for sqli and xss on the target")
        assert "sqli" in entities
        assert "xss" in entities

    def test_extract_tool_entities(self):
        entities = self.rag._extract_entities("use nmap and nuclei to scan")
        assert "nmap" in entities
        assert "nuclei" in entities

    def test_extract_no_entities(self):
        entities = self.rag._extract_entities("hello world")
        assert entities == []

    def test_extract_case_insensitive(self):
        entities = self.rag._extract_entities("DJANGO SQLI NMAP")
        assert "django" in entities
        assert "sqli" in entities
        assert "nmap" in entities


class TestGraphRAGGraphContext:
    @pytest.mark.asyncio
    async def test_empty_entities_returns_empty_context(self):
        rag = GraphRAG(
            neo4j_client=MagicMock(),
            vector_store=MagicMock(),
            embedding_manager=MagicMock(),
        )
        ctx = await rag._get_graph_context([], "eng-1")
        assert ctx.entities == []
        assert ctx.relationships == []
        assert "No graph entities" in ctx.subgraph_text

    @pytest.mark.asyncio
    async def test_graph_context_from_neo4j(self):
        mock_graph = MagicMock()
        mock_graph.query = AsyncMock(return_value=[
            {
                "n": {"name": "django", "labels": ["Technology"]},
                "rel_type": "RUNS_ON",
                "m": {"name": "server1", "labels": ["Host"]},
            },
        ])

        rag = GraphRAG(
            neo4j_client=mock_graph,
            vector_store=MagicMock(),
            embedding_manager=MagicMock(),
        )
        ctx = await rag._get_graph_context(["django"], "eng-1")
        assert len(ctx.entities) >= 1
        assert len(ctx.relationships) >= 1
        assert "django" in ctx.subgraph_text

    @pytest.mark.asyncio
    async def test_graph_context_handles_query_error(self):
        mock_graph = MagicMock()
        mock_graph.query = AsyncMock(side_effect=Exception("connection lost"))

        rag = GraphRAG(
            neo4j_client=mock_graph,
            vector_store=MagicMock(),
            embedding_manager=MagicMock(),
        )
        ctx = await rag._get_graph_context(["django"], "eng-1")
        assert "error" in ctx.subgraph_text.lower()


class TestGraphRAGSearch:
    @pytest.mark.asyncio
    async def test_search_combines_graph_and_vector(self):
        mock_graph = MagicMock()
        mock_graph.query = AsyncMock(return_value=[])

        mock_embeddings = MagicMock()
        mock_embeddings.embed_text = AsyncMock(return_value=[0.1] * 1536)

        mock_vectors = MagicMock()
        mock_vectors.search = AsyncMock(return_value=[
            SearchResult("c1", "Django IDOR payload", {}, 0.85),
        ])

        rag = GraphRAG(
            neo4j_client=mock_graph,
            vector_store=mock_vectors,
            embedding_manager=mock_embeddings,
        )

        results = await rag.search("django idor attack")
        assert len(results) == 1
        assert results[0].chunk_id == "c1"
        mock_embeddings.embed_text.assert_called_once()
        mock_vectors.search.assert_called_once()
