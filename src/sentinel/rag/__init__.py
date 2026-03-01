"""RAG (Retrieval-Augmented Generation) system for cross-engagement learning."""

from sentinel.rag.embeddings import EmbeddingManager, EmbeddedChunk, CHUNK_SIZE, CHUNK_OVERLAP, EMBEDDING_DIM
from sentinel.rag.vector_store import VectorStore, SearchResult, SCHEMA_SQL
from sentinel.rag.hyde import HyDEGenerator
from sentinel.rag.graph_rag import GraphRAG, GraphContext
from sentinel.rag.knowledge_ingestor import KnowledgeIngestor

__all__ = [
    "EmbeddingManager", "EmbeddedChunk", "CHUNK_SIZE", "CHUNK_OVERLAP", "EMBEDDING_DIM",
    "VectorStore", "SearchResult", "SCHEMA_SQL",
    "HyDEGenerator",
    "GraphRAG", "GraphContext",
    "KnowledgeIngestor",
]
