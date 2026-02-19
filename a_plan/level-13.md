# LEVEL 13: GraphRAG + HyDE Retrieval System

## Context
Sentinel has pgvector installed but no RAG code. This level wires it up with security-specific embeddings, HyDE (Hypothetical Document Embeddings) for 10-20% better recall, and GraphRAG that combines Neo4j entity traversal with vector retrieval for multi-hop queries.

Research: Block 7 (RAG Architecture). HyDE, GraphRAG, RAPTOR, ColBERT patterns. SecureBERT/CySecBERT for domain-tuned embeddings.

## Why
Without RAG, every engagement starts from scratch. With RAG, Sentinel retrieves: "Last time we saw Flask + PostgreSQL + /api/users, the IDOR on user_id worked 7/10 times. Here's the payload that worked." This is the data moat — it gets smarter with every scan.

---

## Files to Create

### `src/sentinel/rag/__init__.py`
```python
"""RAG (Retrieval-Augmented Generation) system for cross-engagement learning."""
```

### `src/sentinel/rag/embeddings.py`
```python
"""
Embedding Manager — Generates and manages vector embeddings for security knowledge.

Strategy:
- Use OpenAI text-embedding-3-small for general text (cheap, good enough)
- Chunk size: 500-1000 tokens with 10-20% overlap
- Store in pgvector with HNSW index for fast retrieval
"""
import hashlib
from dataclasses import dataclass
from sentinel.logging import get_logger

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
    
    def chunk_text(self, text: str, metadata: dict = None) -> list[dict]:
        """Split text into overlapping chunks for embedding."""
        metadata = metadata or {}
        chars_per_chunk = CHUNK_SIZE * 4
        overlap_chars = CHUNK_OVERLAP * 4
        
        chunks = []
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
```

### `src/sentinel/rag/vector_store.py`
```python
"""
pgvector Store — Manages vector storage and retrieval in PostgreSQL.

Tables:
  knowledge_chunks: chunk_id, text, embedding (vector), metadata (jsonb), created_at
  
Indexes:
  HNSW on embedding column for approximate nearest neighbor search
  GIN on metadata for filtering by tech_stack, vuln_type, etc.
"""
import json
from dataclasses import dataclass
from sentinel.logging import get_logger

logger = get_logger(__name__)

SCHEMA_SQL = """
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS knowledge_chunks (
    id SERIAL PRIMARY KEY,
    chunk_id TEXT UNIQUE NOT NULL,
    text TEXT NOT NULL,
    embedding vector(1536),
    metadata JSONB DEFAULT '{}',
    engagement_id TEXT,
    vuln_type TEXT,
    tech_stack TEXT[],
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_chunks_embedding 
    ON knowledge_chunks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 32, ef_construction = 128);

CREATE INDEX IF NOT EXISTS idx_chunks_metadata 
    ON knowledge_chunks USING gin (metadata);

CREATE INDEX IF NOT EXISTS idx_chunks_vuln_type 
    ON knowledge_chunks (vuln_type);

CREATE INDEX IF NOT EXISTS idx_chunks_tech_stack 
    ON knowledge_chunks USING gin (tech_stack);
"""


@dataclass
class SearchResult:
    chunk_id: str
    text: str
    metadata: dict
    similarity: float


class VectorStore:
    """pgvector-backed vector store for security knowledge."""
    
    def __init__(self, pool):
        """
        Args:
            pool: asyncpg connection pool to PostgreSQL with pgvector extension
        """
        self.pool = pool
    
    async def initialize(self):
        """Create tables and indexes."""
        async with self.pool.acquire() as conn:
            await conn.execute(SCHEMA_SQL)
        logger.info("Vector store initialized")
    
    async def upsert(self, chunk_id: str, text: str, embedding: list[float],
                     metadata: dict = None, engagement_id: str = "",
                     vuln_type: str = "", tech_stack: list[str] = None):
        """Insert or update a knowledge chunk."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO knowledge_chunks (chunk_id, text, embedding, metadata, 
                                              engagement_id, vuln_type, tech_stack)
                VALUES ($1, $2, $3::vector, $4, $5, $6, $7)
                ON CONFLICT (chunk_id) 
                DO UPDATE SET text = $2, embedding = $3::vector, metadata = $4
                """,
                chunk_id, text, str(embedding), json.dumps(metadata or {}),
                engagement_id, vuln_type, tech_stack or [],
            )
    
    async def search(self, query_embedding: list[float], top_k: int = 10,
                     vuln_type: str = None, tech_stack: str = None,
                     min_similarity: float = 0.5) -> list[SearchResult]:
        """
        Semantic search with optional metadata filtering.
        Uses cosine similarity via pgvector.
        """
        filters = []
        params = [str(query_embedding), top_k]
        param_idx = 3
        
        if vuln_type:
            filters.append(f"vuln_type = ${param_idx}")
            params.append(vuln_type)
            param_idx += 1
        
        if tech_stack:
            filters.append(f"${param_idx} = ANY(tech_stack)")
            params.append(tech_stack)
            param_idx += 1
        
        where_clause = "WHERE " + " AND ".join(filters) if filters else ""
        
        query = f"""
            SELECT chunk_id, text, metadata, 
                   1 - (embedding <=> $1::vector) AS similarity
            FROM knowledge_chunks
            {where_clause}
            ORDER BY embedding <=> $1::vector
            LIMIT $2
        """
        
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(query, *params)
        
        return [
            SearchResult(
                chunk_id=row["chunk_id"],
                text=row["text"],
                metadata=json.loads(row["metadata"]) if isinstance(row["metadata"], str) else row["metadata"],
                similarity=float(row["similarity"]),
            )
            for row in rows
            if float(row["similarity"]) >= min_similarity
        ]
    
    async def hybrid_search(self, query_embedding: list[float], keyword_query: str,
                            top_k: int = 10) -> list[SearchResult]:
        """
        Hybrid search: combine vector similarity with keyword BM25-style matching.
        Uses Reciprocal Rank Fusion (RRF) to merge results.
        """
        # Vector search
        vector_results = await self.search(query_embedding, top_k=top_k * 2)
        
        # Keyword search (simple ILIKE for now; upgrade to tsvector for production)
        async with self.pool.acquire() as conn:
            keyword_rows = await conn.fetch(
                """
                SELECT chunk_id, text, metadata, 0.5 AS similarity
                FROM knowledge_chunks
                WHERE text ILIKE $1
                LIMIT $2
                """,
                f"%{keyword_query}%", top_k * 2,
            )
        
        keyword_results = [
            SearchResult(r["chunk_id"], r["text"],
                        json.loads(r["metadata"]) if isinstance(r["metadata"], str) else r["metadata"],
                        float(r["similarity"]))
            for r in keyword_rows
        ]
        
        # RRF fusion
        return self._rrf_merge(vector_results, keyword_results, top_k)
    
    def _rrf_merge(self, list_a: list[SearchResult], list_b: list[SearchResult],
                   top_k: int, k: int = 60) -> list[SearchResult]:
        """Reciprocal Rank Fusion to merge two ranked lists."""
        scores = {}
        items = {}
        
        for rank, item in enumerate(list_a):
            scores[item.chunk_id] = scores.get(item.chunk_id, 0) + 1.0 / (k + rank + 1)
            items[item.chunk_id] = item
        
        for rank, item in enumerate(list_b):
            scores[item.chunk_id] = scores.get(item.chunk_id, 0) + 1.0 / (k + rank + 1)
            items[item.chunk_id] = item
        
        sorted_ids = sorted(scores, key=scores.get, reverse=True)[:top_k]
        return [items[cid] for cid in sorted_ids if cid in items]
```

### `src/sentinel/rag/hyde.py`
```python
"""
HyDE — Hypothetical Document Embeddings.

Instead of embedding the raw query, ask the LLM to generate a hypothetical
document that would answer the query, then embed THAT. Gets 10-20% better
recall than naive query embedding (Gao et al., 2022).
"""
from sentinel.logging import get_logger

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
        """
        Generate a hypothetical document that would answer the query.
        
        Example:
          Query: "How to test Django IDOR on user profile endpoints"
          HyDE output: "To test for IDOR on Django user profile endpoints,
                        first authenticate as user A and note the profile URL
                        /api/users/42/. Then authenticate as user B and request
                        /api/users/42/. If user B receives user A's data..."
        """
        prompt = f"Query: {query}\n\nGenerate a detailed hypothetical pentest knowledge base entry that answers this query:"
        
        if self.router:
            from sentinel.llm.model_router import TaskType
            model = self.router.route(TaskType.SUMMARIZE_SHORT)
            response = await self.llm.complete(prompt, system=HYDE_SYSTEM_PROMPT,
                                               model=model.model_id, provider=model.provider)
        else:
            response = await self.llm.complete(prompt, system=HYDE_SYSTEM_PROMPT)
        
        return response
```

### `src/sentinel/rag/graph_rag.py`
```python
"""
GraphRAG — Combines Neo4j knowledge graph traversal with vector retrieval.

For multi-hop queries ("What attack chains exist from exposed service X 
to crown jewel Y through known vulnerabilities?"), naive vector search fails.
GraphRAG:
1. Extract entities from query
2. Find those entities in Neo4j
3. Traverse relationships to find connected context
4. Use that context to filter/enhance vector search
"""
from dataclasses import dataclass
from sentinel.rag.vector_store import VectorStore, SearchResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class GraphContext:
    entities: list[dict]          # Matched nodes from Neo4j
    relationships: list[dict]     # Edges connecting entities
    subgraph_text: str            # Natural language summary of graph context


class GraphRAG:
    """Combine graph traversal with vector retrieval."""
    
    def __init__(self, neo4j_client, vector_store: VectorStore, embedding_manager):
        self.graph = neo4j_client
        self.vectors = vector_store
        self.embeddings = embedding_manager
    
    async def search(self, query: str, engagement_id: str = "",
                     top_k: int = 10) -> list[SearchResult]:
        """
        GraphRAG search:
        1. Extract tech/vuln entities from query
        2. Find related nodes in Neo4j
        3. Build context from graph relationships
        4. Enhance vector search with graph context
        """
        # Step 1: Extract key entities from query
        entities = self._extract_entities(query)
        
        # Step 2: Find in Neo4j
        graph_context = await self._get_graph_context(entities, engagement_id)
        
        # Step 3: Enhance query with graph context
        enhanced_query = f"{query}\n\nGraph context: {graph_context.subgraph_text}"
        
        # Step 4: Vector search with enhanced query
        embedding = await self.embeddings.embed_text(enhanced_query)
        results = await self.vectors.search(embedding, top_k=top_k)
        
        return results
    
    def _extract_entities(self, query: str) -> list[str]:
        """Simple entity extraction from query (upgrade to NER later)."""
        # Look for known tech stack terms, vuln types, tool names
        known_terms = {
            "tech": ["django", "flask", "express", "spring", "react", "nginx",
                     "apache", "postgresql", "mongodb", "redis", "docker", "k8s"],
            "vuln": ["sqli", "xss", "idor", "ssrf", "rce", "lfi", "xxe",
                     "deserialization", "csrf", "bola", "injection"],
            "tool": ["nmap", "nuclei", "zap", "sqlmap", "burp", "ffuf"],
        }
        
        entities = []
        query_lower = query.lower()
        for category, terms in known_terms.items():
            for term in terms:
                if term in query_lower:
                    entities.append(term)
        
        return entities
    
    async def _get_graph_context(self, entities: list[str], 
                                  engagement_id: str) -> GraphContext:
        """Query Neo4j for context around extracted entities."""
        if not entities:
            return GraphContext([], [], "No graph entities found.")
        
        # Query for nodes matching entity names (services, vulns, etc.)
        cypher = """
        MATCH (n)
        WHERE toLower(n.name) IN $entities 
           OR toLower(n.service_name) IN $entities
           OR toLower(n.vuln_type) IN $entities
        OPTIONAL MATCH (n)-[r]-(m)
        RETURN n, type(r) as rel_type, m
        LIMIT 50
        """
        
        try:
            results = await self.graph.query(cypher, {"entities": entities})
            
            nodes = []
            rels = []
            for record in results:
                if record.get("n"):
                    nodes.append(dict(record["n"]))
                if record.get("rel_type") and record.get("m"):
                    rels.append({
                        "from": str(record.get("n", {}).get("name", "")),
                        "type": record["rel_type"],
                        "to": str(record.get("m", {}).get("name", "")),
                    })
            
            # Build natural language summary
            summary_parts = []
            for node in nodes[:10]:
                summary_parts.append(f"Found: {node.get('name', 'unknown')} (labels: {node.get('labels', [])})")
            for rel in rels[:10]:
                summary_parts.append(f"  {rel['from']} --[{rel['type']}]--> {rel['to']}")
            
            return GraphContext(
                entities=nodes,
                relationships=rels,
                subgraph_text="\n".join(summary_parts) or "No matching graph data.",
            )
        except Exception as e:
            logger.error(f"GraphRAG Neo4j query failed: {e}")
            return GraphContext([], [], f"Graph query error: {e}")
```

### `src/sentinel/rag/knowledge_ingestor.py`
```python
"""
Knowledge Ingestor — Processes engagement results into the RAG knowledge base.

After each engagement:
1. Extract key findings, techniques, payloads
2. Anonymize (strip IPs, hostnames, paths)
3. Chunk and embed
4. Store in pgvector with metadata tags
"""
import re
from sentinel.rag.embeddings import EmbeddingManager
from sentinel.rag.vector_store import VectorStore
from sentinel.logging import get_logger

logger = get_logger(__name__)

# Patterns to anonymize
ANONYMIZE_PATTERNS = [
    (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', '[IP]'),
    (r'https?://[^\s]+', '[URL]'),
    (r'/home/[^\s/]+', '/home/[USER]'),
    (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', '[EMAIL]'),
    (r'Bearer [A-Za-z0-9\-._~+/]+=*', 'Bearer [TOKEN]'),
    (r'[A-Fa-f0-9]{32,}', '[HASH]'),
]


class KnowledgeIngestor:
    """Ingest engagement results into RAG knowledge base."""
    
    def __init__(self, embedding_manager: EmbeddingManager, vector_store: VectorStore):
        self.embeddings = embedding_manager
        self.store = vector_store
    
    async def ingest_finding(self, finding: dict, engagement_id: str):
        """Ingest a single verified finding into the knowledge base."""
        # Build knowledge text from finding
        text = self._finding_to_text(finding)
        
        # Anonymize
        text = self._anonymize(text)
        
        # Chunk
        chunks = self.embeddings.chunk_text(text, metadata={
            "engagement_id": engagement_id,
            "vuln_type": finding.get("category", ""),
            "source": "finding",
        })
        
        # Embed and store
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
        
        logger.info(f"Ingested finding {finding.get('finding_id', 'unknown')} as {len(chunks)} chunks")
    
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
```

---

## Tests

### `tests/rag/test_embeddings.py`
```python
import pytest
from sentinel.rag.embeddings import EmbeddingManager

class TestEmbeddingManager:
    def test_chunk_text(self):
        mgr = EmbeddingManager()
        text = "A" * 10000
        chunks = mgr.chunk_text(text, {"source": "test"})
        assert len(chunks) > 1
        assert all("chunk_id" in c for c in chunks)
        # Check overlap
        if len(chunks) > 1:
            assert chunks[0]["metadata"]["char_end"] > chunks[1]["metadata"]["char_start"]
    
    def test_chunk_empty(self):
        mgr = EmbeddingManager()
        chunks = mgr.chunk_text("", {})
        assert len(chunks) == 0
```

### `tests/rag/test_vector_store.py`
```python
import pytest
from sentinel.rag.vector_store import VectorStore, SearchResult

class TestVectorStoreRRF:
    def test_rrf_merge(self):
        store = VectorStore(pool=None)
        a = [SearchResult("c1", "text1", {}, 0.9), SearchResult("c2", "text2", {}, 0.8)]
        b = [SearchResult("c2", "text2", {}, 0.7), SearchResult("c3", "text3", {}, 0.6)]
        merged = store._rrf_merge(a, b, top_k=3)
        # c2 should rank highest (appears in both lists)
        assert merged[0].chunk_id == "c2"
```

### `tests/rag/test_knowledge_ingestor.py`
```python
import pytest
from sentinel.rag.knowledge_ingestor import KnowledgeIngestor, ANONYMIZE_PATTERNS
import re

class TestAnonymization:
    def test_ip_anonymized(self):
        ingestor = KnowledgeIngestor(None, None)
        text = "Found at 192.168.1.100 on port 8080"
        result = ingestor._anonymize(text)
        assert "192.168.1.100" not in result
        assert "[IP]" in result
    
    def test_email_anonymized(self):
        ingestor = KnowledgeIngestor(None, None)
        result = ingestor._anonymize("Contact admin@example.com for details")
        assert "admin@example.com" not in result
        assert "[EMAIL]" in result
    
    def test_bearer_token_anonymized(self):
        ingestor = KnowledgeIngestor(None, None)
        result = ingestor._anonymize("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc")
        assert "eyJ" not in result
```

---

## Acceptance Criteria
- [ ] pgvector schema created with HNSW index and metadata GIN index
- [ ] EmbeddingManager chunks text with overlap
- [ ] VectorStore upserts and searches with cosine similarity
- [ ] Hybrid search with RRF fusion works
- [ ] HyDE generates hypothetical documents for improved retrieval
- [ ] GraphRAG combines Neo4j traversal with vector search
- [ ] KnowledgeIngestor anonymizes PII before storage
- [ ] Cross-engagement learning: findings from past scans inform future ones
- [ ] All tests pass