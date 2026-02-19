# PHASE 8: RAG & Genome Feedback Loop

## Context

Read MASTER_PLAN.md and Phases 5-7 first. pgvector is in pyproject.toml but unused. The Security Genome stores patterns in SQLite but doesn't feed back into attacks. This phase wires cross-engagement learning.

## What This Phase Builds

1. **pgvector embedding store** — Embed vulnerability patterns, exploit traces, and remediation for RAG retrieval
2. **RAG grounding pipeline** — Before any LLM decision, retrieve relevant past findings as context
3. **Genome 2.0** — Attack technique clustering, payload fingerprinting, defense effectiveness mapping, root cause taxonomy
4. **Cross-engagement learning** — Query genome DB before starting new tests to prioritize based on historical success
5. **Confidence scoring** — Update pattern confidence based on success/failure across engagements
6. **Exposure Score** — Chain depth × privilege escalation × data sensitivity × exploit confidence (replaces static CVSS)

## Why It Matters

Without learning, every engagement starts from zero. Genome 2.0 turns Sentinel into a system that gets smarter with every pentest — like Horizon3's knowledge graph that improves with scale. RAG grounding reduces LLM hallucination by providing real exploit evidence as context.

---

## File-by-File Implementation

### 1. `src/sentinel/genome/__init__.py`

Update existing init to export new modules.

### 2. `src/sentinel/genome/embedding_store.py`

```python
"""
EmbeddingStore — pgvector-backed vector store for security knowledge.

Stores embeddings of:
- Vulnerability patterns (description + evidence + remediation)
- Exploit payloads (what worked, what didn't, against what tech)
- Attack chains (multi-step sequences)
- Defense patterns (what blocked what)

Used for RAG retrieval before LLM decisions.
"""
import json
from dataclasses import dataclass
from typing import Optional
import asyncpg

from sentinel.config import get_config
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class EmbeddingRecord:
    id: str
    content: str           # The text that was embedded
    embedding: list[float] # The vector
    category: str          # "vulnerability", "exploit", "defense", "chain"
    metadata: dict         # Structured metadata (severity, tech_stack, etc.)
    engagement_id: str
    confidence: float      # 0.0-1.0, updated across engagements
    success_count: int
    failure_count: int


class EmbeddingStore:
    """
    pgvector-backed store for security pattern embeddings.
    
    Schema creates:
    - sentinel_embeddings table with vector(1536) column
    - HNSW index for fast cosine similarity search
    """
    
    def __init__(self):
        self.config = get_config()
        self.pool: Optional[asyncpg.Pool] = None
    
    async def initialize(self):
        """Create connection pool and ensure schema exists."""
        self.pool = await asyncpg.create_pool(
            self.config.get("postgres_url", "postgresql://localhost:5432/sentinel"),
            min_size=2,
            max_size=10,
        )
        
        async with self.pool.acquire() as conn:
            # Enable pgvector extension
            await conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
            
            # Create embeddings table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS sentinel_embeddings (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    embedding vector(1536),
                    category TEXT NOT NULL,
                    metadata JSONB DEFAULT '{}',
                    engagement_id TEXT,
                    confidence FLOAT DEFAULT 0.5,
                    success_count INTEGER DEFAULT 0,
                    failure_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                )
            """)
            
            # Create HNSW index for fast similarity search
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_embeddings_hnsw 
                ON sentinel_embeddings 
                USING hnsw (embedding vector_cosine_ops)
                WITH (m = 16, ef_construction = 64)
            """)
            
            # Category index for filtered search
            await conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_embeddings_category 
                ON sentinel_embeddings (category)
            """)
        
        logger.info("EmbeddingStore initialized")
    
    async def store(self, record: EmbeddingRecord):
        """Store or update an embedding record."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                INSERT INTO sentinel_embeddings (id, content, embedding, category, metadata, engagement_id, confidence, success_count, failure_count)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (id) DO UPDATE SET
                    embedding = EXCLUDED.embedding,
                    confidence = EXCLUDED.confidence,
                    success_count = EXCLUDED.success_count,
                    failure_count = EXCLUDED.failure_count,
                    updated_at = NOW()
            """, record.id, record.content, str(record.embedding), record.category,
                json.dumps(record.metadata), record.engagement_id, record.confidence,
                record.success_count, record.failure_count)
    
    async def search(
        self,
        query_embedding: list[float],
        category: Optional[str] = None,
        limit: int = 10,
        min_confidence: float = 0.0,
    ) -> list[EmbeddingRecord]:
        """Search for similar patterns using cosine similarity."""
        async with self.pool.acquire() as conn:
            if category:
                rows = await conn.fetch("""
                    SELECT *, 1 - (embedding <=> $1::vector) as similarity
                    FROM sentinel_embeddings
                    WHERE category = $2 AND confidence >= $3
                    ORDER BY embedding <=> $1::vector
                    LIMIT $4
                """, str(query_embedding), category, min_confidence, limit)
            else:
                rows = await conn.fetch("""
                    SELECT *, 1 - (embedding <=> $1::vector) as similarity
                    FROM sentinel_embeddings
                    WHERE confidence >= $2
                    ORDER BY embedding <=> $1::vector
                    LIMIT $3
                """, str(query_embedding), min_confidence, limit)
            
            return [
                EmbeddingRecord(
                    id=row["id"],
                    content=row["content"],
                    embedding=[],  # Don't return full vector
                    category=row["category"],
                    metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                    engagement_id=row["engagement_id"],
                    confidence=row["confidence"],
                    success_count=row["success_count"],
                    failure_count=row["failure_count"],
                )
                for row in rows
            ]
    
    async def update_confidence(self, record_id: str, success: bool):
        """Update confidence score based on exploit success/failure."""
        async with self.pool.acquire() as conn:
            if success:
                await conn.execute("""
                    UPDATE sentinel_embeddings 
                    SET success_count = success_count + 1,
                        confidence = (success_count + 1.0) / (success_count + failure_count + 1.0),
                        updated_at = NOW()
                    WHERE id = $1
                """, record_id)
            else:
                await conn.execute("""
                    UPDATE sentinel_embeddings 
                    SET failure_count = failure_count + 1,
                        confidence = (success_count + 0.0) / (success_count + failure_count + 1.0),
                        updated_at = NOW()
                    WHERE id = $1
                """, record_id)
    
    async def close(self):
        if self.pool:
            await self.pool.close()
```

### 3. `src/sentinel/genome/rag_pipeline.py`

```python
"""
RAGPipeline — Retrieval-Augmented Generation for security decisions.

Before any LLM decision, retrieve relevant past patterns:
- "We've seen this tech stack before, here's what worked"
- "This payload was effective against similar endpoints"
- "This defense blocked previous attempts, try alternative"
"""
from sentinel.genome.embedding_store import EmbeddingStore
from sentinel.llm.client import get_llm_client
from sentinel.logging import get_logger

logger = get_logger(__name__)


class RAGPipeline:
    """
    Adds RAG context to LLM prompts for grounded security decisions.
    
    Flow:
    1. Take input context (target info, current hypothesis, tech stack)
    2. Generate embedding of input
    3. Search pgvector for similar past patterns
    4. Inject relevant patterns into LLM prompt
    5. Return grounded LLM response
    """
    
    def __init__(self, embedding_store: EmbeddingStore):
        self.store = embedding_store
        self.embedding_client = get_llm_client(provider="openai", task_type="embedding")
    
    async def generate_embedding(self, text: str) -> list[float]:
        """Generate embedding vector from text using OpenAI."""
        response = await self.embedding_client.embed(text)
        return response
    
    async def retrieve_context(
        self,
        query: str,
        category: str = None,
        limit: int = 5,
    ) -> list[dict]:
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
        category: str = None,
        llm_provider: str = "claude",
    ) -> str:
        """
        LLM completion with RAG-grounded context.
        
        Injects relevant past patterns into the prompt before sending to LLM.
        """
        # Retrieve relevant context
        context = await self.retrieve_context(context_query, category)
        
        if context:
            context_str = "\n\n".join([
                f"[Past Pattern | Confidence: {c['confidence']:.0%} | Success Rate: {c['success_rate']:.0%}]\n{c['content']}"
                for c in context
            ])
            grounded_prompt = f"""You have access to relevant patterns from past engagements:

{context_str}

---

{prompt}

Use the past patterns to inform your decision, but validate against the current context."""
        else:
            grounded_prompt = prompt
        
        llm = get_llm_client(provider=llm_provider)
        return await llm.complete(grounded_prompt)
    
    async def embed_finding(self, finding: dict, engagement_id: str):
        """Embed a verified finding for future retrieval."""
        from sentinel.genome.embedding_store import EmbeddingRecord
        
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
```

### 4. `src/sentinel/genome/genome_v2.py`

```python
"""
Genome 2.0 — Cross-engagement learning engine.

Upgrades the existing genome from simple pattern storage to:
- Attack technique clustering (group similar exploits)
- Payload fingerprinting (track which payloads work against which tech)
- Root cause taxonomy (map findings to root causes)
- Defense effectiveness mapping (track what defenses block what)
- Exposure scoring (chain depth × privilege × sensitivity × confidence)
"""
from dataclasses import dataclass, field
from typing import Optional
from sentinel.genome.embedding_store import EmbeddingStore
from sentinel.genome.rag_pipeline import RAGPipeline
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ExposureScore:
    """
    Replaces static CVSS with context-aware exposure scoring.
    
    Score = chain_depth_factor × privilege_escalation_factor × data_sensitivity × exploit_confidence
    """
    chain_depth: int            # Steps in attack chain
    privilege_level: str        # "none", "user", "admin", "root"
    data_sensitivity: str       # "public", "internal", "confidential", "critical"
    exploit_confidence: float   # From genome: historical success rate
    
    @property
    def score(self) -> float:
        depth_factor = 1.0 / max(self.chain_depth, 1)  # Shorter chains = higher risk
        priv_weights = {"none": 0.2, "user": 0.5, "admin": 0.8, "root": 1.0}
        sens_weights = {"public": 0.2, "internal": 0.5, "confidential": 0.8, "critical": 1.0}
        
        return (
            depth_factor *
            priv_weights.get(self.privilege_level, 0.5) *
            sens_weights.get(self.data_sensitivity, 0.5) *
            self.exploit_confidence
        )
    
    @property
    def rating(self) -> str:
        s = self.score
        if s >= 0.7: return "CRITICAL"
        if s >= 0.5: return "HIGH"
        if s >= 0.3: return "MEDIUM"
        return "LOW"


@dataclass
class TechniqueCluster:
    """Group of related attack techniques."""
    cluster_id: str
    techniques: list[str]  # MITRE ATT&CK IDs
    avg_success_rate: float
    common_targets: list[str]  # Tech stacks this works against
    effective_defenses: list[str]  # What blocks these techniques


class GenomeV2:
    """
    Cross-engagement learning engine.
    
    Before new engagement:
    1. Query genome for target's tech stack → get historical success rates
    2. Prioritize hypotheses based on what worked before
    3. Suggest payloads ranked by historical effectiveness
    
    After engagement:
    4. Update success/failure counts for all patterns
    5. Cluster new techniques
    6. Map defense effectiveness
    7. Store new patterns for future retrieval
    """
    
    def __init__(self, embedding_store: EmbeddingStore, graph: GraphClient):
        self.store = embedding_store
        self.graph = graph
        self.rag = RAGPipeline(embedding_store)
    
    async def pre_engagement_intel(self, target_tech_stack: list[str]) -> dict:
        """
        Query genome for intelligence about target's tech stack.
        
        Returns:
        - Historically effective techniques for this tech stack
        - Payload recommendations ranked by success rate
        - Known defense patterns to expect
        - Suggested hypothesis priority adjustments
        """
        context = await self.rag.retrieve_context(
            query=f"Vulnerabilities in {', '.join(target_tech_stack)}",
            category="vulnerability",
            limit=20,
        )
        
        # Aggregate by technique
        technique_stats = {}
        for c in context:
            cat = c["metadata"].get("category", "unknown")
            if cat not in technique_stats:
                technique_stats[cat] = {"count": 0, "avg_confidence": 0, "total_success": 0}
            technique_stats[cat]["count"] += 1
            technique_stats[cat]["avg_confidence"] += c["confidence"]
            technique_stats[cat]["total_success"] += c["success_rate"]
        
        for cat in technique_stats:
            n = technique_stats[cat]["count"]
            technique_stats[cat]["avg_confidence"] /= n
            technique_stats[cat]["avg_success_rate"] = technique_stats[cat]["total_success"] / n
        
        return {
            "technique_stats": technique_stats,
            "recommended_order": sorted(
                technique_stats.keys(),
                key=lambda k: technique_stats[k]["avg_success_rate"],
                reverse=True
            ),
            "raw_context": context[:5],
        }
    
    async def post_engagement_learn(self, engagement_id: str, findings: list[dict]):
        """
        Learn from completed engagement.
        
        1. Embed all findings
        2. Update confidence scores
        3. Record defense effectiveness
        """
        for finding in findings:
            await self.rag.embed_finding(finding, engagement_id)
            
            # Update existing similar patterns
            existing = await self.rag.retrieve_context(
                query=f"{finding.get('category')} {finding.get('target_url')}",
                category="vulnerability",
                limit=5,
            )
            for e in existing:
                success = finding.get("verified", False)
                await self.store.update_confidence(
                    f"{e.get('engagement_id', '')}:{finding.get('hypothesis_id', '')}",
                    success
                )
    
    def compute_exposure_score(
        self,
        chain_depth: int,
        privilege_level: str,
        data_sensitivity: str,
        historical_success_rate: float,
    ) -> ExposureScore:
        """Compute exposure score for a finding/chain."""
        return ExposureScore(
            chain_depth=chain_depth,
            privilege_level=privilege_level,
            data_sensitivity=data_sensitivity,
            exploit_confidence=historical_success_rate,
        )
    
    async def get_attack_graph_diff(self, engagement_id_1: str, engagement_id_2: str) -> dict:
        """
        Compare attack graphs across two engagements (CTEM diff).
        
        Returns:
        - New attack paths (appeared since last run)
        - Closed attack paths (fixed)
        - Changed chain depths
        """
        graph1 = await self.graph.query(
            "MATCH (f:Finding {engagement_id: $eid}) RETURN f",
            {"eid": engagement_id_1}
        )
        graph2 = await self.graph.query(
            "MATCH (f:Finding {engagement_id: $eid}) RETURN f",
            {"eid": engagement_id_2}
        )
        
        paths1 = {(f.get("target_url"), f.get("category")) for f in graph1}
        paths2 = {(f.get("target_url"), f.get("category")) for f in graph2}
        
        return {
            "new_paths": list(paths2 - paths1),
            "closed_paths": list(paths1 - paths2),
            "persistent_paths": list(paths1 & paths2),
            "delta_count": len(paths2) - len(paths1),
        }
```

---

## Tests

### `tests/genome/test_embedding_store.py`

```python
import pytest
from sentinel.genome.embedding_store import EmbeddingStore, EmbeddingRecord

class TestEmbeddingStore:
    @pytest.mark.asyncio
    async def test_store_and_search(self):
        # Requires running Postgres with pgvector — integration test
        store = EmbeddingStore()
        # Would need actual DB connection for full test
    
    def test_embedding_record_creation(self):
        record = EmbeddingRecord(
            id="test-1",
            content="SQL injection in login form",
            embedding=[0.1] * 1536,
            category="vulnerability",
            metadata={"severity": "critical"},
            engagement_id="eng-1",
            confidence=0.8,
            success_count=4,
            failure_count=1,
        )
        assert record.confidence == 0.8
```

### `tests/genome/test_genome_v2.py`

```python
import pytest
from sentinel.genome.genome_v2 import ExposureScore

class TestExposureScore:
    def test_critical_score(self):
        score = ExposureScore(
            chain_depth=1,
            privilege_level="root",
            data_sensitivity="critical",
            exploit_confidence=0.95,
        )
        assert score.rating == "CRITICAL"
    
    def test_low_score_deep_chain(self):
        score = ExposureScore(
            chain_depth=10,
            privilege_level="none",
            data_sensitivity="public",
            exploit_confidence=0.3,
        )
        assert score.rating == "LOW"
    
    def test_score_range(self):
        score = ExposureScore(1, "root", "critical", 1.0)
        assert 0 <= score.score <= 1.0
```

---

## Integration Points

1. **Hypothesis Engine** (Phase 5): Before generating hypotheses, query genome for tech-stack-specific intelligence
2. **VulnAgent** (Phase 5): Use RAG grounding for LLM decisions during hypothesis testing
3. **ExploitAgent** (Phase 6): Select payloads ranked by historical genome success rate
4. **Activities** (Phase 7): Post-engagement learning activity added to workflow
5. **Existing Genome** (Phase 0-4): Migrate existing SQLite patterns to pgvector
6. **Reporting**: Include exposure scores in reports instead of/alongside CVSS

## Acceptance Criteria

- [ ] pgvector extension enabled and embeddings table created
- [ ] Findings are embedded and stored after each engagement
- [ ] RAG retrieval returns relevant past patterns for new queries
- [ ] Confidence scores update based on success/failure
- [ ] Pre-engagement intel returns technique recommendations
- [ ] Exposure Score computes correctly and replaces static CVSS
- [ ] Attack graph diff shows new/closed paths between engagements
- [ ] All tests pass