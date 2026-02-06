"""Integration test: full genome pipeline end-to-end.

Run: pytest tests/test_integration.py -v

This test mocks the LLM client and verifies the full pipeline:
extract -> dedup -> enrich -> store -> query
"""

import pytest
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from dataclasses import dataclass, field
from typing import Any

from sentinel.core.client import ChatMessage
from sentinel.genome.pipeline import GenomePipeline
from sentinel.genome.database import GenomeDB


@dataclass
class MockAgentResult:
    agent_name: str = "exploit"
    success: bool = True
    findings: dict = field(default_factory=dict)
    metrics: Any = None
    error: str | None = None
    start_time: float = 0.0
    end_time: float = 1.0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def tool_calls_made(self) -> int:
        return 0


# Mock LLM response for pattern extraction
MOCK_LLM_RESPONSE = json.dumps({
    "attack_vector": "sqli_union_based",
    "payload_family": "sql_injection",
    "detection_signature": r"UNION\s+SELECT\s+",
    "root_cause": "string_concatenation_in_sql",
    "affected_component": "search_endpoint",
    "technology_stack": ["express", "sqlite"],
    "severity": "critical",
    "remediation_pattern": "parameterized_queries",
    "remediation_code_example": "db.query('SELECT * FROM users WHERE id = ?', [id])",
    "confidence": 0.95,
    "cwe_id": "CWE-89",
    "capec_id": "CAPEC-66",
})


@pytest.mark.asyncio
async def test_full_pipeline(tmp_path: Path, monkeypatch):
    """Test the full genome pipeline with mocked LLM."""

    # Mock CerebrasClient
    mock_client = AsyncMock()
    mock_msg = ChatMessage(role="assistant", content=MOCK_LLM_RESPONSE)
    mock_metrics = MagicMock()
    mock_client.chat = AsyncMock(return_value=(mock_msg, mock_metrics))

    # Create a unique database path for this test
    db_path = tmp_path / "genome.db"
    
    # Create pipeline with custom DB path by patching the class
    from sentinel.genome import pipeline as pipeline_module
    original_genome_db = pipeline_module.GenomeDB
    
    class TestGenomeDB(original_genome_db):
        def __init__(self, db_path_override=None):
            super().__init__(db_path=db_path)
    
    monkeypatch.setattr(pipeline_module, "GenomeDB", TestGenomeDB)
    
    pipeline = GenomePipeline(client=mock_client, enable_nvd=False)
    # Replace the db with our test db
    pipeline.db = TestGenomeDB()
    # Clear any existing data
    pipeline.db.clear()

    # Mock agent results with findings
    agent_results = {
        "exploit": MockAgentResult(
            findings={
                "vulnerabilities_found": [
                    {
                        "id": "vuln-1",
                        "type": "SQL Injection",
                        "severity": "critical",
                        "endpoint": "/api/search?q=test",
                        "description": "Union-based SQL injection in search parameter",
                        "evidence": "1' UNION SELECT 1,2,3--",
                    },
                    {
                        "id": "vuln-2",
                        "type": "SQL Injection",
                        "severity": "critical",
                        "endpoint": "/api/products?id=1",
                        "description": "Union-based SQL injection in product ID",
                        "evidence": "1 UNION SELECT 1,2,3--",
                    },
                ]
            }
        ),
        "recon": MockAgentResult(
            agent_name="recon",
            findings={
                "potential_vulnerabilities": [
                    {
                        "type": "Reflected XSS",
                        "severity": "medium",
                        "endpoint": "/search?q=<script>",
                    }
                ]
            },
        ),
    }

    # Run pipeline
    stats = await pipeline.run(agent_results, session_id="test-session")

    # Verify pipeline ran
    assert stats["patterns_extracted"] == 3  # 2 sqli + 1 xss
    # Since mock returns identical patterns, all 3 get deduplicated to 1
    # In real usage with varied LLM output, this would be 2 (sqli deduped + xss)
    assert stats["patterns_after_dedup"] == 1  # All identical mock patterns dedup to 1
    assert stats["patterns_stored"] == 1
    assert stats["cwe_coverage"] >= 1

    # Verify patterns in database (use the pipeline's db which was created with the right path)
    all_patterns = pipeline.db.search()
    assert len(all_patterns) == 1

    # Check that CWE enrichment worked
    sqli_patterns = pipeline.db.search(cwe_id="CWE-89")
    assert len(sqli_patterns) >= 1

    # Check stats endpoint
    genome_stats = pipeline.db.get_stats()
    assert genome_stats.total_patterns == 1
    assert genome_stats.sessions_analyzed == 1
