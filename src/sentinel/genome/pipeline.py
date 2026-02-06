"""Security Genome pipeline: extract -> deduplicate -> enrich -> store.

This is the top-level entry point for the genome system. It is called
by the EngagementManager after an engagement completes.

The pipeline:
1. Extracts structured VulnPatterns from engagement findings using the LLM
2. Deduplicates patterns by their identity tuple
3. Enriches patterns with CWE/CAPEC (static) and CVE (NVD, optional)
4. Stores patterns in the SQLite genome database

If any stage fails, the pipeline logs the error and continues to the
next stage. A failure in extraction doesn't prevent dedup; a failure
in NVD doesn't prevent storage. The pipeline is designed to be resilient.

Integration:
    Called from sentinel/api/app.py EngagementManager._run_engagement()
    after the orchestrator completes and result is available.

    from sentinel.genome.pipeline import GenomePipeline
    pipeline = GenomePipeline(client)
    stats = await pipeline.run(result)
"""

import os
import logging
from typing import Any

from sentinel.core.client import CerebrasClient
from sentinel.genome.extractor import PatternExtractor
from sentinel.genome.deduplicator import PatternDeduplicator
from sentinel.genome.enricher import PatternEnricher
from sentinel.genome.database import GenomeDB

logger = logging.getLogger("sentinel.genome.pipeline")


class GenomePipeline:
    """Orchestrates the full genome pipeline.

    Usage:
        pipeline = GenomePipeline(cerebras_client)
        stats = await pipeline.run(engagement_result)
    """

    def __init__(
        self,
        client: CerebrasClient,
        enable_nvd: bool = True,
    ):
        """Initialize pipeline components.

        Args:
            client: CerebrasClient for LLM pattern extraction
            enable_nvd: Whether to attempt NVD CVE lookups
        """
        self.extractor = PatternExtractor(client)
        self.deduplicator = PatternDeduplicator()
        self.enricher = PatternEnricher(
            nvd_api_key=os.environ.get("NVD_API_KEY"),
            enable_nvd=enable_nvd,
        )
        self.db = GenomeDB()

    async def run(
        self,
        agent_results: dict[str, Any],
        session_id: str = "",
    ) -> dict[str, Any]:
        """Run the full genome pipeline.

        Args:
            agent_results: Dict of agent_name -> AgentResult from engagement
            session_id: Engagement session identifier

        Returns:
            Dict with pipeline statistics:
            {
                "findings_processed": int,
                "patterns_extracted": int,
                "patterns_after_dedup": int,
                "patterns_stored": int,
                "cwe_coverage": int,
                "capec_coverage": int,
            }
        """
        stats: dict[str, Any] = {
            "findings_processed": 0,
            "patterns_extracted": 0,
            "patterns_after_dedup": 0,
            "patterns_stored": 0,
            "cwe_coverage": 0,
            "capec_coverage": 0,
        }

        # Stage 1: Extract
        try:
            patterns = await self.extractor.extract_from_results(
                agent_results, session_id
            )
            stats["patterns_extracted"] = len(patterns)
        except Exception as e:
            logger.error("extraction_stage_failed", error=str(e))
            return stats

        if not patterns:
            logger.info("no_patterns_extracted_pipeline_done")
            return stats

        # Stage 2: Deduplicate
        try:
            patterns = self.deduplicator.deduplicate(patterns)
            stats["patterns_after_dedup"] = len(patterns)
        except Exception as e:
            logger.error("dedup_stage_failed", error=str(e))
            stats["patterns_after_dedup"] = len(patterns)

        # Stage 3: Enrich
        try:
            patterns = await self.enricher.enrich(patterns)
            stats["cwe_coverage"] = sum(
                1 for p in patterns if p.cwe_id
            )
            stats["capec_coverage"] = sum(
                1 for p in patterns if p.capec_id
            )
        except Exception as e:
            logger.error("enrichment_stage_failed", error=str(e))

        # Stage 4: Store
        try:
            stored = self.db.store_patterns(patterns)
            stats["patterns_stored"] = stored
        except Exception as e:
            logger.error("storage_stage_failed", error=str(e))

        logger.info("genome_pipeline_complete", **stats)
        return stats
