"""Tests for the Security Genome pipeline.

Run: pytest tests/test_genome.py -v
"""

import pytest
from pathlib import Path
from sentinel.genome.models import VulnPattern
from sentinel.genome.deduplicator import PatternDeduplicator
from sentinel.genome.enricher import PatternEnricher
from sentinel.genome.database import GenomeDB


def _make_pattern(**kwargs) -> VulnPattern:
    """Helper to create a VulnPattern with defaults."""
    defaults = {
        "id": "test-1",
        "attack_vector": "sqli_union",
        "payload_family": "sql_injection",
        "detection_signature": r"UNION\s+SELECT",
        "root_cause": "string_concatenation_in_sql",
        "affected_component": "search_endpoint",
        "severity": "high",
        "remediation_pattern": "parameterized_queries",
        "source_finding_id": "f1",
        "source_session_id": "s1",
        "confidence": 0.9,
    }
    defaults.update(kwargs)
    return VulnPattern(**defaults)


class TestDeduplicator:
    """Test string-tuple deduplication."""

    def test_identical_patterns_deduped(self):
        p1 = _make_pattern(id="1")
        p2 = _make_pattern(id="2")
        # Same attack_vector, payload_family, root_cause -> duplicate

        dedup = PatternDeduplicator()
        result = dedup.deduplicate([p1, p2])
        assert len(result) == 1
        assert result[0].id == "1"  # Keeps first

    def test_different_patterns_kept(self):
        p1 = _make_pattern(id="1", attack_vector="sqli_union")
        p2 = _make_pattern(
            id="2",
            attack_vector="reflected_xss",
            payload_family="cross_site_scripting",
            root_cause="unescaped_output",
        )

        dedup = PatternDeduplicator()
        result = dedup.deduplicate([p1, p2])
        assert len(result) == 2

    def test_empty_list(self):
        dedup = PatternDeduplicator()
        assert dedup.deduplicate([]) == []

    def test_case_insensitive(self):
        p1 = _make_pattern(id="1", attack_vector="SQLi_Union")
        p2 = _make_pattern(id="2", attack_vector="sqli_union")

        dedup = PatternDeduplicator()
        result = dedup.deduplicate([p1, p2])
        assert len(result) == 1

    def test_same_vector_different_root_cause_not_deduped(self):
        p1 = _make_pattern(
            id="1", root_cause="string_concatenation_in_sql"
        )
        p2 = _make_pattern(
            id="2", root_cause="dynamic_query_building"
        )

        dedup = PatternDeduplicator()
        result = dedup.deduplicate([p1, p2])
        assert len(result) == 2


class TestEnricher:
    """Test static CWE/CAPEC enrichment."""

    @pytest.mark.asyncio
    async def test_static_cwe_mapping(self):
        pattern = _make_pattern(cwe_id=None, capec_id=None)
        enricher = PatternEnricher(enable_nvd=False)
        enriched = await enricher.enrich([pattern])

        assert enriched[0].cwe_id == "CWE-89"
        assert enriched[0].capec_id == "CAPEC-66"

    @pytest.mark.asyncio
    async def test_existing_cwe_not_overwritten(self):
        pattern = _make_pattern(cwe_id="CWE-999", capec_id="CAPEC-999")
        enricher = PatternEnricher(enable_nvd=False)
        enriched = await enricher.enrich([pattern])

        assert enriched[0].cwe_id == "CWE-999"
        assert enriched[0].capec_id == "CAPEC-999"

    @pytest.mark.asyncio
    async def test_xss_mapping(self):
        pattern = _make_pattern(
            payload_family="cross_site_scripting",
            cwe_id=None,
            capec_id=None,
        )
        enricher = PatternEnricher(enable_nvd=False)
        enriched = await enricher.enrich([pattern])

        assert enriched[0].cwe_id == "CWE-79"
        assert enriched[0].capec_id == "CAPEC-86"

    @pytest.mark.asyncio
    async def test_unknown_payload_no_crash(self):
        pattern = _make_pattern(
            payload_family="exotic_vuln_type",
            attack_vector="custom_attack",
            cwe_id=None,
            capec_id=None,
        )
        enricher = PatternEnricher(enable_nvd=False)
        enriched = await enricher.enrich([pattern])

        # No CWE/CAPEC found, but no crash
        assert enriched[0].cwe_id is None
        assert enriched[0].capec_id is None


class TestGenomeDB:
    """Test SQLite genome database."""

    def test_store_and_search(self, tmp_path: Path):
        db = GenomeDB(db_path=tmp_path / "test.db")
        pattern = _make_pattern(cwe_id="CWE-89")
        db.store_patterns([pattern])

        results = db.search(cwe_id="CWE-89")
        assert len(results) == 1
        assert results[0].id == "test-1"
        assert results[0].cwe_id == "CWE-89"

    def test_search_by_severity(self, tmp_path: Path):
        db = GenomeDB(db_path=tmp_path / "test.db")
        db.store_patterns([
            _make_pattern(id="1", severity="critical"),
            _make_pattern(
                id="2",
                severity="low",
                attack_vector="info_disclosure",
                root_cause="verbose_errors",
            ),
        ])

        critical = db.search(severity="critical")
        assert len(critical) == 1
        assert critical[0].severity == "critical"

    def test_search_by_attack_vector_substring(self, tmp_path: Path):
        db = GenomeDB(db_path=tmp_path / "test.db")
        db.store_patterns([
            _make_pattern(id="1", attack_vector="sqli_union_based"),
            _make_pattern(
                id="2",
                attack_vector="reflected_xss",
                payload_family="xss",
                root_cause="unescaped",
            ),
        ])

        sqli = db.search(attack_vector="sqli")
        assert len(sqli) == 1

    def test_get_stats(self, tmp_path: Path):
        db = GenomeDB(db_path=tmp_path / "test.db")
        db.store_patterns([
            _make_pattern(id="1", cwe_id="CWE-89", severity="high"),
            _make_pattern(
                id="2",
                attack_vector="xss",
                payload_family="xss",
                root_cause="unescaped",
                cwe_id="CWE-79",
                severity="medium",
            ),
        ])

        stats = db.get_stats()
        assert stats.total_patterns == 2
        assert stats.unique_attack_vectors == 2
        assert stats.sessions_analyzed == 1
        assert len(stats.top_cwe_ids) == 2
        assert "high" in stats.severity_distribution

    def test_idempotent_store(self, tmp_path: Path):
        db = GenomeDB(db_path=tmp_path / "test.db")
        pattern = _make_pattern()

        db.store_patterns([pattern])
        db.store_patterns([pattern])  # Same ID, should replace

        results = db.search()
        assert len(results) == 1

    def test_clear(self, tmp_path: Path):
        db = GenomeDB(db_path=tmp_path / "test.db")
        db.store_patterns([_make_pattern()])
        assert db.get_stats().total_patterns == 1

        db.clear()
        assert db.get_stats().total_patterns == 0
