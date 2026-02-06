"""SQLite-backed genome pattern database.

Stores all extracted, deduplicated, enriched patterns for cross-session
querying. The database file lives at data/genome.db by default.

Thread safety: SQLite in WAL mode supports concurrent reads. Writes are
serialized by SQLite's internal locking. This is fine for a single-instance
deployment.

Table schema:
    patterns(
        id TEXT PRIMARY KEY,
        attack_vector TEXT NOT NULL,
        payload_family TEXT NOT NULL,
        detection_signature TEXT,
        root_cause TEXT,
        cwe_id TEXT,
        capec_id TEXT,
        cve_ids TEXT,           -- JSON array
        affected_component TEXT,
        technology_stack TEXT,   -- JSON array
        severity TEXT,
        remediation_pattern TEXT,
        remediation_code_example TEXT,
        source_finding_id TEXT,
        source_session_id TEXT,
        confidence REAL,
        extracted_at TEXT,       -- ISO 8601
        data TEXT                -- Full JSON for fields not in columns
    )

Indices: cwe_id, severity, attack_vector, source_session_id
"""

import json
import sqlite3
import logging
from pathlib import Path

from sentinel.genome.models import VulnPattern, GenomeStats

logger = logging.getLogger("sentinel.genome.database")

DEFAULT_DB_PATH = Path("data/genome.db")


class GenomeDB:
    """SQLite genome pattern database.

    Usage:
        db = GenomeDB()
        db.store_patterns(patterns)
        results = db.search(cwe_id="CWE-89")
        stats = db.get_stats()
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Create tables and indices if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS patterns (
                    id TEXT PRIMARY KEY,
                    attack_vector TEXT NOT NULL,
                    payload_family TEXT NOT NULL,
                    detection_signature TEXT,
                    root_cause TEXT,
                    cwe_id TEXT,
                    capec_id TEXT,
                    cve_ids TEXT,
                    affected_component TEXT,
                    technology_stack TEXT,
                    severity TEXT,
                    remediation_pattern TEXT,
                    remediation_code_example TEXT,
                    source_finding_id TEXT,
                    source_session_id TEXT,
                    confidence REAL,
                    extracted_at TEXT,
                    data TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cwe ON patterns(cwe_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_severity ON patterns(severity)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_attack_vector "
                "ON patterns(attack_vector)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_session "
                "ON patterns(source_session_id)"
            )

    def store_patterns(self, patterns: list[VulnPattern]) -> int:
        """Store multiple patterns. Returns count of patterns stored.

        Uses INSERT OR REPLACE so re-running the pipeline is idempotent.
        """
        stored = 0
        with sqlite3.connect(self.db_path) as conn:
            for p in patterns:
                try:
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO patterns
                        (id, attack_vector, payload_family, detection_signature,
                         root_cause, cwe_id, capec_id, cve_ids,
                         affected_component, technology_stack, severity,
                         remediation_pattern, remediation_code_example,
                         source_finding_id, source_session_id, confidence,
                         extracted_at, data)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            p.id,
                            p.attack_vector,
                            p.payload_family,
                            p.detection_signature,
                            p.root_cause,
                            p.cwe_id,
                            p.capec_id,
                            json.dumps(p.cve_ids),
                            p.affected_component,
                            json.dumps(p.technology_stack),
                            p.severity,
                            p.remediation_pattern,
                            p.remediation_code_example,
                            p.source_finding_id,
                            p.source_session_id,
                            p.confidence,
                            p.extracted_at.isoformat(),
                            p.model_dump_json(),
                        ),
                    )
                    stored += 1
                except Exception as e:
                    logger.error(
                        "pattern_store_failed", pattern_id=p.id, error=str(e)
                    )

        logger.info("patterns_stored", count=stored)
        return stored

    def search(
        self,
        cwe_id: str | None = None,
        severity: str | None = None,
        attack_vector: str | None = None,
        session_id: str | None = None,
        limit: int = 50,
    ) -> list[VulnPattern]:
        """Search patterns with optional filters.

        All filters are AND-combined. Returns newest first.
        """
        query = "SELECT data FROM patterns WHERE 1=1"
        params: list[str] = []

        if cwe_id:
            query += " AND cwe_id = ?"
            params.append(cwe_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if attack_vector:
            query += " AND attack_vector LIKE ?"
            params.append(f"%{attack_vector}%")
        if session_id:
            query += " AND source_session_id = ?"
            params.append(session_id)

        query += f" ORDER BY extracted_at DESC LIMIT {limit}"

        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(query, params).fetchall()

        return [VulnPattern.model_validate_json(row[0]) for row in rows]

    def get_stats(self) -> GenomeStats:
        """Get genome database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM patterns"
            ).fetchone()[0]

            vectors = conn.execute(
                "SELECT COUNT(DISTINCT attack_vector) FROM patterns"
            ).fetchone()[0]

            families = conn.execute(
                "SELECT COUNT(DISTINCT payload_family) FROM patterns"
            ).fetchone()[0]

            sessions = conn.execute(
                "SELECT COUNT(DISTINCT source_session_id) FROM patterns"
            ).fetchone()[0]

            top_cwe = conn.execute("""
                SELECT cwe_id, COUNT(*) as cnt FROM patterns
                WHERE cwe_id IS NOT NULL
                GROUP BY cwe_id ORDER BY cnt DESC LIMIT 10
            """).fetchall()

            top_causes = conn.execute("""
                SELECT root_cause, COUNT(*) as cnt FROM patterns
                GROUP BY root_cause ORDER BY cnt DESC LIMIT 10
            """).fetchall()

            severity_rows = conn.execute("""
                SELECT severity, COUNT(*) as cnt FROM patterns
                GROUP BY severity
            """).fetchall()

        return GenomeStats(
            total_patterns=total,
            unique_attack_vectors=vectors,
            unique_payload_families=families,
            sessions_analyzed=sessions,
            top_cwe_ids=[
                {"cwe_id": r[0], "count": r[1]} for r in top_cwe
            ],
            top_root_causes=[
                {"root_cause": r[0], "count": r[1]} for r in top_causes
            ],
            severity_distribution={r[0]: r[1] for r in severity_rows},
        )

    def clear(self) -> None:
        """Delete all patterns. Used in testing."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM patterns")
