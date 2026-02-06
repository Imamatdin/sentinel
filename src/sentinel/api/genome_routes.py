"""Genome API endpoints.

Endpoints:
- GET /api/genome/stats     Genome database statistics
- GET /api/genome/patterns  Search genome patterns with filters

These are registered in app.py as:
    app.include_router(genome_router, prefix="/api/genome", tags=["genome"])
"""

from fastapi import APIRouter, Query

from sentinel.genome.database import GenomeDB

router = APIRouter()


@router.get("/stats")
async def genome_stats():
    """Get genome database statistics.

    Returns counts of patterns, unique attack vectors, severity distribution,
    top CWE IDs, and top root causes.
    """
    try:
        db = GenomeDB()
        return db.get_stats().model_dump()
    except Exception as e:
        return {
            "total_patterns": 0,
            "unique_attack_vectors": 0,
            "unique_payload_families": 0,
            "top_cwe_ids": [],
            "top_root_causes": [],
            "severity_distribution": {},
            "sessions_analyzed": 0,
            "error": str(e),
        }


@router.get("/patterns")
async def search_patterns(
    cwe_id: str | None = Query(None, description="Filter by CWE ID"),
    severity: str | None = Query(None, description="Filter by severity"),
    attack_vector: str | None = Query(
        None, description="Filter by attack vector (substring match)"
    ),
    session_id: str | None = Query(
        None, description="Filter by session ID"
    ),
    limit: int = Query(50, ge=1, le=200, description="Max results"),
):
    """Search genome patterns with optional filters.

    All filters are AND-combined. Returns newest patterns first.
    """
    try:
        db = GenomeDB()
        patterns = db.search(
            cwe_id=cwe_id,
            severity=severity,
            attack_vector=attack_vector,
            session_id=session_id,
            limit=limit,
        )
        return {"patterns": [p.model_dump() for p in patterns], "count": len(patterns)}
    except Exception as e:
        return {"patterns": [], "count": 0, "error": str(e)}
