"""Data models for Security Genome entries.

A VulnPattern is a distilled, reusable vulnerability pattern extracted
from a specific finding. Patterns are deduplicated and enriched with
CWE/CAPEC classifications, then stored in SQLite for cross-session querying.
"""

from datetime import datetime
from pydantic import BaseModel, Field


class VulnPattern(BaseModel):
    """A distilled vulnerability pattern extracted from a finding."""

    id: str = Field(description="Unique pattern ID (uuid4)")

    # Core pattern identity
    attack_vector: str = Field(
        description="Specific attack method: sqli_union, sqli_blind, "
        "reflected_xss, stored_xss, ssrf_internal, idor_direct, etc."
    )
    payload_family: str = Field(
        description="Payload category: sql_injection, cross_site_scripting, "
        "server_side_request_forgery, path_traversal, command_injection, etc."
    )
    detection_signature: str = Field(
        description="Regex or string pattern that detects this in traffic"
    )
    root_cause: str = Field(
        description="Why the vuln exists: unsanitized_input, missing_auth_check, "
        "insecure_deserialization, string_concatenation_in_sql, etc."
    )

    # Classification (populated by enricher)
    cwe_id: str | None = Field(None, description="CWE ID, e.g. CWE-89")
    capec_id: str | None = Field(None, description="CAPEC attack pattern ID")
    cve_ids: list[str] = Field(
        default_factory=list, description="Related CVE IDs from NVD lookup"
    )

    # Context
    affected_component: str = Field(
        description="Component type: search_form, login_page, api_endpoint, etc."
    )
    technology_stack: list[str] = Field(
        default_factory=list, description="Relevant technologies: express, flask, etc."
    )
    severity: str = Field(description="critical, high, medium, low, info")

    # Remediation
    remediation_pattern: str = Field(
        description="Fix approach: parameterized_queries, output_encoding, etc."
    )
    remediation_code_example: str | None = Field(
        None, description="Short code example of the fix"
    )

    # Metadata
    source_finding_id: str = Field(description="ID of the original finding")
    source_session_id: str = Field(
        default="", description="Engagement session that produced this"
    )
    extracted_at: datetime = Field(default_factory=datetime.utcnow)
    confidence: float = Field(ge=0, le=1, description="Extraction confidence 0-1")


class GenomeStats(BaseModel):
    """Genome database statistics for the /api/genome/stats endpoint."""

    total_patterns: int
    unique_attack_vectors: int
    unique_payload_families: int
    top_cwe_ids: list[dict]
    top_root_causes: list[dict]
    severity_distribution: dict[str, int]
    sessions_analyzed: int
