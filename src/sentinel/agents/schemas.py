"""Structured output schemas for LLM responses.

These Pydantic models enforce valid outputs from LLMs,
preventing hallucinated or malformed responses.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Confidence(str, Enum):
    """Confidence level for findings."""
    CONFIRMED = "confirmed"  # Validated with PoC
    HIGH = "high"            # Strong evidence
    MEDIUM = "medium"        # Likely but not confirmed
    LOW = "low"              # Possible, needs validation
    UNCERTAIN = "uncertain"  # Speculation


class VulnerabilityType(str, Enum):
    """OWASP-aligned vulnerability types."""
    SQL_INJECTION = "sql_injection"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    XSS_DOM = "xss_dom"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    XXE = "xxe"
    DESERIALIZATION = "deserialization"
    CSRF = "csrf"
    OPEN_REDIRECT = "open_redirect"
    FILE_UPLOAD = "file_upload"
    OTHER = "other"


# === Recon Schemas ===

class DiscoveredHost(BaseModel):
    """A discovered host from reconnaissance."""
    ip_address: str
    hostname: str | None = None
    os_guess: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: str = Field(..., description="Raw evidence that led to this discovery")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        import re
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", v):
            raise ValueError("Invalid IP address format")
        return v


class DiscoveredPort(BaseModel):
    """A discovered open port."""
    port_number: int = Field(..., ge=1, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    service_guess: str | None = None
    version_guess: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    evidence: str


class DiscoveredEndpoint(BaseModel):
    """A discovered web endpoint."""
    url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    parameters: list[str] = Field(default_factory=list)
    requires_auth: bool = False
    interesting_headers: dict[str, str] = Field(default_factory=dict)
    evidence: str


class ReconPlan(BaseModel):
    """Plan for reconnaissance phase."""
    target: str
    techniques: list[str] = Field(
        ...,
        description="List of recon techniques to use",
        min_length=1,
    )
    priority_ports: list[int] = Field(default_factory=lambda: [80, 443, 22, 21, 3306, 5432])
    max_depth: int = Field(default=3, ge=1, le=10)
    estimated_duration_minutes: int = Field(default=30, ge=1)
    justification: str


# === Vulnerability Analysis Schemas ===

class VulnerabilityHypothesis(BaseModel):
    """A hypothesis about a potential vulnerability.

    This is BEFORE validation - we don't claim it exists yet.
    """
    vuln_type: VulnerabilityType
    location: str = Field(..., description="URL, parameter, or component")
    hypothesis: str = Field(..., description="What we think might be vulnerable and why")
    test_to_confirm: str = Field(..., description="Specific test to confirm/deny")
    indicators: list[str] = Field(..., description="Evidence that led to this hypothesis")
    confidence: Confidence = Confidence.LOW  # Always start low until validated

    @field_validator("confidence")
    @classmethod
    def hypothesis_cant_be_confirmed(cls, v: Confidence) -> Confidence:
        if v == Confidence.CONFIRMED:
            raise ValueError("Hypothesis cannot be CONFIRMED - use VulnerabilityFinding for confirmed vulns")
        return v


class VulnerabilityFinding(BaseModel):
    """A confirmed vulnerability finding.

    This is AFTER validation with working PoC.
    """
    vuln_type: VulnerabilityType
    title: str = Field(..., max_length=200)
    description: str
    location: str
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    cvss_score: float | None = Field(None, ge=0.0, le=10.0)
    cve_id: str | None = None
    cwe_id: str | None = None

    # Evidence - REQUIRED for confirmed findings
    poc_request: str = Field(..., description="The exact request that exploits this")
    poc_response: str = Field(..., description="The response proving exploitation")
    reproduction_steps: list[str] = Field(..., min_length=1)

    # Validation
    validated: bool = True
    validated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    false_positive_check: str = Field(
        ...,
        description="How we verified this is not a false positive"
    )

    # Remediation
    remediation: str
    references: list[str] = Field(default_factory=list)

    # MITRE mapping
    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None


class VulnAnalysisPlan(BaseModel):
    """Plan for vulnerability analysis."""
    target_endpoints: list[str]
    techniques_to_apply: list[str]
    priority_vuln_types: list[VulnerabilityType]
    max_tests_per_endpoint: int = Field(default=50, ge=1)
    justification: str


# === Exploitation Schemas ===

class ExploitPlan(BaseModel):
    """Plan for exploiting a vulnerability."""
    vulnerability_id: str
    technique: str
    payload: str
    expected_outcome: str
    rollback_plan: str = Field(..., description="How to undo if something goes wrong")
    risk_assessment: str
    requires_approval: bool = True


class ExploitResult(BaseModel):
    """Result of an exploitation attempt."""
    vulnerability_id: str
    success: bool
    technique_used: str

    # If successful
    session_type: str | None = None
    access_level: str | None = None
    session_token: str | None = None

    # Evidence
    request_sent: str
    response_received: str

    # If failed
    failure_reason: str | None = None

    # Reproducibility
    replay_command: str | None = Field(
        None,
        description="Command to reproduce this exploit (curl, python, etc.)"
    )


# === Agent Decision Schemas ===

class AgentThought(BaseModel):
    """Structured thought process for an agent."""
    observation: str = Field(..., description="What I see/know")
    analysis: str = Field(..., description="What this means")
    hypothesis: str = Field(..., description="What I think might be true")
    next_action: str = Field(..., description="What I should do next")
    justification: str = Field(..., description="Why this action")
    confidence: Confidence
    uncertainties: list[str] = Field(
        default_factory=list,
        description="Things I'm uncertain about"
    )


class ActionProposal(BaseModel):
    """A proposed action from the LLM."""
    action_type: str
    target: str
    parameters: dict[str, Any]
    justification: str
    expected_outcome: str
    risk_level: str = Field(..., pattern="^(low|medium|high|critical)$")
    rollback_possible: bool


class AgentResponse(BaseModel):
    """Complete agent response with reasoning."""
    thought: AgentThought
    proposed_actions: list[ActionProposal]
    findings: list[VulnerabilityHypothesis] = Field(default_factory=list)
    needs_human_input: bool = False
    human_input_reason: str | None = None
