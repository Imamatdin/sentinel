"""Graph node and edge models for Sentinel knowledge graph.

Schema mirrors NodeZero's Cyber Terrain Map:
- Entities discovered during recon become nodes
- Relationships (reachable, authenticated, vulnerable) become edges
- Attack paths are computed via graph traversal
"""

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# === Enums ===

class NodeType(str, Enum):
    """Types of nodes in the attack graph."""
    HOST = "Host"
    PORT = "Port"
    SERVICE = "Service"
    VULNERABILITY = "Vulnerability"
    CREDENTIAL = "Credential"
    SESSION = "Session"
    USER = "User"
    TOKEN = "Token"
    ENDPOINT = "Endpoint"
    CRITICAL_ASSET = "CriticalAsset"


class EdgeType(str, Enum):
    """Types of relationships between nodes."""
    HAS_PORT = "HAS_PORT"
    RUNS_SERVICE = "RUNS_SERVICE"
    HAS_VULNERABILITY = "HAS_VULNERABILITY"
    EXPLOITABLE_BY = "EXPLOITABLE_BY"
    YIELDS_SESSION = "YIELDS_SESSION"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    PIVOTS_TO = "PIVOTS_TO"
    OWNS_CREDENTIAL = "OWNS_CREDENTIAL"
    VALID_FOR = "VALID_FOR"
    HAS_ENDPOINT = "HAS_ENDPOINT"
    ACCESSES = "ACCESSES"
    LEADS_TO = "LEADS_TO"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class SessionType(str, Enum):
    """Types of obtained sessions."""
    SHELL = "shell"
    METERPRETER = "meterpreter"
    WEB = "web"
    API = "api"
    DATABASE = "database"
    SSH = "ssh"
    RDP = "rdp"


class CredentialType(str, Enum):
    """Types of credentials."""
    PASSWORD = "password"
    HASH_NTLM = "hash_ntlm"
    HASH_MD5 = "hash_md5"
    HASH_SHA256 = "hash_sha256"
    TOKEN_JWT = "token_jwt"
    TOKEN_API = "token_api"
    TOKEN_SESSION = "token_session"
    COOKIE = "cookie"
    PRIVATE_KEY = "private_key"
    CERTIFICATE = "certificate"


# === Base Models ===

class BaseNode(BaseModel):
    """Base class for all graph nodes."""
    id: UUID = Field(default_factory=uuid4)
    node_type: NodeType
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    engagement_id: str | None = None

    # Evidence tracking
    discovered_by: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    # Risk scoring
    compromise_risk: float = 0.0
    blast_radius: float = 0.0
    choke_point_score: float = 0.0

    def to_neo4j_properties(self) -> dict[str, Any]:
        """Convert to Neo4j-compatible properties dict."""
        props = self.model_dump(mode="json")
        props["evidence_json"] = str(props.pop("evidence", {}))
        return props


class BaseEdge(BaseModel):
    """Base class for all graph edges."""
    id: UUID = Field(default_factory=uuid4)
    edge_type: EdgeType
    source_id: UUID
    target_id: UUID
    created_at: datetime = Field(default_factory=datetime.utcnow)

    discovered_by: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)

    weight: float = 1.0
    validated: bool = False

    def to_neo4j_properties(self) -> dict[str, Any]:
        """Convert to Neo4j-compatible properties dict."""
        props = self.model_dump(mode="json")
        props["evidence_json"] = str(props.pop("evidence", {}))
        return props


# === Node Types ===

class Host(BaseNode):
    """A host/machine in the target environment."""
    node_type: NodeType = NodeType.HOST

    ip_address: str
    hostname: str | None = None
    mac_address: str | None = None
    os: str | None = None
    os_version: str | None = None

    is_internal: bool = True
    network_segment: str | None = None
    domain: str | None = None

    is_domain_controller: bool = False
    is_database_server: bool = False
    is_web_server: bool = False
    is_critical_asset: bool = False

    is_compromised: bool = False
    compromised_at: datetime | None = None


class Port(BaseNode):
    """An open port on a host."""
    node_type: NodeType = NodeType.PORT

    port_number: int
    protocol: str = "tcp"
    state: str = "open"
    host_id: UUID


class Service(BaseNode):
    """A service running on a port."""
    node_type: NodeType = NodeType.SERVICE

    name: str
    product: str | None = None
    version: str | None = None
    banner: str | None = None

    requires_auth: bool = False
    auth_type: str | None = None
    port_id: UUID


class Vulnerability(BaseNode):
    """A discovered vulnerability."""
    node_type: NodeType = NodeType.VULNERABILITY

    cve_id: str | None = None
    cwe_id: str | None = None
    name: str

    description: str | None = None
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None

    is_exploitable: bool = False
    exploit_available: bool = False
    exploit_poc: str | None = None

    mitre_technique_id: str | None = None
    mitre_tactic: str | None = None


class Credential(BaseNode):
    """A discovered credential."""
    node_type: NodeType = NodeType.CREDENTIAL

    credential_type: CredentialType
    username: str | None = None
    value: str

    realm: str | None = None
    is_valid: bool | None = None
    validated_at: datetime | None = None

    is_admin: bool = False
    is_domain_admin: bool = False
    privilege_level: str | None = None


class Session(BaseNode):
    """An obtained session/access."""
    node_type: NodeType = NodeType.SESSION

    session_type: SessionType

    user: str | None = None
    privilege_level: str | None = None
    is_root: bool = False
    is_system: bool = False

    is_active: bool = True
    obtained_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None

    replay_command: str | None = None


class Endpoint(BaseNode):
    """A web/API endpoint."""
    node_type: NodeType = NodeType.ENDPOINT

    url: str
    method: str = "GET"
    path: str
    parameters: list[str] = Field(default_factory=list)
    requires_auth: bool = False

    response_code: int | None = None
    content_type: str | None = None


class CriticalAsset(BaseNode):
    """A crown jewel / critical asset."""
    node_type: NodeType = NodeType.CRITICAL_ASSET

    name: str
    asset_type: str
    description: str | None = None

    data_classification: str | None = None
    business_impact: str | None = None


# === Attack Path Models ===

class AttackPathStep(BaseModel):
    """A single step in an attack path."""
    step_number: int
    node_id: UUID
    node_type: NodeType
    node_label: str

    edge_type: EdgeType | None = None
    technique: str | None = None

    command: str | None = None
    output: str | None = None


class AttackPath(BaseModel):
    """A complete attack path from entry to target."""
    id: UUID = Field(default_factory=uuid4)

    source_id: UUID
    target_id: UUID
    steps: list[AttackPathStep]

    depth: int
    total_weight: float

    is_validated: bool = False
    validated_at: datetime | None = None

    mitre_techniques: list[str] = Field(default_factory=list)
    summary: str | None = None


class GraphSnapshot(BaseModel):
    """A point-in-time snapshot for CTEM diff."""
    id: UUID = Field(default_factory=uuid4)
    engagement_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

    host_count: int = 0
    vulnerability_count: int = 0
    credential_count: int = 0
    session_count: int = 0
    attack_path_count: int = 0

    critical_assets_at_risk: int = 0
    shortest_path_to_crown_jewel: int | None = None
    choke_points: list[UUID] = Field(default_factory=list)

    node_ids: list[UUID] = Field(default_factory=list)
    edge_ids: list[UUID] = Field(default_factory=list)
