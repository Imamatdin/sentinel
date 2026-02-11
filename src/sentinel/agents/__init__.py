"""SENTINEL agent system.

Exports all agent classes and the base class.
"""

from sentinel.agents.base import BaseAgent, AgentResult
from sentinel.agents.red.recon import ReconAgent
from sentinel.agents.red.exploit import ExploitAgent
from sentinel.agents.red.report import ReportAgent
from sentinel.agents.blue.monitor import MonitorAgent
from sentinel.agents.blue.defender import DefenderAgent
from sentinel.agents.blue.forensics import ForensicsAgent

# Phase 3: Tool-Guarded LLM Execution
from sentinel.agents.llm_client import (
    BaseLLMClient,
    AnthropicClient,
    CerebrasClient,
    LLMProvider,
    LLMMessage,
    LLMResponse,
    LLMError,
    get_llm_client,
)
from sentinel.agents.policy import (
    PolicyEngine,
    EngagementPolicy,
    ActionRequest,
    ActionDecision,
    ActionType,
    RiskLevel,
)
from sentinel.agents.schemas import (
    AgentResponse,
    AgentThought,
    ActionProposal,
    VulnerabilityHypothesis,
    VulnerabilityFinding,
    ExploitPlan,
    ExploitResult,
    Confidence,
    VulnerabilityType,
)
from sentinel.agents.verification import FindingVerifier, VerificationResult
from sentinel.agents.guarded_base import GuardedBaseAgent, AgentContext, GuardedAgentResult

# Phase 4: Reconnaissance Agent
from sentinel.agents.recon_agent import GuardedReconAgent

__all__ = [
    # Original agents
    "BaseAgent",
    "AgentResult",
    "ReconAgent",
    "ExploitAgent",
    "ReportAgent",
    "MonitorAgent",
    "DefenderAgent",
    "ForensicsAgent",
    # Phase 3: LLM Client
    "BaseLLMClient",
    "AnthropicClient",
    "CerebrasClient",
    "LLMProvider",
    "LLMMessage",
    "LLMResponse",
    "LLMError",
    "get_llm_client",
    # Phase 3: Policy
    "PolicyEngine",
    "EngagementPolicy",
    "ActionRequest",
    "ActionDecision",
    "ActionType",
    "RiskLevel",
    # Phase 3: Schemas
    "AgentResponse",
    "AgentThought",
    "ActionProposal",
    "VulnerabilityHypothesis",
    "VulnerabilityFinding",
    "ExploitPlan",
    "ExploitResult",
    "Confidence",
    "VulnerabilityType",
    # Phase 3: Verification
    "FindingVerifier",
    "VerificationResult",
    # Phase 3: Guarded Base
    "GuardedBaseAgent",
    "AgentContext",
    "GuardedAgentResult",
    # Phase 4: Recon Agent
    "GuardedReconAgent",
]
