"""Temporal workflow orchestration for Sentinel."""

from sentinel.orchestration.client import (
    get_temporal_client,
    close_temporal_client,
)
from sentinel.orchestration.activities import (
    EngagementConfig,
    ReconResult,
    VulnAnalysisResult,
    ExploitResult,
    ExploitAttempt,
    VerificationResult,
    ReportResult,
)
from sentinel.orchestration.workflows import (
    PentestWorkflow,
    ReconOnlyWorkflow,
    PentestState,
)

__all__ = [
    # Client
    "get_temporal_client",
    "close_temporal_client",
    # Config
    "EngagementConfig",
    # Results
    "ReconResult",
    "VulnAnalysisResult",
    "ExploitResult",
    "ExploitAttempt",
    "VerificationResult",
    "ReportResult",
    # Workflows
    "PentestWorkflow",
    "ReconOnlyWorkflow",
    "PentestState",
]
