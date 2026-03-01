"""
Federated Aggregation Server — Collects anonymized patterns from deployments.

Architecture:
1. Deployments push anonymized TechniqueStats + AnonymizedRecords
2. Aggregator merges stats with differential privacy (Laplace noise)
3. Aggregator publishes updated global model back to deployments

Differential Privacy: Laplace noise added to counts before publishing.
epsilon-differential privacy with epsilon=1.0 (moderate privacy).
"""

import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class FederatedUpdate:
    deployment_id: str
    timestamp: datetime
    technique_stats: list[dict]
    pattern_records: list[dict]
    deployment_count: int


@dataclass
class GlobalModel:
    version: int = 0
    last_updated: datetime | None = None
    technique_stats: dict = field(default_factory=dict)
    total_deployments: int = 0
    total_engagements: int = 0


class FederatedAggregator:
    """Aggregate anonymized patterns across deployments with differential privacy."""

    EPSILON = 1.0
    MIN_DEPLOYMENTS = 3
    MIN_ENGAGEMENTS = 5

    def __init__(self):
        self.model = GlobalModel()
        self.updates: list[FederatedUpdate] = []

    def receive_update(self, update: FederatedUpdate):
        """Process an incoming update from a deployment."""
        self.updates.append(update)

        for stat in update.technique_stats:
            key = f"{stat['technique']}::{stat['stack']}"
            if key not in self.model.technique_stats:
                self.model.technique_stats[key] = {
                    "technique": stat["technique"],
                    "stack": stat["stack"],
                    "alpha": 1.0,
                    "beta": 1.0,
                    "total_trials": 0,
                    "deployment_count": 0,
                }

            entry = self.model.technique_stats[key]
            entry["alpha"] += stat.get("alpha", 1) - 1
            entry["beta"] += stat.get("beta", 1) - 1
            entry["total_trials"] += stat.get("total_trials", 0)
            entry["deployment_count"] += 1

        self.model.total_deployments += 1
        self.model.total_engagements += update.deployment_count
        self.model.version += 1
        self.model.last_updated = datetime.now(timezone.utc)

        logger.info(
            "federated_update_received",
            deployment=update.deployment_id,
            stats_count=len(update.technique_stats),
        )

    def publish_model(self) -> dict:
        """
        Publish the global model with differential privacy noise.
        Only includes patterns meeting minimum deployment/engagement thresholds.
        """
        published: list[dict] = []

        for entry in self.model.technique_stats.values():
            if entry["deployment_count"] < self.MIN_DEPLOYMENTS:
                continue
            if entry["total_trials"] < self.MIN_ENGAGEMENTS:
                continue

            noisy_alpha = max(1.0, entry["alpha"] + self._laplace_noise())
            noisy_beta = max(1.0, entry["beta"] + self._laplace_noise())

            published.append({
                "technique": entry["technique"],
                "stack": entry["stack"],
                "alpha": round(noisy_alpha, 2),
                "beta": round(noisy_beta, 2),
                "total_trials": entry["total_trials"],
                "mean_success_rate": round(
                    noisy_alpha / (noisy_alpha + noisy_beta), 4
                ),
            })

        return {
            "version": self.model.version,
            "last_updated": str(self.model.last_updated),
            "total_deployments": self.model.total_deployments,
            "technique_stats": published,
        }

    def _laplace_noise(self) -> float:
        """Generate Laplace noise for epsilon-differential privacy."""
        scale = 1.0 / self.EPSILON
        u = random.random() - 0.5
        return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
