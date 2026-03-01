"""Federated learning — cross-deployment pattern sharing with differential privacy."""

from sentinel.federated.anonymizer import Anonymizer, AnonymizedRecord
from sentinel.federated.confidence import BayesianConfidence, TechniqueStats
from sentinel.federated.aggregator import FederatedAggregator, FederatedUpdate, GlobalModel

__all__ = [
    "Anonymizer",
    "AnonymizedRecord",
    "BayesianConfidence",
    "TechniqueStats",
    "FederatedAggregator",
    "FederatedUpdate",
    "GlobalModel",
]
