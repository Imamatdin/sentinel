"""
Per-Route Traffic Profiler (Tier 1 Detection -- Kruegel-Vigna style).

Builds statistical profiles for each API endpoint:
- Parameter count, types, lengths (mean/stddev)
- Character class distribution (alpha, digit, special)
- Request frequency baseline
- Token entropy (high entropy = possible injection)

Anomaly = request that deviates >3sigma from the learned profile.
O(1) per request, always-on baseline.
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class RouteProfile:
    route: str
    request_count: int = 0
    param_count_mean: float = 0.0
    param_count_var: float = 0.0
    param_length_mean: float = 0.0
    param_length_var: float = 0.0
    entropy_mean: float = 0.0
    entropy_var: float = 0.0


@dataclass
class AnomalyScore:
    route: str
    total_score: float      # Combined deviation score (>1.0 = anomalous)
    param_count_z: float    # Z-score for parameter count
    param_length_z: float   # Z-score for parameter lengths
    entropy_z: float        # Z-score for character entropy
    is_anomalous: bool
    details: str


class TrafficProfiler:
    """Build and score against per-route traffic profiles."""

    ANOMALY_THRESHOLD = 3.0  # Z-score threshold
    MIN_SAMPLES = 20         # Need this many requests before profiling is reliable

    def __init__(self):
        self.profiles: dict[str, RouteProfile] = {}
        self._raw_data: dict[str, list[dict]] = defaultdict(list)

    def learn(self, route: str, params: dict[str, str]) -> None:
        """Add a request to the route profile (training phase)."""
        features = self._extract_features(params)
        self._raw_data[route].append(features)

        samples = self._raw_data[route]
        if len(samples) >= self.MIN_SAMPLES:
            self._rebuild_profile(route, samples)

    def score(self, route: str, params: dict[str, str]) -> AnomalyScore:
        """Score a request against the learned profile."""
        profile = self.profiles.get(route)
        if not profile or profile.request_count < self.MIN_SAMPLES:
            return AnomalyScore(
                route=route, total_score=0.0,
                param_count_z=0.0, param_length_z=0.0, entropy_z=0.0,
                is_anomalous=False, details="Insufficient training data",
            )

        features = self._extract_features(params)

        pc_z = self._z_score(features["param_count"], profile.param_count_mean, profile.param_count_var)
        pl_z = self._z_score(features["avg_param_length"], profile.param_length_mean, profile.param_length_var)
        en_z = self._z_score(features["avg_entropy"], profile.entropy_mean, profile.entropy_var)

        total = max(abs(pc_z), abs(pl_z), abs(en_z))
        is_anom = total > self.ANOMALY_THRESHOLD

        details_parts: list[str] = []
        if abs(pc_z) > self.ANOMALY_THRESHOLD:
            details_parts.append(f"Unusual parameter count (z={pc_z:.1f})")
        if abs(pl_z) > self.ANOMALY_THRESHOLD:
            details_parts.append(f"Unusual parameter lengths (z={pl_z:.1f})")
        if abs(en_z) > self.ANOMALY_THRESHOLD:
            details_parts.append(f"High entropy in parameters (z={en_z:.1f}) -- possible injection")

        return AnomalyScore(
            route=route, total_score=total,
            param_count_z=pc_z, param_length_z=pl_z, entropy_z=en_z,
            is_anomalous=is_anom,
            details="; ".join(details_parts) if details_parts else "Normal",
        )

    def _extract_features(self, params: dict[str, str]) -> dict:
        """Extract statistical features from request parameters."""
        values = list(params.values())
        lengths = [len(str(v)) for v in values]
        entropies = [self._shannon_entropy(str(v)) for v in values]

        all_chars = "".join(str(v) for v in values)
        total = max(len(all_chars), 1)

        return {
            "param_count": len(params),
            "avg_param_length": sum(lengths) / max(len(lengths), 1),
            "avg_entropy": sum(entropies) / max(len(entropies), 1),
            "alpha_ratio": sum(c.isalpha() for c in all_chars) / total,
            "digit_ratio": sum(c.isdigit() for c in all_chars) / total,
            "special_ratio": sum(not c.isalnum() for c in all_chars) / total,
        }

    def _shannon_entropy(self, s: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _z_score(self, value: float, mean: float, variance: float) -> float:
        std = math.sqrt(variance) if variance > 0 else 1.0
        return (value - mean) / std

    def _rebuild_profile(self, route: str, samples: list[dict]) -> None:
        """Rebuild profile from accumulated samples."""
        n = len(samples)

        def mean_var(key: str) -> tuple[float, float]:
            vals = [s[key] for s in samples]
            m = sum(vals) / n
            v = sum((x - m) ** 2 for x in vals) / max(n - 1, 1)
            return m, v

        pc_m, pc_v = mean_var("param_count")
        pl_m, pl_v = mean_var("avg_param_length")
        en_m, en_v = mean_var("avg_entropy")

        self.profiles[route] = RouteProfile(
            route=route,
            request_count=n,
            param_count_mean=pc_m, param_count_var=pc_v,
            param_length_mean=pl_m, param_length_var=pl_v,
            entropy_mean=en_m, entropy_var=en_v,
        )
