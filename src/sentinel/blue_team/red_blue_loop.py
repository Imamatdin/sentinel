"""
Red vs Blue Adversarial Loop -- Orchestrates attack/detect/adapt cycles.

Flow:
1. Red team runs exploit against target
2. Blue team's TrafficProfiler + WAFEngine attempt to detect/block
3. If exploit succeeds undetected -> generate new WAF rule from attack trace
4. If exploit blocked -> log evasion failure, try variant
5. Score both sides: red team success rate vs blue team detection rate

Purple team metrics:
- Detection coverage %: attacks detected / total attacks
- Evasion rate %: attacks that bypassed all defenses
- Mean time to detect (MTTD)
- Rule generation rate: auto-rules created per engagement
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.blue_team.adaptive_waf import AdaptiveWAF, WAFRule
from sentinel.blue_team.traffic_profiler import TrafficProfiler
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class AttackAttempt:
    attempt_id: str
    category: str
    payload: str
    target_route: str
    target_param: str
    method: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class DetectionResult:
    attempt_id: str
    detected: bool
    detected_by: str       # "profiler" | "waf" | "tripwire" | "none"
    anomaly_score: float
    waf_rule_matched: int | None
    latency_ms: float


@dataclass
class LoopMetrics:
    total_attacks: int = 0
    attacks_detected: int = 0
    attacks_evaded: int = 0
    rules_generated: int = 0
    detection_rate: float = 0.0
    evasion_rate: float = 0.0
    avg_detection_latency_ms: float = 0.0


class RedBlueLoop:
    """Orchestrate adversarial red-vs-blue testing cycles."""

    def __init__(self):
        self.profiler = TrafficProfiler()
        self.waf = AdaptiveWAF()
        self.attempts: list[AttackAttempt] = []
        self.detections: list[DetectionResult] = []

    def submit_attack(self, attempt: AttackAttempt) -> DetectionResult:
        """Submit a red team attack attempt through the blue team pipeline."""
        self.attempts.append(attempt)
        start = datetime.now(timezone.utc)

        # Layer 1: Traffic Profiler (behavioral)
        anomaly = self.profiler.score(
            attempt.target_route,
            {attempt.target_param: attempt.payload},
        )

        if anomaly.is_anomalous:
            latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            result = DetectionResult(
                attempt_id=attempt.attempt_id,
                detected=True,
                detected_by="profiler",
                anomaly_score=anomaly.total_score,
                waf_rule_matched=None,
                latency_ms=latency,
            )
            self.detections.append(result)
            return result

        # Layer 2: WAF rules (signature + auto-generated)
        matched_rule = self._check_waf_rules(attempt.payload)
        if matched_rule:
            latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            result = DetectionResult(
                attempt_id=attempt.attempt_id,
                detected=True,
                detected_by="waf",
                anomaly_score=anomaly.total_score,
                waf_rule_matched=matched_rule.rule_id,
                latency_ms=latency,
            )
            self.detections.append(result)
            return result

        # Not detected -> generate new WAF rule from this attack
        latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000
        self.waf.generate_from_attack({
            "category": attempt.category,
            "payload": attempt.payload,
            "target_param": attempt.target_param,
            "method": attempt.method,
            "path": attempt.target_route,
        })

        result = DetectionResult(
            attempt_id=attempt.attempt_id,
            detected=False,
            detected_by="none",
            anomaly_score=anomaly.total_score,
            waf_rule_matched=None,
            latency_ms=latency,
        )
        self.detections.append(result)
        return result

    def train_profiler(self, route: str, normal_requests: list[dict[str, str]]) -> None:
        """Feed normal traffic into the profiler for baseline training."""
        for params in normal_requests:
            self.profiler.learn(route, params)
        logger.info("profiler_trained", route=route, sample_count=len(normal_requests))

    def _check_waf_rules(self, payload: str) -> WAFRule | None:
        """Check if payload matches any existing WAF rules."""
        for rule in self.waf.rules:
            try:
                if re.search(rule.pattern, payload):
                    return rule
            except re.error:
                continue
        return None

    def get_metrics(self) -> LoopMetrics:
        """Calculate purple team metrics."""
        total = len(self.detections)
        if total == 0:
            return LoopMetrics()

        detected = sum(1 for d in self.detections if d.detected)
        evaded = total - detected
        latencies = [d.latency_ms for d in self.detections if d.detected]

        return LoopMetrics(
            total_attacks=total,
            attacks_detected=detected,
            attacks_evaded=evaded,
            rules_generated=len(self.waf.rules),
            detection_rate=round(detected / total, 4),
            evasion_rate=round(evaded / total, 4),
            avg_detection_latency_ms=round(
                sum(latencies) / max(len(latencies), 1), 2
            ),
        )
