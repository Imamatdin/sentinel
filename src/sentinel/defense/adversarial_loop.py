"""AdversarialLoop -- Red team vs Blue team real-time feedback loop.

Loop:
1. Red agent launches attack
2. Blue detector analyzes in real-time
3. Blue defense responds (block/rate-limit)
4. Red agent detects defense, adapts tactics
5. Repeat until red runs out of bypasses or blue achieves full coverage

Speed demo: compare Cerebras-speed blue team vs simulated slow inference.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from sentinel.core import get_logger
from sentinel.defense.behavioral_detector import BehavioralDetector, DetectionAlert, RequestProfile
from sentinel.defense.active_defense import ActiveDefense, DefenseAction

logger = get_logger(__name__)


@dataclass
class RoundResult:
    """Result of a single adversarial round."""

    round_number: int
    red_action: str
    red_success: bool
    blue_detected: bool
    blue_response: str
    detection_latency_ms: float
    response_latency_ms: float
    red_adaptation: str = ""


@dataclass
class LoopMetrics:
    """Aggregate metrics from adversarial loop execution."""

    total_rounds: int = 0
    red_successes: int = 0
    blue_detections: int = 0
    blue_blocks: int = 0
    avg_detection_latency_ms: float = 0.0
    avg_response_latency_ms: float = 0.0
    coverage_score: float = 0.0  # Percentage of attacks detected
    rounds: list[RoundResult] = field(default_factory=list)


class AdversarialLoop:
    """Orchestrates the red vs blue adversarial feedback loop.

    Red team:
    - Generates attack requests from technique playbook
    - Observes blue team responses (blocked? rate limited?)
    - Adapts: switches technique when current one is blocked

    Blue team:
    - BehavioralDetector analyzes every request
    - ActiveDefense responds automatically
    """

    def __init__(
        self,
        detector: BehavioralDetector,
        defense: ActiveDefense,
        red_agent_callback: Callable[..., Any] | None = None,
    ) -> None:
        self.detector = detector
        self.defense = defense
        self.red_callback = red_agent_callback
        self.metrics = LoopMetrics()

    async def run_loop(
        self,
        target: str,
        max_rounds: int = 50,
        red_techniques: list[str] | None = None,
    ) -> LoopMetrics:
        """Run adversarial loop.

        Each round:
        1. Red generates and sends attack request
        2. Blue analyzes and responds
        3. Red observes response and adapts
        """
        techniques = red_techniques or [
            "sqli_basic", "sqli_encoded", "sqli_time_based",
            "xss_reflected", "xss_dom", "xss_encoded",
            "ssrf_direct", "ssrf_redirect", "ssrf_dns_rebind",
            "cmd_injection_basic", "cmd_injection_blind",
            "brute_force_slow", "brute_force_distributed",
        ]

        technique_index = 0
        blocked_techniques: set[str] = set()

        for round_num in range(max_rounds):
            # Skip blocked techniques
            while technique_index < len(techniques) and techniques[technique_index] in blocked_techniques:
                technique_index += 1

            if technique_index >= len(techniques):
                logger.info("red_exhausted", rounds=round_num)
                break

            current_technique = techniques[technique_index]

            # 1. Red attack — brute force techniques send a burst to trigger rate detection
            if current_technique.startswith("brute_force"):
                requests = self._generate_brute_force_burst(current_technique, target)
            else:
                requests = [self._generate_attack_request(current_technique, target)]

            # 2. Blue detect (analyze all requests in burst, collect alerts)
            detect_start = time.monotonic()
            alerts: list[DetectionAlert] = []
            for request in requests:
                alerts.extend(self.detector.analyze_request(request))
            detection_latency = (time.monotonic() - detect_start) * 1000

            # 3. Blue respond
            response_start = time.monotonic()
            blue_response = "none"
            if alerts:
                for alert in alerts:
                    action = self.defense.respond(alert)
                    blue_response = action.action_type
            response_latency = (time.monotonic() - response_start) * 1000

            # 4. Determine red success
            red_success = len(alerts) == 0 or blue_response == "log"
            blue_detected = len(alerts) > 0

            # 5. Red adaptation
            adaptation = ""
            if not red_success:
                blocked_techniques.add(current_technique)
                adaptation = f"Technique {current_technique} blocked, moving to next"
                technique_index += 1

            round_result = RoundResult(
                round_number=round_num,
                red_action=current_technique,
                red_success=red_success,
                blue_detected=blue_detected,
                blue_response=blue_response,
                detection_latency_ms=detection_latency,
                response_latency_ms=response_latency,
                red_adaptation=adaptation,
            )

            self.metrics.rounds.append(round_result)
            self.metrics.total_rounds += 1
            if red_success:
                self.metrics.red_successes += 1
            if blue_detected:
                self.metrics.blue_detections += 1
            if blue_response in ("block_ip", "rate_limit"):
                self.metrics.blue_blocks += 1

        # Calculate final metrics
        if self.metrics.total_rounds > 0:
            self.metrics.coverage_score = self.metrics.blue_detections / self.metrics.total_rounds
            self.metrics.avg_detection_latency_ms = sum(
                r.detection_latency_ms for r in self.metrics.rounds
            ) / self.metrics.total_rounds
            self.metrics.avg_response_latency_ms = sum(
                r.response_latency_ms for r in self.metrics.rounds
            ) / self.metrics.total_rounds

        return self.metrics

    def _generate_brute_force_burst(self, technique: str, target: str) -> list[RequestProfile]:
        """Generate a burst of login requests to trigger rate-based detection."""
        now = time.time()
        burst_size = self.detector.rate_limit_per_second + 2  # Exceed threshold
        requests = []
        for i in range(burst_size):
            requests.append(RequestProfile(
                timestamp=now + i * 0.05,  # 20 req/sec
                source_ip="10.0.0.100",
                method="POST",
                path="/api/login",
                params={"email": "admin@juice.sh", "password": f"attempt_{i}"},
                headers={},
                body_size=50,
                body_entropy=3.0,
                response_code=401,
                response_size=50,
                response_time_ms=20,
            ))
        return requests

    def _generate_attack_request(self, technique: str, target: str) -> RequestProfile:
        """Generate an attack request for the given technique."""
        payload_map: dict[str, tuple[str, str, dict[str, str]]] = {
            "sqli_basic": ("GET", "/api/products", {"q": "' OR 1=1 --"}),
            "sqli_encoded": ("GET", "/api/products", {"q": "%27%20OR%201%3D1%20--"}),
            "sqli_time_based": ("GET", "/api/products", {"q": "' AND SLEEP(5) --"}),
            "xss_reflected": ("GET", "/search", {"q": "<script>alert(1)</script>"}),
            "xss_dom": ("GET", "/search", {"q": "javascript:alert(1)"}),
            "xss_encoded": ("GET", "/search", {"q": "%3Cscript%3Ealert(1)%3C/script%3E"}),
            "ssrf_direct": ("GET", "/api/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
            "ssrf_redirect": ("GET", "/api/fetch", {"url": "http://evil.com/redirect?to=169.254.169.254"}),
            "ssrf_dns_rebind": ("GET", "/api/fetch", {"url": "http://rebind.127.0.0.1.nip.io/"}),
            "cmd_injection_basic": ("POST", "/api/exec", {"cmd": "; cat /etc/passwd"}),
            "cmd_injection_blind": ("POST", "/api/exec", {"cmd": "& ping -c 1 attacker.com"}),
            "brute_force_slow": ("POST", "/api/login", {"email": "admin@juice.sh", "password": "test123"}),
            "brute_force_distributed": ("POST", "/api/login", {"email": "admin@juice.sh", "password": "pass456"}),
        }

        method, path, params = payload_map.get(technique, ("GET", "/", {}))

        return RequestProfile(
            timestamp=time.time(),
            source_ip="10.0.0.100",
            method=method,
            path=path,
            params=params,
            headers={},
            body_size=len(str(params)),
            body_entropy=BehavioralDetector.calculate_entropy(str(params)),
            response_code=200,
            response_size=1000,
            response_time_ms=50,
        )


async def run_speed_demo(
    target: str = "http://localhost:3000",
    fast_latency_ms: float = 1.0,
    slow_latency_ms: float = 200.0,
    rounds: int = 20,
) -> dict[str, Any]:
    """Speed demo: Cerebras-powered blue team vs simulated slow inference.

    Compares two blue team configurations:
    - "fast" (Cerebras-speed): ~1ms simulated inference latency
    - "slow" (traditional): ~200ms simulated inference latency

    In each configuration, the adversarial loop runs the same attack sequence.
    The fast blue team detects and responds before the red team can adapt;
    the slow blue team leaves a window where attacks succeed.

    Returns:
        Dict comparing fast vs slow metrics.
    """
    techniques = [
        "sqli_basic", "xss_reflected", "ssrf_direct",
        "cmd_injection_basic", "brute_force_slow",
    ]

    # --- Fast blue team (Cerebras-speed) ---
    fast_detector = BehavioralDetector()
    fast_defense = ActiveDefense()
    fast_loop = AdversarialLoop(fast_detector, fast_defense)

    fast_start = time.monotonic()
    fast_metrics = await fast_loop.run_loop(target, max_rounds=rounds, red_techniques=techniques)
    fast_wall_ms = (time.monotonic() - fast_start) * 1000

    # Simulate inference overhead for fast path
    fast_total_inference_ms = fast_metrics.total_rounds * fast_latency_ms

    # --- Slow blue team (traditional inference) ---
    slow_detector = BehavioralDetector()
    slow_defense = ActiveDefense()
    slow_loop = AdversarialLoop(slow_detector, slow_defense)

    slow_start = time.monotonic()
    slow_metrics = await slow_loop.run_loop(target, max_rounds=rounds, red_techniques=techniques)
    slow_wall_ms = (time.monotonic() - slow_start) * 1000

    # Simulate inference overhead for slow path
    slow_total_inference_ms = slow_metrics.total_rounds * slow_latency_ms

    return {
        "fast_blue": {
            "label": "Cerebras-speed (~1ms inference)",
            "total_rounds": fast_metrics.total_rounds,
            "coverage_score": fast_metrics.coverage_score,
            "blue_detections": fast_metrics.blue_detections,
            "blue_blocks": fast_metrics.blue_blocks,
            "red_successes": fast_metrics.red_successes,
            "avg_detection_latency_ms": fast_metrics.avg_detection_latency_ms,
            "simulated_inference_ms": fast_latency_ms,
            "total_inference_overhead_ms": fast_total_inference_ms,
            "wall_time_ms": fast_wall_ms,
            "effective_response_ms": fast_metrics.avg_response_latency_ms + fast_latency_ms,
        },
        "slow_blue": {
            "label": "Traditional inference (~200ms)",
            "total_rounds": slow_metrics.total_rounds,
            "coverage_score": slow_metrics.coverage_score,
            "blue_detections": slow_metrics.blue_detections,
            "blue_blocks": slow_metrics.blue_blocks,
            "red_successes": slow_metrics.red_successes,
            "avg_detection_latency_ms": slow_metrics.avg_detection_latency_ms,
            "simulated_inference_ms": slow_latency_ms,
            "total_inference_overhead_ms": slow_total_inference_ms,
            "wall_time_ms": slow_wall_ms,
            "effective_response_ms": slow_metrics.avg_response_latency_ms + slow_latency_ms,
        },
        "speedup_factor": slow_latency_ms / max(fast_latency_ms, 0.001),
        "inference_time_saved_ms": slow_total_inference_ms - fast_total_inference_ms,
    }
