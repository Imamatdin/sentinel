# PHASE 9: Advanced Blue Team & Red vs Blue Adversarial Loop

## Context

Read MASTER_PLAN.md and Phases 5-8 first. Current blue team has regex-based WAF, basic network monitor, and audit log responder. This phase upgrades defense to behavioral detection and creates a real-time adversarial loop where red team adapts to blue team defenses.

## What This Phase Builds

1. **Behavioral Detection Engine** — ML-based anomaly detection replacing regex-only WAF
2. **Active Defense System** — auto-block IPs, rate limiting, CSP deployment, header hardening
3. **Red vs Blue Adversarial Loop** — red team adapts tactics in real-time when blue team blocks attacks
4. **Defense Effectiveness Scoring** — detection latency, response time, attacks blocked, coverage gaps
5. **MITRE ATT&CK Mapping** — map both attacks and defenses to ATT&CK framework
6. **Autonomous Blue Hardening** — suggest WAF rules, header configs, IAM restrictions post-exploit; re-run exploit to verify blocked

## Why It Matters

This is what makes Sentinel a hybrid red/blue platform, not just an attacker. No tool does post-exploit remediation verification cleanly. If Sentinel can exploit → suggest fix → re-test → confirm blocked, that's genuinely novel.

---

## File-by-File Implementation

### 1. `src/sentinel/defense/behavioral_detector.py`

```python
"""
BehavioralDetector — ML-based anomaly detection for attack identification.

Replaces regex-only pattern matching with:
- Request frequency analysis (detect brute force, fuzzing)
- Payload entropy analysis (detect encoded/obfuscated attacks)
- Session behavior profiling (detect session hijacking, IDOR probing)
- Response anomaly detection (detect data exfiltration)
"""
import time
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RequestProfile:
    timestamp: float
    source_ip: str
    method: str
    path: str
    params: dict
    headers: dict
    body_size: int
    body_entropy: float
    response_code: int
    response_size: int
    response_time_ms: float


@dataclass
class DetectionAlert:
    alert_type: str         # "brute_force", "fuzzing", "sqli", "xss", "data_exfil", "anomaly"
    confidence: float       # 0.0-1.0
    source_ip: str
    evidence: str
    mitre_technique: str    # ATT&CK ID
    timestamp: float
    request: Optional[RequestProfile] = None
    recommended_action: str = ""  # "block_ip", "rate_limit", "challenge", "log"


class BehavioralDetector:
    """
    Real-time behavioral detection engine.
    
    Maintains per-IP and per-session state to detect:
    1. Volumetric attacks (brute force, credential stuffing)
    2. Payload anomalies (high entropy, unusual encoding)
    3. Scanning behavior (sequential endpoint probing)
    4. Data exfiltration (large/unusual responses)
    5. Session anomalies (impossible travel, token reuse)
    """
    
    def __init__(self):
        # Per-IP request history (sliding window)
        self.ip_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        # Per-IP rate counters
        self.ip_rates: dict[str, list[float]] = defaultdict(list)
        # Known attack patterns (updated by genome)
        self.attack_signatures: list[dict] = []
        # Thresholds
        self.rate_limit_per_second = 10
        self.rate_limit_per_minute = 100
        self.entropy_threshold = 4.5  # Shannon entropy for suspicious payloads
        self.scan_pattern_threshold = 20  # Unique paths in 60 seconds
    
    def analyze_request(self, request: RequestProfile) -> list[DetectionAlert]:
        """Analyze a single request for suspicious behavior."""
        alerts = []
        
        # Track history
        self.ip_history[request.source_ip].append(request)
        self.ip_rates[request.source_ip].append(request.timestamp)
        
        # 1. Rate-based detection
        rate_alert = self._check_rate(request)
        if rate_alert:
            alerts.append(rate_alert)
        
        # 2. Payload entropy analysis
        if request.body_entropy > self.entropy_threshold:
            alerts.append(DetectionAlert(
                alert_type="suspicious_payload",
                confidence=min(request.body_entropy / 8.0, 1.0),
                source_ip=request.source_ip,
                evidence=f"High entropy payload: {request.body_entropy:.2f} bits",
                mitre_technique="T1027",  # Obfuscated Files
                timestamp=request.timestamp,
                request=request,
                recommended_action="challenge",
            ))
        
        # 3. Scanning detection
        scan_alert = self._check_scanning(request)
        if scan_alert:
            alerts.append(scan_alert)
        
        # 4. SQLi/XSS pattern detection (enhanced beyond regex)
        injection_alert = self._check_injection_patterns(request)
        if injection_alert:
            alerts.append(injection_alert)
        
        # 5. Data exfiltration detection
        if request.response_size > 100000:  # 100KB+
            alerts.append(DetectionAlert(
                alert_type="data_exfil",
                confidence=0.6,
                source_ip=request.source_ip,
                evidence=f"Large response: {request.response_size} bytes",
                mitre_technique="T1041",  # Exfiltration Over C2 Channel
                timestamp=request.timestamp,
                request=request,
                recommended_action="log",
            ))
        
        return alerts
    
    def _check_rate(self, request: RequestProfile) -> Optional[DetectionAlert]:
        """Check for rate-based attacks."""
        now = request.timestamp
        recent = [t for t in self.ip_rates[request.source_ip] if now - t < 60]
        self.ip_rates[request.source_ip] = recent
        
        per_second = sum(1 for t in recent if now - t < 1)
        per_minute = len(recent)
        
        if per_second > self.rate_limit_per_second:
            return DetectionAlert(
                alert_type="brute_force",
                confidence=0.9,
                source_ip=request.source_ip,
                evidence=f"{per_second} requests/sec (limit: {self.rate_limit_per_second})",
                mitre_technique="T1110",  # Brute Force
                timestamp=now,
                request=request,
                recommended_action="block_ip",
            )
        elif per_minute > self.rate_limit_per_minute:
            return DetectionAlert(
                alert_type="fuzzing",
                confidence=0.7,
                source_ip=request.source_ip,
                evidence=f"{per_minute} requests/min (limit: {self.rate_limit_per_minute})",
                mitre_technique="T1595",  # Active Scanning
                timestamp=now,
                request=request,
                recommended_action="rate_limit",
            )
        return None
    
    def _check_scanning(self, request: RequestProfile) -> Optional[DetectionAlert]:
        """Detect sequential endpoint probing."""
        now = request.timestamp
        recent = [r for r in self.ip_history[request.source_ip] if now - r.timestamp < 60]
        unique_paths = len(set(r.path for r in recent))
        
        if unique_paths > self.scan_pattern_threshold:
            return DetectionAlert(
                alert_type="scanning",
                confidence=0.8,
                source_ip=request.source_ip,
                evidence=f"{unique_paths} unique paths in 60s",
                mitre_technique="T1595.002",  # Vulnerability Scanning
                timestamp=now,
                request=request,
                recommended_action="rate_limit",
            )
        return None
    
    def _check_injection_patterns(self, request: RequestProfile) -> Optional[DetectionAlert]:
        """Enhanced injection detection beyond simple regex."""
        suspicious_patterns = {
            "sqli": ["' OR ", "UNION SELECT", "1=1", "' AND ", "ORDER BY", "GROUP BY", "--", "/*"],
            "xss": ["<script", "onerror=", "onload=", "javascript:", "alert(", "document.cookie"],
            "cmd_injection": ["; id", "| cat", "`id`", "$(", "& ping"],
            "ssrf": ["169.254.169.254", "metadata.google", "127.0.0.1", "file:///"],
            "xxe": ["<!DOCTYPE", "<!ENTITY", "SYSTEM", "file:///"],
        }
        
        # Check all request components
        search_text = " ".join([
            request.path,
            str(request.params),
            str(request.headers.get("Cookie", "")),
        ]).lower()
        
        for category, patterns in suspicious_patterns.items():
            matches = [p for p in patterns if p.lower() in search_text]
            if matches:
                mitre_map = {
                    "sqli": "T1190", "xss": "T1059.007", "cmd_injection": "T1059",
                    "ssrf": "T1090", "xxe": "T1190",
                }
                return DetectionAlert(
                    alert_type=category,
                    confidence=min(0.5 + 0.1 * len(matches), 0.95),
                    source_ip=request.source_ip,
                    evidence=f"Matched patterns: {matches[:3]}",
                    mitre_technique=mitre_map.get(category, "T1190"),
                    timestamp=request.timestamp,
                    request=request,
                    recommended_action="block_ip" if len(matches) > 2 else "challenge",
                )
        return None
    
    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for c in data:
            freq[c] += 1
        length = len(data)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
```

### 2. `src/sentinel/defense/active_defense.py`

```python
"""
ActiveDefense — Automated defense response system.

Actions:
- Block IP (firewall rule)
- Rate limit IP
- Deploy CSP headers
- Add WAF rules
- Harden response headers
- Rotate tokens/sessions
"""
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from sentinel.defense.behavioral_detector import DetectionAlert
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class DefenseAction:
    action_type: str      # "block_ip", "rate_limit", "add_waf_rule", "deploy_csp", "harden_headers"
    target: str           # IP, endpoint, or global
    parameters: dict
    triggered_by: str     # Alert ID
    expires_at: Optional[datetime] = None
    mitre_mitigation: str = ""  # MITRE mitigation ID


class ActiveDefense:
    """
    Automated defense execution.
    
    Takes detection alerts and executes appropriate countermeasures.
    Tracks all actions for defense effectiveness scoring.
    """
    
    def __init__(self):
        self.blocked_ips: set[str] = set()
        self.rate_limited_ips: dict[str, int] = {}  # IP → max requests/min
        self.waf_rules: list[dict] = []
        self.defense_actions: list[DefenseAction] = []
        self.csp_policy: str = ""
    
    def respond(self, alert: DetectionAlert) -> DefenseAction:
        """Generate and execute defense response for a detection alert."""
        action_map = {
            "block_ip": self._block_ip,
            "rate_limit": self._rate_limit,
            "challenge": self._add_challenge,
            "log": self._log_only,
        }
        
        handler = action_map.get(alert.recommended_action, self._log_only)
        action = handler(alert)
        self.defense_actions.append(action)
        
        logger.info(f"Defense action: {action.action_type} for {alert.source_ip} (alert: {alert.alert_type})")
        return action
    
    def _block_ip(self, alert: DetectionAlert) -> DefenseAction:
        """Block an IP address."""
        self.blocked_ips.add(alert.source_ip)
        return DefenseAction(
            action_type="block_ip",
            target=alert.source_ip,
            parameters={"duration_minutes": 60},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
            expires_at=datetime.now() + timedelta(minutes=60),
            mitre_mitigation="M1035",  # Limit Access to Resource Over Network
        )
    
    def _rate_limit(self, alert: DetectionAlert) -> DefenseAction:
        """Apply rate limiting to an IP."""
        self.rate_limited_ips[alert.source_ip] = 10  # 10 req/min
        return DefenseAction(
            action_type="rate_limit",
            target=alert.source_ip,
            parameters={"max_requests_per_minute": 10},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
            expires_at=datetime.now() + timedelta(minutes=30),
            mitre_mitigation="M1031",  # Network Intrusion Prevention
        )
    
    def _add_challenge(self, alert: DetectionAlert) -> DefenseAction:
        """Add CAPTCHA/challenge for suspicious requests."""
        return DefenseAction(
            action_type="challenge",
            target=alert.source_ip,
            parameters={"type": "captcha"},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
            mitre_mitigation="M1036",  # Account Use Policies
        )
    
    def _log_only(self, alert: DetectionAlert) -> DefenseAction:
        return DefenseAction(
            action_type="log",
            target=alert.source_ip,
            parameters={"severity": alert.alert_type},
            triggered_by=f"{alert.alert_type}:{alert.timestamp}",
        )
    
    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips
    
    def get_rate_limit(self, ip: str) -> Optional[int]:
        return self.rate_limited_ips.get(ip)
    
    def suggest_hardening(self, findings: list[dict]) -> list[dict]:
        """
        Suggest hardening measures based on findings.
        
        For each finding, suggest:
        - Specific WAF rule
        - Header configuration
        - IAM restriction
        - Patch version
        """
        suggestions = []
        for finding in findings:
            category = finding.get("category", "")
            
            if category in ("injection", "sqli"):
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "waf_rule",
                    "rule": "Block requests with SQL keywords in parameters",
                    "config": {"pattern": "UNION|SELECT|INSERT|UPDATE|DELETE|DROP", "action": "block"},
                    "header": {"X-Content-Type-Options": "nosniff"},
                    "code_fix": "Use parameterized queries / prepared statements",
                })
            elif category == "xss":
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "csp",
                    "rule": "Deploy Content Security Policy",
                    "config": {"Content-Security-Policy": "default-src 'self'; script-src 'self'"},
                    "header": {"X-XSS-Protection": "1; mode=block"},
                    "code_fix": "HTML-encode all user input in templates",
                })
            elif category == "ssrf":
                suggestions.append({
                    "finding_id": finding.get("hypothesis_id"),
                    "type": "network",
                    "rule": "Block outbound requests to internal IPs",
                    "config": {"blocked_ranges": ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]},
                    "code_fix": "Validate and whitelist allowed URL schemes and hosts",
                })
        
        return suggestions
```

### 3. `src/sentinel/defense/adversarial_loop.py`

```python
"""
AdversarialLoop — Red team vs Blue team real-time feedback loop.

The speed narrative: Red team attacks at Cerebras speed (1000-1700 tok/s).
Blue team MUST react faster than attacks land.

Loop:
1. Red agent launches attack
2. Blue detector analyzes in real-time
3. Blue defense responds (block/rate-limit)
4. Red agent detects defense, adapts tactics
5. Repeat until red runs out of bypasses or blue achieves full coverage
"""
import asyncio
import time
from dataclasses import dataclass, field
from typing import Callable

from sentinel.defense.behavioral_detector import BehavioralDetector, DetectionAlert, RequestProfile
from sentinel.defense.active_defense import ActiveDefense, DefenseAction
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class RoundResult:
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
    total_rounds: int = 0
    red_successes: int = 0
    blue_detections: int = 0
    blue_blocks: int = 0
    avg_detection_latency_ms: float = 0
    avg_response_latency_ms: float = 0
    coverage_score: float = 0  # Percentage of attacks detected
    rounds: list[RoundResult] = field(default_factory=list)


class AdversarialLoop:
    """
    Orchestrates the red vs blue adversarial feedback loop.
    
    Red team:
    - Uses GuardedExploitAgent to launch attacks
    - Observes blue team responses (blocked? rate limited?)
    - Adapts: switches payload, changes timing, uses different technique
    - Uses Cerebras for speed (real-time adaptation)
    
    Blue team:
    - BehavioralDetector analyzes every request
    - ActiveDefense responds automatically
    - Uses Cerebras for speed (must be faster than red)
    
    Speed is the product: faster inference = better defense.
    """
    
    def __init__(
        self,
        detector: BehavioralDetector,
        defense: ActiveDefense,
        red_agent_callback: Callable = None,
    ):
        self.detector = detector
        self.defense = defense
        self.red_callback = red_agent_callback
        self.metrics = LoopMetrics()
    
    async def run_loop(
        self,
        target: str,
        max_rounds: int = 50,
        red_techniques: list[str] = None,
    ) -> LoopMetrics:
        """
        Run adversarial loop.
        
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
        blocked_techniques = set()
        
        for round_num in range(max_rounds):
            # Skip blocked techniques, try next
            while technique_index < len(techniques) and techniques[technique_index] in blocked_techniques:
                technique_index += 1
            
            if technique_index >= len(techniques):
                logger.info(f"Red team exhausted all techniques after {round_num} rounds")
                break
            
            current_technique = techniques[technique_index]
            
            # 1. Red attack
            attack_start = time.monotonic()
            request = self._generate_attack_request(current_technique, target)
            
            # 2. Blue detect
            detect_start = time.monotonic()
            alerts = self.detector.analyze_request(request)
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
    
    def _generate_attack_request(self, technique: str, target: str) -> RequestProfile:
        """Generate a mock attack request for the given technique."""
        # This would integrate with actual red team tools in production
        payload_map = {
            "sqli_basic": ("GET", "/api/products", {"q": "' OR 1=1 --"}),
            "sqli_encoded": ("GET", "/api/products", {"q": "%27%20OR%201%3D1%20--"}),
            "sqli_time_based": ("GET", "/api/products", {"q": "' AND SLEEP(5) --"}),
            "xss_reflected": ("GET", "/search", {"q": "<script>alert(1)</script>"}),
            "xss_dom": ("GET", "/search", {"q": "javascript:alert(1)"}),
            "xss_encoded": ("GET", "/search", {"q": "%3Cscript%3Ealert(1)%3C/script%3E"}),
            "ssrf_direct": ("GET", "/api/fetch", {"url": "http://169.254.169.254/latest/meta-data/"}),
            "ssrf_redirect": ("GET", "/api/fetch", {"url": "http://evil.com/redirect?to=169.254.169.254"}),
            "cmd_injection_basic": ("POST", "/api/exec", {"cmd": "; cat /etc/passwd"}),
            "brute_force_slow": ("POST", "/api/login", {"email": "admin@juice.sh", "password": "test123"}),
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
```

### 4. `src/sentinel/defense/mitre_mapper.py`

```python
"""
MITREMapper — Map attacks and defenses to MITRE ATT&CK framework.
"""
from dataclasses import dataclass


@dataclass
class MITREMapping:
    technique_id: str
    technique_name: str
    tactic: str
    mitigation_id: str
    mitigation_name: str


ATTACK_MAPPING = {
    "sqli": MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", "M1030", "Network Segmentation"),
    "xss": MITREMapping("T1059.007", "JavaScript", "Execution", "M1021", "Restrict Web-Based Content"),
    "ssrf": MITREMapping("T1090", "Proxy", "Command and Control", "M1037", "Filter Network Traffic"),
    "cmd_injection": MITREMapping("T1059", "Command and Scripting Interpreter", "Execution", "M1038", "Execution Prevention"),
    "file_upload": MITREMapping("T1105", "Ingress Tool Transfer", "Command and Control", "M1031", "Network Intrusion Prevention"),
    "xxe": MITREMapping("T1190", "Exploit Public-Facing Application", "Initial Access", "M1048", "Application Isolation"),
    "auth_bypass": MITREMapping("T1078", "Valid Accounts", "Defense Evasion", "M1032", "Multi-factor Authentication"),
    "idor": MITREMapping("T1078", "Valid Accounts", "Initial Access", "M1018", "User Account Management"),
    "brute_force": MITREMapping("T1110", "Brute Force", "Credential Access", "M1036", "Account Use Policies"),
    "data_exfil": MITREMapping("T1041", "Exfiltration Over C2 Channel", "Exfiltration", "M1057", "Data Loss Prevention"),
}


class MITREMapper:
    def map_attack(self, category: str) -> MITREMapping:
        return ATTACK_MAPPING.get(category, MITREMapping("T1190", "Unknown", "Unknown", "M1030", "Unknown"))
    
    def get_attack_coverage(self, findings: list[dict]) -> dict:
        """Calculate ATT&CK coverage from findings."""
        tactics_covered = set()
        techniques_used = set()
        
        for f in findings:
            mapping = self.map_attack(f.get("category", ""))
            tactics_covered.add(mapping.tactic)
            techniques_used.add(mapping.technique_id)
        
        return {
            "tactics_covered": list(tactics_covered),
            "techniques_used": list(techniques_used),
            "total_tactics": len(tactics_covered),
            "total_techniques": len(techniques_used),
        }
```

### 5. `src/sentinel/defense/remediation_verifier.py`

```python
"""
RemediationVerifier — Post-fix verification.

After exploit:
1. Suggest specific remediation
2. (Optional) Apply fix
3. Re-run exploit
4. Verify fix worked
"""
from sentinel.logging import get_logger

logger = get_logger(__name__)


class RemediationVerifier:
    """
    Autonomous blue hardening verification.
    
    For each exploited finding:
    1. Generate specific remediation recommendation
    2. Re-run the exact exploit that succeeded
    3. Confirm it now fails (fix verified)
    4. Log result for defense effectiveness scoring
    """
    
    async def verify_remediation(self, finding: dict, replay_tool) -> dict:
        """Re-run exploit after fix and verify it's blocked."""
        result = await replay_tool(finding)
        
        return {
            "finding_id": finding.get("hypothesis_id"),
            "fix_verified": not result.get("success", True),
            "original_severity": finding.get("severity"),
            "retest_result": "BLOCKED" if not result.get("success") else "STILL_VULNERABLE",
        }
    
    async def bulk_verify(self, findings: list[dict], replay_tool) -> dict:
        """Verify remediation for all findings."""
        results = []
        for finding in findings:
            result = await self.verify_remediation(finding, replay_tool)
            results.append(result)
        
        verified = sum(1 for r in results if r["fix_verified"])
        return {
            "total": len(results),
            "verified_fixed": verified,
            "still_vulnerable": len(results) - verified,
            "fix_rate": verified / max(len(results), 1),
            "details": results,
        }
```

---

## Tests

### `tests/defense/test_behavioral_detector.py`

```python
import time
import pytest
from sentinel.defense.behavioral_detector import BehavioralDetector, RequestProfile

class TestBehavioralDetector:
    def setup_method(self):
        self.detector = BehavioralDetector()
    
    def test_detects_sqli(self):
        req = RequestProfile(
            timestamp=time.time(), source_ip="10.0.0.1", method="GET",
            path="/api/products", params={"q": "' OR 1=1 --"}, headers={},
            body_size=0, body_entropy=0, response_code=200, response_size=100, response_time_ms=50
        )
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "sqli" for a in alerts)
    
    def test_detects_brute_force(self):
        now = time.time()
        for i in range(15):
            req = RequestProfile(
                timestamp=now + i * 0.05, source_ip="10.0.0.2", method="POST",
                path="/login", params={}, headers={}, body_size=100,
                body_entropy=3.0, response_code=401, response_size=50, response_time_ms=20
            )
            self.detector.analyze_request(req)
        
        # Next request should trigger brute force
        req = RequestProfile(
            timestamp=now + 0.8, source_ip="10.0.0.2", method="POST",
            path="/login", params={}, headers={}, body_size=100,
            body_entropy=3.0, response_code=401, response_size=50, response_time_ms=20
        )
        alerts = self.detector.analyze_request(req)
        assert any(a.alert_type == "brute_force" for a in alerts)
    
    def test_entropy_calculation(self):
        assert BehavioralDetector.calculate_entropy("aaaa") < BehavioralDetector.calculate_entropy("a1b2c3d4!")
        assert BehavioralDetector.calculate_entropy("") == 0.0

class TestAdversarialLoop:
    @pytest.mark.asyncio
    async def test_loop_runs(self):
        from sentinel.defense.adversarial_loop import AdversarialLoop
        detector = BehavioralDetector()
        from sentinel.defense.active_defense import ActiveDefense
        defense = ActiveDefense()
        loop = AdversarialLoop(detector, defense)
        metrics = await loop.run_loop("http://localhost:3000", max_rounds=5)
        assert metrics.total_rounds == 5
```

---

## Acceptance Criteria

- [ ] BehavioralDetector detects SQLi, XSS, brute force, scanning, data exfil
- [ ] ActiveDefense blocks IPs, rate limits, and suggests hardening
- [ ] AdversarialLoop runs red vs blue with metrics
- [ ] Defense effectiveness score calculated (detection rate, latency)
- [ ] MITRE ATT&CK mapping for all attacks and defenses
- [ ] RemediationVerifier re-tests exploits after fixes
- [ ] Speed demo: Cerebras-powered blue team vs simulated slow inference
- [ ] All tests pass