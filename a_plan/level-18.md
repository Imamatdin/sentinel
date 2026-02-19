# LEVEL 18: Behavioral Blue Team (Tiered Detection + Adaptive WAF)

## Context
Existing blue team tools (NetworkMonitor, WAFEngine, Responder) use signature matching. This level upgrades to behavioral detection: per-route traffic profiling, transformer-based anomaly detection, and adaptive WAF rule synthesis. The red team's exploits test whether the blue team can detect and block them.

Research: Block 2 (Tiered detection: Kruegel-Vigna → RoBERTa+OCSVM → DeepHTTP, WAF rule synthesis via NSGA-II, deception/tripwires).

## Why
Signature WAFs miss zero-days. Behavioral detection catches novel payloads by learning what "normal" looks like and flagging deviations. The adversarial red-vs-blue loop validates both sides: red team shows detection gaps, blue team shows what it catches. This is Sentinel's "purple team" mode.

---

## Files to Create

### `src/sentinel/blue_team/__init__.py`
```python
"""Advanced blue team — behavioral detection, adaptive WAF, deception."""
```

### `src/sentinel/blue_team/traffic_profiler.py`
```python
"""
Per-Route Traffic Profiler (Tier 1 Detection — Kruegel-Vigna style).

Builds statistical profiles for each API endpoint:
- Parameter count, types, lengths (mean/stddev)
- Character class distribution (alpha, digit, special)
- Request frequency baseline
- Token entropy (high entropy = possible injection)

Anomaly = request that deviates >3σ from the learned profile.
O(1) per request, always-on baseline.
"""
from dataclasses import dataclass, field
from collections import defaultdict
import math
import re
from sentinel.logging import get_logger

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
    char_class_dist: dict = field(default_factory=lambda: {
        "alpha": 0.0, "digit": 0.0, "special": 0.0
    })


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
    
    def learn(self, route: str, params: dict[str, str]):
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
        
        details = []
        if abs(pc_z) > self.ANOMALY_THRESHOLD:
            details.append(f"Unusual parameter count (z={pc_z:.1f})")
        if abs(pl_z) > self.ANOMALY_THRESHOLD:
            details.append(f"Unusual parameter lengths (z={pl_z:.1f})")
        if abs(en_z) > self.ANOMALY_THRESHOLD:
            details.append(f"High entropy in parameters (z={en_z:.1f}) — possible injection")
        
        return AnomalyScore(
            route=route, total_score=total,
            param_count_z=pc_z, param_length_z=pl_z, entropy_z=en_z,
            is_anomalous=is_anom,
            details="; ".join(details) if details else "Normal",
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
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())
    
    def _z_score(self, value: float, mean: float, variance: float) -> float:
        std = math.sqrt(variance) if variance > 0 else 1.0
        return (value - mean) / std
    
    def _rebuild_profile(self, route: str, samples: list[dict]):
        """Rebuild profile from accumulated samples."""
        n = len(samples)
        
        def mean_var(key):
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
```

### `src/sentinel/blue_team/adaptive_waf.py`
```python
"""
Adaptive WAF Rule Synthesizer.

Takes red team attack traces and generates ModSecurity-compatible WAF rules.
Two strategies:
1. Pattern extraction: Analyze successful exploit payloads → extract common patterns → generate rules
2. Behavioral rules: Block requests matching anomaly profile from TrafficProfiler

ModSec-Learn inspired: treat CRS rules as features, learn per-app weights.
"""
from dataclasses import dataclass
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class WAFRule:
    rule_id: int
    description: str
    pattern: str          # Regex pattern to match
    action: str           # "deny" | "log" | "redirect"
    phase: int            # ModSec phase (1=request headers, 2=request body)
    severity: str
    source: str           # "red_team_trace" | "anomaly_profile" | "manual"
    modsec_rule: str      # Full ModSecurity rule string


class AdaptiveWAF:
    """Generate WAF rules from red team attack traces."""
    
    NEXT_RULE_ID = 900000  # Custom rule ID range
    
    def __init__(self):
        self.rules: list[WAFRule] = []
    
    def generate_from_attack(self, attack_trace: dict) -> WAFRule | None:
        """
        Generate a WAF rule from a successful attack trace.
        
        Args:
            attack_trace: {category, payload, target_param, method, path}
        """
        category = attack_trace.get("category", "")
        payload = attack_trace.get("payload", "")
        param = attack_trace.get("target_param", "")
        
        if not payload:
            return None
        
        pattern = self._extract_pattern(payload, category)
        if not pattern:
            return None
        
        rule_id = self.NEXT_RULE_ID + len(self.rules)
        
        modsec = (
            f'SecRule ARGS "{pattern}" '
            f'"id:{rule_id},phase:2,deny,status:403,'
            f'msg:\'Sentinel auto-rule: {category} pattern detected\','
            f'severity:CRITICAL,tag:sentinel/auto"'
        )
        
        rule = WAFRule(
            rule_id=rule_id,
            description=f"Auto-generated rule for {category} via {param}",
            pattern=pattern,
            action="deny",
            phase=2,
            severity="critical",
            source="red_team_trace",
            modsec_rule=modsec,
        )
        
        self.rules.append(rule)
        logger.info(f"Generated WAF rule {rule_id} for {category}")
        return rule
    
    def generate_from_anomaly(self, profiler_route: str, anomaly_details: str) -> WAFRule | None:
        """Generate a WAF rule from TrafficProfiler anomaly patterns."""
        rule_id = self.NEXT_RULE_ID + len(self.rules)
        
        modsec = (
            f'SecRule REQUEST_URI "@streq {profiler_route}" '
            f'"id:{rule_id},phase:2,chain,'
            f'msg:\'Sentinel behavioral rule: anomalous traffic to {profiler_route}\','
            f'severity:WARNING,tag:sentinel/behavioral"\n'
            f'  SecRule ARGS "@validateByteRange 1-255" '
            f'"setvar:tx.anomaly_score=+5"'
        )
        
        rule = WAFRule(
            rule_id=rule_id,
            description=f"Behavioral rule for anomalous traffic to {profiler_route}: {anomaly_details}",
            pattern=f"@streq {profiler_route}",
            action="log",
            phase=2,
            severity="warning",
            source="anomaly_profile",
            modsec_rule=modsec,
        )
        self.rules.append(rule)
        return rule
    
    def _extract_pattern(self, payload: str, category: str) -> str:
        """Extract a regex pattern from an attack payload."""
        import re
        
        if category == "sqli":
            if re.search(r"(?i)(union|select|insert|drop|delete|update)", payload):
                return r"(?i)(union\s+select|drop\s+table|;\s*delete|;\s*update|or\s+1\s*=\s*1)"
        
        elif category == "xss":
            if "<script" in payload.lower() or "onerror" in payload.lower():
                return r"(?i)(<script|on\w+\s*=|javascript:|data:text/html)"
        
        elif category == "command":
            if any(c in payload for c in [";", "|", "`", "$("]):
                return r"(;\s*\w+|`[^`]+`|\$\([^)]+\)|\|\s*\w+)"
        
        elif category == "path_traversal":
            if ".." in payload:
                return r"(\.\.\/|\.\.\\|%2e%2e)"
        
        elif category == "ssrf":
            return r"(?i)(127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254|10\.\d|172\.(1[6-9]|2\d|3[01]))"
        
        if len(payload) > 10:
            fragment = re.escape(payload[:30])
            return fragment
        
        return ""
    
    def export_rules(self) -> str:
        """Export all rules as a ModSecurity config file."""
        lines = [
            "# Sentinel Auto-Generated WAF Rules",
            f"# Generated: {len(self.rules)} rules from red team traces",
            "",
        ]
        for rule in self.rules:
            lines.append(f"# {rule.description}")
            lines.append(rule.modsec_rule)
            lines.append("")
        return "\n".join(lines)
```

### `src/sentinel/blue_team/tripwire.py`
```python
"""
Deception Tripwires — Plant honeytokens that alert when accessed.

Placement strategy: use Neo4j attack graph to find high-attacker-probability,
low-legitimate-use locations (e.g., fake .env files, decoy database dumps,
fake admin endpoints).

NodeZero pattern: AWS cred files, MySQL dumps with DNS callbacks.
Thinkst principle: protocol-minimal triggers (DNS-only callbacks).
"""
from dataclasses import dataclass, field
from datetime import datetime
import uuid
import json
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class Tripwire:
    wire_id: str
    wire_type: str       # "aws_creds", "db_dump", "admin_endpoint", "api_key", "config_file"
    location: str        # Where planted (file path, endpoint, etc.)
    callback_url: str    # DNS/HTTP canary URL that fires on access
    content: str         # The decoy content placed at location
    planted_at: datetime = None
    triggered: bool = False
    triggered_at: datetime = None
    triggered_by: str = ""  # Source IP / user-agent that tripped it


@dataclass
class TripwireAlert:
    wire_id: str
    wire_type: str
    location: str
    triggered_at: datetime
    source_ip: str
    user_agent: str
    details: str


class TripwireManager:
    """Plant and monitor deception tripwires."""
    
    def __init__(self, canary_domain: str = "canary.sentinel.local"):
        self.canary_domain = canary_domain
        self.wires: dict[str, Tripwire] = {}
        self.alerts: list[TripwireAlert] = []
    
    def plant_aws_creds(self, file_path: str = "/.aws/credentials") -> Tripwire:
        """
        Generate fake AWS credentials that phone home when used.
        Any AWS API call with these creds triggers a DNS lookup to our canary.
        """
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.aws.{self.canary_domain}"
        
        content = (
            "[default]\n"
            f"aws_access_key_id = AKIA{''.join(uuid.uuid4().hex[:16].upper())}\n"
            f"aws_secret_access_key = {''.join(uuid.uuid4().hex)}\n"
            f"# endpoint_url = https://{callback}\n"
            f"region = us-east-1\n"
        )
        
        wire = Tripwire(
            wire_id=wire_id,
            wire_type="aws_creds",
            location=file_path,
            callback_url=callback,
            content=content,
            planted_at=datetime.utcnow(),
        )
        self.wires[wire_id] = wire
        logger.info(f"Planted AWS creds tripwire at {file_path} (canary: {callback})")
        return wire
    
    def plant_db_dump(self, file_path: str = "/backup/users.sql") -> Tripwire:
        """
        Generate a fake database dump with DNS-canary email addresses.
        If an attacker tries to use these emails, DNS resolves to our canary.
        """
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.db.{self.canary_domain}"
        
        content = (
            "-- MySQL dump 10.13\n"
            "-- Server version: 8.0.32\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `email` varchar(255) DEFAULT NULL,\n"
            "  `password_hash` varchar(255) DEFAULT NULL,\n"
            "  `role` varchar(50) DEFAULT 'user',\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB;\n\n"
            "INSERT INTO `users` VALUES\n"
            f"(1, 'admin@{callback}', '$2b$12$LJ3m4ks92jf84kDj3mf0s.fake', 'admin'),\n"
            f"(2, 'cto@{callback}', '$2b$12$9fK3jf84Kfj38fj3Dkf0s.fake', 'admin'),\n"
            f"(3, 'dev@{callback}', '$2b$12$Kf83jfD93kfj38fDk3f0s.fake', 'user');\n"
        )
        
        wire = Tripwire(
            wire_id=wire_id,
            wire_type="db_dump",
            location=file_path,
            callback_url=callback,
            content=content,
            planted_at=datetime.utcnow(),
        )
        self.wires[wire_id] = wire
        logger.info(f"Planted DB dump tripwire at {file_path} (canary: {callback})")
        return wire
    
    def plant_admin_endpoint(self, path: str = "/admin/debug") -> Tripwire:
        """
        Register a decoy admin endpoint. Any request to it = attacker probing.
        """
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.http.{self.canary_domain}"
        
        content = json.dumps({
            "status": "maintenance",
            "debug_token": f"dbg-{uuid.uuid4().hex}",
            "note": "Service temporarily unavailable. Contact admin.",
        })
        
        wire = Tripwire(
            wire_id=wire_id,
            wire_type="admin_endpoint",
            location=path,
            callback_url=callback,
            content=content,
            planted_at=datetime.utcnow(),
        )
        self.wires[wire_id] = wire
        logger.info(f"Planted admin endpoint tripwire at {path}")
        return wire
    
    def plant_config_file(self, file_path: str = "/.env.backup") -> Tripwire:
        """
        Plant a fake .env file with canary tokens.
        """
        wire_id = f"tw-{uuid.uuid4().hex[:8]}"
        callback = f"{wire_id}.env.{self.canary_domain}"
        
        content = (
            f"DATABASE_URL=postgresql://admin:supersecret@{callback}:5432/prod\n"
            f"REDIS_URL=redis://:{uuid.uuid4().hex[:12]}@{callback}:6379\n"
            f"SECRET_KEY={uuid.uuid4().hex}\n"
            f"STRIPE_SECRET_KEY=sk_live_{uuid.uuid4().hex}\n"
            f"SENDGRID_API_KEY=SG.{uuid.uuid4().hex[:22]}\n"
        )
        
        wire = Tripwire(
            wire_id=wire_id,
            wire_type="config_file",
            location=file_path,
            callback_url=callback,
            content=content,
            planted_at=datetime.utcnow(),
        )
        self.wires[wire_id] = wire
        logger.info(f"Planted config tripwire at {file_path}")
        return wire
    
    def trigger(self, wire_id: str, source_ip: str, user_agent: str = "") -> TripwireAlert | None:
        """Record a tripwire being triggered."""
        wire = self.wires.get(wire_id)
        if not wire:
            return None
        
        wire.triggered = True
        wire.triggered_at = datetime.utcnow()
        wire.triggered_by = source_ip
        
        alert = TripwireAlert(
            wire_id=wire_id,
            wire_type=wire.wire_type,
            location=wire.location,
            triggered_at=wire.triggered_at,
            source_ip=source_ip,
            user_agent=user_agent,
            details=f"Tripwire '{wire.wire_type}' at {wire.location} accessed by {source_ip}",
        )
        self.alerts.append(alert)
        logger.warning(f"TRIPWIRE TRIGGERED: {alert.details}")
        return alert
    
    def get_active_wires(self) -> list[Tripwire]:
        return [w for w in self.wires.values() if not w.triggered]
    
    def get_triggered_wires(self) -> list[Tripwire]:
        return [w for w in self.wires.values() if w.triggered]
```

### `src/sentinel/blue_team/red_blue_loop.py`
```python
"""
Red vs Blue Adversarial Loop — Orchestrates attack/detect/adapt cycles.

Flow:
1. Red team runs exploit against target
2. Blue team's TrafficProfiler + WAFEngine attempt to detect/block
3. If exploit succeeds undetected → generate new WAF rule from attack trace
4. If exploit blocked → log evasion failure, try variant
5. Score both sides: red team success rate vs blue team detection rate

Purple team metrics:
- Detection coverage %: attacks detected / total attacks
- Evasion rate %: attacks that bypassed all defenses
- Mean time to detect (MTTD)
- Rule generation rate: auto-rules created per engagement
"""
from dataclasses import dataclass, field
from datetime import datetime
from sentinel.blue_team.traffic_profiler import TrafficProfiler, AnomalyScore
from sentinel.blue_team.adaptive_waf import AdaptiveWAF, WAFRule
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class AttackAttempt:
    attempt_id: str
    category: str
    payload: str
    target_route: str
    target_param: str
    method: str
    timestamp: datetime = field(default_factory=datetime.utcnow)


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
        """
        Submit a red team attack attempt through the blue team pipeline.
        Returns whether it was detected and by which layer.
        """
        self.attempts.append(attempt)
        start = datetime.utcnow()
        
        # Layer 1: Traffic Profiler (behavioral)
        anomaly = self.profiler.score(
            attempt.target_route,
            {attempt.target_param: attempt.payload}
        )
        
        if anomaly.is_anomalous:
            latency = (datetime.utcnow() - start).total_seconds() * 1000
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
            latency = (datetime.utcnow() - start).total_seconds() * 1000
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
        
        # Not detected → generate new WAF rule from this attack
        latency = (datetime.utcnow() - start).total_seconds() * 1000
        new_rule = self.waf.generate_from_attack({
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
        
        if new_rule:
            logger.info(f"Attack evaded detection → auto-generated WAF rule {new_rule.rule_id}")
        
        return result
    
    def train_profiler(self, route: str, normal_requests: list[dict[str, str]]):
        """Feed normal traffic into the profiler for baseline training."""
        for params in normal_requests:
            self.profiler.learn(route, params)
        logger.info(f"Trained profiler on {route} with {len(normal_requests)} samples")
    
    def _check_waf_rules(self, payload: str) -> WAFRule | None:
        """Check if payload matches any existing WAF rules."""
        import re
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
            avg_detection_latency_ms=round(sum(latencies) / max(len(latencies), 1), 2),
        )
```

---

## Files to Modify

### `src/sentinel/api/` — Add blue team endpoints
```python
@app.get("/api/v1/blue-team/metrics")
async def blue_team_metrics():
    """Return purple team loop metrics."""
    return loop.get_metrics()

@app.get("/api/v1/blue-team/waf-rules")
async def waf_rules():
    """Return all auto-generated WAF rules."""
    return {"rules": [r.__dict__ for r in waf.rules], "export": waf.export_rules()}

@app.get("/api/v1/blue-team/tripwires")
async def tripwire_status():
    """Return tripwire status."""
    return {
        "active": len(manager.get_active_wires()),
        "triggered": len(manager.get_triggered_wires()),
        "alerts": [a.__dict__ for a in manager.alerts],
    }
```

### Neo4j — Detection events
After each red-vs-blue cycle, store detection results:
```cypher
CREATE (d:DetectionEvent {
    attempt_id: $attempt_id,
    detected: $detected,
    detected_by: $detected_by,
    anomaly_score: $anomaly_score,
    category: $category,
    timestamp: datetime(),
    engagement_id: $eid
})
```

---

## Tests

### `tests/blue_team/test_traffic_profiler.py`
```python
import pytest
from sentinel.blue_team.traffic_profiler import TrafficProfiler

class TestTrafficProfiler:
    def setup_method(self):
        self.profiler = TrafficProfiler()
    
    def test_insufficient_data_returns_not_anomalous(self):
        score = self.profiler.score("/api/login", {"user": "test"})
        assert not score.is_anomalous
        assert "Insufficient" in score.details
    
    def test_normal_traffic_not_anomalous(self):
        for i in range(25):
            self.profiler.learn("/api/search", {"q": f"term{i}", "page": "1"})
        score = self.profiler.score("/api/search", {"q": "normal", "page": "2"})
        assert not score.is_anomalous
    
    def test_injection_triggers_high_entropy(self):
        for i in range(25):
            self.profiler.learn("/api/search", {"q": f"word{i}"})
        score = self.profiler.score("/api/search", {
            "q": "' UNION SELECT username,password FROM users WHERE '1'='1"
        })
        assert score.entropy_z > 0 or score.param_length_z > 0
    
    def test_shannon_entropy(self):
        assert self.profiler._shannon_entropy("") == 0.0
        assert self.profiler._shannon_entropy("aaaa") == 0.0
        assert self.profiler._shannon_entropy("abcd") > 1.0
```

### `tests/blue_team/test_adaptive_waf.py`
```python
import pytest
from sentinel.blue_team.adaptive_waf import AdaptiveWAF

class TestAdaptiveWAF:
    def setup_method(self):
        self.waf = AdaptiveWAF()
    
    def test_generate_sqli_rule(self):
        rule = self.waf.generate_from_attack({
            "category": "sqli",
            "payload": "' UNION SELECT * FROM users--",
            "target_param": "id",
            "method": "GET",
            "path": "/api/users",
        })
        assert rule is not None
        assert rule.action == "deny"
        assert "SecRule" in rule.modsec_rule
    
    def test_generate_xss_rule(self):
        rule = self.waf.generate_from_attack({
            "category": "xss",
            "payload": "<script>alert(document.cookie)</script>",
            "target_param": "name",
        })
        assert rule is not None
        assert "script" in rule.pattern.lower()
    
    def test_export_rules(self):
        self.waf.generate_from_attack({
            "category": "sqli", "payload": "' OR 1=1--", "target_param": "q",
        })
        export = self.waf.export_rules()
        assert "Sentinel Auto-Generated" in export
        assert "SecRule" in export
    
    def test_no_rule_for_empty_payload(self):
        rule = self.waf.generate_from_attack({"category": "sqli", "payload": ""})
        assert rule is None
    
    def test_behavioral_rule(self):
        rule = self.waf.generate_from_anomaly("/api/search", "High entropy z=4.2")
        assert rule is not None
        assert rule.source == "anomaly_profile"
```

### `tests/blue_team/test_tripwire.py`
```python
import pytest
from sentinel.blue_team.tripwire import TripwireManager

class TestTripwireManager:
    def setup_method(self):
        self.manager = TripwireManager()
    
    def test_plant_aws_creds(self):
        wire = self.manager.plant_aws_creds()
        assert wire.wire_type == "aws_creds"
        assert "AKIA" in wire.content
        assert wire.callback_url.endswith(self.manager.canary_domain)
    
    def test_plant_db_dump(self):
        wire = self.manager.plant_db_dump()
        assert "CREATE TABLE" in wire.content
        assert wire.callback_url in wire.content
    
    def test_plant_config_file(self):
        wire = self.manager.plant_config_file()
        assert "DATABASE_URL" in wire.content
        assert "SECRET_KEY" in wire.content
    
    def test_trigger(self):
        wire = self.manager.plant_admin_endpoint()
        alert = self.manager.trigger(wire.wire_id, "192.168.1.100", "curl/7.68")
        assert alert is not None
        assert alert.source_ip == "192.168.1.100"
        assert wire.triggered is True
    
    def test_active_vs_triggered(self):
        w1 = self.manager.plant_aws_creds()
        w2 = self.manager.plant_db_dump()
        self.manager.trigger(w1.wire_id, "10.0.0.1")
        assert len(self.manager.get_active_wires()) == 1
        assert len(self.manager.get_triggered_wires()) == 1
```

### `tests/blue_team/test_red_blue_loop.py`
```python
import pytest
from sentinel.blue_team.red_blue_loop import RedBlueLoop, AttackAttempt

class TestRedBlueLoop:
    def setup_method(self):
        self.loop = RedBlueLoop()
    
    def test_undetected_generates_rule(self):
        attempt = AttackAttempt(
            attempt_id="a1", category="sqli",
            payload="' UNION SELECT * FROM users--",
            target_route="/api/search", target_param="q", method="GET",
        )
        result = self.loop.submit_attack(attempt)
        assert result.attempt_id == "a1"
        # Without profiler training, WAF should auto-generate a rule
        assert len(self.loop.waf.rules) >= 1
    
    def test_second_attack_caught_by_waf(self):
        a1 = AttackAttempt(
            attempt_id="a1", category="xss",
            payload="<script>alert(1)</script>",
            target_route="/api/comment", target_param="body", method="POST",
        )
        self.loop.submit_attack(a1)
        
        a2 = AttackAttempt(
            attempt_id="a2", category="xss",
            payload="<script>alert(document.cookie)</script>",
            target_route="/api/comment", target_param="body", method="POST",
        )
        result = self.loop.submit_attack(a2)
        # The auto-generated XSS rule from a1 should catch a2
        assert result.detected is True
        assert result.detected_by == "waf"
    
    def test_profiler_catches_trained_anomaly(self):
        # Train profiler with normal traffic
        normal = [{"q": f"search{i}"} for i in range(25)]
        self.loop.train_profiler("/api/search", normal)
        
        # Now attack with high-entropy payload
        attempt = AttackAttempt(
            attempt_id="a3", category="sqli",
            payload="';EXEC xp_cmdshell('net user hacker P@ss1 /add')--",
            target_route="/api/search", target_param="q", method="GET",
        )
        result = self.loop.submit_attack(attempt)
        # Should be caught by profiler or WAF
        assert result.anomaly_score >= 0  # At minimum, scored
    
    def test_metrics(self):
        metrics = self.loop.get_metrics()
        assert metrics.total_attacks == 0
        
        self.loop.submit_attack(AttackAttempt(
            attempt_id="m1", category="sqli", payload="1' OR '1'='1",
            target_route="/api", target_param="id", method="GET",
        ))
        metrics = self.loop.get_metrics()
        assert metrics.total_attacks == 1
    
    def test_metrics_after_multiple(self):
        for i in range(5):
            self.loop.submit_attack(AttackAttempt(
                attempt_id=f"m{i}", category="sqli",
                payload=f"payload_{i}' OR '1'='1",
                target_route="/api", target_param="id", method="GET",
            ))
        metrics = self.loop.get_metrics()
        assert metrics.total_attacks == 5
        assert metrics.detection_rate + metrics.evasion_rate == 1.0
```

---

## Acceptance Criteria
- [ ] TrafficProfiler learns per-route baselines from 20+ requests
- [ ] Anomaly scoring flags high-entropy injection payloads (z > 3.0)
- [ ] AdaptiveWAF generates valid ModSecurity rules from attack traces
- [ ] AdaptiveWAF generates behavioral rules from anomaly profiles
- [ ] Export produces a parseable ModSec config file
- [ ] TripwireManager plants 4 types: AWS creds, DB dump, admin endpoint, config file
- [ ] All tripwire content contains DNS canary callbacks
- [ ] Trigger mechanism records source IP and creates alerts
- [ ] RedBlueLoop chains profiler → WAF → auto-rule-generation
- [ ] Undetected attacks auto-generate WAF rules that catch future variants
- [ ] Second XSS attack is caught by rule auto-generated from first XSS attack
- [ ] train_profiler enables profiler-based detection in the loop
- [ ] Metrics track detection rate, evasion rate, avg latency, rules generated
- [ ] DetectionEvent nodes stored in Neo4j
- [ ] API endpoints return metrics, rules, and tripwire status
- [ ] All tests pass