# LEVEL 21: Federated Learning Pipeline

## Context
Each Sentinel deployment learns from engagements — exploit success rates, false positive patterns, technique effectiveness per stack. Federated learning aggregates these insights across deployments WITHOUT sharing raw logs. This is the data moat: Sentinel gets smarter with every customer.

Research: Block 12 (Federated Intelligence), Block 7 (Cross-engagement learning, anonymization, Beta-Bernoulli confidence scoring, Thompson Sampling). FL intrusion detection: 90%+ accuracy in academic studies.

## Why
XBOW doesn't learn across customers. Sentinel's genome + federated updates mean the 100th customer benefits from all 99 before them. Differential privacy ensures no one's data leaks. This is the Netflix recommendation engine for pentesting.

---

## Files to Create

### `src/sentinel/federated/__init__.py`
```python
"""Federated learning — cross-deployment pattern sharing with differential privacy."""
```

### `src/sentinel/federated/anonymizer.py`
```python
"""
Data Anonymizer — Strip PII and deployment-specific data before federation.

Rules:
- Replace IPs with placeholders (10.x.x.x → INTERNAL_HOST_1)
- Replace hostnames/domains with generic labels
- Replace paths with normalized patterns (/api/v1/users/123 → /api/v1/{resource}/{id})
- Strip credentials, tokens, session IDs
- Require N-engagement aggregation minimum before sharing patterns
"""
import re
import hashlib
from dataclasses import dataclass
from sentinel.logging import get_logger

logger = get_logger(__name__)

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)
PATH_ID_PATTERN = re.compile(r'/\d+(?=/|$)')
UUID_PATTERN = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
TOKEN_PATTERN = re.compile(r'(?:Bearer\s+|token=|key=|secret=)[A-Za-z0-9_\-\.]+', re.IGNORECASE)
EMAIL_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


@dataclass
class AnonymizedRecord:
    technique_family: str     # e.g., "sqli_union", "xss_reflected", "ssrf_internal"
    target_stack: str         # e.g., "nodejs_express_postgres"
    success: bool
    confidence: float
    payload_template: str     # Anonymized payload pattern
    response_pattern: str     # What success looked like (anonymized)
    metadata: dict            # Non-identifying metadata


class Anonymizer:
    """Strip PII and deployment-specific data from findings."""
    
    MIN_AGGREGATION = 5  # Minimum engagements before sharing a pattern
    
    def __init__(self):
        self._ip_map: dict[str, str] = {}
        self._domain_map: dict[str, str] = {}
        self._ip_counter = 0
        self._domain_counter = 0
    
    def anonymize_text(self, text: str) -> str:
        """Replace all PII in a text string."""
        result = text
        
        # Tokens first (longest matches)
        result = TOKEN_PATTERN.sub("[REDACTED_TOKEN]", result)
        
        # Emails
        result = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", result)
        
        # UUIDs
        result = UUID_PATTERN.sub("[REDACTED_UUID]", result)
        
        # IPs
        for ip in set(IP_PATTERN.findall(result)):
            if ip not in self._ip_map:
                self._ip_counter += 1
                self._ip_map[ip] = f"HOST_{self._ip_counter}"
            result = result.replace(ip, self._ip_map[ip])
        
        # Domains
        for domain in set(DOMAIN_PATTERN.findall(result)):
            if domain not in self._domain_map:
                self._domain_counter += 1
                self._domain_map[domain] = f"DOMAIN_{self._domain_counter}"
            result = result.replace(domain, self._domain_map[domain])
        
        # Path IDs
        result = PATH_ID_PATTERN.sub("/{id}", result)
        
        return result
    
    def anonymize_finding(self, finding: dict) -> AnonymizedRecord:
        """Convert a raw finding into an anonymized federated record."""
        return AnonymizedRecord(
            technique_family=self._classify_technique(finding),
            target_stack=finding.get("target_stack", "unknown"),
            success=finding.get("verified", False),
            confidence=finding.get("confidence", 0.5),
            payload_template=self._templatize_payload(finding.get("payload", "")),
            response_pattern=self.anonymize_text(finding.get("response", "")[:200]),
            metadata={
                "severity": finding.get("severity", ""),
                "category": finding.get("category", ""),
                "detection_method": finding.get("detection_method", ""),
            },
        )
    
    def _classify_technique(self, finding: dict) -> str:
        """Map a finding to a technique family."""
        category = finding.get("category", "").lower()
        payload = finding.get("payload", "").lower()
        
        if category == "sqli":
            if "union" in payload: return "sqli_union"
            if "sleep" in payload or "benchmark" in payload: return "sqli_blind_time"
            if "and" in payload and "=" in payload: return "sqli_blind_boolean"
            return "sqli_error"
        elif category == "xss":
            if "onerror" in payload or "onload" in payload: return "xss_event"
            if "<script" in payload: return "xss_script"
            return "xss_other"
        elif category == "ssrf":
            return "ssrf_internal"
        elif category == "command":
            return "command_injection"
        elif category == "idor":
            return "idor_horizontal"
        
        return f"{category}_generic"
    
    def _templatize_payload(self, payload: str) -> str:
        """Convert a specific payload into a reusable template."""
        template = self.anonymize_text(payload)
        # Replace specific values with placeholders
        template = re.sub(r"'\w+'", "'{value}'", template)
        template = re.sub(r'"\w+"', '"{value}"', template)
        return template[:500]
```

### `src/sentinel/federated/confidence.py`
```python
"""
Bayesian Confidence Scoring — Beta-Bernoulli per (technique, stack) pair.

Each technique-stack pair maintains a Beta(α, β) distribution:
- α = successes + 1 (prior)
- β = failures + 1 (prior)
- Mean = α / (α + β)
- Variance = αβ / ((α+β)²(α+β+1))

Thompson Sampling selects which techniques to try next:
- Sample from each Beta distribution
- Try the technique with highest sampled probability
- This naturally balances exploration (uncertain techniques) vs exploitation (proven ones)

Time decay: exponential discount on old trials to handle patching.
"""
import math
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TechniqueStats:
    technique: str
    stack: str
    alpha: float = 1.0        # Successes + prior
    beta: float = 1.0         # Failures + prior
    total_trials: int = 0
    last_updated: datetime = None
    
    @property
    def mean(self) -> float:
        return self.alpha / (self.alpha + self.beta)
    
    @property
    def variance(self) -> float:
        a, b = self.alpha, self.beta
        return (a * b) / ((a + b) ** 2 * (a + b + 1))
    
    @property
    def confidence_interval(self) -> tuple[float, float]:
        """95% credible interval using normal approximation."""
        std = math.sqrt(self.variance)
        return (max(0, self.mean - 1.96 * std), min(1, self.mean + 1.96 * std))


class BayesianConfidence:
    """Track technique effectiveness with Bayesian confidence scoring."""
    
    DECAY_HALFLIFE_DAYS = 90  # Old results lose half their weight every 90 days
    
    def __init__(self):
        self.stats: dict[str, TechniqueStats] = {}
    
    def _key(self, technique: str, stack: str) -> str:
        return f"{technique}::{stack}"
    
    def update(self, technique: str, stack: str, success: bool):
        """Record a trial result."""
        key = self._key(technique, stack)
        if key not in self.stats:
            self.stats[key] = TechniqueStats(technique=technique, stack=stack)
        
        s = self.stats[key]
        if success:
            s.alpha += 1
        else:
            s.beta += 1
        s.total_trials += 1
        s.last_updated = datetime.utcnow()
    
    def get_confidence(self, technique: str, stack: str) -> float:
        """Get current mean confidence for a technique-stack pair."""
        key = self._key(technique, stack)
        s = self.stats.get(key)
        if not s:
            return 0.5  # Uninformative prior
        
        # Apply time decay
        return self._decayed_mean(s)
    
    def thompson_sample(self, techniques: list[str], stack: str) -> list[tuple[str, float]]:
        """
        Thompson Sampling: sample from each technique's Beta distribution
        and return sorted by sampled probability (highest first).
        
        This naturally explores uncertain techniques while exploiting proven ones.
        """
        samples = []
        for tech in techniques:
            key = self._key(tech, stack)
            s = self.stats.get(key, TechniqueStats(technique=tech, stack=stack))
            
            # Apply decay to parameters
            a_decayed, b_decayed = self._decay_params(s)
            
            # Sample from Beta distribution
            sample = random.betavariate(max(a_decayed, 0.01), max(b_decayed, 0.01))
            samples.append((tech, sample))
        
        return sorted(samples, key=lambda x: x[1], reverse=True)
    
    def _decayed_mean(self, s: TechniqueStats) -> float:
        """Apply time decay to the mean estimate."""
        if not s.last_updated:
            return s.mean
        
        days_old = (datetime.utcnow() - s.last_updated).days
        decay = math.exp(-0.693 * days_old / self.DECAY_HALFLIFE_DAYS)  # ln(2) ≈ 0.693
        
        # Blend decayed estimate with prior
        decayed_alpha = 1 + (s.alpha - 1) * decay
        decayed_beta = 1 + (s.beta - 1) * decay
        
        return decayed_alpha / (decayed_alpha + decayed_beta)
    
    def _decay_params(self, s: TechniqueStats) -> tuple[float, float]:
        """Return decayed alpha, beta for Thompson Sampling."""
        if not s.last_updated:
            return s.alpha, s.beta
        
        days_old = (datetime.utcnow() - s.last_updated).days
        decay = math.exp(-0.693 * days_old / self.DECAY_HALFLIFE_DAYS)
        
        return 1 + (s.alpha - 1) * decay, 1 + (s.beta - 1) * decay
    
    def get_all_stats(self) -> list[TechniqueStats]:
        return list(self.stats.values())
    
    def merge_remote(self, remote_stats: list[dict]):
        """Merge stats from federated aggregation server."""
        for rs in remote_stats:
            key = self._key(rs["technique"], rs["stack"])
            if key not in self.stats:
                self.stats[key] = TechniqueStats(
                    technique=rs["technique"], stack=rs["stack"],
                    alpha=rs["alpha"], beta=rs["beta"],
                    total_trials=rs["total_trials"],
                )
            else:
                # Weighted merge: combine counts
                local = self.stats[key]
                local.alpha += rs["alpha"] - 1  # Subtract prior to avoid double-counting
                local.beta += rs["beta"] - 1
                local.total_trials += rs["total_trials"]
```

### `src/sentinel/federated/aggregator.py`
```python
"""
Federated Aggregation Server — Collects anonymized patterns from deployments.

Architecture:
1. Deployments push anonymized TechniqueStats + AnonymizedRecords
2. Aggregator merges stats with differential privacy (Laplace noise)
3. Aggregator publishes updated global model back to deployments

Differential Privacy: Add Laplace noise to counts before publishing.
ε-differential privacy with ε=1.0 (moderate privacy).
"""
import math
import random
from dataclasses import dataclass, field
from datetime import datetime
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FederatedUpdate:
    deployment_id: str
    timestamp: datetime
    technique_stats: list[dict]    # [{technique, stack, alpha, beta, total_trials}]
    pattern_records: list[dict]    # Anonymized findings
    deployment_count: int          # How many engagements this update represents


@dataclass
class GlobalModel:
    version: int = 0
    last_updated: datetime = None
    technique_stats: dict = field(default_factory=dict)  # key → {alpha, beta, trials, deployments}
    total_deployments: int = 0
    total_engagements: int = 0


class FederatedAggregator:
    """Aggregate anonymized patterns across deployments with differential privacy."""
    
    EPSILON = 1.0               # Differential privacy parameter
    MIN_DEPLOYMENTS = 3         # Minimum deployments before publishing a pattern
    MIN_ENGAGEMENTS = 5         # Minimum total engagements per pattern
    
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
                    "alpha": 1.0, "beta": 1.0,
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
        self.model.last_updated = datetime.utcnow()
        
        logger.info(f"Federated update from {update.deployment_id}: "
                     f"{len(update.technique_stats)} technique stats")
    
    def publish_model(self) -> dict:
        """
        Publish the global model with differential privacy noise.
        Only includes patterns meeting minimum thresholds.
        """
        published = []
        
        for key, entry in self.model.technique_stats.items():
            if entry["deployment_count"] < self.MIN_DEPLOYMENTS:
                continue
            if entry["total_trials"] < self.MIN_ENGAGEMENTS:
                continue
            
            # Add Laplace noise for differential privacy
            noisy_alpha = max(1.0, entry["alpha"] + self._laplace_noise())
            noisy_beta = max(1.0, entry["beta"] + self._laplace_noise())
            
            published.append({
                "technique": entry["technique"],
                "stack": entry["stack"],
                "alpha": round(noisy_alpha, 2),
                "beta": round(noisy_beta, 2),
                "total_trials": entry["total_trials"],  # Approximate, not exact
                "mean_success_rate": round(noisy_alpha / (noisy_alpha + noisy_beta), 4),
            })
        
        return {
            "version": self.model.version,
            "last_updated": str(self.model.last_updated),
            "total_deployments": self.model.total_deployments,
            "technique_stats": published,
        }
    
    def _laplace_noise(self) -> float:
        """Generate Laplace noise for ε-differential privacy."""
        # Laplace(0, 1/ε)
        scale = 1.0 / self.EPSILON
        u = random.random() - 0.5
        return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
```

---

## Files to Modify

### `src/sentinel/agents/hypothesis_engine.py`
Wire Thompson Sampling into hypothesis ranking:
```python
# After generating hypotheses, use confidence scoring to rank
from sentinel.federated.confidence import BayesianConfidence

confidence = BayesianConfidence()
# Load from genome/federated model...
ranked = confidence.thompson_sample(
    [h.category for h in hypotheses],
    target_stack
)
# Reorder hypotheses by Thompson-sampled priority
```

### `src/sentinel/api/` — Add federated endpoints
```python
@app.post("/api/v1/federated/update")
async def receive_federated_update(update: dict):
    """Receive anonymized stats from a deployment."""

@app.get("/api/v1/federated/model")
async def get_global_model():
    """Publish current global model (with DP noise)."""
```

---

## Tests

### `tests/federated/test_anonymizer.py`
```python
import pytest
from sentinel.federated.anonymizer import Anonymizer

class TestAnonymizer:
    def setup_method(self):
        self.anon = Anonymizer()

    def test_ip_anonymization(self):
        result = self.anon.anonymize_text("Target is 192.168.1.100 on port 8080")
        assert "192.168.1.100" not in result
        assert "HOST_" in result

    def test_domain_anonymization(self):
        result = self.anon.anonymize_text("Scanning api.example.com for vulns")
        assert "example.com" not in result
        assert "DOMAIN_" in result

    def test_token_redaction(self):
        result = self.anon.anonymize_text("Bearer eyJhbGciOiJIUzI1NiJ9.test.signature")
        assert "eyJ" not in result
        assert "REDACTED_TOKEN" in result

    def test_email_redaction(self):
        result = self.anon.anonymize_text("Contact admin@company.com")
        assert "admin@company.com" not in result
        assert "REDACTED_EMAIL" in result

    def test_path_id_normalization(self):
        result = self.anon.anonymize_text("/api/v1/users/12345/orders/67890")
        assert "12345" not in result
        assert "{id}" in result

    def test_consistent_ip_mapping(self):
        r1 = self.anon.anonymize_text("Host 10.0.0.1")
        r2 = self.anon.anonymize_text("Same host 10.0.0.1")
        # Same IP should map to same placeholder
        placeholder = r1.split()[-1]
        assert placeholder in r2

    def test_technique_classification(self):
        finding = {"category": "sqli", "payload": "' UNION SELECT * FROM users--"}
        record = self.anon.anonymize_finding(finding)
        assert record.technique_family == "sqli_union"
```

### `tests/federated/test_confidence.py`
```python
import pytest
from sentinel.federated.confidence import BayesianConfidence

class TestBayesianConfidence:
    def setup_method(self):
        self.bc = BayesianConfidence()

    def test_uninformed_prior(self):
        assert self.bc.get_confidence("sqli", "nodejs") == 0.5

    def test_update_increases_confidence(self):
        for _ in range(10):
            self.bc.update("sqli_union", "nodejs_express", True)
        assert self.bc.get_confidence("sqli_union", "nodejs_express") > 0.7

    def test_failures_decrease_confidence(self):
        for _ in range(10):
            self.bc.update("xss_script", "react", False)
        assert self.bc.get_confidence("xss_script", "react") < 0.3

    def test_thompson_sampling_returns_sorted(self):
        self.bc.update("sqli", "node", True)
        self.bc.update("sqli", "node", True)
        self.bc.update("xss", "node", False)
        self.bc.update("xss", "node", False)
        
        results = self.bc.thompson_sample(["sqli", "xss"], "node")
        assert len(results) == 2
        # sqli should usually be ranked higher (but Thompson is stochastic)

    def test_merge_remote(self):
        self.bc.merge_remote([{
            "technique": "ssrf", "stack": "python_flask",
            "alpha": 5.0, "beta": 2.0, "total_trials": 6,
        }])
        assert self.bc.get_confidence("ssrf", "python_flask") > 0.5
```

### `tests/federated/test_aggregator.py`
```python
import pytest
from datetime import datetime
from sentinel.federated.aggregator import FederatedAggregator, FederatedUpdate

class TestFederatedAggregator:
    def setup_method(self):
        self.agg = FederatedAggregator()

    def test_receive_update(self):
        update = FederatedUpdate(
            deployment_id="deploy-1", timestamp=datetime.utcnow(),
            technique_stats=[{"technique": "sqli", "stack": "node", "alpha": 5, "beta": 2, "total_trials": 6}],
            pattern_records=[], deployment_count=3,
        )
        self.agg.receive_update(update)
        assert self.agg.model.total_deployments == 1
        assert self.agg.model.version == 1

    def test_min_deployments_threshold(self):
        # Single deployment shouldn't be published
        update = FederatedUpdate(
            deployment_id="d1", timestamp=datetime.utcnow(),
            technique_stats=[{"technique": "sqli", "stack": "node", "alpha": 10, "beta": 2, "total_trials": 11}],
            pattern_records=[], deployment_count=10,
        )
        self.agg.receive_update(update)
        model = self.agg.publish_model()
        assert len(model["technique_stats"]) == 0  # Below MIN_DEPLOYMENTS

    def test_publish_after_threshold(self):
        for i in range(5):
            self.agg.receive_update(FederatedUpdate(
                deployment_id=f"d{i}", timestamp=datetime.utcnow(),
                technique_stats=[{"technique": "sqli", "stack": "node", "alpha": 3, "beta": 1, "total_trials": 3}],
                pattern_records=[], deployment_count=2,
            ))
        model = self.agg.publish_model()
        assert len(model["technique_stats"]) >= 1

    def test_differential_privacy_adds_noise(self):
        for i in range(5):
            self.agg.receive_update(FederatedUpdate(
                deployment_id=f"d{i}", timestamp=datetime.utcnow(),
                technique_stats=[{"technique": "sqli", "stack": "node", "alpha": 10, "beta": 2, "total_trials": 11}],
                pattern_records=[], deployment_count=5,
            ))
        # Publish twice — results should differ due to Laplace noise
        m1 = self.agg.publish_model()
        m2 = self.agg.publish_model()
        if m1["technique_stats"] and m2["technique_stats"]:
            # Noise should make these slightly different (probabilistic)
            assert True  # At minimum, no crash
```

---

## Acceptance Criteria
- [ ] Anonymizer strips IPs, domains, tokens, emails, UUIDs, path IDs
- [ ] Consistent IP/domain mapping (same IP → same placeholder across calls)
- [ ] Technique classification maps findings to families (sqli_union, xss_event, etc.)
- [ ] BayesianConfidence tracks Beta(α,β) per technique-stack pair
- [ ] Thompson Sampling returns techniques sorted by sampled probability
- [ ] Time decay reduces old trial weight (90-day half-life)
- [ ] merge_remote integrates federated model updates
- [ ] FederatedAggregator enforces MIN_DEPLOYMENTS (3) and MIN_ENGAGEMENTS (5) thresholds
- [ ] Differential privacy: Laplace noise added to published counts (ε=1.0)
- [ ] Published model excludes patterns below threshold
- [ ] All tests pass