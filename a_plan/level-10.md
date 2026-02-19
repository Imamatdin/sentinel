# LEVEL 10: Predictive Vulnerability Scoring

## Context
Instead of testing all bug classes equally, predict which ones are most likely for a given tech stack. Uses historical engagement data (genome) + EPSS + code metrics to produce a ranked test plan. Requires L01 (EPSS) for CVE scoring.

Research: Block 12 (Predictive Models), Block 6 (ML scoring), Block 7 (Bayesian confidence).

## Why
Testing everything is slow and expensive. A Django + PostgreSQL stack is unlikely to have IIS misconfigs but very likely to have Django ORM bypass issues. Predictive scoring focuses 80% of effort on the 20% most likely bug classes.

---

## Files to Create

### `src/sentinel/intel/predictive_scorer.py`
```python
"""
Predictive Vulnerability Scorer.

Uses a Bayesian model to predict which vulnerability classes are most likely
for a given target's tech stack, based on:
1. Known tech stack (from recon)
2. Historical success rates from genome DB (Beta-Bernoulli per technique+stack pair)
3. EPSS scores for known CVEs
4. Code complexity metrics (if SAST data available from L08)

Output: ranked list of (vuln_class, probability) to prioritize hypothesis generation.
"""
import math
from dataclasses import dataclass, field
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class TechStackProfile:
    """Describes the target's detected technology stack."""
    languages: list[str] = field(default_factory=list)        # python, javascript, java
    frameworks: list[str] = field(default_factory=list)        # django, express, spring
    databases: list[str] = field(default_factory=list)         # postgresql, mongodb, redis
    web_servers: list[str] = field(default_factory=list)       # nginx, apache, iis
    os: list[str] = field(default_factory=list)                # linux, windows
    cloud_provider: str = ""                                    # aws, gcp, azure
    container_runtime: str = ""                                 # docker, k8s


@dataclass
class VulnPrediction:
    vuln_class: str
    probability: float       # 0.0-1.0 predicted likelihood
    confidence: float        # How sure we are about the prediction
    reasoning: list[str]     # Why we predict this
    suggested_tools: list[str]
    priority_rank: int = 0


# Prior knowledge: base rates for vuln classes given tech stack signals
# Format: {(tech_signal, vuln_class): (alpha, beta)} for Beta distribution
# alpha = pseudo-successes, beta = pseudo-failures
TECH_STACK_PRIORS = {
    # Python/Django
    ("django", "injection"): (3, 7),       # Django ORM usually prevents, but raw() exists
    ("django", "xss"): (4, 6),             # Template auto-escaping, but |safe filter
    ("django", "idor"): (6, 4),            # Common in Django views
    ("django", "auth_bypass"): (3, 7),     # Django auth is decent
    ("django", "ssrf"): (4, 6),            # Common in webhook features
    
    # Node/Express
    ("express", "injection"): (5, 5),      # No ORM by default
    ("express", "xss"): (6, 4),            # EJS/Pug often vulnerable
    ("express", "prototype_pollution"): (5, 5),
    ("express", "ssrf"): (5, 5),
    ("express", "auth_bypass"): (5, 5),    # Middleware-dependent
    
    # Java/Spring
    ("spring", "injection"): (3, 7),       # PreparedStatement usually used
    ("spring", "deserialization"): (6, 4), # Java deser is common
    ("spring", "xxe"): (5, 5),             # XML processing common
    ("spring", "auth_bypass"): (4, 6),     # Spring Security decent
    
    # Database-specific
    ("mongodb", "nosqli"): (6, 4),         # Very common
    ("postgresql", "injection"): (4, 6),   # Parameterized queries common but not universal
    ("redis", "injection"): (3, 7),        # Redis injection rare
    
    # Server-specific
    ("nginx", "misconfig"): (4, 6),
    ("apache", "misconfig"): (5, 5),
    ("iis", "misconfig"): (6, 4),          # IIS misconfigs very common
}

# Default prior when no stack-specific data exists
DEFAULT_PRIOR = (2, 8)  # Weakly informative: assume 20% base rate


class PredictiveScorer:
    """Predict vulnerability likelihood for a tech stack using Bayesian model."""
    
    def __init__(self, genome_db=None):
        self.genome_db = genome_db  # Historical engagement data
    
    def predict(self, stack: TechStackProfile, 
                historical: dict = None) -> list[VulnPrediction]:
        """
        Generate ranked vulnerability predictions.
        
        Args:
            stack: Detected tech stack
            historical: Optional {(tech, vuln_class): (successes, trials)} from genome
        """
        predictions = {}
        all_vuln_classes = self._get_all_vuln_classes()
        
        for vuln_class in all_vuln_classes:
            alpha_total, beta_total = DEFAULT_PRIOR
            reasons = []
            
            # Aggregate priors from all matching tech signals
            for tech in self._get_tech_signals(stack):
                key = (tech, vuln_class)
                if key in TECH_STACK_PRIORS:
                    a, b = TECH_STACK_PRIORS[key]
                    alpha_total += a - 1  # Combine evidence (subtract 1 to avoid double-counting uniform prior)
                    beta_total += b - 1
                    reasons.append(f"{tech} stack: Beta({a},{b}) prior")
            
            # Add historical genome data (strongest signal)
            if historical:
                for tech in self._get_tech_signals(stack):
                    hist_key = (tech, vuln_class)
                    if hist_key in historical:
                        successes, trials = historical[hist_key]
                        alpha_total += successes
                        beta_total += (trials - successes)
                        reasons.append(f"Genome: {successes}/{trials} success rate on {tech}")
            
            # Calculate posterior mean: E[Beta(a,b)] = a/(a+b)
            prob = alpha_total / (alpha_total + beta_total)
            
            # Confidence: based on effective sample size
            n_eff = alpha_total + beta_total
            confidence = min(1.0, n_eff / 50.0)  # Max confidence at 50 effective observations
            
            predictions[vuln_class] = VulnPrediction(
                vuln_class=vuln_class,
                probability=round(prob, 3),
                confidence=round(confidence, 3),
                reasoning=reasons or ["Default prior only"],
                suggested_tools=self._suggest_tools(vuln_class),
            )
        
        # Rank by probability
        ranked = sorted(predictions.values(), key=lambda p: p.probability, reverse=True)
        for i, pred in enumerate(ranked):
            pred.priority_rank = i + 1
        
        return ranked
    
    def thompson_sample(self, predictions: list[VulnPrediction]) -> list[VulnPrediction]:
        """
        Thompson Sampling for exploration-exploitation.
        Instead of always testing highest-probability class first,
        sample from the posterior to occasionally explore uncertain classes.
        """
        import random
        sampled = []
        for pred in predictions:
            a = pred.probability * 10 + 1
            b = (1 - pred.probability) * 10 + 1
            sample = random.betavariate(a, b)
            sampled.append((sample, pred))
        
        sampled.sort(key=lambda x: x[0], reverse=True)
        result = [pred for _, pred in sampled]
        for i, pred in enumerate(result):
            pred.priority_rank = i + 1
        return result
    
    def _get_tech_signals(self, stack: TechStackProfile) -> list[str]:
        """Extract all tech signals from stack for lookup."""
        signals = []
        signals.extend(s.lower() for s in stack.languages)
        signals.extend(s.lower() for s in stack.frameworks)
        signals.extend(s.lower() for s in stack.databases)
        signals.extend(s.lower() for s in stack.web_servers)
        signals.extend(s.lower() for s in stack.os)
        return signals
    
    def _get_all_vuln_classes(self) -> list[str]:
        return list(set(vc for _, vc in TECH_STACK_PRIORS.keys()))
    
    def _suggest_tools(self, vuln_class: str) -> list[str]:
        tool_map = {
            "injection": ["sqli_tool", "nuclei"],
            "xss": ["xss_tool", "nuclei"],
            "idor": ["idor_tool"],
            "auth_bypass": ["auth_brute", "nuclei"],
            "ssrf": ["ssrf_tool"],
            "nosqli": ["nosqli_tool"],
            "deserialization": ["nuclei", "custom_deser"],
            "xxe": ["xxe_tool"],
            "misconfig": ["nuclei", "nikto"],
            "prototype_pollution": ["custom_proto"],
        }
        return tool_map.get(vuln_class, ["nuclei"])
```

---

## Tests

### `tests/intel/test_predictive_scorer.py`
```python
import pytest
from sentinel.intel.predictive_scorer import PredictiveScorer, TechStackProfile

class TestPredictiveScorer:
    def setup_method(self):
        self.scorer = PredictiveScorer()
    
    def test_django_stack_predictions(self):
        stack = TechStackProfile(
            languages=["python"],
            frameworks=["django"],
            databases=["postgresql"],
        )
        preds = self.scorer.predict(stack)
        assert len(preds) > 0
        # IDOR should rank high for Django
        idor = next((p for p in preds if p.vuln_class == "idor"), None)
        assert idor is not None
        assert idor.probability > 0.3
    
    def test_express_stack_predictions(self):
        stack = TechStackProfile(
            languages=["javascript"],
            frameworks=["express"],
            databases=["mongodb"],
        )
        preds = self.scorer.predict(stack)
        nosqli = next((p for p in preds if p.vuln_class == "nosqli"), None)
        assert nosqli is not None
        assert nosqli.probability > 0.4  # MongoDB + NoSQLi should be high
    
    def test_historical_data_updates_posterior(self):
        stack = TechStackProfile(frameworks=["django"])
        historical = {("django", "idor"): (8, 10)}  # 80% success rate
        preds = self.scorer.predict(stack, historical=historical)
        idor = next(p for p in preds if p.vuln_class == "idor")
        assert idor.probability > 0.5  # Should be boosted by history
    
    def test_thompson_sampling_changes_order(self):
        stack = TechStackProfile(frameworks=["express"])
        preds = self.scorer.predict(stack)
        # Run Thompson sampling many times — order should vary
        orders = set()
        for _ in range(20):
            sampled = self.scorer.thompson_sample(preds)
            orders.add(tuple(p.vuln_class for p in sampled[:3]))
        assert len(orders) > 1  # Should see different orderings
    
    def test_predictions_are_ranked(self):
        stack = TechStackProfile(frameworks=["spring"])
        preds = self.scorer.predict(stack)
        for i, pred in enumerate(preds):
            assert pred.priority_rank == i + 1
```

---

## Acceptance Criteria
- [ ] PredictiveScorer generates ranked predictions for Django/Express/Spring stacks
- [ ] Beta-Bernoulli posteriors correctly combine priors with historical data
- [ ] Thompson Sampling produces varied exploration orders
- [ ] Predictions include reasoning and suggested tools
- [ ] Historical genome data significantly updates probabilities
- [ ] All tests pass