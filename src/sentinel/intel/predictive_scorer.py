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

import random
from dataclasses import dataclass, field

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class TechStackProfile:
    """Describes the target's detected technology stack."""
    languages: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    databases: list[str] = field(default_factory=list)
    web_servers: list[str] = field(default_factory=list)
    os: list[str] = field(default_factory=list)
    cloud_provider: str = ""
    container_runtime: str = ""


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
TECH_STACK_PRIORS: dict[tuple[str, str], tuple[int, int]] = {
    # Python/Django
    ("django", "injection"): (3, 7),
    ("django", "xss"): (4, 6),
    ("django", "idor"): (6, 4),
    ("django", "auth_bypass"): (3, 7),
    ("django", "ssrf"): (4, 6),

    # Node/Express
    ("express", "injection"): (5, 5),
    ("express", "xss"): (6, 4),
    ("express", "prototype_pollution"): (5, 5),
    ("express", "ssrf"): (5, 5),
    ("express", "auth_bypass"): (5, 5),

    # Java/Spring
    ("spring", "injection"): (3, 7),
    ("spring", "deserialization"): (6, 4),
    ("spring", "xxe"): (5, 5),
    ("spring", "auth_bypass"): (4, 6),

    # FastAPI
    ("fastapi", "injection"): (3, 7),
    ("fastapi", "idor"): (5, 5),
    ("fastapi", "ssrf"): (4, 6),
    ("fastapi", "auth_bypass"): (4, 6),

    # Database-specific
    ("mongodb", "nosqli"): (6, 4),
    ("postgresql", "injection"): (4, 6),
    ("redis", "injection"): (3, 7),
    ("mysql", "injection"): (5, 5),

    # Server-specific
    ("nginx", "misconfig"): (4, 6),
    ("apache", "misconfig"): (5, 5),
    ("iis", "misconfig"): (6, 4),
}

DEFAULT_PRIOR = (2, 8)  # Weakly informative: assume 20% base rate


class PredictiveScorer:
    """Predict vulnerability likelihood for a tech stack using Bayesian model."""

    def __init__(self, genome_db=None):
        self.genome_db = genome_db

    def predict(
        self,
        stack: TechStackProfile,
        historical: dict | None = None,
    ) -> list[VulnPrediction]:
        """Generate ranked vulnerability predictions.

        Args:
            stack: Detected tech stack.
            historical: Optional {(tech, vuln_class): (successes, trials)} from genome.
        """
        predictions: dict[str, VulnPrediction] = {}
        all_vuln_classes = self._get_all_vuln_classes()

        for vuln_class in all_vuln_classes:
            alpha_total, beta_total = DEFAULT_PRIOR
            reasons: list[str] = []

            # Aggregate priors from all matching tech signals
            for tech in self._get_tech_signals(stack):
                key = (tech, vuln_class)
                if key in TECH_STACK_PRIORS:
                    a, b = TECH_STACK_PRIORS[key]
                    # Combine evidence (subtract 1 to avoid double-counting uniform prior)
                    alpha_total += a - 1
                    beta_total += b - 1
                    reasons.append(f"{tech} stack: Beta({a},{b}) prior")

            # Add historical genome data (strongest signal)
            if historical:
                for tech in self._get_tech_signals(stack):
                    hist_key = (tech, vuln_class)
                    if hist_key in historical:
                        successes, trials = historical[hist_key]
                        alpha_total += successes
                        beta_total += trials - successes
                        reasons.append(f"Genome: {successes}/{trials} success rate on {tech}")

            # Posterior mean: E[Beta(a,b)] = a/(a+b)
            prob = alpha_total / (alpha_total + beta_total)

            # Confidence based on effective sample size
            n_eff = alpha_total + beta_total
            confidence = min(1.0, n_eff / 50.0)

            predictions[vuln_class] = VulnPrediction(
                vuln_class=vuln_class,
                probability=round(prob, 3),
                confidence=round(confidence, 3),
                reasoning=reasons or ["Default prior only"],
                suggested_tools=self._suggest_tools(vuln_class),
            )

        ranked = sorted(predictions.values(), key=lambda p: p.probability, reverse=True)
        for i, pred in enumerate(ranked):
            pred.priority_rank = i + 1

        return ranked

    def thompson_sample(self, predictions: list[VulnPrediction]) -> list[VulnPrediction]:
        """Thompson Sampling for exploration-exploitation.

        Instead of always testing highest-probability class first,
        sample from the posterior to occasionally explore uncertain classes.
        """
        sampled: list[tuple[float, VulnPrediction]] = []
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
        signals: list[str] = []
        signals.extend(s.lower() for s in stack.languages)
        signals.extend(s.lower() for s in stack.frameworks)
        signals.extend(s.lower() for s in stack.databases)
        signals.extend(s.lower() for s in stack.web_servers)
        signals.extend(s.lower() for s in stack.os)
        return signals

    def _get_all_vuln_classes(self) -> list[str]:
        return sorted(set(vc for _, vc in TECH_STACK_PRIORS.keys()))

    def _suggest_tools(self, vuln_class: str) -> list[str]:
        tool_map: dict[str, list[str]] = {
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
