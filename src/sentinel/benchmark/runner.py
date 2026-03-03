"""
Benchmark Runner -- Orchestrate full benchmark runs.

Flow:
1. Deploy target (Docker Compose up)
2. Wait for target to be healthy
3. Run Sentinel scan against target
4. Collect findings
5. Score against ground truth
6. Teardown target
7. Aggregate scores across all targets
"""

import time
from dataclasses import dataclass, field

from sentinel.benchmark.scorer import BenchmarkScore, BenchmarkScorer, Finding
from sentinel.benchmark.targets import BenchmarkTarget, Difficulty, TargetRegistry
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class BenchmarkRun:
    run_id: str
    runner_name: str
    timestamp: str
    scores: list[BenchmarkScore]
    aggregate: dict = field(default_factory=dict)


class BenchmarkRunner:
    """Run benchmarks against targets and aggregate results."""

    def __init__(self, registry: TargetRegistry | None = None):
        self.registry = registry or TargetRegistry()
        self.scorer = BenchmarkScorer()

    async def run_single(
        self,
        target_id: str,
        scanner_fn=None,
    ) -> BenchmarkScore:
        """Run benchmark against a single target."""
        target = self.registry.get(target_id)
        if not target:
            raise ValueError(f"Unknown target: {target_id}")

        logger.info(f"Benchmark: scanning {target.name}...")
        start = time.time()

        if scanner_fn:
            findings = await scanner_fn(target.base_url)
        else:
            findings = []

        scan_time = time.time() - start

        score = self.scorer.score(target, findings, scan_time)
        logger.info(
            f"Benchmark: {target.name} -- "
            f"P={score.precision:.1%} R={score.recall:.1%} F1={score.f1:.1%}"
        )
        return score

    async def run_suite(
        self,
        difficulty: Difficulty | None = None,
        domain: str | None = None,
        scanner_fn=None,
        run_id: str = "default",
        runner_name: str = "sentinel",
    ) -> BenchmarkRun:
        """Run full benchmark suite and aggregate."""
        targets = self.registry.list_targets(difficulty=difficulty, domain=domain)
        scores: list[BenchmarkScore] = []

        for target in targets:
            try:
                score = await self.run_single(target.target_id, scanner_fn)
                scores.append(score)
            except Exception as e:
                logger.error(f"Benchmark failed for {target.name}: {e}")

        aggregate = self._aggregate(scores)

        return BenchmarkRun(
            run_id=run_id,
            runner_name=runner_name,
            timestamp=str(time.time()),
            scores=scores,
            aggregate=aggregate,
        )

    def _aggregate(self, scores: list[BenchmarkScore]) -> dict:
        """Compute aggregate metrics across all targets."""
        if not scores:
            return {}

        total_tp = sum(s.true_positives for s in scores)
        total_fp = sum(s.false_positives for s in scores)
        total_fn = sum(s.false_negatives for s in scores)

        precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

        return {
            "total_targets": len(scores),
            "total_ground_truth": sum(s.total_ground_truth for s in scores),
            "total_true_positives": total_tp,
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "aggregate_precision": round(precision, 4),
            "aggregate_recall": round(recall, 4),
            "aggregate_f1": round(f1, 4),
            "avg_scan_time": round(
                sum(s.scan_time_seconds for s in scores) / len(scores), 2
            ),
            "avg_false_positive_rate": round(
                sum(s.false_positive_rate for s in scores) / len(scores), 4
            ),
        }
