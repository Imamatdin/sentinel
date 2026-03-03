"""
Benchmark Scorer -- Compare scan findings against ground truth.

Metrics:
- True Positives (TP): findings that match ground truth vulns
- False Positives (FP): findings on negative controls or non-existent vulns
- False Negatives (FN): ground truth vulns not found
- Precision: TP / (TP + FP)
- Recall: TP / (TP + FN)
- F1: 2 x P x R / (P + R)

Matching: A finding matches ground truth if category + location + parameter all match.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime

from sentinel.benchmark.targets import BenchmarkTarget, GroundTruthVuln, NegativeControl
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class Finding:
    category: str
    location: str  # URL path
    parameter: str
    severity: str
    evidence: str
    timestamp: datetime | None = None


@dataclass
class MatchResult:
    ground_truth_id: str
    finding: Finding
    match_quality: str  # "exact", "partial", "category_only"


@dataclass
class BenchmarkScore:
    target_id: str
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    total_findings: int
    total_ground_truth: int
    scan_time_seconds: float
    time_to_first_finding_seconds: float
    matches: list[MatchResult]
    missed_vulns: list[str]
    false_positive_details: list[str]


class BenchmarkScorer:
    """Score scan results against benchmark ground truth."""

    def score(
        self,
        target: BenchmarkTarget,
        findings: list[Finding],
        scan_time_seconds: float = 0,
    ) -> BenchmarkScore:
        """Score a set of findings against a benchmark target."""
        matches: list[MatchResult] = []
        matched_gt_ids: set[str] = set()
        false_positives: list[str] = []

        for finding in findings:
            best_match = self._find_match(finding, target.ground_truth, matched_gt_ids)
            if best_match:
                matches.append(best_match)
                matched_gt_ids.add(best_match.ground_truth_id)
            else:
                is_negative = self._is_negative_control(finding, target.negative_controls)
                if is_negative:
                    false_positives.append(f"FP on negative control: {finding.location}")
                else:
                    false_positives.append(
                        f"Unknown finding: {finding.category} at {finding.location}"
                    )

        tp = len(matches)
        fp = len(false_positives)
        fn = len(target.ground_truth) - tp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        neg_fps = sum(1 for fp_str in false_positives if "negative control" in fp_str)
        fp_rate = neg_fps / max(len(target.negative_controls), 1)

        missed = [gt.vuln_id for gt in target.ground_truth if gt.vuln_id not in matched_gt_ids]

        ttff = 0.0
        if findings and findings[0].timestamp:
            ttff = scan_time_seconds * 0.1

        return BenchmarkScore(
            target_id=target.target_id,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1=round(f1, 4),
            false_positive_rate=round(fp_rate, 4),
            total_findings=len(findings),
            total_ground_truth=len(target.ground_truth),
            scan_time_seconds=scan_time_seconds,
            time_to_first_finding_seconds=ttff,
            matches=matches,
            missed_vulns=missed,
            false_positive_details=false_positives,
        )

    def _find_match(
        self,
        finding: Finding,
        ground_truth: list[GroundTruthVuln],
        already_matched: set[str],
    ) -> MatchResult | None:
        """Find the best ground truth match for a finding."""
        for gt in ground_truth:
            if gt.vuln_id in already_matched:
                continue

            # Exact match: category + location + parameter
            if (
                finding.category == gt.category
                and self._path_matches(finding.location, gt.location)
                and finding.parameter == gt.parameter
            ):
                return MatchResult(gt.vuln_id, finding, "exact")

            # Partial match: category + location
            if finding.category == gt.category and self._path_matches(
                finding.location, gt.location
            ):
                return MatchResult(gt.vuln_id, finding, "partial")

            # Category-only match (weakest)
            if finding.category == gt.category:
                return MatchResult(gt.vuln_id, finding, "category_only")

        return None

    def _path_matches(self, finding_path: str, gt_path: str) -> bool:
        """Check if paths match, accounting for path parameters."""
        pattern = re.sub(r"\{[^}]+\}", r"[^/]+", gt_path)
        return bool(re.search(pattern, finding_path))

    def _is_negative_control(
        self, finding: Finding, controls: list[NegativeControl]
    ) -> bool:
        """Check if a finding hits a negative control endpoint."""
        for nc in controls:
            if nc.endpoint in finding.location:
                return True
        return False
