"""
Compliance Report Generator.

Takes a list of verified findings and generates a compliance appendix
that maps each finding to relevant framework controls.
"""

from dataclasses import dataclass, field
from sentinel.compliance.framework_maps import get_controls, FRAMEWORKS
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class ComplianceFindingEntry:
    finding_id: str
    category: str
    severity: str
    target: str
    controls: dict[str, list[str]]  # framework_name -> [control_ids]
    status: str = "FAIL"  # FAIL = vuln found, this control is not met


@dataclass
class ComplianceReport:
    engagement_id: str
    frameworks_covered: list[str]
    entries: list[ComplianceFindingEntry]
    control_summary: dict  # framework -> {control_id: "FAIL"/"PASS"}
    coverage_stats: dict   # framework -> {tested: N, failed: N, coverage_pct: float}


class ComplianceReportGenerator:
    """Generate compliance appendix from verified findings."""

    def generate(
        self,
        findings: list[dict],
        engagement_id: str,
        frameworks: list[str] | None = None,
    ) -> ComplianceReport:
        """
        Map findings to compliance controls and generate report.

        Args:
            findings: list of verified finding dicts with "category", "severity", etc.
            engagement_id: engagement identifier
            frameworks: which frameworks to include (None = all)
        """
        fw_keys = frameworks or list(FRAMEWORKS.keys())
        entries: list[ComplianceFindingEntry] = []
        control_tracker: dict[str, dict[str, str]] = {
            FRAMEWORKS[k]["name"]: {} for k in fw_keys if k in FRAMEWORKS
        }

        for finding in findings:
            category = finding.get("category", "")
            controls = get_controls(category, fw_keys)

            entry = ComplianceFindingEntry(
                finding_id=finding.get("hypothesis_id", finding.get("finding_id", "")),
                category=category,
                severity=finding.get("severity", ""),
                target=finding.get("target_url", ""),
                controls=controls,
            )
            entries.append(entry)

            # Track which controls failed
            for fw_name, ctrl_ids in controls.items():
                if fw_name not in control_tracker:
                    control_tracker[fw_name] = {}
                for ctrl in ctrl_ids:
                    control_tracker[fw_name][ctrl] = "FAIL"

        # Calculate coverage stats
        coverage: dict[str, dict] = {}
        for fw_key in fw_keys:
            if fw_key not in FRAMEWORKS:
                continue
            fw_name = FRAMEWORKS[fw_key]["name"]
            all_controls: set[str] = set()
            for ctrls in FRAMEWORKS[fw_key]["mappings"].values():
                all_controls.update(ctrls)

            tested = len(control_tracker.get(fw_name, {}))
            failed = sum(
                1
                for v in control_tracker.get(fw_name, {}).values()
                if v == "FAIL"
            )
            coverage[fw_name] = {
                "total_controls": len(all_controls),
                "tested": tested,
                "failed": failed,
                "coverage_pct": round(tested / len(all_controls) * 100, 1)
                if all_controls
                else 0,
            }

        return ComplianceReport(
            engagement_id=engagement_id,
            frameworks_covered=[
                FRAMEWORKS[k]["name"] for k in fw_keys if k in FRAMEWORKS
            ],
            entries=entries,
            control_summary=control_tracker,
            coverage_stats=coverage,
        )
