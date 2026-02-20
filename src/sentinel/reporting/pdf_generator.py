"""Generate professional PDF pentest reports from engagement results.

Uses weasyprint to convert a Jinja2 HTML template to PDF. The report includes:
- Executive summary with engagement scoreboard
- Attack surface overview
- Red team findings sorted by severity with evidence
- Blue team defense performance
- Security Genome patterns (if available)
- Remediation recommendations

Dependencies:
    pip install weasyprint jinja2 --break-system-packages

    weasyprint requires system packages on Linux:
    apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2

Integration:
    Called from sentinel/api/export_routes.py when user requests PDF download.
"""

import logging
from pathlib import Path
from datetime import datetime
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader

from sentinel.genome.models import VulnPattern
from sentinel.compliance.report_generator import ComplianceReportGenerator

logger = logging.getLogger("sentinel.reporting.pdf")

TEMPLATE_DIR = Path(__file__).parent / "templates"


class PDFReportGenerator:
    """Generate PDF reports from engagement data.

    Usage:
        generator = PDFReportGenerator()
        path = generator.generate(result, genome_patterns, "/tmp/report.pdf")
    """

    def __init__(self):
        self.env = Environment(
            loader=FileSystemLoader(str(TEMPLATE_DIR)),
            autoescape=True,
        )

    def generate(
        self,
        result: Any,
        genome_patterns: Optional[list[VulnPattern]] = None,
        output_path: str = "sentinel_report.pdf",
    ) -> str:
        """Generate the complete PDF report.

        Args:
            result: EngagementResult from the orchestrator.
                    Expected attributes: target_url, duration, event_count,
                    speed_stats, agent_results, red_report, blue_report
            genome_patterns: Optional list of genome patterns to include
            output_path: Where to write the PDF file

        Returns:
            The output_path where the PDF was written
        """
        template = self.env.get_template("report.html")

        # Extract data from EngagementResult
        agent_results = getattr(result, "agent_results", {})
        speed_stats = getattr(result, "speed_stats", {})

        # Collect all findings from agent results
        all_findings: list[dict[str, Any]] = []
        for name, ar in agent_results.items():
            findings = getattr(ar, "findings", {})
            if isinstance(findings, dict):
                for key in [
                    "vulnerabilities_found",
                    "exploitation_attempts",
                    "potential_vulnerabilities",
                ]:
                    items = findings.get(key, [])
                    if isinstance(items, list):
                        for item in items:
                            if isinstance(item, dict):
                                item.setdefault("source_agent", name)
                                all_findings.append(item)

        # Sort findings by severity
        severity_order = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
        }
        all_findings.sort(
            key=lambda f: severity_order.get(
                f.get("severity", "info").lower(), 5
            )
        )

        context = {
            "target_url": getattr(result, "target_url", "unknown"),
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            "duration": getattr(result, "duration", 0),
            "event_count": getattr(result, "event_count", 0),
            "success": getattr(result, "success", False),

            # Speed stats
            "total_tokens": speed_stats.get("total_tokens", 0),
            "avg_tokens_per_second": speed_stats.get(
                "avg_tokens_per_second", 0
            ),
            "total_tool_calls": speed_stats.get("total_tool_calls", 0),
            "total_llm_time": speed_stats.get(
                "total_llm_time_seconds", 0
            ),

            # Agent results
            "agents": {
                name: {
                    "success": getattr(ar, "success", False),
                    "duration": getattr(ar, "duration", 0),
                    "tool_calls": getattr(ar, "tool_calls_made", 0),
                    "output_tokens": getattr(ar, "metrics", None)
                    and getattr(ar.metrics, "output_tokens", 0)
                    or 0,
                    "error": getattr(ar, "error", None),
                }
                for name, ar in agent_results.items()
            },

            # Reports
            "red_report": getattr(result, "red_report", ""),
            "blue_report": getattr(result, "blue_report", ""),

            # Findings
            "findings": all_findings,
            "finding_count": len(all_findings),

            # Genome patterns
            "genome_patterns": [
                p.model_dump() for p in (genome_patterns or [])
            ],

            # Compliance appendix
            "compliance": self._build_compliance(all_findings, result),
        }

        # Render HTML
        html_content = template.render(**context)

        # Convert to PDF
        try:
            from weasyprint import HTML

            html = HTML(string=html_content, base_url=str(TEMPLATE_DIR))
            html.write_pdf(output_path)
            logger.info("pdf_generated", path=output_path)
        except ImportError:
            # weasyprint not installed: write HTML instead
            html_path = output_path.replace(".pdf", ".html")
            Path(html_path).write_text(html_content)
            logger.warning(
                f"weasyprint_not_installed_writing_html path={html_path}"
            )
            return html_path

        return output_path

    def _build_compliance(
        self, findings: list[dict[str, Any]], result: Any
    ) -> dict[str, Any] | None:
        """Build compliance appendix data from findings."""
        if not findings:
            return None
        try:
            gen = ComplianceReportGenerator()
            engagement_id = getattr(result, "engagement_id", "unknown")
            # Normalize findings to have category field
            normalized = []
            for f in findings:
                category = f.get("category", "")
                if not category:
                    # Infer category from finding type/title
                    title = f.get("type", f.get("title", "")).lower()
                    if "inject" in title or "sqli" in title:
                        category = "injection"
                    elif "xss" in title or "cross-site" in title:
                        category = "xss"
                    elif "idor" in title:
                        category = "idor"
                    elif "ssrf" in title:
                        category = "ssrf"
                    elif "auth" in title:
                        category = "auth_bypass"
                    elif "config" in title:
                        category = "misconfig"
                normalized.append({
                    "finding_id": f.get("id", ""),
                    "category": category,
                    "severity": f.get("severity", "info"),
                    "target_url": f.get("endpoint", f.get("url", "")),
                })
            report = gen.generate(normalized, engagement_id)
            return {
                "frameworks": report.frameworks_covered,
                "entries": [
                    {
                        "finding_id": e.finding_id,
                        "category": e.category,
                        "severity": e.severity,
                        "target": e.target,
                        "controls": e.controls,
                    }
                    for e in report.entries
                ],
                "coverage_stats": report.coverage_stats,
                "control_summary": report.control_summary,
            }
        except Exception as e:
            logger.warning(f"compliance_appendix_failed: {e}")
            return None
