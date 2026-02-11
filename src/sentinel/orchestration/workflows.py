"""Temporal workflows for pentest orchestration.

Workflows define the control flow - they don't do I/O directly,
but orchestrate activities and handle signals/queries.
"""

import asyncio
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    from sentinel.orchestration.activities import (
        EngagementConfig,
        ExploitAttempt,
        discover_hosts,
        scan_ports,
        identify_services,
        crawl_endpoints,
        analyze_service_vulns,
        analyze_endpoint_vulns,
        attempt_exploit,
        verify_exploit,
        generate_replay_script,
        create_snapshot,
        generate_report,
    )


# === Retry Policies ===

FAST_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=1),
    maximum_interval=timedelta(seconds=10),
    maximum_attempts=3,
)

STANDARD_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    maximum_interval=timedelta(minutes=1),
    maximum_attempts=5,
    non_retryable_error_types=["AuthorizationError"],
)

EXPLOIT_RETRY = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    maximum_interval=timedelta(minutes=5),
    maximum_attempts=3,
)


@dataclass
class PentestState:
    """Current state of the pentest workflow."""
    phase: str = "initialized"
    hosts_discovered: int = 0
    ports_discovered: int = 0
    services_discovered: int = 0
    endpoints_discovered: int = 0
    vulnerabilities_found: int = 0
    exploits_attempted: int = 0
    exploits_successful: int = 0
    sessions_obtained: int = 0
    awaiting_approval: bool = False
    approval_granted: bool = False
    errors: list[str] = field(default_factory=list)


@workflow.defn(sandboxed=False)
class PentestWorkflow:
    """Main pentest orchestration workflow.

    Phases:
    1. Reconnaissance - discover hosts, ports, services, endpoints
    2. Vulnerability Analysis - identify vulnerabilities
    3. Exploitation - attempt exploits (with optional approval gate)
    4. Verification - verify exploits are reproducible
    5. Reporting - generate final report
    """

    def __init__(self):
        self.state = PentestState()
        self.config: EngagementConfig | None = None

        self.host_ids: list[str] = []
        self.port_ids: list[str] = []
        self.service_ids: list[str] = []
        self.endpoint_ids: list[str] = []
        self.vuln_ids: list[str] = []
        self.exploit_results: list[ExploitAttempt] = []

    # === Signals ===

    @workflow.signal
    async def approve_exploitation(self) -> None:
        """Signal to approve exploitation phase."""
        workflow.logger.info("Exploitation approved")
        self.state.approval_granted = True
        self.state.awaiting_approval = False

    @workflow.signal
    async def cancel_engagement(self) -> None:
        """Signal to cancel the engagement."""
        workflow.logger.info("Engagement cancelled")
        self.state.phase = "cancelled"

    @workflow.signal
    async def pause(self) -> None:
        """Signal to pause the workflow."""
        workflow.logger.info("Workflow paused")
        self.state.phase = "paused"

    @workflow.signal
    async def resume(self) -> None:
        """Signal to resume the workflow."""
        workflow.logger.info("Workflow resumed")

    # === Queries ===

    @workflow.query
    def get_state(self) -> dict[str, Any]:
        """Query current workflow state."""
        return {
            "phase": self.state.phase,
            "hosts_discovered": self.state.hosts_discovered,
            "ports_discovered": self.state.ports_discovered,
            "services_discovered": self.state.services_discovered,
            "endpoints_discovered": self.state.endpoints_discovered,
            "vulnerabilities_found": self.state.vulnerabilities_found,
            "exploits_attempted": self.state.exploits_attempted,
            "exploits_successful": self.state.exploits_successful,
            "sessions_obtained": self.state.sessions_obtained,
            "awaiting_approval": self.state.awaiting_approval,
            "errors": self.state.errors,
        }

    @workflow.query
    def get_findings(self) -> dict[str, Any]:
        """Query discovered findings."""
        return {
            "hosts": self.host_ids,
            "vulnerabilities": self.vuln_ids,
            "successful_exploits": [
                e for e in self.exploit_results if e.success
            ],
        }

    # === Main Workflow ===

    @workflow.run
    async def run(self, config: EngagementConfig) -> dict[str, Any]:
        """Execute the full pentest workflow."""
        self.config = config
        workflow.logger.info(f"Starting pentest engagement: {config.engagement_id}")

        try:
            # Phase 1: Reconnaissance
            await self._phase_recon()

            if self.state.phase == "cancelled":
                return {"status": "cancelled", "state": self.get_state()}

            # Phase 2: Vulnerability Analysis
            await self._phase_vuln_analysis()

            # Phase 3: Exploitation (with optional approval gate)
            if config.require_approval_for_exploitation:
                await self._wait_for_approval()

            if self.state.approval_granted or not config.require_approval_for_exploitation:
                await self._phase_exploitation()

            # Phase 4: Verification
            await self._phase_verification()

            # Phase 5: Reporting
            report = await self._phase_reporting()

            self.state.phase = "completed"

            return {
                "status": "completed",
                "state": self.get_state(),
                "report": report,
            }

        except Exception as e:
            self.state.phase = "error"
            self.state.errors.append(str(e))
            workflow.logger.error(f"Workflow failed: {e}")
            raise

    async def _phase_recon(self) -> None:
        """Execute reconnaissance phase."""
        self.state.phase = "reconnaissance"
        workflow.logger.info("Phase 1: Reconnaissance")

        # Discover hosts
        self.host_ids = await workflow.execute_activity(
            discover_hosts,
            self.config,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=STANDARD_RETRY,
        )
        self.state.hosts_discovered = len(self.host_ids)

        # Scan ports in parallel for all hosts
        port_results = await asyncio.gather(*[
            workflow.execute_activity(
                scan_ports,
                args=[host_id, self.config.engagement_id],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=STANDARD_RETRY,
            )
            for host_id in self.host_ids
        ])
        for result in port_results:
            self.port_ids.extend(result)
        self.state.ports_discovered = len(self.port_ids)

        # Identify services in parallel
        service_results = await asyncio.gather(*[
            workflow.execute_activity(
                identify_services,
                args=[port_id, self.config.engagement_id],
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=FAST_RETRY,
            )
            for port_id in self.port_ids
        ])
        self.service_ids = [s for s in service_results if s is not None]
        self.state.services_discovered = len(self.service_ids)

        # Crawl endpoints for web services
        endpoint_results = await asyncio.gather(*[
            workflow.execute_activity(
                crawl_endpoints,
                args=[service_id, self.config.engagement_id, self.config.target_url],
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=STANDARD_RETRY,
            )
            for service_id in self.service_ids
        ])
        for result in endpoint_results:
            self.endpoint_ids.extend(result)
        self.state.endpoints_discovered = len(self.endpoint_ids)

        workflow.logger.info(
            f"Recon complete: {self.state.hosts_discovered} hosts, "
            f"{self.state.ports_discovered} ports, "
            f"{self.state.services_discovered} services, "
            f"{self.state.endpoints_discovered} endpoints"
        )

    async def _phase_vuln_analysis(self) -> None:
        """Execute vulnerability analysis phase."""
        self.state.phase = "vulnerability_analysis"
        workflow.logger.info("Phase 2: Vulnerability Analysis")

        # Analyze services in parallel
        service_vuln_results = await asyncio.gather(*[
            workflow.execute_activity(
                analyze_service_vulns,
                args=[service_id, self.config.engagement_id],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=STANDARD_RETRY,
            )
            for service_id in self.service_ids
        ])
        for result in service_vuln_results:
            self.vuln_ids.extend(result)

        # Analyze endpoints in parallel
        endpoint_vuln_results = await asyncio.gather(*[
            workflow.execute_activity(
                analyze_endpoint_vulns,
                args=[endpoint_id, self.config.engagement_id],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=STANDARD_RETRY,
            )
            for endpoint_id in self.endpoint_ids
        ])
        for result in endpoint_vuln_results:
            self.vuln_ids.extend(result)

        self.state.vulnerabilities_found = len(self.vuln_ids)
        workflow.logger.info(f"Vuln analysis complete: {self.state.vulnerabilities_found} vulnerabilities")

    async def _wait_for_approval(self) -> None:
        """Wait for human approval before exploitation."""
        self.state.phase = "awaiting_approval"
        self.state.awaiting_approval = True
        workflow.logger.info("Waiting for exploitation approval...")

        await workflow.wait_condition(
            lambda: self.state.approval_granted or self.state.phase == "cancelled",
            timeout=timedelta(hours=24),
        )

        if not self.state.approval_granted and self.state.phase != "cancelled":
            self.state.errors.append("Approval timeout - exploitation skipped")
            workflow.logger.warning("Approval timeout")

    async def _phase_exploitation(self) -> None:
        """Execute exploitation phase."""
        self.state.phase = "exploitation"
        workflow.logger.info("Phase 3: Exploitation")

        for vuln_id in self.vuln_ids:
            result = await workflow.execute_activity(
                attempt_exploit,
                args=[vuln_id, self.config.engagement_id, False],
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=EXPLOIT_RETRY,
            )
            self.exploit_results.append(result)
            self.state.exploits_attempted += 1

            if result.success:
                self.state.exploits_successful += 1
            if result.session_obtained:
                self.state.sessions_obtained += 1

        workflow.logger.info(
            f"Exploitation complete: {self.state.exploits_successful}/{self.state.exploits_attempted} successful"
        )

    async def _phase_verification(self) -> None:
        """Execute verification phase."""
        self.state.phase = "verification"
        workflow.logger.info("Phase 4: Verification")

        successful_exploits = [e for e in self.exploit_results if e.success]

        for exploit in successful_exploits:
            if exploit.session_id:
                await workflow.execute_activity(
                    verify_exploit,
                    args=[exploit.vulnerability_id, exploit.session_id, self.config.engagement_id],
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=FAST_RETRY,
                )

                await workflow.execute_activity(
                    generate_replay_script,
                    args=[exploit.vulnerability_id, "curl"],
                    start_to_close_timeout=timedelta(minutes=1),
                    retry_policy=FAST_RETRY,
                )

        workflow.logger.info("Verification complete")

    async def _phase_reporting(self) -> dict[str, Any]:
        """Execute reporting phase."""
        self.state.phase = "reporting"
        workflow.logger.info("Phase 5: Reporting")

        snapshot = await workflow.execute_activity(
            create_snapshot,
            self.config.engagement_id,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=FAST_RETRY,
        )

        report_path = f"reports/{self.config.engagement_id}/report.txt"
        report = await workflow.execute_activity(
            generate_report,
            args=[self.config.engagement_id, report_path],
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=FAST_RETRY,
        )

        workflow.logger.info(f"Report generated: {report.report_path}")

        return {
            "path": report.report_path,
            "total_findings": report.total_findings,
            "critical_findings": report.critical_findings,
            "snapshot": snapshot,
        }


@workflow.defn(sandboxed=False)
class ReconOnlyWorkflow:
    """Lightweight workflow for reconnaissance only."""

    @workflow.run
    async def run(self, config: EngagementConfig) -> dict[str, Any]:
        """Run reconnaissance only."""
        workflow.logger.info(f"Starting recon-only: {config.engagement_id}")

        host_ids = await workflow.execute_activity(
            discover_hosts,
            config,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=STANDARD_RETRY,
        )

        all_ports = []
        for host_id in host_ids:
            ports = await workflow.execute_activity(
                scan_ports,
                args=[host_id, config.engagement_id],
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=STANDARD_RETRY,
            )
            all_ports.extend(ports)

        return {
            "hosts": len(host_ids),
            "ports": len(all_ports),
        }
