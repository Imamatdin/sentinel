"""Temporal worker for Sentinel activities."""

import asyncio
from temporalio.worker import Worker

from sentinel.core import get_logger, get_settings, setup_logging
from sentinel.orchestration.client import get_temporal_client
from sentinel.orchestration.workflows import PentestWorkflow, ReconOnlyWorkflow
from sentinel.orchestration.activities import (
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

logger = get_logger(__name__)


async def run_worker() -> None:
    """Start the Temporal worker."""
    setup_logging()
    settings = get_settings()

    client = await get_temporal_client()

    worker = Worker(
        client,
        task_queue=settings.temporal_task_queue,
        workflows=[
            PentestWorkflow,
            ReconOnlyWorkflow,
        ],
        activities=[
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
        ],
    )

    logger.info(
        "Starting Temporal worker",
        task_queue=settings.temporal_task_queue,
        workflows=["PentestWorkflow", "ReconOnlyWorkflow"],
    )

    await worker.run()


def main() -> None:
    """Entry point for worker."""
    asyncio.run(run_worker())


if __name__ == "__main__":
    main()
