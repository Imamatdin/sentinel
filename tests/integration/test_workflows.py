"""Integration tests for Temporal workflows."""

import pytest
import asyncio
from uuid import uuid4

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from sentinel.orchestration import (
    EngagementConfig,
    PentestWorkflow,
    ReconOnlyWorkflow,
)
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
from sentinel.graph import get_graph_client, close_graph_client


@pytest.fixture
async def workflow_env():
    """Create Temporal test environment."""
    async with await WorkflowEnvironment.start_time_skipping() as env:
        yield env


@pytest.fixture
async def graph_cleanup():
    """Cleanup graph after tests."""
    yield
    client = await get_graph_client()
    await client.clear_engagement("test-workflow")
    await close_graph_client()


@pytest.mark.asyncio
async def test_recon_workflow(workflow_env, graph_cleanup):
    """Test reconnaissance-only workflow."""
    task_queue = f"test-queue-{uuid4()}"

    async with Worker(
        workflow_env.client,
        task_queue=task_queue,
        workflows=[ReconOnlyWorkflow],
        activities=[discover_hosts, scan_ports],
    ):
        config = EngagementConfig(
            engagement_id="test-workflow",
            target_url="http://localhost:3000",
            target_ips=["127.0.0.1", "192.168.1.1"],
            scope_includes=[".*"],
            scope_excludes=[],
        )

        result = await workflow_env.client.execute_workflow(
            ReconOnlyWorkflow.run,
            config,
            id=f"test-recon-{uuid4()}",
            task_queue=task_queue,
        )

        assert result["hosts"] == 2
        assert result["ports"] > 0


@pytest.mark.asyncio
async def test_full_pentest_workflow(workflow_env, graph_cleanup):
    """Test full pentest workflow."""
    task_queue = f"test-queue-{uuid4()}"

    async with Worker(
        workflow_env.client,
        task_queue=task_queue,
        workflows=[PentestWorkflow],
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
    ):
        config = EngagementConfig(
            engagement_id="test-workflow",
            target_url="http://localhost:3000",
            target_ips=["127.0.0.1"],
            scope_includes=[".*"],
            scope_excludes=[],
            require_approval_for_exploitation=False,
        )

        handle = await workflow_env.client.start_workflow(
            PentestWorkflow.run,
            config,
            id=f"test-pentest-{uuid4()}",
            task_queue=task_queue,
        )

        result = await handle.result()

        assert result["status"] == "completed"
        assert result["state"]["hosts_discovered"] == 1
        assert result["state"]["vulnerabilities_found"] > 0


@pytest.mark.asyncio
async def test_workflow_with_approval(workflow_env, graph_cleanup):
    """Test workflow pauses for approval."""
    task_queue = f"test-queue-{uuid4()}"

    async with Worker(
        workflow_env.client,
        task_queue=task_queue,
        workflows=[PentestWorkflow],
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
    ):
        config = EngagementConfig(
            engagement_id="test-workflow",
            target_url="http://localhost:3000",
            target_ips=["127.0.0.1"],
            scope_includes=[".*"],
            scope_excludes=[],
            require_approval_for_exploitation=True,
        )

        handle = await workflow_env.client.start_workflow(
            PentestWorkflow.run,
            config,
            id=f"test-approval-{uuid4()}",
            task_queue=task_queue,
        )

        # Wait for it to reach approval state
        for _ in range(20):
            state = await handle.query(PentestWorkflow.get_state)
            if state["awaiting_approval"]:
                break
            await asyncio.sleep(0.5)

        state = await handle.query(PentestWorkflow.get_state)
        assert state["awaiting_approval"] is True
        assert state["phase"] == "awaiting_approval"

        # Send approval signal
        await handle.signal(PentestWorkflow.approve_exploitation)

        # Wait for completion
        result = await handle.result()
        assert result["status"] == "completed"
        assert result["state"]["exploits_attempted"] > 0
