"""Sentinel CLI."""

import asyncio
from datetime import datetime
from uuid import uuid4

import typer
from rich.console import Console
from rich.table import Table

from sentinel.core import setup_logging, get_logger
from sentinel.orchestration import (
    get_temporal_client,
    EngagementConfig,
    PentestWorkflow,
    ReconOnlyWorkflow,
)
from sentinel.orchestration.worker import run_worker

app = typer.Typer(name="sentinel", help="Autonomous AI Pentesting Platform")
console = Console()
logger = get_logger(__name__)


@app.command()
def worker():
    """Start the Temporal worker."""
    console.print("[green]Starting Sentinel worker...[/green]")
    asyncio.run(run_worker())


@app.command()
def scan(
    target: str = typer.Argument(..., help="Target URL"),
    target_ips: list[str] = typer.Option(["127.0.0.1"], "--ip", "-i", help="Target IPs"),
    engagement_id: str = typer.Option(None, "--id", help="Engagement ID"),
    no_approval: bool = typer.Option(False, "--no-approval", help="Skip exploitation approval"),
    recon_only: bool = typer.Option(False, "--recon-only", help="Reconnaissance only"),
):
    """Start a pentest scan."""
    setup_logging()

    if not engagement_id:
        engagement_id = f"sentinel-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    config = EngagementConfig(
        engagement_id=engagement_id,
        target_url=target,
        target_ips=target_ips,
        scope_includes=[".*"],
        scope_excludes=[],
        require_approval_for_exploitation=not no_approval,
    )

    async def run():
        client = await get_temporal_client()

        workflow_class = ReconOnlyWorkflow if recon_only else PentestWorkflow
        workflow_id = f"{engagement_id}-{uuid4().hex[:8]}"

        console.print(f"[green]Starting scan: {engagement_id}[/green]")
        console.print(f"[dim]Workflow ID: {workflow_id}[/dim]")
        console.print(f"[dim]Target: {target}[/dim]")

        handle = await client.start_workflow(
            workflow_class.run,
            config,
            id=workflow_id,
            task_queue="sentinel-tasks",
        )

        console.print(f"\n[yellow]Workflow started. Monitor at: http://localhost:8233/namespaces/default/workflows/{workflow_id}[/yellow]")

        if not recon_only and not no_approval:
            console.print("\n[cyan]Waiting for exploitation approval...[/cyan]")
            console.print(f"[dim]Send approval with: sentinel approve {workflow_id}[/dim]")

        result = await handle.result()

        table = Table(title=f"Scan Results: {engagement_id}")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        state = result.get("state", result)
        for key, value in state.items():
            if key != "errors":
                table.add_row(key.replace("_", " ").title(), str(value))

        console.print(table)

        if result.get("report"):
            console.print(f"\n[green]Report: {result['report'].get('path')}[/green]")

    asyncio.run(run())


@app.command()
def approve(workflow_id: str = typer.Argument(..., help="Workflow ID to approve")):
    """Approve exploitation for a workflow."""
    setup_logging()

    async def run():
        client = await get_temporal_client()
        handle = client.get_workflow_handle(workflow_id)
        await handle.signal(PentestWorkflow.approve_exploitation)
        console.print(f"[green]Exploitation approved for {workflow_id}[/green]")

    asyncio.run(run())


@app.command()
def status(workflow_id: str = typer.Argument(..., help="Workflow ID")):
    """Get status of a workflow."""
    setup_logging()

    async def run():
        client = await get_temporal_client()
        handle = client.get_workflow_handle(workflow_id)

        try:
            state = await handle.query(PentestWorkflow.get_state)

            table = Table(title=f"Workflow Status: {workflow_id}")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")

            for key, value in state.items():
                if key != "errors":
                    table.add_row(key.replace("_", " ").title(), str(value))

            console.print(table)

            if state.get("errors"):
                console.print("\n[red]Errors:[/red]")
                for err in state["errors"]:
                    console.print(f"  - {err}")
        except Exception as e:
            console.print(f"[red]Error querying workflow: {e}[/red]")

    asyncio.run(run())


if __name__ == "__main__":
    app()
