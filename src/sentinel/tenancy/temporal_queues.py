"""
Tenant Temporal Queues -- Per-tenant task queue isolation.

Each tenant gets a dedicated Temporal task queue: "sentinel-{tenant_id}"
Workers process only their tenant's queue.
Enterprise tenants can get dedicated worker pools.
"""

from dataclasses import dataclass

from sentinel.core import get_logger
from sentinel.tenancy.context import require_tenant

logger = get_logger(__name__)


@dataclass
class TenantQueue:
    tenant_id: str
    queue_name: str
    worker_count: int
    max_concurrent_workflows: int
    priority: int  # 1=low, 2=normal, 3=high


def get_task_queue() -> str:
    """Get the Temporal task queue for the current tenant."""
    tid = require_tenant()
    return f"sentinel-{tid}"


def get_workflow_id(engagement_id: str) -> str:
    """Generate a tenant-scoped workflow ID."""
    tid = require_tenant()
    return f"{tid}:{engagement_id}"


class TenantQueueManager:
    """Manage per-tenant Temporal queues."""

    PLANS = {
        "free": {"workers": 1, "max_concurrent": 2, "priority": 1},
        "pro": {"workers": 2, "max_concurrent": 5, "priority": 2},
        "enterprise": {"workers": 4, "max_concurrent": 20, "priority": 3},
    }

    def __init__(self):
        self.queues: dict[str, TenantQueue] = {}

    def provision_queue(self, tenant_id: str, plan: str = "free") -> TenantQueue:
        """Create or update a tenant's queue configuration."""
        config = self.PLANS.get(plan, self.PLANS["free"])
        queue = TenantQueue(
            tenant_id=tenant_id,
            queue_name=f"sentinel-{tenant_id}",
            worker_count=config["workers"],
            max_concurrent_workflows=config["max_concurrent"],
            priority=config["priority"],
        )
        self.queues[tenant_id] = queue
        logger.info(f"Provisioned queue for {tenant_id}: plan={plan}, workers={config['workers']}")
        return queue

    def get_queue(self, tenant_id: str) -> TenantQueue | None:
        return self.queues.get(tenant_id)

    def list_queues(self) -> list[TenantQueue]:
        return list(self.queues.values())
