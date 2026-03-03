"""
Tenant Context -- Thread-local / async-context tenant ID for all operations.

Every database query, graph operation, and Temporal workflow automatically
scopes to the current tenant. No explicit tenant_id passing needed.
"""

import contextvars
from dataclasses import dataclass

from sentinel.core import get_logger

logger = get_logger(__name__)

_current_tenant: contextvars.ContextVar[str] = contextvars.ContextVar(
    "current_tenant", default=""
)

_current_tenant_config: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "current_tenant_config", default={}
)


@dataclass
class TenantInfo:
    tenant_id: str
    name: str
    plan: str  # "free" | "pro" | "enterprise"
    max_engagements: int
    max_scans_per_month: int
    allowed_tools: list[str]
    neo4j_label: str
    temporal_queue: str


def set_tenant(tenant_id: str, config: dict | None = None):
    """Set the current tenant context."""
    _current_tenant.set(tenant_id)
    _current_tenant_config.set(config or {})
    logger.debug(f"Tenant context set: {tenant_id}")


def get_tenant() -> str:
    """Get the current tenant ID."""
    return _current_tenant.get()


def get_tenant_config() -> dict:
    """Get current tenant configuration."""
    return _current_tenant_config.get()


def require_tenant() -> str:
    """Get tenant ID, raising if not set."""
    tid = _current_tenant.get()
    if not tid:
        raise PermissionError("No tenant context set. All operations require a tenant.")
    return tid


class TenantMiddleware:
    """FastAPI middleware to extract tenant from JWT/API key and set context."""

    def __init__(self, tenant_store):
        self.tenant_store = tenant_store

    async def __call__(self, request, call_next):
        tenant_id = self._extract_tenant(request)
        if tenant_id:
            config = await self.tenant_store.get_tenant_config(tenant_id)
            set_tenant(tenant_id, config)
        response = await call_next(request)
        return response

    def _extract_tenant(self, request) -> str:
        """Extract tenant ID from Authorization header or API key."""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:]
        return request.headers.get("X-Tenant-Key", "")
