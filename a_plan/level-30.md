# LEVEL 30: Multi-Tenant Architecture

## Context
Sentinel needs to serve multiple customers from shared infrastructure without data leakage. This level adds row-level security in Postgres, label-based isolation in Neo4j, per-tenant Temporal task queues, scoped API authentication, and tenant-aware configuration.

Research: Block 11 (Infrastructure/Scaling — multi-tenant SaaS patterns, RLS, graph isolation, Temporal namespace isolation, hybrid agent deployment on-prem/cloud).

## Why
This is the difference between "tool" and "platform." Without multi-tenancy, every customer needs a separate deployment. With it, Sentinel scales to 1000 customers on shared infra with strict data isolation. This unlocks SaaS pricing and federated learning (L21).

---

## Files to Create

### `src/sentinel/tenancy/__init__.py`
```python
"""Multi-tenant isolation — RLS, graph labels, scoped queues, tenant context."""
```

### `src/sentinel/tenancy/context.py`
```python
"""
Tenant Context — Thread-local / async-context tenant ID for all operations.

Every database query, graph operation, and Temporal workflow automatically
scopes to the current tenant. No explicit tenant_id passing needed.
"""
import contextvars
from dataclasses import dataclass
from sentinel.logging import get_logger

logger = get_logger(__name__)

_current_tenant: contextvars.ContextVar[str] = contextvars.ContextVar(
    'current_tenant', default='')

_current_tenant_config: contextvars.ContextVar[dict] = contextvars.ContextVar(
    'current_tenant_config', default={})


@dataclass
class TenantInfo:
    tenant_id: str
    name: str
    plan: str             # "free" | "pro" | "enterprise"
    max_engagements: int
    max_scans_per_month: int
    allowed_tools: list[str]
    neo4j_label: str      # Unique label prefix for graph isolation
    temporal_queue: str   # Per-tenant Temporal task queue


def set_tenant(tenant_id: str, config: dict = None):
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
            token = auth[7:]
            # In production: decode JWT, extract tenant_id claim
            # For now: assume token IS the tenant_id (simplified)
            return token
        api_key = request.headers.get("X-Tenant-Key", "")
        return api_key
```

### `src/sentinel/tenancy/postgres_rls.py`
```python
"""
Postgres Row-Level Security — Enforce tenant isolation at the database level.

Every table with tenant data gets:
1. A tenant_id column
2. An RLS policy that filters rows by current_setting('app.current_tenant')
3. Functions to set tenant context per-connection

Even if application code has a bug, RLS prevents cross-tenant data access.
"""
from sentinel.logging import get_logger

logger = get_logger(__name__)


RLS_SETUP_SQL = """
-- Enable RLS on all tenant-scoped tables

-- Engagements
ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagements FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_engagements ON engagements
    USING (tenant_id = current_setting('app.current_tenant', true));

-- Findings
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_findings ON findings
    USING (tenant_id = current_setting('app.current_tenant', true));

-- Scans
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_scans ON scans
    USING (tenant_id = current_setting('app.current_tenant', true));

-- Reports
ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_reports ON reports
    USING (tenant_id = current_setting('app.current_tenant', true));

-- API keys
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_api_keys ON api_keys
    USING (tenant_id = current_setting('app.current_tenant', true));
"""

SET_TENANT_SQL = "SET app.current_tenant = %s;"
RESET_TENANT_SQL = "RESET app.current_tenant;"


class TenantAwareConnection:
    """Wraps a Postgres connection pool with automatic tenant scoping."""

    def __init__(self, pool):
        self.pool = pool

    async def acquire(self, tenant_id: str):
        """Acquire a connection scoped to tenant."""
        conn = await self.pool.acquire()
        await conn.execute(SET_TENANT_SQL, tenant_id)
        return conn

    async def release(self, conn):
        """Reset tenant context and release connection."""
        await conn.execute(RESET_TENANT_SQL)
        await self.pool.release(conn)

    async def execute(self, tenant_id: str, query: str, *args):
        """Execute a query scoped to tenant."""
        conn = await self.acquire(tenant_id)
        try:
            return await conn.fetch(query, *args)
        finally:
            await self.release(conn)


def generate_migration_sql(tables: list[str]) -> str:
    """Generate RLS migration SQL for a list of tables."""
    lines = ["-- Auto-generated RLS migration\n"]
    for table in tables:
        lines.append(f"-- {table}")
        lines.append(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL;")
        lines.append(f"CREATE INDEX IF NOT EXISTS idx_{table}_tenant ON {table}(tenant_id);")
        lines.append(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        lines.append(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")
        lines.append(f"CREATE POLICY tenant_{table} ON {table}")
        lines.append(f"    USING (tenant_id = current_setting('app.current_tenant', true));")
        lines.append("")
    return "\n".join(lines)
```

### `src/sentinel/tenancy/neo4j_isolation.py`
```python
"""
Neo4j Tenant Isolation — Label-based graph separation.

Every node gets a tenant label: (:Tenant_abc123:Host {...})
All Cypher queries include the tenant label filter.
Cross-tenant traversals are impossible because labels don't overlap.
"""
from sentinel.tenancy.context import require_tenant
from sentinel.logging import get_logger

logger = get_logger(__name__)


def tenant_label() -> str:
    """Get the Neo4j label for the current tenant."""
    tid = require_tenant()
    # Sanitize: only alphanumeric + underscore
    safe = "".join(c if c.isalnum() else "_" for c in tid)
    return f"Tenant_{safe}"


def scoped_create(node_type: str, properties: dict) -> str:
    """Generate a CREATE query with tenant label."""
    label = tenant_label()
    props = ", ".join(f"{k}: ${k}" for k in properties)
    return f"CREATE (n:{label}:{node_type} {{{props}}})"


def scoped_match(node_type: str, conditions: str = "") -> str:
    """Generate a MATCH query scoped to current tenant."""
    label = tenant_label()
    where = f" WHERE {conditions}" if conditions else ""
    return f"MATCH (n:{label}:{node_type}){where}"


def scoped_query(cypher: str) -> str:
    """
    Inject tenant label into an existing Cypher query.
    Replaces (:NodeType) with (:Tenant_xxx:NodeType).
    """
    import re
    label = tenant_label()
    # Replace (:Type patterns with (:Tenant_xxx:Type
    result = re.sub(
        r'\(:(\w+)',
        lambda m: f'(:{label}:{m.group(1)}',
        cypher
    )
    return result


class TenantGraphService:
    """Neo4j operations scoped to current tenant."""

    def __init__(self, driver):
        self.driver = driver

    async def create_node(self, node_type: str, properties: dict):
        query = scoped_create(node_type, properties)
        async with self.driver.session() as session:
            await session.run(query, **properties)

    async def find_nodes(self, node_type: str, conditions: str = "", **params):
        query = scoped_match(node_type, conditions) + " RETURN n"
        async with self.driver.session() as session:
            result = await session.run(query, **params)
            return [record["n"] async for record in result]

    async def run_scoped(self, cypher: str, **params):
        scoped = scoped_query(cypher)
        async with self.driver.session() as session:
            return await session.run(scoped, **params)
```

### `src/sentinel/tenancy/temporal_queues.py`
```python
"""
Tenant Temporal Queues — Per-tenant task queue isolation.

Each tenant gets a dedicated Temporal task queue: "sentinel-{tenant_id}"
Workers process only their tenant's queue.
Enterprise tenants can get dedicated worker pools.
"""
from dataclasses import dataclass
from sentinel.tenancy.context import require_tenant
from sentinel.logging import get_logger

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
```

---

## Files to Modify

### `src/sentinel/api/` — Add tenant middleware
```python
from sentinel.tenancy.context import TenantMiddleware
app.middleware("http")(TenantMiddleware(tenant_store))
```

### All database queries — Scope to tenant
Every Postgres query must use `TenantAwareConnection`.
Every Neo4j query must use `TenantGraphService` or `scoped_query()`.
Every Temporal workflow must use `get_task_queue()`.

---

## Tests

### `tests/tenancy/test_context.py`
```python
import pytest
from sentinel.tenancy.context import set_tenant, get_tenant, require_tenant

class TestTenantContext:
    def test_set_and_get(self):
        set_tenant("tenant_abc")
        assert get_tenant() == "tenant_abc"

    def test_require_raises_when_empty(self):
        set_tenant("")
        with pytest.raises(PermissionError):
            require_tenant()

    def test_require_returns_when_set(self):
        set_tenant("t1")
        assert require_tenant() == "t1"
```

### `tests/tenancy/test_neo4j_isolation.py`
```python
import pytest
from sentinel.tenancy.context import set_tenant
from sentinel.tenancy.neo4j_isolation import tenant_label, scoped_create, scoped_match, scoped_query

class TestNeo4jIsolation:
    def test_tenant_label(self):
        set_tenant("acme-corp")
        assert tenant_label() == "Tenant_acme_corp"

    def test_scoped_create(self):
        set_tenant("t1")
        query = scoped_create("Host", {"ip": "10.0.0.1"})
        assert "Tenant_t1" in query
        assert ":Host" in query

    def test_scoped_match(self):
        set_tenant("t1")
        query = scoped_match("Vulnerability", "n.severity = 'critical'")
        assert "Tenant_t1" in query
        assert "severity" in query

    def test_scoped_query_injection(self):
        set_tenant("t2")
        cypher = "MATCH (:Host)-[:HAS]->(:Vulnerability) RETURN count(*)"
        scoped = scoped_query(cypher)
        assert "Tenant_t2:Host" in scoped
        assert "Tenant_t2:Vulnerability" in scoped
```

### `tests/tenancy/test_postgres_rls.py`
```python
import pytest
from sentinel.tenancy.postgres_rls import generate_migration_sql

class TestPostgresRLS:
    def test_migration_generation(self):
        sql = generate_migration_sql(["engagements", "findings"])
        assert "ALTER TABLE engagements" in sql
        assert "ENABLE ROW LEVEL SECURITY" in sql
        assert "tenant_id" in sql
        assert "CREATE POLICY" in sql
        assert "ALTER TABLE findings" in sql

    def test_migration_index(self):
        sql = generate_migration_sql(["scans"])
        assert "CREATE INDEX" in sql
        assert "idx_scans_tenant" in sql
```

### `tests/tenancy/test_temporal_queues.py`
```python
import pytest
from sentinel.tenancy.temporal_queues import TenantQueueManager
from sentinel.tenancy.context import set_tenant
from sentinel.tenancy.temporal_queues import get_task_queue

class TestTenantQueues:
    def test_provision_free(self):
        mgr = TenantQueueManager()
        queue = mgr.provision_queue("t1", "free")
        assert queue.worker_count == 1
        assert queue.max_concurrent_workflows == 2

    def test_provision_enterprise(self):
        mgr = TenantQueueManager()
        queue = mgr.provision_queue("t1", "enterprise")
        assert queue.worker_count == 4
        assert queue.max_concurrent_workflows == 20

    def test_get_task_queue(self):
        set_tenant("acme")
        assert get_task_queue() == "sentinel-acme"

    def test_list_queues(self):
        mgr = TenantQueueManager()
        mgr.provision_queue("t1", "free")
        mgr.provision_queue("t2", "pro")
        assert len(mgr.list_queues()) == 2
```

---

## Acceptance Criteria
- [ ] TenantContext sets/gets tenant via contextvars (async-safe)
- [ ] require_tenant() raises PermissionError when no tenant set
- [ ] TenantMiddleware extracts tenant from Bearer token or X-Tenant-Key header
- [ ] RLS migration adds tenant_id column, index, and policy to all tables
- [ ] SET/RESET app.current_tenant scopes Postgres connections
- [ ] Neo4j tenant labels sanitize special characters
- [ ] scoped_create/scoped_match inject tenant label into Cypher
- [ ] scoped_query injects labels into arbitrary Cypher queries
- [ ] Per-tenant Temporal queues follow naming convention "sentinel-{tenant_id}"
- [ ] Plan-based queue provisioning: free=1 worker, pro=2, enterprise=4
- [ ] All tests pass