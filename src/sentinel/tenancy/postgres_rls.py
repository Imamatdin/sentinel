"""
Postgres Row-Level Security -- Enforce tenant isolation at the database level.

Every table with tenant data gets:
1. A tenant_id column
2. An RLS policy that filters rows by current_setting('app.current_tenant')
3. Functions to set tenant context per-connection
"""

from sentinel.core import get_logger

logger = get_logger(__name__)


RLS_SETUP_SQL = """
-- Enable RLS on all tenant-scoped tables

ALTER TABLE engagements ENABLE ROW LEVEL SECURITY;
ALTER TABLE engagements FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_engagements ON engagements
    USING (tenant_id = current_setting('app.current_tenant', true));

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_findings ON findings
    USING (tenant_id = current_setting('app.current_tenant', true));

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scans ON scans
    USING (tenant_id = current_setting('app.current_tenant', true));

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_reports ON reports
    USING (tenant_id = current_setting('app.current_tenant', true));

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
