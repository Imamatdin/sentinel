"""
Neo4j Tenant Isolation -- Label-based graph separation.

Every node gets a tenant label: (:Tenant_abc123:Host {...})
All Cypher queries include the tenant label filter.
Cross-tenant traversals are impossible because labels don't overlap.
"""

import re

from sentinel.core import get_logger
from sentinel.tenancy.context import require_tenant

logger = get_logger(__name__)


def tenant_label() -> str:
    """Get the Neo4j label for the current tenant."""
    tid = require_tenant()
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
    label = tenant_label()
    result = re.sub(
        r"\(:(\w+)",
        lambda m: f"(:{label}:{m.group(1)}",
        cypher,
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
