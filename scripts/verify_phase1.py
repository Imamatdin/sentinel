#!/usr/bin/env python3
"""Verify Sentinel Phase 1 - Knowledge Graph Engine."""

import asyncio
from sentinel.graph import get_graph_client, close_graph_client, Host


async def main():
    client = await get_graph_client()
    print("[PASS] Connected to Neo4j")

    host = Host(ip_address="127.0.0.1", hostname="localhost", engagement_id="verify")
    await client.create_node(host)
    print("[PASS] Created test node")

    result = await client.get_node(str(host.id), host.node_type)
    print(f"[PASS] Retrieved: {result['hostname']}")

    await client.clear_engagement("verify")
    await close_graph_client()
    print("[PASS] Phase 1 complete")


if __name__ == "__main__":
    asyncio.run(main())
