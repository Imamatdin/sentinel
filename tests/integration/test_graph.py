"""Integration tests for Neo4j knowledge graph."""

import pytest

from sentinel.graph import (
    get_graph_client,
    close_graph_client,
    Host,
    Port,
    Service,
    Vulnerability,
    CriticalAsset,
    BaseEdge,
    NodeType,
    EdgeType,
    Severity,
)


@pytest.fixture
async def graph_client():
    """Get graph client for tests."""
    client = await get_graph_client()
    yield client
    await client.clear_engagement("test-engagement")
    await close_graph_client()


@pytest.mark.asyncio
async def test_create_host(graph_client):
    """Test creating a host node."""
    host = Host(
        ip_address="192.168.1.100",
        hostname="test-server",
        os="Linux",
        engagement_id="test-engagement",
    )

    node_id = await graph_client.create_node(host)
    assert node_id == str(host.id)

    retrieved = await graph_client.get_node(str(host.id), NodeType.HOST)
    assert retrieved is not None
    assert retrieved["ip_address"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_create_attack_chain(graph_client):
    """Test creating a complete attack chain."""
    engagement_id = "test-engagement"

    host = Host(
        ip_address="192.168.1.100",
        hostname="web-server",
        engagement_id=engagement_id,
    )
    await graph_client.create_node(host)

    port = Port(
        port_number=443,
        protocol="tcp",
        host_id=host.id,
        engagement_id=engagement_id,
    )
    await graph_client.create_node(port)

    edge = BaseEdge(
        edge_type=EdgeType.HAS_PORT,
        source_id=host.id,
        target_id=port.id,
    )
    await graph_client.create_edge(
        str(host.id), NodeType.HOST,
        str(port.id), NodeType.PORT,
        edge,
    )

    service = Service(
        name="https",
        product="nginx",
        version="1.18.0",
        port_id=port.id,
        engagement_id=engagement_id,
    )
    await graph_client.create_node(service)

    edge = BaseEdge(
        edge_type=EdgeType.RUNS_SERVICE,
        source_id=port.id,
        target_id=service.id,
    )
    await graph_client.create_edge(
        str(port.id), NodeType.PORT,
        str(service.id), NodeType.SERVICE,
        edge,
    )

    vuln = Vulnerability(
        name="SQL Injection in login",
        cve_id="CVE-2024-1234",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        is_exploitable=True,
        engagement_id=engagement_id,
    )
    await graph_client.create_node(vuln)

    edge = BaseEdge(
        edge_type=EdgeType.HAS_VULNERABILITY,
        source_id=service.id,
        target_id=vuln.id,
    )
    await graph_client.create_edge(
        str(service.id), NodeType.SERVICE,
        str(vuln.id), NodeType.VULNERABILITY,
        edge,
    )

    vulns = await graph_client.find_vulnerabilities(
        host_id=str(host.id),
        is_exploitable=True,
    )
    assert len(vulns) == 1
    assert vulns[0]["cve_id"] == "CVE-2024-1234"


@pytest.mark.asyncio
async def test_attack_path_computation(graph_client):
    """Test finding attack paths."""
    engagement_id = "test-engagement"

    entry = Host(
        ip_address="10.0.0.1",
        hostname="entry-point",
        engagement_id=engagement_id,
    )
    await graph_client.create_node(entry)

    middle = Host(
        ip_address="10.0.0.50",
        hostname="middle-server",
        engagement_id=engagement_id,
    )
    await graph_client.create_node(middle)

    crown_jewel = CriticalAsset(
        name="Customer Database",
        asset_type="database",
        engagement_id=engagement_id,
    )
    await graph_client.create_node(crown_jewel)

    edge1 = BaseEdge(edge_type=EdgeType.PIVOTS_TO, source_id=entry.id, target_id=middle.id)
    await graph_client.create_edge(
        str(entry.id), NodeType.HOST,
        str(middle.id), NodeType.HOST,
        edge1,
    )

    edge2 = BaseEdge(edge_type=EdgeType.ACCESSES, source_id=middle.id, target_id=crown_jewel.id)
    await graph_client.create_edge(
        str(middle.id), NodeType.HOST,
        str(crown_jewel.id), NodeType.CRITICAL_ASSET,
        edge2,
    )

    path = await graph_client.find_shortest_path(
        str(entry.id),
        str(crown_jewel.id),
    )
    assert path is not None
    assert path["depth"] == 2
    assert len(path["nodes"]) == 3


@pytest.mark.asyncio
async def test_snapshot_creation(graph_client):
    """Test creating graph snapshots."""
    engagement_id = "test-engagement"

    for i in range(5):
        host = Host(
            ip_address=f"192.168.1.{i+1}",
            engagement_id=engagement_id,
        )
        await graph_client.create_node(host)

    snapshot = await graph_client.create_snapshot(engagement_id)
    assert snapshot.host_count == 5
    assert len(snapshot.node_ids) == 5
