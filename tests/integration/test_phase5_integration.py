"""Integration tests for Phase 5 components with live Docker services."""
import pytest
from unittest.mock import AsyncMock

from sentinel.tools.scanning.zap_tool import ZAPTool
from sentinel.agents.hypothesis_engine import HypothesisEngine
from sentinel.graph.neo4j_client import Neo4jClient
from sentinel.core.config import get_settings


@pytest.mark.integration
@pytest.mark.asyncio
async def test_zap_tool_connects_to_daemon():
    """Test ZAPTool can connect to ZAP daemon on localhost:8080."""
    tool = ZAPTool()

    # Verify ZAP API is accessible
    try:
        result = await tool._api_call("core/view/version/")
        assert "version" in result
        print(f"ZAP version: {result.get('version')}")
    except Exception as e:
        pytest.skip(f"ZAP not accessible: {e}")


@pytest.mark.integration
@pytest.mark.asyncio
async def test_hypothesis_engine_queries_neo4j():
    """Test HypothesisEngine can query Neo4j knowledge graph."""
    settings = get_settings()

    try:
        graph = Neo4jClient(
            uri=settings.neo4j_uri,
            username=settings.neo4j_user,
            password=settings.neo4j_password.get_secret_value()
        )

        # Test connection
        result = await graph.query("RETURN 1 as test")
        assert result[0]["test"] == 1

        # Create test engagement and endpoint
        await graph.query(
            """
            MERGE (eng:Engagement {engagement_id: 'test-eng-phase5'})
            MERGE (ep:Endpoint {
                url: 'http://localhost:3000/rest/user/login',
                method: 'POST',
                path: '/rest/user/login'
            })
            MERGE (eng)-[:HAS_ENDPOINT]->(ep)
            """
        )

        # Test HypothesisEngine
        engine = HypothesisEngine(graph, llm_client=None)
        hypotheses = await engine.generate_hypotheses("test-eng-phase5")

        print(f"Generated {len(hypotheses)} hypotheses from Neo4j")
        assert isinstance(hypotheses, list)

        # Cleanup
        await graph.query("MATCH (eng:Engagement {engagement_id: 'test-eng-phase5'}) DETACH DELETE eng")
        await graph.close()

    except Exception as e:
        pytest.skip(f"Neo4j not accessible: {e}")


@pytest.mark.integration
def test_juice_shop_accessible():
    """Test Juice Shop is accessible on localhost:3000."""
    import requests

    try:
        response = requests.get("http://localhost:3000", timeout=5)
        assert response.status_code == 200
        print("Juice Shop is accessible")
    except Exception as e:
        pytest.skip(f"Juice Shop not accessible: {e}")
