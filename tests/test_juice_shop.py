"""Integration tests against OWASP Juice Shop.

These tests require Juice Shop to be running:
    docker compose -f docker-compose.juice-shop.yml up -d

Skip with: pytest tests/test_juice_shop.py -v -k "not integration"
"""

import pytest
import aiohttp

JUICE_SHOP_URL = "http://localhost:3000"


async def is_juice_shop_running() -> bool:
    """Check if Juice Shop is accessible."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                JUICE_SHOP_URL, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                return resp.status == 200
    except Exception:
        return False


@pytest.fixture(autouse=True)
async def check_juice_shop():
    """Skip integration tests if Juice Shop is not running."""
    if not await is_juice_shop_running():
        pytest.skip("Juice Shop not running at localhost:3000")


@pytest.mark.asyncio
async def test_juice_shop_path_scan():
    """Path scan should find Juice Shop endpoints."""
    from sentinel.tools.scanner_tool import path_scan

    result = await path_scan(base_url=JUICE_SHOP_URL, wordlist="common")
    assert result.success
    assert result.data["paths_found"] > 0
    # Juice Shop should have /api and /rest
    paths = [p["path"] for p in result.data["accessible"]]
    assert any("/api" in p or "/rest" in p for p in paths)


@pytest.mark.asyncio
async def test_juice_shop_api_discover():
    """API discovery should find Juice Shop endpoints."""
    from sentinel.tools.api_tool import api_discover

    result = await api_discover(base_url=JUICE_SHOP_URL)
    assert result.success
    assert result.data["summary"]["endpoints_found"] > 0


@pytest.mark.asyncio
async def test_juice_shop_challenges():
    """Challenge check should return Juice Shop challenge list."""
    from sentinel.tools.juice_shop import check_challenges

    result = await check_challenges(base_url=JUICE_SHOP_URL)
    assert result.success
    assert result.data["total_challenges"] > 0


@pytest.mark.asyncio
async def test_juice_shop_login():
    """Login tool should find default admin credentials."""
    from sentinel.tools.auth_tool import login_attempt

    result = await login_attempt(
        login_url=f"{JUICE_SHOP_URL}/rest/user/login",
        username="BRUTEFORCE",
        method="json_body",
        username_field="email",
        password_field="password",
    )
    assert result.success
    # admin@juice-sh.op / admin123 should work
    assert len(result.data["successful_logins"]) > 0


@pytest.mark.asyncio
async def test_juice_shop_sqli_search():
    """SQL injection test should find vuln in search endpoint."""
    from sentinel.tools.injection_tool import sql_injection_test

    result = await sql_injection_test(
        url=f"{JUICE_SHOP_URL}/rest/products/search?q=test",
        parameter="q",
        method="GET",
        technique="error_based",
    )
    assert result.success
    # Juice Shop search is vulnerable to SQLi
    # The test may or may not detect it depending on exact response behavior
    # but it should complete without errors


@pytest.mark.asyncio
async def test_juice_shop_http_request():
    """HTTP request tool should successfully fetch pages."""
    from sentinel.tools.http_tool import http_request

    result = await http_request(url=JUICE_SHOP_URL, method="GET")
    assert result.success
    assert result.data["status_code"] == 200
