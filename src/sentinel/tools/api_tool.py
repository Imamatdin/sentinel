"""API endpoint discovery and analysis tools."""

import asyncio
import json
from typing import Any
from urllib.parse import urljoin

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.tools.http_tool import get_session
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@tool_schema(
    name="api_discover",
    description=(
        "Discover and enumerate API endpoints on the target. Fetches common API documentation "
        "paths (swagger, openapi, api-docs) and probes for REST endpoints. "
        "Use this after port/path scanning to map the API attack surface."
    ),
    parameters=[
        ToolParameter("base_url", "string", "Base URL of the target"),
        ToolParameter("auth_header", "string", "Authorization header if needed", required=False),
    ],
)
@timed
async def api_discover(
    base_url: str,
    auth_header: str | None = None,
) -> ToolOutput:
    """Discover API endpoints and documentation."""
    session = await get_session()
    headers: dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header

    # API documentation paths to check
    doc_paths = [
        "/api-docs",
        "/api-docs/",
        "/swagger.json",
        "/swagger/",
        "/openapi.json",
        "/api/swagger.json",
        "/docs",
        "/redoc",
    ]

    # REST API endpoint patterns to probe
    api_paths = [
        "/api/Users", "/api/Products", "/api/Feedbacks",
        "/api/Complaints", "/api/Recycles", "/api/SecurityQuestions",
        "/api/SecurityAnswers", "/api/Challenges", "/api/Quantitys",
        "/api/Cards", "/api/Addresss", "/api/Deliverys",
        "/api/BasketItems", "/api/Memories",
        "/rest/products/search", "/rest/user/login",
        "/rest/user/change-password", "/rest/user/reset-password",
        "/rest/user/whoami", "/rest/user/authentication-details",
        "/rest/basket", "/rest/admin/application-version",
        "/rest/admin/application-configuration",
        "/rest/captcha", "/rest/image-captcha",
        "/rest/chatbot/status", "/rest/chatbot/respond",
        "/rest/memories", "/rest/saveLoginIp",
        "/rest/deluxe-membership", "/rest/continue-code",
        "/rest/repeat-notification", "/rest/wallet/balance",
        "/b2bOrder",
        "/file-upload", "/profile/image/upload",
        "/dataerasure",
        "/redirect",
        "/snippets", "/snippets/1", "/snippets/2",
    ]

    docs_found: list[dict[str, Any]] = []
    endpoints_found: list[dict[str, Any]] = []

    # Check documentation paths
    for path in doc_paths:
        url = base_url.rstrip("/") + path
        try:
            async with session.get(
                url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    docs_found.append({
                        "path": path,
                        "status": resp.status,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "preview": body[:500],
                    })
        except Exception:
            pass

    # Probe API endpoints
    semaphore = asyncio.Semaphore(10)

    async def probe_endpoint(path: str) -> dict[str, Any] | None:
        async with semaphore:
            url = base_url.rstrip("/") + path
            try:
                async with session.get(
                    url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 404:
                        body = await resp.text()
                        content_type = resp.headers.get("Content-Type", "")

                        # Determine if it's a JSON API
                        is_json = "json" in content_type.lower()
                        data_preview = ""
                        if is_json:
                            try:
                                parsed = json.loads(body)
                                if isinstance(parsed, dict):
                                    data_preview = str(list(parsed.keys()))[:200]
                                elif isinstance(parsed, list):
                                    data_preview = f"Array with {len(parsed)} items"
                            except json.JSONDecodeError:
                                data_preview = body[:200]
                        else:
                            data_preview = body[:200]

                        return {
                            "path": path,
                            "status": resp.status,
                            "content_type": content_type.split(";")[0],
                            "is_json_api": is_json,
                            "data_preview": data_preview,
                            "methods_to_test": ["GET", "POST", "PUT", "DELETE"],
                        }
            except Exception:
                pass
            return None

    results = await asyncio.gather(
        *[probe_endpoint(p) for p in api_paths], return_exceptions=True
    )
    endpoints_found = [r for r in results if isinstance(r, dict)]

    return ToolOutput(
        tool_name="api_discover",
        success=True,
        data={
            "base_url": base_url,
            "documentation": docs_found,
            "endpoints": endpoints_found,
            "summary": {
                "docs_found": len(docs_found),
                "endpoints_found": len(endpoints_found),
                "json_apis": len([e for e in endpoints_found if e.get("is_json_api")]),
            },
        },
    )
