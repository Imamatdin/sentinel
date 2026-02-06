"""HTTP request tool for web application interaction."""

import json
from typing import Any
from urllib.parse import urljoin

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.logging_config import get_logger

logger = get_logger(__name__)

# Shared session for connection pooling
_session: aiohttp.ClientSession | None = None


async def get_session() -> aiohttp.ClientSession:
    """Get or create shared aiohttp session."""
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            connector=aiohttp.TCPConnector(ssl=False),
        )
    return _session


async def close_session() -> None:
    """Close shared session. Call on shutdown."""
    global _session
    if _session and not _session.closed:
        await _session.close()
        _session = None


@tool_schema(
    name="http_request",
    description=(
        "Make an HTTP request to a URL. Use this to interact with the target web application: "
        "fetch pages, submit forms, test endpoints, send payloads. "
        "Returns status code, headers, and response body (truncated if large)."
    ),
    parameters=[
        ToolParameter("url", "string", "Full URL to request"),
        ToolParameter(
            "method",
            "string",
            "HTTP method",
            required=False,
            enum=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"],
        ),
        ToolParameter(
            "headers",
            "string",
            "JSON string of headers to send (e.g. '{\"Cookie\": \"token=abc\"}')",
            required=False,
        ),
        ToolParameter(
            "body",
            "string",
            "Request body. For JSON, pass a JSON string. For form data, use key=value&key2=value2 format.",
            required=False,
        ),
        ToolParameter(
            "content_type",
            "string",
            "Content-Type header shortcut",
            required=False,
            enum=["json", "form", "text", "none"],
        ),
        ToolParameter(
            "follow_redirects",
            "string",
            "Whether to follow redirects: 'true' or 'false'",
            required=False,
        ),
    ],
)
@timed
async def http_request(
    url: str,
    method: str = "GET",
    headers: str | None = None,
    body: str | None = None,
    content_type: str = "none",
    follow_redirects: str = "true",
) -> ToolOutput:
    """Make an HTTP request and return the response."""
    session = await get_session()

    # Parse headers
    req_headers: dict[str, str] = {}
    if headers:
        try:
            req_headers = json.loads(headers)
        except json.JSONDecodeError:
            return ToolOutput(
                tool_name="http_request",
                success=False,
                data={},
                error=f"Invalid headers JSON: {headers[:200]}",
            )

    # Set content type
    if content_type == "json":
        req_headers.setdefault("Content-Type", "application/json")
    elif content_type == "form":
        req_headers.setdefault(
            "Content-Type", "application/x-www-form-urlencoded"
        )

    # Build request kwargs
    kwargs: dict[str, Any] = {
        "method": method.upper(),
        "url": url,
        "headers": req_headers,
        "allow_redirects": follow_redirects.lower() != "false",
    }

    if body:
        if content_type == "json":
            try:
                kwargs["json"] = json.loads(body)
            except json.JSONDecodeError:
                kwargs["data"] = body
        elif content_type == "form":
            kwargs["data"] = body
        else:
            kwargs["data"] = body

    try:
        async with session.request(**kwargs) as resp:
            status = resp.status
            resp_headers = dict(resp.headers)
            try:
                resp_body = await resp.text(encoding="utf-8")
            except Exception:
                resp_body = "(binary response, cannot decode as text)"

            # Truncate very large responses for the LLM
            body_truncated = False
            if len(resp_body) > 6000:
                resp_body = resp_body[:6000]
                body_truncated = True

            # Extract useful info
            data = {
                "status_code": status,
                "url": str(resp.url),
                "headers": {
                    k: v
                    for k, v in resp_headers.items()
                    if k.lower()
                    in (
                        "content-type",
                        "set-cookie",
                        "location",
                        "server",
                        "x-powered-by",
                        "www-authenticate",
                        "access-control-allow-origin",
                    )
                },
                "body": resp_body,
                "body_length": len(resp_body),
                "truncated": body_truncated,
            }

            logger.info(
                "http_request_complete",
                method=method,
                url=url,
                status=status,
                body_length=data["body_length"],
            )

            return ToolOutput(
                tool_name="http_request",
                success=True,
                data=data,
            )

    except aiohttp.ClientError as e:
        return ToolOutput(
            tool_name="http_request",
            success=False,
            data={"url": url, "method": method},
            error=f"HTTP error: {type(e).__name__}: {str(e)}",
        )
    except Exception as e:
        return ToolOutput(
            tool_name="http_request",
            success=False,
            data={"url": url, "method": method},
            error=f"Request failed: {type(e).__name__}: {str(e)}",
        )
