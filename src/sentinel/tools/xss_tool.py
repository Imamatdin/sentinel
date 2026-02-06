"""Cross-site scripting (XSS) detection tools."""

import json
import re
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.tools.http_tool import get_session
from sentinel.logging_config import get_logger

logger = get_logger(__name__)

# XSS payloads with unique markers for detection
XSS_PAYLOADS = [
    # Basic script injection
    {"payload": '<script>alert("SENTINEL_XSS_1")</script>', "marker": "SENTINEL_XSS_1", "type": "script_tag"},
    {"payload": '<img src=x onerror=alert("SENTINEL_XSS_2")>', "marker": "SENTINEL_XSS_2", "type": "event_handler"},
    {"payload": '<svg onload=alert("SENTINEL_XSS_3")>', "marker": "SENTINEL_XSS_3", "type": "svg_event"},
    {"payload": '"><script>alert("SENTINEL_XSS_4")</script>', "marker": "SENTINEL_XSS_4", "type": "attribute_break"},
    {"payload": "'-alert('SENTINEL_XSS_5')-'", "marker": "SENTINEL_XSS_5", "type": "js_context"},
    # Encoding bypasses
    {"payload": '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>', "marker": "onerror=", "type": "html_entity"},
    {"payload": '<iframe src="javascript:alert(`SENTINEL_XSS_6`)"></iframe>', "marker": "SENTINEL_XSS_6", "type": "iframe"},
    # DOM-based
    {"payload": '#<script>alert("SENTINEL_XSS_7")</script>', "marker": "SENTINEL_XSS_7", "type": "dom_hash"},
]


@tool_schema(
    name="xss_test",
    description=(
        "Test a URL parameter or form field for Cross-Site Scripting (XSS) vulnerabilities. "
        "Injects various XSS payloads and checks if they are reflected in the response unescaped. "
        "Tests reflected XSS. Returns which payloads were reflected and the type of XSS found."
    ),
    parameters=[
        ToolParameter("url", "string", "URL to test (e.g. 'http://localhost:3000/#/search?q=test')"),
        ToolParameter("parameter", "string", "Name of the parameter to inject into"),
        ToolParameter(
            "method",
            "string",
            "HTTP method",
            required=False,
            enum=["GET", "POST"],
        ),
        ToolParameter(
            "auth_header",
            "string",
            "Authorization header if needed",
            required=False,
        ),
    ],
)
@timed
async def xss_test(
    url: str,
    parameter: str,
    method: str = "GET",
    auth_header: str | None = None,
) -> ToolOutput:
    """Test for XSS vulnerabilities."""
    session = await get_session()
    results: list[dict[str, Any]] = []
    vulnerable = False

    headers: dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header

    for xss_entry in XSS_PAYLOADS:
        payload = xss_entry["payload"]
        marker = xss_entry["marker"]
        xss_type = xss_entry["type"]

        try:
            if method == "GET":
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                async with session.get(
                    test_url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.text()
                    status = resp.status
            else:
                data = {parameter: payload}
                async with session.post(
                    url, data=data, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.text()
                    status = resp.status

            # Check if payload is reflected unescaped
            reflected = False
            context = ""

            if payload in body:
                reflected = True
                context = "exact_reflection"
            elif marker in body:
                reflected = True
                context = "marker_reflected"

            # Check for partial reflection (tag attributes present)
            if not reflected and xss_type == "event_handler":
                if "onerror=" in body and "SENTINEL" in body:
                    reflected = True
                    context = "event_handler_reflected"

            if reflected:
                vulnerable = True
                # Extract surrounding context
                idx = body.find(marker)
                if idx >= 0:
                    snippet_start = max(0, idx - 100)
                    snippet_end = min(len(body), idx + len(marker) + 100)
                    context_snippet = body[snippet_start:snippet_end]
                else:
                    context_snippet = ""

                results.append(
                    {
                        "payload": payload,
                        "xss_type": xss_type,
                        "reflected": True,
                        "context": context,
                        "status": status,
                        "evidence": context_snippet[:300],
                    }
                )

        except Exception:
            pass  # Skip failed payloads

    return ToolOutput(
        tool_name="xss_test",
        success=True,
        data={
            "url": url,
            "parameter": parameter,
            "vulnerable": vulnerable,
            "findings": results,
            "payloads_tested": len(XSS_PAYLOADS),
            "summary": (
                f"XSS VULNERABLE: {len(results)} payloads reflected unescaped"
                if vulnerable
                else f"No XSS found after testing {len(XSS_PAYLOADS)} payloads"
            ),
        },
    )
