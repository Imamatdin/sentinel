"""HTTP client for web reconnaissance.

This module provides structured HTTP capabilities for recon,
complementing the existing http_tool.py (which is aiohttp-based
for the legacy tool system).
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class HTTPResponse:
    """Structured HTTP response."""
    url: str
    method: str
    status_code: int
    headers: dict[str, str]
    body: str
    body_size: int
    content_type: str | None
    elapsed_ms: float
    redirects: list[str] = field(default_factory=list)
    cookies: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    # Security-relevant headers
    security_headers: dict[str, str] = field(default_factory=dict)

    # Extracted data
    title: str | None = None
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    scripts: list[str] = field(default_factory=list)


@dataclass
class HTTPRequest:
    """HTTP request specification."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    data: dict[str, Any] | str | None = None
    json_data: dict[str, Any] | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    timeout: float = 30.0
    follow_redirects: bool = True
    verify_ssl: bool = True


_SECURITY_HEADER_NAMES = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "x-xss-protection",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
]


class HTTPReconTool:
    """Async HTTP client for web reconnaissance."""

    def __init__(
        self,
        proxy_url: str | None = None,
        default_headers: dict[str, str] | None = None,
    ):
        self.proxy_url = proxy_url
        self.default_headers = default_headers or {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        self.logger = get_logger("tool.http_recon")

    async def request(self, req: HTTPRequest) -> HTTPResponse:
        """Send an HTTP request."""
        start = datetime.now(timezone.utc)

        headers = {**self.default_headers, **req.headers}

        transport = None
        if self.proxy_url:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy_url)

        try:
            async with httpx.AsyncClient(
                transport=transport,
                verify=req.verify_ssl,
                follow_redirects=req.follow_redirects,
                timeout=req.timeout,
            ) as client:
                response = await client.request(
                    method=req.method,
                    url=req.url,
                    headers=headers,
                    params=req.params,
                    data=req.data if not req.json_data else None,
                    json=req.json_data,
                    cookies=req.cookies,
                )

                elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000

                body = response.text[:500_000]  # 500KB limit

                security_headers = {
                    name: response.headers[name]
                    for name in _SECURITY_HEADER_NAMES
                    if name in response.headers
                }

                redirects = [str(r.url) for r in response.history]
                cookies = dict(response.cookies)

                result = HTTPResponse(
                    url=str(response.url),
                    method=req.method,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    body=body,
                    body_size=len(response.content),
                    content_type=response.headers.get("content-type"),
                    elapsed_ms=elapsed,
                    redirects=redirects,
                    cookies=cookies,
                    security_headers=security_headers,
                )

                if result.content_type and "html" in result.content_type:
                    _parse_html(result, body)

                self.logger.debug(
                    "HTTP request complete",
                    url=req.url,
                    status=result.status_code,
                    elapsed_ms=elapsed,
                )

                return result

        except httpx.TimeoutException:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            return HTTPResponse(
                url=req.url, method=req.method, status_code=0,
                headers={}, body="", body_size=0, content_type=None,
                elapsed_ms=elapsed, error="Request timed out",
            )
        except httpx.RequestError as e:
            elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
            return HTTPResponse(
                url=req.url, method=req.method, status_code=0,
                headers={}, body="", body_size=0, content_type=None,
                elapsed_ms=elapsed, error=str(e),
            )

    async def get(self, url: str, **kwargs: Any) -> HTTPResponse:
        """GET request shorthand."""
        return await self.request(HTTPRequest(url=url, method="GET", **kwargs))

    async def post(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        json_data: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> HTTPResponse:
        """POST request shorthand."""
        return await self.request(HTTPRequest(
            url=url, method="POST", data=data, json_data=json_data, **kwargs,
        ))

    async def check_url(self, url: str) -> tuple[bool, int]:
        """Quick check if URL is accessible. Returns (accessible, status_code)."""
        response = await self.request(HTTPRequest(url=url, method="HEAD", timeout=10.0))
        return response.error is None, response.status_code

    async def discover_endpoints(
        self,
        base_url: str,
        wordlist: list[str] | None = None,
        concurrency: int = 20,
    ) -> list[HTTPResponse]:
        """Discover endpoints via directory brute force."""
        if wordlist is None:
            wordlist = [
                "", "api", "api/v1", "api/v2", "v1", "v2",
                "admin", "login", "register", "signup", "signin",
                "dashboard", "panel", "console", "portal",
                "user", "users", "account", "profile",
                "auth", "oauth", "token", "session",
                "graphql", "graphiql", "playground",
                "swagger", "swagger-ui", "api-docs", "docs", "redoc",
                "health", "healthz", "status", "ping", "ready",
                "metrics", "prometheus", "actuator",
                "robots.txt", "sitemap.xml", ".well-known",
                "wp-admin", "wp-login.php", "wp-content",
                ".git", ".env", "config", "backup",
                "test", "debug", "dev", "staging",
            ]

        semaphore = asyncio.Semaphore(concurrency)
        results: list[HTTPResponse] = []

        async def check_path(path: str) -> HTTPResponse | None:
            async with semaphore:
                url = urljoin(base_url.rstrip("/") + "/", path)
                response = await self.get(url, timeout=10.0)
                if response.status_code in [200, 201, 301, 302, 401, 403]:
                    return response
                return None

        self.logger.info(
            "Starting endpoint discovery",
            base_url=base_url,
            paths_to_check=len(wordlist),
        )

        tasks = [check_path(path) for path in wordlist]
        responses = await asyncio.gather(*tasks)
        results = [r for r in responses if r is not None]

        self.logger.info(
            "Endpoint discovery complete",
            endpoints_found=len(results),
        )

        return results


def _parse_html(response: HTTPResponse, body: str) -> None:
    """Parse HTML for interesting data."""
    # Extract title
    title_match = re.search(r"<title[^>]*>([^<]+)</title>", body, re.IGNORECASE)
    if title_match:
        response.title = title_match.group(1).strip()

    # Extract forms
    form_pattern = re.compile(
        r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
        re.IGNORECASE | re.DOTALL,
    )
    for match in form_pattern.finditer(body):
        action, method, form_content = match.groups()
        inputs = re.findall(
            r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>',
            form_content,
            re.IGNORECASE,
        )
        response.forms.append({
            "action": action,
            "method": method.upper(),
            "inputs": inputs,
        })

    # Extract links
    base_url = response.url
    for match in re.finditer(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE):
        href = match.group(1)
        if not href.startswith(("javascript:", "mailto:", "#")):
            full_url = urljoin(base_url, href)
            if full_url not in response.links:
                response.links.append(full_url)

    # Extract script sources
    for match in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', body, re.IGNORECASE):
        response.scripts.append(urljoin(base_url, match.group(1)))
