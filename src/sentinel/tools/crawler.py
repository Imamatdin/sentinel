"""Web crawler for comprehensive endpoint discovery.

Handles SPAs by following JavaScript-rendered links.
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

from sentinel.core import get_logger
from sentinel.tools.http_recon import HTTPReconTool, HTTPResponse

logger = get_logger(__name__)


@dataclass
class CrawlResult:
    """Result of web crawling."""
    base_url: str
    pages_crawled: int = 0
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    api_endpoints: list[dict[str, Any]] = field(default_factory=list)
    static_files: list[str] = field(default_factory=list)
    external_links: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


class WebCrawler:
    """Async web crawler with SPA support."""

    def __init__(
        self,
        http_tool: HTTPReconTool | None = None,
        max_depth: int = 3,
        max_pages: int = 100,
        concurrency: int = 10,
        same_domain_only: bool = True,
    ):
        self.http = http_tool or HTTPReconTool()
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.concurrency = concurrency
        self.same_domain_only = same_domain_only
        self.logger = get_logger("tool.crawler")

    async def crawl(
        self,
        start_url: str,
        scope_pattern: str | None = None,
    ) -> CrawlResult:
        """Crawl a website starting from the given URL."""
        start_time = datetime.now(timezone.utc)

        result = CrawlResult(base_url=start_url)
        visited: set[str] = set()
        queue: list[tuple[str, int]] = [(start_url, 0)]  # (url, depth)
        semaphore = asyncio.Semaphore(self.concurrency)

        parsed_start = urlparse(start_url)
        base_domain = parsed_start.netloc

        scope_regex = re.compile(scope_pattern) if scope_pattern else None

        self.logger.info(
            "Starting crawl",
            url=start_url,
            max_depth=self.max_depth,
            max_pages=self.max_pages,
        )

        while queue and len(visited) < self.max_pages:
            # Process batch
            batch: list[tuple[str, int]] = []
            while queue and len(batch) < self.concurrency:
                url, depth = queue.pop(0)
                if url not in visited and depth <= self.max_depth:
                    visited.add(url)
                    batch.append((url, depth))

            if not batch:
                break

            async def crawl_page(
                url: str, depth: int,
            ) -> tuple[HTTPResponse | None, list[str]]:
                async with semaphore:
                    try:
                        response = await self.http.get(url, timeout=15.0)
                        if response.error:
                            result.errors.append(f"{url}: {response.error}")
                            return None, []

                        new_urls: list[str] = []
                        for link in response.links:
                            parsed = urlparse(link)

                            if self.same_domain_only and parsed.netloc != base_domain:
                                if link not in result.external_links:
                                    result.external_links.append(link)
                                continue

                            if scope_regex and not scope_regex.match(link):
                                continue

                            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                            if normalized not in visited:
                                new_urls.append(normalized)

                        return response, new_urls

                    except Exception as e:
                        result.errors.append(f"{url}: {e!s}")
                        return None, []

            tasks = [crawl_page(url, depth) for url, depth in batch]
            responses = await asyncio.gather(*tasks)

            for (url, depth), (response, new_urls) in zip(batch, responses):
                if response is None:
                    continue

                result.endpoints.append({
                    "url": response.url,
                    "method": "GET",
                    "status_code": response.status_code,
                    "content_type": response.content_type,
                    "title": response.title,
                    "depth": depth,
                })

                for form in response.forms:
                    form_url = urljoin(response.url, form["action"])
                    form_entry = {
                        "page_url": response.url,
                        "action": form_url,
                        "method": form["method"],
                        "inputs": form["inputs"],
                    }
                    if form_entry not in result.forms:
                        result.forms.append(form_entry)

                if response.content_type:
                    if "json" in response.content_type or "api" in url.lower():
                        result.api_endpoints.append({
                            "url": response.url,
                            "content_type": response.content_type,
                        })

                for script in response.scripts:
                    if script not in result.static_files:
                        result.static_files.append(script)

                for new_url in new_urls:
                    if new_url not in visited:
                        queue.append((new_url, depth + 1))

        result.pages_crawled = len(visited)
        result.duration_seconds = (datetime.now(timezone.utc) - start_time).total_seconds()

        self.logger.info(
            "Crawl complete",
            pages_crawled=result.pages_crawled,
            endpoints=len(result.endpoints),
            forms=len(result.forms),
            api_endpoints=len(result.api_endpoints),
            duration_seconds=result.duration_seconds,
        )

        return result

    async def extract_api_endpoints(self, js_urls: list[str]) -> list[dict[str, Any]]:
        """Extract API endpoints from JavaScript files."""
        api_patterns = [
            re.compile(r'["\']/(api|v\d)/[^"\']+["\']'),
            re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']'),
            re.compile(r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']'),
            re.compile(r'url:\s*["\']([^"\']+)["\']'),
            re.compile(r'\$\.(?:get|post|ajax)\s*\(\s*["\']([^"\']+)["\']'),
        ]

        endpoints: list[dict[str, Any]] = []

        async def extract_from_js(js_url: str) -> list[str]:
            response = await self.http.get(js_url)
            if response.error:
                return []

            found: list[str] = []
            for pattern in api_patterns:
                matches = pattern.findall(response.body)
                found.extend(matches)
            return found

        tasks = [extract_from_js(url) for url in js_urls]
        results = await asyncio.gather(*tasks)

        for js_url, found_endpoints in zip(js_urls, results):
            for endpoint in found_endpoints:
                if endpoint.startswith("/"):
                    endpoints.append({
                        "path": endpoint,
                        "source": js_url,
                        "type": "extracted_from_js",
                    })

        return endpoints
