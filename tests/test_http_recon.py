"""Tests for HTTP recon tool and web crawler."""

import pytest

from sentinel.tools.http_recon import HTTPReconTool, HTTPRequest, HTTPResponse, _parse_html
from sentinel.tools.crawler import WebCrawler, CrawlResult


class TestHTTPReconTool:
    """Test HTTP recon tool."""

    @pytest.mark.asyncio
    async def test_get_request(self):
        """GET request to httpbin."""
        tool = HTTPReconTool()
        response = await tool.get("https://httpbin.org/get")
        assert response.status_code == 200
        assert response.error is None
        assert response.body_size > 0

    @pytest.mark.asyncio
    async def test_post_request(self):
        """POST request with JSON data."""
        tool = HTTPReconTool()
        response = await tool.post(
            "https://httpbin.org/post",
            json_data={"test": "value"},
        )
        assert response.status_code == 200
        assert "test" in response.body

    @pytest.mark.asyncio
    async def test_timeout_handling(self):
        """Timeout should return error, not raise."""
        tool = HTTPReconTool()
        response = await tool.request(HTTPRequest(
            url="https://httpbin.org/delay/10",
            timeout=1.0,
        ))
        assert response.status_code == 0
        assert response.error is not None

    @pytest.mark.asyncio
    async def test_invalid_url(self):
        """Invalid URL should return error."""
        tool = HTTPReconTool()
        response = await tool.get("https://this-does-not-exist-sentinel.invalid")
        assert response.status_code == 0
        assert response.error is not None

    @pytest.mark.asyncio
    async def test_check_url(self):
        """check_url should return (accessible, status_code)."""
        tool = HTTPReconTool()
        accessible, status = await tool.check_url("https://httpbin.org/get")
        assert accessible is True
        assert status == 200

    @pytest.mark.asyncio
    async def test_security_headers_extracted(self):
        """Security headers should be extracted when present."""
        tool = HTTPReconTool()
        response = await tool.get("https://httpbin.org/response-headers?X-Frame-Options=DENY")
        # httpbin may or may not set these, but shouldn't crash
        assert isinstance(response.security_headers, dict)

    @pytest.mark.asyncio
    async def test_redirects_followed(self):
        """Redirects should be followed and recorded."""
        tool = HTTPReconTool()
        response = await tool.get("https://httpbin.org/redirect/1")
        assert response.status_code == 200
        assert len(response.redirects) >= 1


class TestHTMLParsing:
    """Test HTML parsing functions."""

    def test_parse_title(self):
        response = HTTPResponse(
            url="http://example.com", method="GET", status_code=200,
            headers={}, body="", body_size=0, content_type="text/html",
            elapsed_ms=0,
        )
        html = "<html><head><title>Test Page</title></head><body></body></html>"
        _parse_html(response, html)
        assert response.title == "Test Page"

    def test_parse_forms(self):
        response = HTTPResponse(
            url="http://example.com", method="GET", status_code=200,
            headers={}, body="", body_size=0, content_type="text/html",
            elapsed_ms=0,
        )
        html = '''
        <form action="/login" method="POST">
            <input name="username" type="text"/>
            <input name="password" type="password"/>
        </form>
        '''
        _parse_html(response, html)
        assert len(response.forms) == 1
        assert response.forms[0]["action"] == "/login"
        assert response.forms[0]["method"] == "POST"
        assert "username" in response.forms[0]["inputs"]
        assert "password" in response.forms[0]["inputs"]

    def test_parse_links(self):
        response = HTTPResponse(
            url="http://example.com", method="GET", status_code=200,
            headers={}, body="", body_size=0, content_type="text/html",
            elapsed_ms=0,
        )
        html = '''
        <a href="/about">About</a>
        <a href="https://external.com">External</a>
        <a href="javascript:void(0)">JS</a>
        <a href="#section">Anchor</a>
        '''
        _parse_html(response, html)
        assert "http://example.com/about" in response.links
        assert "https://external.com" in response.links
        # javascript: and # links should be excluded
        js_links = [l for l in response.links if "javascript:" in l or l.endswith("#section")]
        assert len(js_links) == 0

    def test_parse_scripts(self):
        response = HTTPResponse(
            url="http://example.com", method="GET", status_code=200,
            headers={}, body="", body_size=0, content_type="text/html",
            elapsed_ms=0,
        )
        html = '<script src="/js/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        _parse_html(response, html)
        assert "http://example.com/js/app.js" in response.scripts
        assert "https://cdn.example.com/lib.js" in response.scripts


class TestCrawlResult:
    """Test CrawlResult dataclass."""

    def test_empty_result(self):
        result = CrawlResult(base_url="http://example.com")
        assert result.pages_crawled == 0
        assert result.endpoints == []
        assert result.forms == []
        assert result.duration_seconds == 0.0


class TestWebCrawler:
    """Test web crawler (requires network)."""

    @pytest.mark.asyncio
    async def test_crawl_httpbin(self):
        """Crawl httpbin with shallow depth."""
        crawler = WebCrawler(max_depth=1, max_pages=5, concurrency=3)
        result = await crawler.crawl("https://httpbin.org")
        assert result.pages_crawled >= 1
        assert len(result.endpoints) >= 1
        assert result.duration_seconds > 0

    @pytest.mark.asyncio
    async def test_crawl_respects_max_pages(self):
        """Crawler should stop at max_pages."""
        crawler = WebCrawler(max_depth=5, max_pages=3, concurrency=2)
        result = await crawler.crawl("https://httpbin.org")
        assert result.pages_crawled <= 3
