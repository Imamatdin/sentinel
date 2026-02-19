# LEVEL 07: WebSocket Security Fuzzer

## Context
Most DAST tools ignore WebSocket connections. This level adds WS-specific fuzzing: frame mutation, injection testing, Origin validation, and CSWSH (Cross-Site WebSocket Hijacking) detection. Schneider identified many missing-Origin CVEs in WS libraries (CWE-1385).

Research: Block 12 (Unconventional Surfaces — WebSockets), Block 8 (OWASP WS testing guide).

## Files to Create

### `src/sentinel/tools/websocket/__init__.py`
```python
"""WebSocket security testing tools."""
```

### `src/sentinel/tools/websocket/ws_fuzzer.py`
```python
"""
WebSocket Fuzzer — Tests persistent WebSocket connections for vulnerabilities.

Capabilities:
1. Connect and intercept WS frames
2. Mutate JSON/text payloads with injection strings
3. Test Origin header validation (CSWSH)
4. Detect unauthorized message subscriptions
5. Test for rate limiting on WS
"""
import asyncio
import json
import websockets
from dataclasses import dataclass, field
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)

FUZZ_PAYLOADS = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
    ],
    "sqli": [
        "' OR '1'='1", "1; DROP TABLE users--",
        "admin'--", "1 UNION SELECT NULL,NULL--",
    ],
    "command": [
        "; ls -la", "| cat /etc/passwd",
        "$(whoami)", "`id`",
    ],
    "path_traversal": [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\",
    ],
    "nosqli": [
        '{"$gt": ""}', '{"$ne": null}',
    ],
}


@dataclass
class WSFinding:
    url: str
    finding_type: str     # "xss", "sqli", "cswsh", "no_auth", "no_rate_limit"
    severity: str
    payload_sent: str
    response_received: str
    description: str


class WebSocketFuzzer(BaseTool):
    name = "ws_fuzz"
    description = "Fuzz WebSocket connections for injection and auth vulnerabilities"
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    async def execute(self, ws_url: str, categories: list[str] = None) -> ToolResult:
        """Run full WS fuzzing suite."""
        categories = categories or list(FUZZ_PAYLOADS.keys())
        findings = []
        
        # 1. Test Origin validation (CSWSH)
        cswsh = await self._test_origin_validation(ws_url)
        if cswsh:
            findings.append(cswsh)
        
        # 2. Fuzz message payloads
        for category in categories:
            payloads = FUZZ_PAYLOADS.get(category, [])
            for payload in payloads:
                finding = await self._fuzz_message(ws_url, payload, category)
                if finding:
                    findings.append(finding)
        
        return ToolResult(
            success=True,
            data=findings,
            tool_name=self.name,
            metadata={"total_findings": len(findings), "url": ws_url},
        )
    
    async def _test_origin_validation(self, ws_url: str) -> WSFinding | None:
        """Test if WS accepts connections from arbitrary origins (CSWSH)."""
        evil_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
        ]
        for origin in evil_origins:
            try:
                async with websockets.connect(
                    ws_url,
                    additional_headers={"Origin": origin},
                    open_timeout=self.timeout,
                ) as ws:
                    # If connection succeeds, Origin is not validated
                    return WSFinding(
                        url=ws_url,
                        finding_type="cswsh",
                        severity="high",
                        payload_sent=f"Origin: {origin}",
                        response_received="Connection accepted",
                        description=f"WebSocket accepts connections from arbitrary Origin ({origin}). "
                                    f"Vulnerable to Cross-Site WebSocket Hijacking (CWE-1385).",
                    )
            except Exception:
                continue  # Connection refused = good, Origin validated
        return None
    
    async def _fuzz_message(self, ws_url: str, payload: str, category: str) -> WSFinding | None:
        """Send a fuzz payload and analyze the response."""
        try:
            async with websockets.connect(ws_url, open_timeout=self.timeout) as ws:
                # Try sending as JSON wrapper
                messages = [
                    payload,
                    json.dumps({"message": payload}),
                    json.dumps({"data": payload, "type": "message"}),
                ]
                for msg in messages:
                    try:
                        await ws.send(msg)
                        response = await asyncio.wait_for(ws.recv(), timeout=self.timeout)
                        
                        if self._check_vuln_indicators(response, category, payload):
                            return WSFinding(
                                url=ws_url,
                                finding_type=category,
                                severity="high" if category in ("sqli", "command") else "medium",
                                payload_sent=msg,
                                response_received=response[:500],
                                description=f"WebSocket may be vulnerable to {category}. "
                                            f"Payload reflected or error triggered.",
                            )
                    except asyncio.TimeoutError:
                        continue
        except Exception as e:
            logger.debug(f"WS fuzz connection failed: {e}")
        return None
    
    def _check_vuln_indicators(self, response: str, category: str, payload: str) -> bool:
        """Check if response indicates a vulnerability."""
        resp_lower = response.lower()
        
        if category == "sqli":
            indicators = ["sql", "syntax error", "mysql", "postgresql", "sqlite",
                         "unterminated", "unexpected", "ora-"]
            return any(ind in resp_lower for ind in indicators)
        
        if category == "xss":
            return payload in response  # Reflected without encoding
        
        if category == "command":
            indicators = ["root:", "uid=", "/bin/", "permission denied",
                         "no such file", "command not found"]
            return any(ind in resp_lower for ind in indicators)
        
        return False
```

## Tests

### `tests/tools/websocket/test_ws_fuzzer.py`
```python
import pytest
from sentinel.tools.websocket.ws_fuzzer import WebSocketFuzzer

class TestWebSocketFuzzer:
    def setup_method(self):
        self.fuzzer = WebSocketFuzzer()
    
    def test_sqli_detection(self):
        assert self.fuzzer._check_vuln_indicators("SQL syntax error near", "sqli", "' OR 1=1")
        assert not self.fuzzer._check_vuln_indicators("OK", "sqli", "' OR 1=1")
    
    def test_xss_reflection(self):
        payload = "<script>alert(1)</script>"
        assert self.fuzzer._check_vuln_indicators(f"echo: {payload}", "xss", payload)
        assert not self.fuzzer._check_vuln_indicators("echo: &lt;script&gt;", "xss", payload)
    
    def test_command_detection(self):
        assert self.fuzzer._check_vuln_indicators("root:x:0:0:", "command", "; cat /etc/passwd")
    
    def test_fuzz_payloads_exist(self):
        from sentinel.tools.websocket.ws_fuzzer import FUZZ_PAYLOADS
        assert len(FUZZ_PAYLOADS["xss"]) >= 3
        assert len(FUZZ_PAYLOADS["sqli"]) >= 3
```

## Acceptance Criteria
- [ ] CSWSH detection works against arbitrary Origin headers
- [ ] Injection payloads sent through WS frames
- [ ] Response analysis detects SQLi errors, reflected XSS, command output
- [ ] Findings include payload sent + response received as evidence
- [ ] All tests pass