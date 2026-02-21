"""
WebSocket Fuzzer — Tests persistent WebSocket connections for vulnerabilities.

Capabilities:
1. Connect and intercept WS frames
2. Mutate JSON/text payloads with injection strings
3. Test Origin header validation (CSWSH — CWE-1385)
4. Detect reflected payloads, SQL errors, command output
5. Record evidence (payload sent + response received)
"""

import asyncio
import json
from dataclasses import dataclass, field

import websockets

from sentinel.tools.base import ToolOutput
from sentinel.core import get_logger

logger = get_logger(__name__)


FUZZ_PAYLOADS: dict[str, list[str]] = {
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "{{constructor.constructor('alert(1)')()}}",
        "'-alert(1)-'",
    ],
    "sqli": [
        "' OR '1'='1",
        "1; DROP TABLE users--",
        "admin'--",
        "1 UNION SELECT NULL,NULL--",
    ],
    "command": [
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",
        "`id`",
    ],
    "path_traversal": [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\",
    ],
    "nosqli": [
        '{"$gt": ""}',
        '{"$ne": null}',
    ],
}

EVIL_ORIGINS = [
    "https://evil.com",
    "https://attacker.example.com",
    "null",
]


@dataclass
class WSFinding:
    """A finding from WebSocket fuzzing."""
    url: str
    finding_type: str       # "xss", "sqli", "cswsh", "command", etc.
    severity: str           # critical/high/medium/low
    payload_sent: str
    response_received: str
    description: str


class WebSocketFuzzer:
    """Fuzz WebSocket connections for injection and auth vulnerabilities."""

    name = "ws_fuzz"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    async def execute(
        self, ws_url: str, categories: list[str] | None = None
    ) -> ToolOutput:
        """Run full WS fuzzing suite against a WebSocket URL."""
        categories = categories or list(FUZZ_PAYLOADS.keys())
        findings: list[WSFinding] = []

        # 1. Test Origin validation (CSWSH)
        cswsh = await self._test_origin_validation(ws_url)
        if cswsh:
            findings.append(cswsh)

        # 2. Fuzz message payloads per category
        for category in categories:
            payloads = FUZZ_PAYLOADS.get(category, [])
            for payload in payloads:
                finding = await self._fuzz_message(ws_url, payload, category)
                if finding:
                    findings.append(finding)

        return ToolOutput(
            tool_name=self.name,
            success=True,
            data={
                "findings": [self._finding_to_dict(f) for f in findings],
                "total_findings": len(findings),
                "url": ws_url,
                "categories_tested": categories,
            },
            raw_output="",
        )

    async def _test_origin_validation(
        self, ws_url: str
    ) -> WSFinding | None:
        """Test if WS accepts connections from arbitrary origins (CSWSH)."""
        for origin in EVIL_ORIGINS:
            try:
                async with websockets.connect(
                    ws_url,
                    additional_headers={"Origin": origin},
                    open_timeout=self.timeout,
                ) as ws:
                    return WSFinding(
                        url=ws_url,
                        finding_type="cswsh",
                        severity="high",
                        payload_sent=f"Origin: {origin}",
                        response_received="Connection accepted",
                        description=(
                            f"WebSocket accepts connections from arbitrary Origin ({origin}). "
                            f"Vulnerable to Cross-Site WebSocket Hijacking (CWE-1385)."
                        ),
                    )
            except Exception:
                continue
        return None

    async def _fuzz_message(
        self, ws_url: str, payload: str, category: str
    ) -> WSFinding | None:
        """Send a fuzz payload and analyze the response."""
        try:
            async with websockets.connect(
                ws_url, open_timeout=self.timeout
            ) as ws:
                # Send payload in multiple formats
                messages = [
                    payload,
                    json.dumps({"message": payload}),
                    json.dumps({"data": payload, "type": "message"}),
                ]
                for msg in messages:
                    try:
                        await ws.send(msg)
                        response = await asyncio.wait_for(
                            ws.recv(), timeout=self.timeout
                        )

                        if self._check_vuln_indicators(
                            response, category, payload
                        ):
                            return WSFinding(
                                url=ws_url,
                                finding_type=category,
                                severity=self._severity_for_category(category),
                                payload_sent=msg,
                                response_received=response[:500],
                                description=(
                                    f"WebSocket may be vulnerable to {category}. "
                                    f"Payload reflected or error triggered."
                                ),
                            )
                    except asyncio.TimeoutError:
                        continue
        except Exception as e:
            logger.debug("ws_fuzz_failed", url=ws_url, error=str(e))
        return None

    def _check_vuln_indicators(
        self, response: str, category: str, payload: str
    ) -> bool:
        """Check if response indicates a vulnerability."""
        resp_lower = response.lower()

        if category == "sqli":
            indicators = [
                "sql", "syntax error", "mysql", "postgresql", "sqlite",
                "unterminated", "unexpected", "ora-", "odbc",
            ]
            return any(ind in resp_lower for ind in indicators)

        if category == "xss":
            # Reflected without encoding = vulnerable
            return payload in response

        if category == "command":
            indicators = [
                "root:", "uid=", "/bin/", "permission denied",
                "no such file", "command not found", "not recognized",
            ]
            return any(ind in resp_lower for ind in indicators)

        if category == "path_traversal":
            indicators = [
                "root:", "[boot loader]", "passwd", "shadow",
            ]
            return any(ind in resp_lower for ind in indicators)

        if category == "nosqli":
            # If we get data back that shouldn't be there
            try:
                data = json.loads(response)
                if isinstance(data, (list, dict)) and len(str(data)) > 100:
                    return True
            except (json.JSONDecodeError, TypeError):
                pass

        return False

    @staticmethod
    def _severity_for_category(category: str) -> str:
        severity_map = {
            "sqli": "critical",
            "command": "critical",
            "xss": "high",
            "path_traversal": "high",
            "nosqli": "high",
            "cswsh": "high",
        }
        return severity_map.get(category, "medium")

    @staticmethod
    def _finding_to_dict(finding: WSFinding) -> dict:
        return {
            "url": finding.url,
            "finding_type": finding.finding_type,
            "severity": finding.severity,
            "payload_sent": finding.payload_sent,
            "response_received": finding.response_received,
            "description": finding.description,
        }
