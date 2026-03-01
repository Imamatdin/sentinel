"""
Race Condition Tester -- Single-Packet Attack Technique.

James Kettle's technique: send multiple HTTP requests in a single TCP packet
so they arrive at the server simultaneously, bypassing network jitter.
This catches: double-spending, duplicate coupons, parallel login, TOCTOU bugs.
"""

import asyncio
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

from sentinel.tools.base import ToolOutput
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class RaceResult:
    endpoint: str
    method: str
    num_requests: int
    unique_responses: int
    status_codes: list[int]
    is_vulnerable: bool
    description: str
    evidence: list[str]


class RaceConditionTester:
    name = "race_condition"
    description = "Test for race conditions using single-packet technique"

    async def execute(
        self,
        target_url: str,
        method: str = "POST",
        body: str = "",
        headers: dict | None = None,
        num_concurrent: int = 10,
    ) -> ToolOutput:
        """Send N identical requests simultaneously via single-packet technique.

        If the server processes them all (e.g., applies a coupon 10 times),
        it's a race condition.
        """
        headers = headers or {}
        parsed = urlparse(target_url)

        try:
            result = await self._single_packet_race(
                host=parsed.hostname or "localhost",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                path=parsed.path + (f"?{parsed.query}" if parsed.query else ""),
                method=method,
                body=body,
                headers=headers,
                num_requests=num_concurrent,
                use_tls=parsed.scheme == "https",
            )

            return ToolOutput(
                tool_name=self.name,
                success=True,
                data={
                    "endpoint": result.endpoint,
                    "method": result.method,
                    "num_requests": result.num_requests,
                    "unique_responses": result.unique_responses,
                    "status_codes": result.status_codes,
                    "is_vulnerable": result.is_vulnerable,
                    "description": result.description,
                    "evidence": result.evidence,
                },
            )
        except Exception as e:
            return ToolOutput(
                tool_name=self.name,
                success=False,
                data={},
                error=str(e),
            )

    async def _single_packet_race(
        self, host: str, port: int, path: str, method: str, body: str,
        headers: dict, num_requests: int, use_tls: bool,
    ) -> RaceResult:
        """Build N HTTP requests and send them in a single TCP write."""

        # Build raw HTTP request
        req_headers = {
            "Host": host,
            "Content-Length": str(len(body)),
            "Connection": "keep-alive",
            **headers,
        }
        header_str = "\r\n".join(f"{k}: {v}" for k, v in req_headers.items())
        single_request = f"{method} {path} HTTP/1.1\r\n{header_str}\r\n\r\n{body}"

        # Concatenate N requests into one payload
        payload = (single_request * num_requests).encode()

        # Send as single write (run blocking socket I/O in executor)
        loop = asyncio.get_event_loop()
        status_codes, bodies = await loop.run_in_executor(
            None, self._send_raw, host, port, payload, use_tls
        )

        unique_bodies = len(set(bodies))
        success_count = sum(1 for s in status_codes if 200 <= s < 300)

        # Vulnerability: if more successes than expected (e.g., coupon applied 10x)
        is_vulnerable = success_count > 1

        return RaceResult(
            endpoint=f"{method} {path}",
            method=method,
            num_requests=num_requests,
            unique_responses=unique_bodies,
            status_codes=status_codes,
            is_vulnerable=is_vulnerable,
            description=(
                f"Sent {num_requests} simultaneous requests. "
                f"Got {success_count} successes, {unique_bodies} unique responses."
            ),
            evidence=[
                f"Status codes: {status_codes}",
                f"Unique response bodies: {unique_bodies}",
            ],
        )

    def _send_raw(
        self, host: str, port: int, payload: bytes, use_tls: bool
    ) -> tuple[list[int], list[str]]:
        """Blocking socket send + receive. Runs in executor."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)

        try:
            sock.connect((host, port))
            sock.sendall(payload)

            # Read responses
            buffer = b""
            try:
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
            except socket.timeout:
                pass

            # Parse individual HTTP responses from buffer
            raw_responses = buffer.decode(errors="replace").split("HTTP/1.")
            status_codes: list[int] = []
            bodies: list[str] = []
            for resp in raw_responses[1:]:  # Skip empty first split
                lines = resp.split("\r\n")
                if lines:
                    try:
                        status = int(lines[0].split(" ")[1])
                        status_codes.append(status)
                    except (IndexError, ValueError):
                        pass
                    body_idx = resp.find("\r\n\r\n")
                    if body_idx > 0:
                        bodies.append(resp[body_idx + 4:])

            return status_codes, bodies
        finally:
            sock.close()
