# LEVEL 11: Business Logic Vulnerability Tester

## Context
XBOW's confirmed weakness: business logic and stateful multi-user exploits. This level adds BOLA/IDOR differential testing, race condition detection (single-packet technique), and workflow state machine abuse. This is Sentinel's competitive differentiator.

Research: Block 5 (Business Logic/API Security). James Kettle's single-packet race condition technique.

## Why
Business logic bugs are the #1 OWASP API risk (BOLA) and the hardest to automate. Traditional scanners can't test "user A can access user B's data" because they don't model multi-user state. Sentinel's knowledge graph makes this possible.

---

## Files to Create

### `src/sentinel/tools/attack/bola_tester.py`
```python
"""
BOLA/IDOR Differential Tester.

Strategy:
1. Authenticate as User A, collect resource IDs (orders, profiles, etc.)
2. Authenticate as User B (different role/tenant)
3. Try accessing User A's resources as User B
4. Compare responses: if User B gets User A's data → BOLA confirmed

This is the "gold standard" for IDOR testing — requires two valid sessions.
"""
import asyncio
import aiohttp
from dataclasses import dataclass, field
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BOLATestCase:
    endpoint: str
    method: str
    resource_id: str
    owner_user: str        # User who owns the resource
    attacker_user: str     # User trying to access it


@dataclass
class BOLAFinding:
    endpoint: str
    method: str
    resource_id: str
    owner: str
    attacker: str
    owner_status: int
    attacker_status: int
    data_leaked: bool
    response_similarity: float  # 0.0-1.0 how similar attacker response is to owner's
    severity: str = "critical"


class BOLATester(BaseTool):
    name = "bola_test"
    description = "Test for Broken Object Level Authorization (IDOR)"
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def execute(
        self,
        test_cases: list[BOLATestCase],
        owner_session: dict,     # {"headers": {"Authorization": "Bearer ..."}}
        attacker_session: dict,
    ) -> ToolResult:
        """Run BOLA differential tests."""
        findings = []
        
        for tc in test_cases:
            finding = await self._test_single(tc, owner_session, attacker_session)
            if finding:
                findings.append(finding)
        
        return ToolResult(
            success=True,
            data=findings,
            tool_name=self.name,
            metadata={
                "total_tests": len(test_cases),
                "bola_confirmed": len(findings),
            },
        )
    
    async def _test_single(
        self, tc: BOLATestCase, owner_session: dict, attacker_session: dict
    ) -> BOLAFinding | None:
        """Test a single endpoint for BOLA."""
        try:
            async with aiohttp.ClientSession() as session:
                # Step 1: Get owner's response (baseline)
                owner_resp = await self._make_request(
                    session, tc.method, tc.endpoint, owner_session["headers"]
                )
                
                if owner_resp["status"] >= 400:
                    return None  # Owner can't access their own resource — skip
                
                # Step 2: Try same request as attacker
                attacker_resp = await self._make_request(
                    session, tc.method, tc.endpoint, attacker_session["headers"]
                )
                
                # Step 3: Analyze
                if attacker_resp["status"] < 400:
                    # Attacker got a 2xx/3xx — potential BOLA
                    similarity = self._compare_responses(
                        owner_resp["body"], attacker_resp["body"]
                    )
                    
                    if similarity > 0.5:  # Attacker sees similar data to owner
                        return BOLAFinding(
                            endpoint=tc.endpoint,
                            method=tc.method,
                            resource_id=tc.resource_id,
                            owner=tc.owner_user,
                            attacker=tc.attacker_user,
                            owner_status=owner_resp["status"],
                            attacker_status=attacker_resp["status"],
                            data_leaked=True,
                            response_similarity=similarity,
                        )
                
                return None
        except Exception as e:
            logger.error(f"BOLA test failed for {tc.endpoint}: {e}")
            return None
    
    async def _make_request(self, session, method: str, url: str, headers: dict) -> dict:
        async with session.request(method, url, headers=headers, timeout=aiohttp.ClientTimeout(total=self.timeout)) as resp:
            body = await resp.text()
            return {"status": resp.status, "body": body, "headers": dict(resp.headers)}
    
    def _compare_responses(self, body_a: str, body_b: str) -> float:
        """Compare two response bodies for similarity (0.0-1.0)."""
        if not body_a or not body_b:
            return 0.0
        if body_a == body_b:
            return 1.0
        
        # Simple Jaccard similarity on tokens
        tokens_a = set(body_a.split())
        tokens_b = set(body_b.split())
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)
```

### `src/sentinel/tools/attack/race_condition.py`
```python
"""
Race Condition Tester — Single-Packet Attack Technique.

James Kettle's technique: send multiple HTTP requests in a single TCP packet
so they arrive at the server simultaneously, bypassing network jitter.
This catches: double-spending, duplicate coupons, parallel login, TOCTOU bugs.
"""
import asyncio
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger

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


class RaceConditionTester(BaseTool):
    name = "race_condition"
    description = "Test for race conditions using single-packet technique"
    
    async def execute(
        self,
        target_url: str,
        method: str = "POST",
        body: str = "",
        headers: dict = None,
        num_concurrent: int = 10,
    ) -> ToolResult:
        """
        Send N identical requests simultaneously via single-packet technique.
        If the server processes them all (e.g., applies a coupon 10 times),
        it's a race condition.
        """
        headers = headers or {}
        parsed = urlparse(target_url)
        
        try:
            result = await self._single_packet_race(
                host=parsed.hostname,
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                path=parsed.path + (f"?{parsed.query}" if parsed.query else ""),
                method=method,
                body=body,
                headers=headers,
                num_requests=num_concurrent,
                use_tls=parsed.scheme == "https",
            )
            
            return ToolResult(
                success=True,
                data=result,
                tool_name=self.name,
            )
        except Exception as e:
            return ToolResult(success=False, error=str(e), tool_name=self.name)
    
    async def _single_packet_race(
        self, host, port, path, method, body, headers, num_requests, use_tls
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
        
        # Send as single write
        loop = asyncio.get_event_loop()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        if use_tls:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=host)
        
        try:
            sock.connect((host, port))
            sock.sendall(payload)
            
            # Read responses
            responses = []
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
            status_codes = []
            bodies = []
            for resp in raw_responses[1:]:  # Skip empty first split
                lines = resp.split("\r\n")
                if lines:
                    try:
                        status = int(lines[0].split(" ")[1])
                        status_codes.append(status)
                    except (IndexError, ValueError):
                        pass
                    # Get body (after empty line)
                    body_idx = resp.find("\r\n\r\n")
                    if body_idx > 0:
                        bodies.append(resp[body_idx+4:])
            
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
                description=f"Sent {num_requests} simultaneous requests. "
                            f"Got {success_count} successes, {unique_bodies} unique responses.",
                evidence=[f"Status codes: {status_codes}",
                         f"Unique response bodies: {unique_bodies}"],
            )
        finally:
            sock.close()
```

### `src/sentinel/tools/attack/workflow_abuse.py`
```python
"""
Workflow State Machine Abuse Tester.

Tests for state machine bypass: skip steps, replay steps, access wrong-state endpoints.
Example: jump from "cart" directly to "order_complete" skipping "payment".
"""
from dataclasses import dataclass, field
from sentinel.tools.base import BaseTool, ToolResult
from sentinel.logging import get_logger
import aiohttp

logger = get_logger(__name__)


@dataclass
class WorkflowStep:
    name: str
    endpoint: str
    method: str
    body: dict = field(default_factory=dict)
    expected_status: int = 200


@dataclass
class WorkflowAbuseFinding:
    attack_type: str     # "step_skip", "step_replay", "state_bypass"
    skipped_steps: list[str]
    endpoint_accessed: str
    status_code: int
    description: str
    severity: str = "high"


class WorkflowAbuseTester(BaseTool):
    name = "workflow_abuse"
    description = "Test workflow state machines for step-skipping and state bypass"
    
    async def execute(
        self,
        workflow_steps: list[WorkflowStep],
        session_headers: dict,
        base_url: str,
    ) -> ToolResult:
        """
        Test workflow by:
        1. Trying to access each step out of order (skip preceding steps)
        2. Replaying completed steps
        3. Accessing final step directly without any preceding steps
        """
        findings = []
        
        # Test 1: Skip to last step directly
        if len(workflow_steps) > 1:
            last = workflow_steps[-1]
            finding = await self._try_step(
                base_url, last, session_headers,
                skipped=[s.name for s in workflow_steps[:-1]]
            )
            if finding:
                findings.append(finding)
        
        # Test 2: Skip intermediate steps (try step N without doing step N-1)
        for i in range(1, len(workflow_steps)):
            # Do steps 0..i-2, skip step i-1, try step i
            finding = await self._try_with_partial(
                base_url, workflow_steps, i, session_headers
            )
            if finding:
                findings.append(finding)
        
        return ToolResult(
            success=True,
            data=findings,
            tool_name=self.name,
            metadata={"tests_run": len(workflow_steps), "findings": len(findings)},
        )
    
    async def _try_step(self, base_url, step: WorkflowStep, 
                        headers: dict, skipped: list[str]) -> WorkflowAbuseFinding | None:
        """Try accessing a step without completing prerequisites."""
        url = base_url.rstrip("/") + step.endpoint
        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    step.method, url, json=step.body, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status < 400:  # Success without prerequisites
                        return WorkflowAbuseFinding(
                            attack_type="step_skip",
                            skipped_steps=skipped,
                            endpoint_accessed=step.endpoint,
                            status_code=resp.status,
                            description=f"Accessed '{step.name}' ({step.endpoint}) without completing: {skipped}. "
                                        f"Server returned {resp.status} instead of rejecting.",
                        )
        except Exception as e:
            logger.debug(f"Workflow test failed: {e}")
        return None
    
    async def _try_with_partial(self, base_url, steps, target_idx, headers):
        """Execute steps up to target_idx-2, skip target_idx-1, try target_idx."""
        async with aiohttp.ClientSession() as session:
            # Execute prerequisite steps (except the one we're skipping)
            for i in range(target_idx - 1):
                step = steps[i]
                url = base_url.rstrip("/") + step.endpoint
                try:
                    async with session.request(step.method, url, json=step.body, headers=headers) as resp:
                        pass
                except Exception:
                    return None
            
            # Now try the target step (skipping step target_idx-1)
            target = steps[target_idx]
            skipped_step = steps[target_idx - 1]
            return await self._try_step(
                base_url, target, headers, skipped=[skipped_step.name]
            )
```

---

## Tests

### `tests/tools/attack/test_bola_tester.py`
```python
import pytest
from sentinel.tools.attack.bola_tester import BOLATester

class TestBOLATester:
    def setup_method(self):
        self.tester = BOLATester()
    
    def test_response_comparison_identical(self):
        assert self.tester._compare_responses("hello world", "hello world") == 1.0
    
    def test_response_comparison_similar(self):
        sim = self.tester._compare_responses(
            '{"id": 1, "name": "Alice", "email": "a@b.com"}',
            '{"id": 1, "name": "Alice", "email": "a@b.com"}'
        )
        assert sim == 1.0
    
    def test_response_comparison_different(self):
        sim = self.tester._compare_responses("hello world", "goodbye universe")
        assert sim < 0.3
    
    def test_response_comparison_empty(self):
        assert self.tester._compare_responses("", "hello") == 0.0
```

### `tests/tools/attack/test_race_condition.py`
```python
import pytest
from sentinel.tools.attack.race_condition import RaceConditionTester

class TestRaceCondition:
    def test_result_dataclass(self):
        from sentinel.tools.attack.race_condition import RaceResult
        r = RaceResult(
            endpoint="POST /apply-coupon",
            method="POST",
            num_requests=10,
            unique_responses=1,
            status_codes=[200]*10,
            is_vulnerable=True,
            description="test",
            evidence=[],
        )
        assert r.is_vulnerable
        assert r.num_requests == 10
```

---

## Acceptance Criteria
- [ ] BOLATester performs differential access testing between two user sessions
- [ ] Response similarity correctly identifies leaked data
- [ ] RaceConditionTester sends N requests via single TCP write
- [ ] WorkflowAbuseTester detects step-skipping in multi-step flows
- [ ] All findings include evidence (status codes, response data)
- [ ] All tests pass