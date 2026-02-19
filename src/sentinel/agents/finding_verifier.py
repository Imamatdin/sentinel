"""
FindingVerifier — Validates findings before they're promoted.

Implements "No Exploit, No Report" policy:
1. Replays the exploit to confirm reproducibility
2. Checks for false positives
3. Generates PoC replay scripts
4. Assigns final severity rating
"""
from dataclasses import dataclass
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class VerifiedFinding:
    finding_id: str
    category: str
    target_url: str
    severity: str
    evidence: str
    poc_script: str         # Reproducible proof-of-concept
    replay_commands: list[str]  # CLI commands to reproduce
    http_trace: list[dict]  # Full HTTP request/response log
    confirmed_count: int    # How many times exploit succeeded
    false_positive_check: bool
    remediation: str
    mitre_technique: str


class FindingVerifier:
    """
    Verifies findings by replaying exploits.

    For each finding:
    1. Replay the exact tool call that produced it
    2. Confirm same result (at least 2/3 replays succeed)
    3. Generate PoC script (Python, curl, or Postman)
    4. Log full HTTP trace for evidence
    """

    async def verify(self, finding: dict, replay_count: int = 3) -> VerifiedFinding:
        """Verify a single finding by replaying it."""
        # Replay the exploit
        successes = 0
        http_traces = []

        for i in range(replay_count):
            result = await self._replay_exploit(finding)
            if result["success"]:
                successes += 1
                http_traces.append(result["trace"])

        confirmed = successes >= 2  # At least 2/3 must succeed

        # Generate PoC script
        poc = self._generate_poc(finding, http_traces)
        replay_cmds = self._generate_replay_commands(finding, http_traces)

        return VerifiedFinding(
            finding_id=finding.get("hypothesis_id", "unknown"),
            category=finding.get("category", "unknown"),
            target_url=finding.get("target_url", ""),
            severity=finding.get("severity", "unknown"),
            evidence=finding.get("evidence", ""),
            poc_script=poc,
            replay_commands=replay_cmds,
            http_trace=http_traces,
            confirmed_count=successes,
            false_positive_check=confirmed,
            remediation=finding.get("remediation", ""),
            mitre_technique=finding.get("mitre_technique", ""),
        )

    async def _replay_exploit(self, finding: dict) -> dict:
        """Replay the specific exploit that produced this finding."""
        # Re-execute the tool with same parameters
        # Return success/failure + HTTP trace
        # TODO: Implement actual replay logic once tool wiring is complete
        return {"success": False, "trace": {}}

    def _generate_poc(self, finding: dict, traces: list[dict]) -> str:
        """Generate Python PoC script from HTTP traces."""
        if not traces:
            return "# No HTTP traces available for PoC generation"

        trace = traces[0]
        method = trace.get("method", "get").lower()
        headers = trace.get("headers", {})
        body = trace.get("body", "")

        category = finding.get("category", "unknown")
        target_url = finding.get("target_url", "")

        script = f'''#!/usr/bin/env python3
"""PoC for {category} at {target_url}"""
import requests

url = "{target_url}"

# HTTP headers
headers = {repr(headers)}

# Request body/data
data = {repr(body)}

# Reproduce the exploit
response = requests.{method}(
    url,
    headers=headers,
    data=data,
)

print(f"Status: {{response.status_code}}")
print(f"Response: {{response.text[:500]}}")

# Check for vulnerability indicators
if response.status_code == 200:
    print("[+] Vulnerability appears to be present")
else:
    print("[-] Could not reproduce vulnerability")
'''
        return script

    def _generate_replay_commands(self, finding: dict, traces: list[dict]) -> list[str]:
        """Generate curl commands for replay."""
        commands = []
        for trace in traces:
            method = trace.get("method", "GET")
            url = finding.get("target_url", "")
            headers = trace.get("headers", {})
            body = trace.get("body", "")

            # Build curl command
            cmd_parts = ["curl", "-X", method]

            # Add headers
            for key, value in headers.items():
                cmd_parts.extend(["-H", f"'{key}: {value}'"])

            # Add body if present
            if body:
                cmd_parts.extend(["-d", f"'{body}'"])

            # Add URL
            cmd_parts.append(f"'{url}'")

            commands.append(" ".join(cmd_parts))

        return commands
