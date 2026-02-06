"""Network traffic monitoring and anomaly detection for blue team."""

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class RequestLog:
    """Logged HTTP request."""
    timestamp: float
    source_ip: str
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: str
    status_code: int = 0
    response_time_ms: int = 0
    flagged: bool = False
    flag_reasons: list[str] = field(default_factory=list)


# Attack signature patterns
ATTACK_SIGNATURES = {
    "sqli": [
        r"(?i)(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|;\s*drop\s|--\s*$|/\*.*\*/)",
        r"(?i)(select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from)",
        r"(?i)(waitfor\s+delay|sleep\s*\(|benchmark\s*\()",
    ],
    "xss": [
        r"(?i)(<script|javascript:|on\w+\s*=|<img\s+[^>]*onerror|<svg\s+[^>]*onload)",
        r"(?i)(alert\s*\(|prompt\s*\(|confirm\s*\(|document\.cookie)",
    ],
    "path_traversal": [
        r"(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/)",
    ],
    "command_injection": [
        r"(?i)(;\s*\w+|`[^`]+`|\$\([^)]+\)|\|\s*\w+)",
    ],
    "ssrf": [
        r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.\d|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)",
    ],
}


class NetworkMonitor:
    """Monitors and analyzes network traffic for attack patterns.

    The blue team's eyes. Logs all requests from the red team's tools
    and flags suspicious patterns.
    """

    def __init__(self):
        self._requests: list[RequestLog] = []
        self._alerts: list[dict[str, Any]] = []
        self._request_counts: dict[str, int] = defaultdict(int)  # IP -> count
        self._rate_windows: dict[str, list[float]] = defaultdict(list)  # IP -> timestamps
        self._max_requests = 50000

    def log_request(self, request: RequestLog) -> None:
        """Log an incoming request and check for attack patterns."""
        # Trim old requests if buffer is full
        if len(self._requests) >= self._max_requests:
            self._requests = self._requests[-self._max_requests // 2 :]

        # Check for attack patterns
        full_input = f"{request.path}?{request.query_string} {request.body}"
        for attack_type, patterns in ATTACK_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, full_input):
                    request.flagged = True
                    request.flag_reasons.append(
                        f"{attack_type}: matched pattern"
                    )
                    self._alerts.append(
                        {
                            "timestamp": time.time(),
                            "type": attack_type,
                            "source_ip": request.source_ip,
                            "path": request.path,
                            "severity": "high"
                            if attack_type in ("sqli", "command_injection")
                            else "medium",
                            "detail": f"Suspicious {attack_type} pattern in request to {request.path}",
                        }
                    )
                    break

        # Rate limit check
        now = time.time()
        window = self._rate_windows[request.source_ip]
        window.append(now)
        # Keep only last 60 seconds
        self._rate_windows[request.source_ip] = [
            t for t in window if now - t < 60
        ]
        if len(self._rate_windows[request.source_ip]) > 100:
            request.flagged = True
            request.flag_reasons.append("rate_limit: >100 requests/minute")

        self._request_counts[request.source_ip] += 1
        self._requests.append(request)

    @tool_schema(
        name="get_network_logs",
        description=(
            "Get recent network traffic logs captured by the blue team monitor. "
            "Shows all requests made to the target, flagged suspicious patterns, "
            "and request rates. Use to understand what the attacker is doing."
        ),
        parameters=[
            ToolParameter(
                "since_seconds",
                "string",
                "Only show logs from the last N seconds (e.g. '60' for last minute)",
                required=False,
            ),
            ToolParameter(
                "flagged_only",
                "string",
                "Only show flagged (suspicious) requests: 'true' or 'false'",
                required=False,
            ),
            ToolParameter(
                "limit",
                "string",
                "Maximum number of log entries to return",
                required=False,
            ),
        ],
    )
    @timed
    async def get_logs(
        self,
        since_seconds: str = "60",
        flagged_only: str = "false",
        limit: str = "50",
    ) -> ToolOutput:
        """Get recent network logs."""
        try:
            since = float(since_seconds)
            max_entries = int(limit)
            only_flagged = flagged_only.lower() == "true"
        except ValueError:
            since = 60.0
            max_entries = 50
            only_flagged = False

        cutoff = time.time() - since
        filtered = [
            r for r in self._requests if r.timestamp >= cutoff
        ]
        if only_flagged:
            filtered = [r for r in filtered if r.flagged]

        # Take most recent
        filtered = filtered[-max_entries:]

        entries = [
            {
                "timestamp": r.timestamp,
                "method": r.method,
                "path": r.path,
                "query": r.query_string[:200],
                "status": r.status_code,
                "flagged": r.flagged,
                "flags": r.flag_reasons,
                "source_ip": r.source_ip,
            }
            for r in filtered
        ]

        return ToolOutput(
            tool_name="get_network_logs",
            success=True,
            data={
                "entries": entries,
                "total_in_window": len(filtered),
                "total_flagged": len([e for e in entries if e["flagged"]]),
                "alerts": self._alerts[-20:],
            },
        )

    @tool_schema(
        name="analyze_attack_pattern",
        description=(
            "Analyze recent network traffic to identify attack patterns. "
            "Returns a summary of attack types detected, targeted endpoints, "
            "request rates, and suspicious behavior patterns."
        ),
        parameters=[
            ToolParameter(
                "since_seconds",
                "string",
                "Analysis window in seconds",
                required=False,
            ),
        ],
    )
    @timed
    async def analyze_pattern(self, since_seconds: str = "300") -> ToolOutput:
        """Analyze traffic for attack patterns."""
        try:
            since = float(since_seconds)
        except ValueError:
            since = 300.0

        cutoff = time.time() - since
        recent = [r for r in self._requests if r.timestamp >= cutoff]

        # Analyze
        attack_types: dict[str, int] = defaultdict(int)
        targeted_paths: dict[str, int] = defaultdict(int)
        flagged_count = 0

        for req in recent:
            targeted_paths[req.path] += 1
            if req.flagged:
                flagged_count += 1
                for reason in req.flag_reasons:
                    attack_type = reason.split(":")[0]
                    attack_types[attack_type] += 1

        # Sort by frequency
        top_paths = sorted(
            targeted_paths.items(), key=lambda x: x[1], reverse=True
        )[:10]

        return ToolOutput(
            tool_name="analyze_attack_pattern",
            success=True,
            data={
                "window_seconds": since,
                "total_requests": len(recent),
                "flagged_requests": flagged_count,
                "attack_types": dict(attack_types),
                "top_targeted_paths": [
                    {"path": p, "count": c} for p, c in top_paths
                ],
                "request_rate_per_minute": (
                    round(len(recent) / (since / 60), 1) if since > 0 else 0
                ),
                "assessment": (
                    "HIGH THREAT: Active attack detected"
                    if flagged_count > 10
                    else "MEDIUM THREAT: Suspicious activity"
                    if flagged_count > 0
                    else "LOW THREAT: Normal traffic"
                ),
            },
        )
