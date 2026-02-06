"""Authentication testing tools: login, session analysis, IDOR."""

import json
from typing import Any
from urllib.parse import urljoin

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.tools.http_tool import get_session
from sentinel.logging_config import get_logger

logger = get_logger(__name__)

# Common weak credentials
COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin@juice-sh.op", "admin123"),
    ("admin@admin.com", "admin123"),
    ("user", "user"),
    ("test", "test"),
    ("' OR 1=1--", "anything"),
    ("admin'--", "anything"),
]


@tool_schema(
    name="login_attempt",
    description=(
        "Attempt to log in to the target application. Tries provided credentials "
        "or brute-forces with common weak credentials. Returns whether login succeeded, "
        "any tokens or cookies received, and the response."
    ),
    parameters=[
        ToolParameter("login_url", "string", "URL of the login endpoint (e.g. 'http://localhost:3000/rest/user/login')"),
        ToolParameter("username", "string", "Username or email to try. Use 'BRUTEFORCE' to try common credentials.", required=False),
        ToolParameter("password", "string", "Password to try", required=False),
        ToolParameter(
            "method",
            "string",
            "How credentials are sent",
            required=False,
            enum=["json_body", "form_body", "basic_auth"],
        ),
        ToolParameter(
            "username_field",
            "string",
            "Name of the username/email field in the request body",
            required=False,
        ),
        ToolParameter(
            "password_field",
            "string",
            "Name of the password field in the request body",
            required=False,
        ),
    ],
)
@timed
async def login_attempt(
    login_url: str,
    username: str = "BRUTEFORCE",
    password: str = "",
    method: str = "json_body",
    username_field: str = "email",
    password_field: str = "password",
) -> ToolOutput:
    """Attempt login with provided or common credentials."""
    session = await get_session()

    creds_to_try: list[tuple[str, str]] = []
    if username == "BRUTEFORCE":
        creds_to_try = list(COMMON_CREDENTIALS)
    else:
        creds_to_try = [(username, password)]

    successful_logins: list[dict[str, Any]] = []
    failed_attempts: list[dict[str, Any]] = []

    for user, passwd in creds_to_try:
        try:
            if method == "json_body":
                payload = json.dumps({username_field: user, password_field: passwd})
                async with session.post(
                    login_url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = dict(resp.headers)

            elif method == "form_body":
                async with session.post(
                    login_url,
                    data={username_field: user, password_field: passwd},
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = dict(resp.headers)

            elif method == "basic_auth":
                auth = aiohttp.BasicAuth(user, passwd)
                async with session.post(
                    login_url,
                    auth=auth,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    status = resp.status
                    body = await resp.text()
                    resp_headers = dict(resp.headers)
            else:
                continue

            # Determine if login succeeded
            success = False

            # Check status codes
            if status in (200, 301, 302):
                # Parse response body for tokens
                try:
                    resp_json = json.loads(body)
                    if "token" in resp_json or "authentication" in resp_json:
                        success = True
                except json.JSONDecodeError:
                    pass

                # Check for auth cookies
                if "set-cookie" in {k.lower() for k in resp_headers}:
                    cookie_header = resp_headers.get(
                        "Set-Cookie", resp_headers.get("set-cookie", "")
                    )
                    if any(
                        kw in cookie_header.lower()
                        for kw in ["token", "session", "auth", "jwt"]
                    ):
                        success = True

                # Check for redirect to dashboard/home (common success pattern)
                location = resp_headers.get("Location", "")
                if location and any(
                    p in location for p in ["/dashboard", "/home", "/profile", "/#"]
                ):
                    success = True

            if success:
                # Extract token if present
                token = ""
                try:
                    resp_json = json.loads(body)
                    token = resp_json.get("authentication", {}).get("token", "")
                    if not token:
                        token = resp_json.get("token", "")
                except Exception:
                    pass

                successful_logins.append(
                    {
                        "username": user,
                        "password": passwd,
                        "status": status,
                        "token": token[:100] if token else "",
                        "response_snippet": body[:300],
                    }
                )
                logger.info(
                    "login_success",
                    url=login_url,
                    username=user,
                )
            else:
                failed_attempts.append(
                    {
                        "username": user,
                        "password": passwd,
                        "status": status,
                    }
                )

        except Exception as e:
            failed_attempts.append(
                {
                    "username": user,
                    "password": passwd,
                    "error": str(e),
                }
            )

    return ToolOutput(
        tool_name="login_attempt",
        success=True,
        data={
            "login_url": login_url,
            "credentials_tested": len(creds_to_try),
            "successful_logins": successful_logins,
            "failed_count": len(failed_attempts),
            "summary": (
                f"LOGIN SUCCESS: {len(successful_logins)} valid credential(s) found"
                if successful_logins
                else f"All {len(creds_to_try)} credential combinations failed"
            ),
        },
    )


@tool_schema(
    name="idor_test",
    description=(
        "Test for Insecure Direct Object Reference (IDOR) vulnerabilities. "
        "Accesses resources with sequential or guessable IDs to check if authorization "
        "is properly enforced. Tests whether user A can access user B's data."
    ),
    parameters=[
        ToolParameter("url_pattern", "string", "URL with {ID} placeholder (e.g. 'http://localhost:3000/api/Users/{ID}')"),
        ToolParameter("id_range", "string", "Range of IDs to test (e.g. '1-20')", required=False),
        ToolParameter("auth_header", "string", "Authorization header for the authenticated user", required=False),
        ToolParameter("expected_user_id", "string", "The ID that SHOULD be accessible (to compare with unauthorized access)", required=False),
    ],
)
@timed
async def idor_test(
    url_pattern: str,
    id_range: str = "1-10",
    auth_header: str | None = None,
    expected_user_id: str | None = None,
) -> ToolOutput:
    """Test for IDOR vulnerabilities by accessing sequential resource IDs."""
    session = await get_session()

    # Parse ID range
    try:
        start, end = id_range.split("-")
        ids_to_test = list(range(int(start), int(end) + 1))
    except ValueError:
        ids_to_test = [int(x.strip()) for x in id_range.split(",")]

    headers: dict[str, str] = {}
    if auth_header:
        headers["Authorization"] = auth_header

    accessible: list[dict[str, Any]] = []
    denied: list[int] = []

    for test_id in ids_to_test:
        url = url_pattern.replace("{ID}", str(test_id))
        try:
            async with session.get(
                url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                status = resp.status
                if status == 200:
                    body = await resp.text()
                    try:
                        data = json.loads(body)
                    except json.JSONDecodeError:
                        data = body[:300]

                    accessible.append(
                        {
                            "id": test_id,
                            "status": status,
                            "data_preview": str(data)[:300],
                            "unauthorized": (
                                expected_user_id is not None
                                and str(test_id) != expected_user_id
                            ),
                        }
                    )
                elif status in (401, 403):
                    denied.append(test_id)
                # Ignore other status codes

        except Exception:
            pass

    unauthorized_access = [a for a in accessible if a.get("unauthorized", False)]

    return ToolOutput(
        tool_name="idor_test",
        success=True,
        data={
            "url_pattern": url_pattern,
            "ids_tested": len(ids_to_test),
            "accessible": accessible,
            "denied_count": len(denied),
            "unauthorized_access": unauthorized_access,
            "vulnerable": len(unauthorized_access) > 0 or (
                len(accessible) > 1 and auth_header is None
            ),
            "summary": (
                f"IDOR VULNERABLE: Accessed {len(unauthorized_access)} resources belonging to other users"
                if unauthorized_access
                else f"Accessed {len(accessible)}/{len(ids_to_test)} resources, {len(denied)} denied"
            ),
        },
    )
