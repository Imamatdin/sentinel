"""Juice Shop specific utilities: challenge tracking, score monitoring."""

import asyncio
import json
from typing import Any

import aiohttp
import structlog

from sentinel.core.tools import ToolParameter, tool_schema
from sentinel.tools.base import ToolOutput, timed
from sentinel.tools.http_tool import get_session
from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@tool_schema(
    name="check_challenges",
    description=(
        "Check the status of OWASP Juice Shop challenges. Returns which challenges "
        "have been solved during the pentest, providing a concrete score metric. "
        "Use periodically to track progress."
    ),
    parameters=[
        ToolParameter("base_url", "string", "Juice Shop base URL (e.g. 'http://localhost:3000')"),
    ],
)
@timed
async def check_challenges(base_url: str) -> ToolOutput:
    """Query Juice Shop challenge API for solved challenges."""
    session = await get_session()
    url = base_url.rstrip("/") + "/api/Challenges/"

    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status != 200:
                return ToolOutput(
                    tool_name="check_challenges",
                    success=False,
                    data={},
                    error=f"Challenge API returned status {resp.status}",
                )

            body = await resp.text()
            data = json.loads(body)
            challenges = data.get("data", [])

            solved = [
                {
                    "name": c.get("name", ""),
                    "category": c.get("category", ""),
                    "difficulty": c.get("difficulty", 0),
                    "description": c.get("description", "")[:100],
                }
                for c in challenges
                if c.get("solved", False)
            ]

            unsolved = [
                {
                    "name": c.get("name", ""),
                    "category": c.get("category", ""),
                    "difficulty": c.get("difficulty", 0),
                    "description": c.get("description", "")[:100],
                }
                for c in challenges
                if not c.get("solved", False)
            ]

            # Group by category
            categories: dict[str, int] = {}
            for c in challenges:
                cat = c.get("category", "Unknown")
                if cat not in categories:
                    categories[cat] = 0
                if c.get("solved"):
                    categories[cat] += 1

            return ToolOutput(
                tool_name="check_challenges",
                success=True,
                data={
                    "total_challenges": len(challenges),
                    "solved_count": len(solved),
                    "unsolved_count": len(unsolved),
                    "solved": solved[:20],  # Limit for LLM context
                    "unsolved_easy": [
                        u for u in unsolved if u["difficulty"] <= 2
                    ][:15],
                    "categories": categories,
                    "score_percentage": (
                        round(len(solved) / len(challenges) * 100, 1)
                        if challenges
                        else 0
                    ),
                },
            )

    except Exception as e:
        return ToolOutput(
            tool_name="check_challenges",
            success=False,
            data={},
            error=f"Failed to check challenges: {e}",
        )


async def wait_for_juice_shop(base_url: str, timeout: int = 60) -> bool:
    """Wait for Juice Shop to be ready. Returns True if ready."""
    session = await get_session()
    for _ in range(timeout // 2):
        try:
            async with session.get(
                base_url, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    logger.info("juice_shop_ready", url=base_url)
                    return True
        except Exception:
            pass
        await asyncio.sleep(2)
    logger.error("juice_shop_timeout", url=base_url, timeout=timeout)
    return False
