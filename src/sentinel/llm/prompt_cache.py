"""
Prompt Cache — Caches static prompt prefixes to reduce tokens and cost.

Claude's prompt caching gives 85% latency reduction and 90% cost savings
on cached prefixes. This module manages cache keys for system prompts,
tool schemas, and other static content.
"""

import hashlib
from dataclasses import dataclass

from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class CachedPrompt:
    cache_key: str
    prefix: str
    token_count: int


class PromptCache:
    """Manage prompt prefix caching for cost optimization."""

    def __init__(self):
        self._cache: dict[str, CachedPrompt] = {}

    def get_or_create(self, prefix: str, label: str = "") -> CachedPrompt:
        """Get cached prompt prefix or create new cache entry."""
        key = hashlib.sha256(prefix.encode()).hexdigest()[:16]

        if key in self._cache:
            return self._cache[key]

        cached = CachedPrompt(
            cache_key=key,
            prefix=prefix,
            token_count=len(prefix) // 4,  # rough estimate
        )
        self._cache[key] = cached
        logger.debug(
            "cached_prompt_prefix",
            label=label,
            est_tokens=cached.token_count,
        )
        return cached

    def build_messages(
        self, cached_prefix: CachedPrompt, user_content: str
    ) -> list[dict]:
        """Build messages array with cached system prompt for Anthropic API."""
        return [
            {
                "role": "system",
                "content": [
                    {
                        "type": "text",
                        "text": cached_prefix.prefix,
                        "cache_control": {"type": "ephemeral"},
                    }
                ],
            },
            {"role": "user", "content": user_content},
        ]

    def invalidate(self, prefix: str) -> bool:
        """Remove a cached prefix."""
        key = hashlib.sha256(prefix.encode()).hexdigest()[:16]
        if key in self._cache:
            del self._cache[key]
            return True
        return False

    def clear(self):
        """Clear all cached prefixes."""
        self._cache.clear()

    def stats(self) -> dict:
        return {
            "cached_prefixes": len(self._cache),
            "total_cached_tokens": sum(
                c.token_count for c in self._cache.values()
            ),
        }
