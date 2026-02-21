"""Tests for prompt cache."""

import pytest
from sentinel.llm.prompt_cache import PromptCache, CachedPrompt


class TestPromptCache:
    def setup_method(self):
        self.cache = PromptCache()

    def test_get_or_create_returns_cached_prompt(self):
        result = self.cache.get_or_create("You are a security expert.", "system")
        assert isinstance(result, CachedPrompt)
        assert result.prefix == "You are a security expert."
        assert len(result.cache_key) == 16

    def test_same_prefix_returns_same_cache_key(self):
        r1 = self.cache.get_or_create("Same prefix")
        r2 = self.cache.get_or_create("Same prefix")
        assert r1.cache_key == r2.cache_key

    def test_different_prefix_returns_different_key(self):
        r1 = self.cache.get_or_create("Prefix A")
        r2 = self.cache.get_or_create("Prefix B")
        assert r1.cache_key != r2.cache_key

    def test_token_count_estimate(self):
        text = "a" * 400  # ~100 tokens at 4 chars/token
        result = self.cache.get_or_create(text)
        assert result.token_count == 100

    def test_build_messages_structure(self):
        cached = self.cache.get_or_create("System prompt here")
        messages = self.cache.build_messages(cached, "What vulns exist?")
        assert len(messages) == 2
        assert messages[0]["role"] == "system"
        assert messages[1]["role"] == "user"
        assert messages[1]["content"] == "What vulns exist?"

    def test_build_messages_has_cache_control(self):
        cached = self.cache.get_or_create("System prompt here")
        messages = self.cache.build_messages(cached, "user input")
        system_content = messages[0]["content"]
        assert isinstance(system_content, list)
        assert system_content[0]["type"] == "text"
        assert system_content[0]["cache_control"] == {"type": "ephemeral"}

    def test_stats_empty(self):
        stats = self.cache.stats()
        assert stats["cached_prefixes"] == 0
        assert stats["total_cached_tokens"] == 0

    def test_stats_after_caching(self):
        self.cache.get_or_create("a" * 100)
        self.cache.get_or_create("b" * 200)
        stats = self.cache.stats()
        assert stats["cached_prefixes"] == 2
        assert stats["total_cached_tokens"] == 75  # 25 + 50

    def test_invalidate_existing(self):
        self.cache.get_or_create("to remove")
        assert self.cache.stats()["cached_prefixes"] == 1
        removed = self.cache.invalidate("to remove")
        assert removed is True
        assert self.cache.stats()["cached_prefixes"] == 0

    def test_invalidate_nonexistent(self):
        removed = self.cache.invalidate("never cached")
        assert removed is False

    def test_clear(self):
        self.cache.get_or_create("one")
        self.cache.get_or_create("two")
        self.cache.clear()
        assert self.cache.stats()["cached_prefixes"] == 0

    def test_deduplication(self):
        """Caching same prefix twice doesn't create duplicate."""
        self.cache.get_or_create("duplicate")
        self.cache.get_or_create("duplicate")
        assert self.cache.stats()["cached_prefixes"] == 1
