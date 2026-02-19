# LLM CLIENTS — Multi-Provider Implementation

## Context

Append this to the end of PHASE_7.md. The `get_llm_client()` factory in `src/sentinel/llm/client.py` (Phase 7) returns provider-specific clients, but those clients don't exist yet. This spec defines them.

## What This Builds

1. **CerebrasClient** — Speed-optimized client (1000-1700 tok/s) for real-time blue team defense and rapid hypothesis generation
2. **ClaudeClient** — Reasoning-optimized client for exploit chain planning, report generation, code analysis
3. **OpenAIClient** — Fallback + embedding generation for pgvector (Phase 8)
4. **BaseLLMClient** — Abstract base class all clients extend
5. **Retry + fallback logic** — Automatic retry with exponential backoff, provider fallback on failure

## Provider Strategy Recap

- **Cerebras** (zai-glm-4.7): Speed. Blue team real-time defense, rapid hypothesis generation, adversarial loop.
- **Claude** (claude-sonnet-4-5-20250929): Reasoning. Complex exploit chain planning, vulnerability analysis, report writing.
- **OpenAI** (gpt-4o): Fallback for general tasks. text-embedding-3-small for pgvector embeddings.

---

## File-by-File Implementation

### 1. `src/sentinel/llm/__init__.py`

```python
"""Multi-provider LLM client layer."""
```

### 2. `src/sentinel/llm/base.py`

```python
"""
BaseLLMClient — Abstract interface all LLM providers implement.

Every client must support:
- complete(): Single-turn completion with system prompt
- complete_structured(): Completion with JSON schema enforcement
- stream(): Streaming completion (yields chunks)
- embed(): Text embedding (only OpenAI implements this by default)
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional


@dataclass
class LLMResponse:
    content: str
    model: str
    provider: str
    usage: dict = field(default_factory=dict)  # {"input_tokens": N, "output_tokens": N}
    latency_ms: float = 0.0
    raw_response: Optional[dict] = None


@dataclass
class LLMConfig:
    api_key: str
    model: str
    base_url: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.1  # Low temp for security analysis
    timeout_seconds: int = 60
    max_retries: int = 3
    retry_delay_seconds: float = 1.0


class BaseLLMClient(ABC):
    """Abstract base for all LLM providers."""
    
    provider_name: str = "base"
    
    def __init__(self, config: LLMConfig):
        self.config = config
    
    @abstractmethod
    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Single-turn completion."""
        ...
    
    @abstractmethod
    async def complete_structured(
        self,
        prompt: str,
        system_prompt: str = "",
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        """Completion expecting structured JSON output."""
        ...
    
    @abstractmethod
    async def stream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        """Streaming completion — yields text chunks."""
        ...
    
    async def embed(self, text: str) -> list[float]:
        """Generate embedding vector. Override in providers that support it."""
        raise NotImplementedError(f"{self.provider_name} does not support embeddings")
    
    async def _retry_with_backoff(self, func, *args, **kwargs):
        """Retry with exponential backoff."""
        import asyncio
        last_error = None
        
        for attempt in range(self.config.max_retries):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    delay = self.config.retry_delay_seconds * (2 ** attempt)
                    await asyncio.sleep(delay)
        
        raise last_error
```

### 3. `src/sentinel/llm/cerebras_client.py`

```python
"""
CerebrasClient — Speed-optimized LLM client.

Cerebras provides 1000-1700 tokens/second inference.
Used for: real-time blue team defense, rapid hypothesis generation, adversarial loop.

API: OpenAI-compatible endpoint at https://api.cerebras.ai/v1
Model: zai-glm-4.7 (or as configured)
"""
import time
import aiohttp
from typing import AsyncIterator, Optional

from sentinel.llm.base import BaseLLMClient, LLMConfig, LLMResponse
from sentinel.logging import get_logger

logger = get_logger(__name__)


class CerebrasClient(BaseLLMClient):
    provider_name = "cerebras"
    
    def __init__(self, api_key: str, model: str = "zai-glm-4.7", **kwargs):
        config = LLMConfig(
            api_key=api_key,
            model=model,
            base_url="https://api.cerebras.ai/v1",
            temperature=0.1,
            timeout_seconds=30,  # Cerebras is fast, shorter timeout
            **kwargs,
        )
        super().__init__(config)
    
    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        """Single-turn completion via Cerebras API (OpenAI-compatible)."""
        return await self._retry_with_backoff(
            self._do_complete, prompt, system_prompt, temperature, max_tokens
        )
    
    async def _do_complete(
        self, prompt: str, system_prompt: str, temperature: Optional[float], max_tokens: Optional[int]
    ) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        
        start = time.monotonic()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                data = await resp.json()
                
                if resp.status != 200:
                    raise Exception(f"Cerebras API error {resp.status}: {data}")
                
                latency = (time.monotonic() - start) * 1000
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                
                logger.debug(f"Cerebras completion: {usage.get('total_tokens', 0)} tokens in {latency:.0f}ms")
                
                return LLMResponse(
                    content=content,
                    model=self.config.model,
                    provider=self.provider_name,
                    usage={
                        "input_tokens": usage.get("prompt_tokens", 0),
                        "output_tokens": usage.get("completion_tokens", 0),
                    },
                    latency_ms=latency,
                    raw_response=data,
                )
    
    async def complete_structured(
        self,
        prompt: str,
        system_prompt: str = "",
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        """Structured completion — append JSON instruction to prompt."""
        structured_prompt = prompt
        if response_format:
            structured_prompt += "\n\nRespond ONLY with valid JSON matching this schema. No other text.\n"
            structured_prompt += f"Schema: {response_format}"
        
        if not system_prompt:
            system_prompt = "You are a security analysis assistant. Always respond with valid JSON."
        
        return await self.complete(structured_prompt, system_prompt)
    
    async def stream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        """Streaming completion via SSE."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                async for line in resp.content:
                    line = line.decode().strip()
                    if line.startswith("data: ") and line != "data: [DONE]":
                        import json
                        try:
                            chunk = json.loads(line[6:])
                            delta = chunk["choices"][0].get("delta", {}).get("content", "")
                            if delta:
                                yield delta
                        except (json.JSONDecodeError, KeyError, IndexError):
                            pass
```

### 4. `src/sentinel/llm/claude_client.py`

```python
"""
ClaudeClient — Reasoning-optimized LLM client.

Used for: complex exploit chain planning, vulnerability analysis, report generation, code analysis.
These tasks benefit from Claude's strong reasoning and long context.

API: Anthropic Messages API at https://api.anthropic.com/v1
Model: claude-sonnet-4-5-20250929 (or as configured)
"""
import time
import aiohttp
from typing import AsyncIterator, Optional

from sentinel.llm.base import BaseLLMClient, LLMConfig, LLMResponse
from sentinel.logging import get_logger

logger = get_logger(__name__)


class ClaudeClient(BaseLLMClient):
    provider_name = "claude"
    
    def __init__(self, api_key: str, model: str = "claude-sonnet-4-5-20250929", **kwargs):
        config = LLMConfig(
            api_key=api_key,
            model=model,
            base_url="https://api.anthropic.com/v1",
            temperature=0.1,
            timeout_seconds=120,  # Claude reasoning can take longer
            max_tokens=8192,
            **kwargs,
        )
        super().__init__(config)
    
    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        return await self._retry_with_backoff(
            self._do_complete, prompt, system_prompt, temperature, max_tokens
        )
    
    async def _do_complete(
        self, prompt: str, system_prompt: str, temperature: Optional[float], max_tokens: Optional[int]
    ) -> LLMResponse:
        payload = {
            "model": self.config.model,
            "max_tokens": max_tokens or self.config.max_tokens,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        
        if system_prompt:
            payload["system"] = system_prompt
        
        start = time.monotonic()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/messages",
                json=payload,
                headers={
                    "x-api-key": self.config.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                data = await resp.json()
                
                if resp.status != 200:
                    error_msg = data.get("error", {}).get("message", str(data))
                    raise Exception(f"Claude API error {resp.status}: {error_msg}")
                
                latency = (time.monotonic() - start) * 1000
                
                # Extract text from content blocks
                content = ""
                for block in data.get("content", []):
                    if block.get("type") == "text":
                        content += block.get("text", "")
                
                usage = data.get("usage", {})
                
                logger.debug(f"Claude completion: {usage.get('input_tokens', 0)}+{usage.get('output_tokens', 0)} tokens in {latency:.0f}ms")
                
                return LLMResponse(
                    content=content,
                    model=self.config.model,
                    provider=self.provider_name,
                    usage={
                        "input_tokens": usage.get("input_tokens", 0),
                        "output_tokens": usage.get("output_tokens", 0),
                    },
                    latency_ms=latency,
                    raw_response=data,
                )
    
    async def complete_structured(
        self,
        prompt: str,
        system_prompt: str = "",
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        structured_system = system_prompt or "You are a security analysis assistant."
        structured_system += "\n\nAlways respond with valid JSON. No markdown, no backticks, just raw JSON."
        
        structured_prompt = prompt
        if response_format:
            structured_prompt += f"\n\nJSON schema to follow: {response_format}"
        
        return await self.complete(structured_prompt, structured_system)
    
    async def stream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        """Streaming via Anthropic SSE."""
        payload = {
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
        }
        if system_prompt:
            payload["system"] = system_prompt
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/messages",
                json=payload,
                headers={
                    "x-api-key": self.config.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                async for line in resp.content:
                    line = line.decode().strip()
                    if line.startswith("data: "):
                        import json
                        try:
                            event = json.loads(line[6:])
                            if event.get("type") == "content_block_delta":
                                delta = event.get("delta", {}).get("text", "")
                                if delta:
                                    yield delta
                        except (json.JSONDecodeError, KeyError):
                            pass
```

### 5. `src/sentinel/llm/openai_client.py`

```python
"""
OpenAIClient — Fallback + Embedding provider.

Used for:
- General fallback when Cerebras/Claude are unavailable
- text-embedding-3-small for pgvector embeddings (Phase 8 RAG)

API: OpenAI Chat Completions + Embeddings
Model: gpt-4o (completions), text-embedding-3-small (embeddings)
"""
import time
import aiohttp
from typing import AsyncIterator, Optional

from sentinel.llm.base import BaseLLMClient, LLMConfig, LLMResponse
from sentinel.logging import get_logger

logger = get_logger(__name__)


class OpenAIClient(BaseLLMClient):
    provider_name = "openai"
    
    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        embedding_model: str = "text-embedding-3-small",
        **kwargs,
    ):
        config = LLMConfig(
            api_key=api_key,
            model=model,
            base_url="https://api.openai.com/v1",
            temperature=0.1,
            timeout_seconds=60,
            **kwargs,
        )
        super().__init__(config)
        self.embedding_model = embedding_model
    
    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        return await self._retry_with_backoff(
            self._do_complete, prompt, system_prompt, temperature, max_tokens
        )
    
    async def _do_complete(
        self, prompt: str, system_prompt: str, temperature: Optional[float], max_tokens: Optional[int]
    ) -> LLMResponse:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.config.temperature,
            "max_tokens": max_tokens or self.config.max_tokens,
        }
        
        start = time.monotonic()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                data = await resp.json()
                
                if resp.status != 200:
                    raise Exception(f"OpenAI API error {resp.status}: {data}")
                
                latency = (time.monotonic() - start) * 1000
                content = data["choices"][0]["message"]["content"]
                usage = data.get("usage", {})
                
                return LLMResponse(
                    content=content,
                    model=self.config.model,
                    provider=self.provider_name,
                    usage={
                        "input_tokens": usage.get("prompt_tokens", 0),
                        "output_tokens": usage.get("completion_tokens", 0),
                    },
                    latency_ms=latency,
                    raw_response=data,
                )
    
    async def complete_structured(
        self,
        prompt: str,
        system_prompt: str = "",
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        """OpenAI supports response_format natively."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }
        
        if response_format:
            payload["response_format"] = {"type": "json_object"}
        
        start = time.monotonic()
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                data = await resp.json()
                latency = (time.monotonic() - start) * 1000
                content = data["choices"][0]["message"]["content"]
                
                return LLMResponse(
                    content=content,
                    model=self.config.model,
                    provider=self.provider_name,
                    latency_ms=latency,
                    raw_response=data,
                )
    
    async def stream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "stream": True,
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/chat/completions",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
            ) as resp:
                async for line in resp.content:
                    line = line.decode().strip()
                    if line.startswith("data: ") and line != "data: [DONE]":
                        import json
                        try:
                            chunk = json.loads(line[6:])
                            delta = chunk["choices"][0].get("delta", {}).get("content", "")
                            if delta:
                                yield delta
                        except (json.JSONDecodeError, KeyError, IndexError):
                            pass
    
    async def embed(self, text: str) -> list[float]:
        """Generate embedding using text-embedding-3-small (1536 dimensions)."""
        return await self._retry_with_backoff(self._do_embed, text)
    
    async def _do_embed(self, text: str) -> list[float]:
        payload = {
            "model": self.embedding_model,
            "input": text,
            "encoding_format": "float",
        }
        
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.config.base_url}/embeddings",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.config.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                data = await resp.json()
                
                if resp.status != 200:
                    raise Exception(f"OpenAI Embedding error {resp.status}: {data}")
                
                embedding = data["data"][0]["embedding"]
                logger.debug(f"Generated embedding: {len(embedding)} dimensions")
                return embedding
```

### 6. `src/sentinel/llm/fallback.py`

```python
"""
FallbackLLMClient — Wraps multiple providers with automatic fallback.

If primary provider fails, falls back to secondary, then tertiary.
Order: configured primary → Claude → OpenAI
"""
from typing import AsyncIterator, Optional

from sentinel.llm.base import BaseLLMClient, LLMConfig, LLMResponse
from sentinel.logging import get_logger

logger = get_logger(__name__)


class FallbackLLMClient(BaseLLMClient):
    """
    Tries providers in order until one succeeds.
    
    Usage:
        client = FallbackLLMClient([cerebras_client, claude_client, openai_client])
        response = await client.complete("prompt")  # Tries cerebras → claude → openai
    """
    
    provider_name = "fallback"
    
    def __init__(self, clients: list[BaseLLMClient]):
        self.clients = clients
        # Use first client's config as default
        super().__init__(clients[0].config if clients else LLMConfig(api_key="", model=""))
    
    async def complete(
        self,
        prompt: str,
        system_prompt: str = "",
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> LLMResponse:
        last_error = None
        for client in self.clients:
            try:
                response = await client.complete(prompt, system_prompt, temperature, max_tokens)
                return response
            except Exception as e:
                logger.warning(f"Provider {client.provider_name} failed: {e}, trying next")
                last_error = e
        
        raise Exception(f"All LLM providers failed. Last error: {last_error}")
    
    async def complete_structured(
        self,
        prompt: str,
        system_prompt: str = "",
        response_format: Optional[dict] = None,
    ) -> LLMResponse:
        last_error = None
        for client in self.clients:
            try:
                return await client.complete_structured(prompt, system_prompt, response_format)
            except Exception as e:
                logger.warning(f"Provider {client.provider_name} structured failed: {e}")
                last_error = e
        raise Exception(f"All providers failed for structured completion: {last_error}")
    
    async def stream(
        self,
        prompt: str,
        system_prompt: str = "",
    ) -> AsyncIterator[str]:
        for client in self.clients:
            try:
                async for chunk in client.stream(prompt, system_prompt):
                    yield chunk
                return
            except Exception as e:
                logger.warning(f"Provider {client.provider_name} stream failed: {e}")
        raise Exception("All LLM providers failed for streaming")
    
    async def embed(self, text: str) -> list[float]:
        """Only try providers that support embeddings."""
        for client in self.clients:
            try:
                return await client.embed(text)
            except NotImplementedError:
                continue
            except Exception as e:
                logger.warning(f"Provider {client.provider_name} embed failed: {e}")
        raise Exception("No LLM provider available for embeddings")
```

### Updated `src/sentinel/llm/client.py` (replaces Phase 7 version)

```python
"""
Multi-LLM client factory.

Returns the appropriate LLM client based on configuration and task type.
Supports: Cerebras (speed), Claude (reasoning), OpenAI (fallback/embeddings).
"""
from sentinel.config import get_config
from sentinel.llm.base import BaseLLMClient
from sentinel.logging import get_logger

logger = get_logger(__name__)

# Cache initialized clients
_clients: dict[str, BaseLLMClient] = {}


def get_llm_client(provider: str = None, task_type: str = "general") -> BaseLLMClient:
    """
    Get LLM client for a specific task.
    
    Task types and default providers:
    - "speed": Cerebras (real-time defense, rapid hypothesis generation)
    - "reasoning": Claude (exploit chain planning, report generation)
    - "embedding": OpenAI (pgvector embeddings)
    - "general": Use configured default
    - "fallback": Returns FallbackLLMClient with all available providers
    """
    config = get_config()
    
    if provider is None:
        provider_map = {
            "speed": "cerebras",
            "reasoning": "claude",
            "embedding": "openai",
            "general": config.get("default_llm_provider", "cerebras"),
            "fallback": "fallback",
        }
        provider = provider_map.get(task_type, "cerebras")
    
    # Return cached client if available
    if provider in _clients:
        return _clients[provider]
    
    if provider == "cerebras":
        from sentinel.llm.cerebras_client import CerebrasClient
        client = CerebrasClient(
            api_key=config.get("cerebras_api_key", ""),
            model=config.get("cerebras_model", "zai-glm-4.7"),
        )
    elif provider == "claude":
        from sentinel.llm.claude_client import ClaudeClient
        client = ClaudeClient(
            api_key=config.get("anthropic_api_key", ""),
            model=config.get("claude_model", "claude-sonnet-4-5-20250929"),
        )
    elif provider == "openai":
        from sentinel.llm.openai_client import OpenAIClient
        client = OpenAIClient(
            api_key=config.get("openai_api_key", ""),
            model=config.get("openai_model", "gpt-4o"),
            embedding_model=config.get("openai_embedding_model", "text-embedding-3-small"),
        )
    elif provider == "fallback":
        from sentinel.llm.fallback import FallbackLLMClient
        clients = []
        for p in ["cerebras", "claude", "openai"]:
            try:
                clients.append(get_llm_client(provider=p))
            except Exception:
                pass
        if not clients:
            raise ValueError("No LLM providers available")
        client = FallbackLLMClient(clients)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
    
    _clients[provider] = client
    return client


def clear_client_cache():
    """Clear cached clients (useful for testing)."""
    _clients.clear()
```

---

## Tests

### `tests/llm/test_base.py`

```python
import pytest
from sentinel.llm.base import LLMResponse, LLMConfig

class TestLLMResponse:
    def test_creation(self):
        resp = LLMResponse(content="test", model="gpt-4o", provider="openai")
        assert resp.content == "test"
        assert resp.usage == {}
    
    def test_config_defaults(self):
        config = LLMConfig(api_key="test", model="test-model")
        assert config.temperature == 0.1
        assert config.max_retries == 3
```

### `tests/llm/test_client_factory.py`

```python
import pytest
from unittest.mock import patch
from sentinel.llm.client import get_llm_client, clear_client_cache

class TestClientFactory:
    def setup_method(self):
        clear_client_cache()
    
    @patch("sentinel.llm.client.get_config")
    def test_speed_returns_cerebras(self, mock_config):
        mock_config.return_value = {"cerebras_api_key": "test"}
        client = get_llm_client(task_type="speed")
        assert client.provider_name == "cerebras"
    
    @patch("sentinel.llm.client.get_config")
    def test_reasoning_returns_claude(self, mock_config):
        mock_config.return_value = {"anthropic_api_key": "test"}
        client = get_llm_client(task_type="reasoning")
        assert client.provider_name == "claude"
    
    @patch("sentinel.llm.client.get_config")
    def test_embedding_returns_openai(self, mock_config):
        mock_config.return_value = {"openai_api_key": "test"}
        client = get_llm_client(task_type="embedding")
        assert client.provider_name == "openai"
    
    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError):
            get_llm_client(provider="nonexistent")
```

### `tests/llm/test_fallback.py`

```python
import pytest
from unittest.mock import AsyncMock
from sentinel.llm.fallback import FallbackLLMClient
from sentinel.llm.base import LLMResponse, LLMConfig

class TestFallbackClient:
    @pytest.mark.asyncio
    async def test_uses_first_available(self):
        client1 = AsyncMock()
        client1.provider_name = "primary"
        client1.config = LLMConfig(api_key="", model="")
        client1.complete = AsyncMock(return_value=LLMResponse(
            content="from primary", model="m", provider="primary"
        ))
        
        client2 = AsyncMock()
        client2.provider_name = "secondary"
        
        fallback = FallbackLLMClient([client1, client2])
        result = await fallback.complete("test")
        assert result.content == "from primary"
        client2.complete.assert_not_called()
    
    @pytest.mark.asyncio
    async def test_falls_back_on_error(self):
        client1 = AsyncMock()
        client1.provider_name = "primary"
        client1.config = LLMConfig(api_key="", model="")
        client1.complete = AsyncMock(side_effect=Exception("primary down"))
        
        client2 = AsyncMock()
        client2.provider_name = "secondary"
        client2.complete = AsyncMock(return_value=LLMResponse(
            content="from secondary", model="m", provider="secondary"
        ))
        
        fallback = FallbackLLMClient([client1, client2])
        result = await fallback.complete("test")
        assert result.content == "from secondary"
```

---

## Environment Variables Required

```bash
# .env
CEREBRAS_API_KEY=csk-...          # Cerebras API key
ANTHROPIC_API_KEY=sk-ant-...      # Anthropic API key
OPENAI_API_KEY=sk-...             # OpenAI API key
DEFAULT_LLM_PROVIDER=cerebras     # Default provider for general tasks
CEREBRAS_MODEL=zai-glm-4.7       # Cerebras model name
CLAUDE_MODEL=claude-sonnet-4-5-20250929  # Claude model name
OPENAI_MODEL=gpt-4o              # OpenAI model name
OPENAI_EMBEDDING_MODEL=text-embedding-3-small  # Embedding model
```

## Acceptance Criteria

- [ ] CerebrasClient completes successfully against Cerebras API
- [ ] ClaudeClient completes successfully against Anthropic API
- [ ] OpenAIClient completes and generates embeddings successfully
- [ ] FallbackLLMClient tries providers in order, falls back on failure
- [ ] `get_llm_client()` returns correct provider for each task type
- [ ] Streaming works for all three providers
- [ ] Retry with exponential backoff on transient failures
- [ ] Client caching prevents redundant initialization
- [ ] All tests pass