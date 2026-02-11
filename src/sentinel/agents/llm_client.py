"""LLM client abstraction for Sentinel.

Supports multiple providers with unified interface:
- Anthropic Claude (primary - best reasoning)
- Cerebras (speed demos)
- OpenAI (embeddings)
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar
import json

from pydantic import BaseModel, ValidationError
import anthropic
import httpx

from sentinel.core import get_settings, get_logger, SentinelError

logger = get_logger(__name__)
T = TypeVar("T", bound=BaseModel)


class LLMProvider(str, Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    CEREBRAS = "cerebras"
    OPENAI = "openai"


class LLMError(SentinelError):
    """LLM-related errors."""
    pass


@dataclass
class LLMMessage:
    """A message in the conversation."""
    role: str  # "user", "assistant", "system"
    content: str


@dataclass
class LLMResponse:
    """Response from LLM."""
    content: str
    model: str
    provider: LLMProvider
    usage: dict[str, int] = field(default_factory=dict)
    latency_ms: float = 0.0
    raw_response: Any = None


@dataclass
class ToolCall:
    """A tool call requested by the LLM."""
    tool_name: str
    tool_input: dict[str, Any]
    tool_id: str


@dataclass
class ToolResult:
    """Result of a tool execution."""
    tool_id: str
    result: str
    is_error: bool = False


class BaseLLMClient(ABC):
    """Abstract base for LLM clients."""

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Generate a completion."""
        pass

    @abstractmethod
    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> tuple[LLMResponse, list[ToolCall]]:
        """Generate a completion with tool use."""
        pass

    async def complete_structured(
        self,
        messages: list[LLMMessage],
        output_schema: type[T],
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> T:
        """Generate a completion that conforms to a Pydantic schema."""
        schema_json = json.dumps(output_schema.model_json_schema(), indent=2)

        enhanced_system = f"""{system or ''}

You must respond with valid JSON that conforms to this schema:
{schema_json}

Respond ONLY with the JSON object, no other text or markdown."""

        response = await self.complete(
            messages=messages,
            system=enhanced_system.strip(),
            max_tokens=max_tokens,
            temperature=0.0,
        )

        # Parse and validate
        try:
            # Clean potential markdown
            content = response.content.strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
                content = content.strip()

            data = json.loads(content)
            return output_schema.model_validate(data)
        except json.JSONDecodeError as e:
            raise LLMError(f"Invalid JSON response: {e}")
        except ValidationError as e:
            raise LLMError(f"Response doesn't match schema: {e}")


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude client."""

    def __init__(self, model: str = "claude-sonnet-4-20250514"):
        settings = get_settings()
        self.client = anthropic.AsyncAnthropic(
            api_key=settings.anthropic_api_key.get_secret_value()
        )
        self.model = model
        self.provider = LLMProvider.ANTHROPIC

    async def complete(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        start = datetime.now()

        api_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
        ]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": api_messages,
        }
        if system:
            kwargs["system"] = system

        response = await self.client.messages.create(**kwargs)

        latency = (datetime.now() - start).total_seconds() * 1000

        return LLMResponse(
            content=response.content[0].text,
            model=self.model,
            provider=self.provider,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
            latency_ms=latency,
            raw_response=response,
        )

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> tuple[LLMResponse, list[ToolCall]]:
        start = datetime.now()

        api_messages = [
            {"role": m.role, "content": m.content}
            for m in messages
        ]

        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": api_messages,
            "tools": tools,
        }
        if system:
            kwargs["system"] = system

        response = await self.client.messages.create(**kwargs)

        latency = (datetime.now() - start).total_seconds() * 1000

        # Extract tool calls
        tool_calls = []
        text_content = ""

        for block in response.content:
            if block.type == "text":
                text_content += block.text
            elif block.type == "tool_use":
                tool_calls.append(ToolCall(
                    tool_name=block.name,
                    tool_input=block.input,
                    tool_id=block.id,
                ))

        llm_response = LLMResponse(
            content=text_content,
            model=self.model,
            provider=self.provider,
            usage={
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            },
            latency_ms=latency,
            raw_response=response,
        )

        return llm_response, tool_calls


class CerebrasClient(BaseLLMClient):
    """Cerebras client for high-speed inference."""

    def __init__(self, model: str = "llama-3.3-70b"):
        settings = get_settings()
        self.api_key = settings.cerebras_api_key.get_secret_value()
        self.model = model
        self.provider = LLMProvider.CEREBRAS
        self.base_url = "https://api.cerebras.ai/v1"

    async def complete(
        self,
        messages: list[LLMMessage],
        system: str | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        start = datetime.now()

        api_messages: list[dict[str, str]] = []
        if system:
            api_messages.append({"role": "system", "content": system})
        api_messages.extend([
            {"role": m.role, "content": m.content}
            for m in messages
        ])

        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": api_messages,
                    "max_tokens": max_tokens,
                    "temperature": temperature,
                },
                timeout=60.0,
            )
            response.raise_for_status()
            data = response.json()

        latency = (datetime.now() - start).total_seconds() * 1000

        return LLMResponse(
            content=data["choices"][0]["message"]["content"],
            model=self.model,
            provider=self.provider,
            usage=data.get("usage", {}),
            latency_ms=latency,
            raw_response=data,
        )

    async def complete_with_tools(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int = 4096,
    ) -> tuple[LLMResponse, list[ToolCall]]:
        # Cerebras tool use via function calling
        # For now, fall back to structured prompting
        raise NotImplementedError("Cerebras tool use not yet implemented")


# === Factory ===

def get_llm_client(
    provider: LLMProvider = LLMProvider.ANTHROPIC,
    model: str | None = None,
) -> BaseLLMClient:
    """Get an LLM client for the specified provider."""
    if provider == LLMProvider.ANTHROPIC:
        return AnthropicClient(model=model or "claude-sonnet-4-20250514")
    elif provider == LLMProvider.CEREBRAS:
        return CerebrasClient(model=model or "llama-3.3-70b")
    else:
        raise ValueError(f"Unsupported provider: {provider}")
