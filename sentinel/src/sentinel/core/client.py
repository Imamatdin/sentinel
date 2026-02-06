"""Cerebras LLM client with tool calling support."""

import asyncio
import json
from typing import Any, AsyncIterator, Literal, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime

from openai import AsyncOpenAI
from openai.types.chat import ChatCompletion
from openai.types.chat.chat_completion_message_param import ChatCompletionMessageParam
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
)

from sentinel.logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class ChatMessage:
    """Message in a conversation."""

    role: Literal["system", "user", "assistant", "tool"]
    content: str
    tool_calls: Optional[list["ToolCall"]] = None
    tool_call_id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class ToolCall:
    """Tool call from the model."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """Result from tool execution."""

    tool_call_id: str
    tool_name: str
    result: str
    error: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class CompletionMetrics:
    """Metrics for a completion request."""

    ttft: Optional[float] = None  # Time to first token (streaming only)
    total_time: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""


class CerebrasClient:
    """Client for Cerebras LLM API with tool calling support.

    Uses the OpenAI Python SDK since Cerebras is OpenAI-API-compatible.
    Supports single completions, streaming, and multi-turn ReAct tool loops.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.cerebras.ai/v1",
        model: str = "zai-glm-4.7",
        temperature: float = 0.7,
        max_tokens: int = 4096,
        tool_call_timeout: int = 30,
        max_tool_iterations: int = 10,
    ):
        """Initialize Cerebras client.

        Args:
            api_key: Cerebras API key (must start with 'csk-')
            base_url: API base URL
            model: Model identifier
            temperature: Sampling temperature
            max_tokens: Max tokens in response
            tool_call_timeout: Timeout per tool execution in seconds
            max_tool_iterations: Max ReAct loop iterations
        """
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.tool_call_timeout = tool_call_timeout
        self.max_tool_iterations = max_tool_iterations

        self.client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
        )

        logger.info(
            "cerebras_client_initialized",
            model=self.model,
            base_url=base_url,
        )

    @classmethod
    def from_settings(cls, settings: Any) -> "CerebrasClient":
        """Create client from a Settings instance.

        Usage:
            from sentinel.config import get_settings
            client = CerebrasClient.from_settings(get_settings())
        """
        return cls(
            api_key=settings.cerebras_api_key,
            base_url=settings.cerebras_base_url,
            model=settings.primary_model,
            temperature=settings.default_temperature,
            max_tokens=settings.default_max_tokens,
            tool_call_timeout=settings.tool_call_timeout,
            max_tool_iterations=settings.max_tool_iterations,
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((Exception,)),
        reraise=True,
    )
    async def chat(
        self,
        messages: list[ChatMessage],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        model: Optional[str] = None,
    ) -> tuple[ChatMessage, CompletionMetrics]:
        """Send a single chat completion request.

        Args:
            messages: Conversation history
            tools: Optional OpenAI-format tool definitions
            temperature: Override default temperature
            max_tokens: Override default max tokens
            model: Override default model (e.g. use router model for classification)

        Returns:
            Tuple of (assistant response message, metrics)
        """
        start_time = datetime.now()
        use_model = model or self.model

        formatted_messages = self._format_messages(messages)

        params: dict[str, Any] = {
            "model": use_model,
            "messages": formatted_messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }

        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"
            params["parallel_tool_calls"] = True

        logger.debug(
            "cerebras_request",
            model=use_model,
            message_count=len(messages),
            has_tools=bool(tools),
        )

        try:
            response: ChatCompletion = await self.client.chat.completions.create(**params)
            total_time = (datetime.now() - start_time).total_seconds()

            choice = response.choices[0]
            message = choice.message

            # Parse tool calls if present
            tool_calls = None
            if message.tool_calls:
                tool_calls = []
                for tc in message.tool_calls:
                    try:
                        arguments = json.loads(tc.function.arguments)
                    except json.JSONDecodeError:
                        logger.warning(
                            "malformed_tool_call_json",
                            tool_call_id=tc.id,
                            raw_arguments=tc.function.arguments[:200],
                        )
                        arguments = {}
                    tool_calls.append(
                        ToolCall(id=tc.id, name=tc.function.name, arguments=arguments)
                    )

            response_message = ChatMessage(
                role="assistant",
                content=message.content or "",
                tool_calls=tool_calls,
            )

            metrics = CompletionMetrics(
                total_time=total_time,
                input_tokens=response.usage.prompt_tokens if response.usage else 0,
                output_tokens=response.usage.completion_tokens if response.usage else 0,
                model=response.model,
            )

            logger.info(
                "cerebras_response",
                model=use_model,
                total_time=f"{total_time:.2f}s",
                input_tokens=metrics.input_tokens,
                output_tokens=metrics.output_tokens,
                has_tool_calls=bool(tool_calls),
                tok_per_sec=(
                    round(metrics.output_tokens / total_time)
                    if total_time > 0
                    else 0
                ),
            )

            return response_message, metrics

        except Exception as e:
            logger.error(
                "cerebras_request_failed",
                model=use_model,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    async def stream_chat(
        self,
        messages: list[ChatMessage],
        tools: Optional[list[dict[str, Any]]] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
    ) -> AsyncIterator[Union[str, ToolCall]]:
        """Stream a chat completion. Yields text chunks and completed ToolCalls.

        Text content arrives as strings. Tool calls are accumulated from deltas
        and yielded as complete ToolCall objects after the stream ends.
        """
        start_time = datetime.now()
        ttft: Optional[float] = None

        formatted_messages = self._format_messages(messages)

        params: dict[str, Any] = {
            "model": self.model,
            "messages": formatted_messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens or self.max_tokens,
            "stream": True,
        }

        if tools:
            params["tools"] = tools
            params["tool_choice"] = "auto"
            params["parallel_tool_calls"] = True

        try:
            stream = await self.client.chat.completions.create(**params)

            # Buffer for accumulating streamed tool calls
            tool_call_buffer: dict[int, dict[str, Any]] = {}

            async for chunk in stream:
                if ttft is None:
                    ttft = (datetime.now() - start_time).total_seconds()

                if not chunk.choices:
                    continue

                delta = chunk.choices[0].delta

                # Yield text content immediately
                if delta.content:
                    yield delta.content

                # Accumulate tool call deltas
                if delta.tool_calls:
                    for tc_delta in delta.tool_calls:
                        idx = tc_delta.index
                        if idx not in tool_call_buffer:
                            tool_call_buffer[idx] = {
                                "id": tc_delta.id or "",
                                "name": "",
                                "arguments": "",
                            }
                        buf = tool_call_buffer[idx]
                        if tc_delta.id:
                            buf["id"] = tc_delta.id
                        if tc_delta.function:
                            if tc_delta.function.name:
                                buf["name"] = tc_delta.function.name
                            if tc_delta.function.arguments:
                                buf["arguments"] += tc_delta.function.arguments

            # Yield completed tool calls after stream ends
            for idx in sorted(tool_call_buffer.keys()):
                tc_data = tool_call_buffer[idx]
                try:
                    arguments = json.loads(tc_data["arguments"])
                    yield ToolCall(
                        id=tc_data["id"],
                        name=tc_data["name"],
                        arguments=arguments,
                    )
                except json.JSONDecodeError as e:
                    logger.error(
                        "tool_call_parse_error",
                        tool_call_id=tc_data["id"],
                        error=str(e),
                    )

            total_time = (datetime.now() - start_time).total_seconds()
            logger.info(
                "cerebras_stream_complete",
                ttft=f"{ttft:.3f}s" if ttft else None,
                total_time=f"{total_time:.2f}s",
            )

        except Exception as e:
            logger.error(
                "cerebras_stream_failed",
                error=str(e),
                error_type=type(e).__name__,
            )
            raise

    async def tool_loop(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]],
        tool_executor: Any,
        max_iterations: Optional[int] = None,
        on_tool_call: Optional[Any] = None,
        on_tool_result: Optional[Any] = None,
    ) -> tuple[list[ChatMessage], CompletionMetrics]:
        """Execute a ReAct-style tool loop.

        Repeatedly calls the model with tools until it returns a text-only response
        (no tool calls) or max iterations is reached.

        Args:
            messages: Initial conversation history
            tools: OpenAI-format tool definitions
            tool_executor: Object with async execute_tool(name: str, arguments: dict) -> Any
            max_iterations: Max loop iterations (defaults to self.max_tool_iterations)
            on_tool_call: Optional async callback(ToolCall) called before each tool execution
            on_tool_result: Optional async callback(ToolResult) called after each tool execution

        Returns:
            Tuple of (complete conversation history, cumulative metrics)
        """
        max_iter = max_iterations or self.max_tool_iterations
        conversation = list(messages)  # Copy to avoid mutating input

        cumulative = CompletionMetrics(model=self.model)

        logger.info("tool_loop_start", max_iterations=max_iter, tool_count=len(tools))

        for iteration in range(max_iter):
            logger.debug("tool_loop_iteration", iteration=iteration + 1)

            # Get model response
            response, metrics = await self.chat(
                messages=conversation,
                tools=tools,
            )

            # Accumulate metrics
            cumulative.total_time += metrics.total_time
            cumulative.input_tokens += metrics.input_tokens
            cumulative.output_tokens += metrics.output_tokens

            conversation.append(response)

            # If no tool calls, model is done reasoning
            if not response.tool_calls:
                logger.info(
                    "tool_loop_complete",
                    iterations=iteration + 1,
                    total_time=f"{cumulative.total_time:.2f}s",
                    total_tokens=cumulative.input_tokens + cumulative.output_tokens,
                )
                break

            # Execute all tool calls (concurrently)
            tool_results = await self._execute_tools(
                response.tool_calls,
                tool_executor,
                on_tool_call=on_tool_call,
                on_tool_result=on_tool_result,
            )

            # Add tool results to conversation
            for result in tool_results:
                content = result.result if result.result else f"Error: {result.error}"
                conversation.append(
                    ChatMessage(
                        role="tool",
                        content=content,
                        tool_call_id=result.tool_call_id,
                        name=result.tool_name,
                    )
                )
        else:
            logger.warning(
                "tool_loop_max_iterations",
                max_iterations=max_iter,
                total_time=f"{cumulative.total_time:.2f}s",
            )

        return conversation, cumulative

    async def _execute_tools(
        self,
        tool_calls: list[ToolCall],
        tool_executor: Any,
        on_tool_call: Optional[Any] = None,
        on_tool_result: Optional[Any] = None,
    ) -> list[ToolResult]:
        """Execute multiple tool calls concurrently."""
        tasks = [
            self._execute_single_tool(tc, tool_executor, on_tool_call, on_tool_result)
            for tc in tool_calls
        ]
        return await asyncio.gather(*tasks)

    async def _execute_single_tool(
        self,
        tool_call: ToolCall,
        tool_executor: Any,
        on_tool_call: Optional[Any] = None,
        on_tool_result: Optional[Any] = None,
    ) -> ToolResult:
        """Execute a single tool call with timeout and error handling."""
        start_time = datetime.now()

        # Notify listener before execution
        if on_tool_call:
            try:
                await on_tool_call(tool_call)
            except Exception:
                pass  # Don't let callback errors break the loop

        try:
            raw_result = await asyncio.wait_for(
                tool_executor.execute_tool(tool_call.name, tool_call.arguments),
                timeout=self.tool_call_timeout,
            )

            # Convert to string and truncate
            result_str = str(raw_result)
            if len(result_str) > 8000:
                result_str = result_str[:8000] + "\n\n[Result truncated to 8000 chars]"

            execution_time = (datetime.now() - start_time).total_seconds()

            logger.info(
                "tool_executed",
                tool_name=tool_call.name,
                execution_time=f"{execution_time:.2f}s",
                result_length=len(result_str),
            )

            result = ToolResult(
                tool_call_id=tool_call.id,
                tool_name=tool_call.name,
                result=result_str,
                execution_time=execution_time,
            )

        except asyncio.TimeoutError:
            error_msg = f"Tool execution timed out after {self.tool_call_timeout}s"
            logger.error("tool_timeout", tool_name=tool_call.name)
            result = ToolResult(
                tool_call_id=tool_call.id,
                tool_name=tool_call.name,
                result="",
                error=error_msg,
            )

        except Exception as e:
            error_msg = f"Tool execution failed: {type(e).__name__}: {str(e)}"
            logger.error(
                "tool_execution_failed",
                tool_name=tool_call.name,
                error=str(e),
                error_type=type(e).__name__,
            )
            result = ToolResult(
                tool_call_id=tool_call.id,
                tool_name=tool_call.name,
                result="",
                error=error_msg,
            )

        # Notify listener after execution
        if on_tool_result:
            try:
                await on_tool_result(result)
            except Exception:
                pass

        return result

    def _format_messages(
        self,
        messages: list[ChatMessage],
    ) -> list[ChatCompletionMessageParam]:
        """Convert ChatMessage list to OpenAI SDK format."""
        formatted: list[ChatCompletionMessageParam] = []

        for msg in messages:
            if msg.role == "tool":
                formatted.append({
                    "role": "tool",
                    "content": msg.content,
                    "tool_call_id": msg.tool_call_id or "",
                })
            elif msg.tool_calls:
                formatted.append({
                    "role": "assistant",
                    "content": msg.content or None,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": tc.name,
                                "arguments": json.dumps(tc.arguments),
                            },
                        }
                        for tc in msg.tool_calls
                    ],
                })
            else:
                formatted.append({
                    "role": msg.role,
                    "content": msg.content,
                })

        return formatted
