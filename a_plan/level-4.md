# LEVEL 04: LLM Cost Optimizer & Model Router

## Context
Sentinel uses multiple LLMs (Cerebras, Claude, OpenAI). Without intelligent routing, every call goes to the most expensive model. This level adds a model router that sends simple tasks to cheap/fast models and complex reasoning to expensive ones. Research shows a fine-tuned 2B Gemma matched GPT-4 on vuln detection (NDSS 2025). MAPTA achieved $0.20/challenge.

Research source: Block 11 (LLM Cost Optimization).

## Why
At scale (100 apps, 10 LLM calls/app/day), costs balloon to $600/mo on GPT-4 alone. With tiered routing + prompt caching, cut to ~$150/mo. This is the difference between viable margins and burning cash.

---

## Files to Create

### `src/sentinel/llm/__init__.py`
```python
"""LLM client management, routing, and cost optimization."""
```

### `src/sentinel/llm/model_router.py`
```python
"""
Model Router — Routes LLM calls to the optimal model based on task complexity.

Tiers:
  FAST: Cerebras (1000+ tok/s) — recon summaries, simple classification, log parsing
  STANDARD: GPT-4o-mini / Claude Haiku — hypothesis generation, tool selection
  REASONING: Claude Sonnet / GPT-4o — exploit chain planning, code analysis, report writing
  
Routes based on:
  1. Task type (explicit label from caller)
  2. Input token count (proxy for complexity)
  3. Required capabilities (code analysis, structured output, etc.)
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from sentinel.logging import get_logger

logger = get_logger(__name__)


class ModelTier(str, Enum):
    FAST = "fast"           # Cerebras, Groq — speed over quality
    STANDARD = "standard"   # GPT-4o-mini, Haiku — balanced
    REASONING = "reasoning" # Claude Sonnet, GPT-4o — max quality


class TaskType(str, Enum):
    # FAST tier
    LOG_PARSE = "log_parse"
    CLASSIFY = "classify"
    SUMMARIZE_SHORT = "summarize_short"
    
    # STANDARD tier
    HYPOTHESIS_GEN = "hypothesis_gen"
    TOOL_SELECT = "tool_select"
    RESULT_TRIAGE = "result_triage"
    
    # REASONING tier
    EXPLOIT_CHAIN = "exploit_chain"
    CODE_ANALYSIS = "code_analysis"
    REPORT_WRITE = "report_write"
    VERIFY_FINDING = "verify_finding"
    PATCH_GENERATE = "patch_generate"


TASK_TO_TIER = {
    TaskType.LOG_PARSE: ModelTier.FAST,
    TaskType.CLASSIFY: ModelTier.FAST,
    TaskType.SUMMARIZE_SHORT: ModelTier.FAST,
    TaskType.HYPOTHESIS_GEN: ModelTier.STANDARD,
    TaskType.TOOL_SELECT: ModelTier.STANDARD,
    TaskType.RESULT_TRIAGE: ModelTier.STANDARD,
    TaskType.EXPLOIT_CHAIN: ModelTier.REASONING,
    TaskType.CODE_ANALYSIS: ModelTier.REASONING,
    TaskType.REPORT_WRITE: ModelTier.REASONING,
    TaskType.VERIFY_FINDING: ModelTier.REASONING,
    TaskType.PATCH_GENERATE: ModelTier.REASONING,
}


@dataclass
class ModelConfig:
    provider: str       # "cerebras", "anthropic", "openai"
    model_id: str       # "zai-glm-4.7", "claude-sonnet-4-5-20250929", etc.
    cost_per_1k_input: float
    cost_per_1k_output: float
    max_tokens: int
    supports_tools: bool = True
    supports_vision: bool = False


# Default model configs — override via sentinel config
DEFAULT_MODELS = {
    ModelTier.FAST: ModelConfig(
        provider="cerebras", model_id="zai-glm-4.7",
        cost_per_1k_input=0.0001, cost_per_1k_output=0.0002,
        max_tokens=8192, supports_tools=False,
    ),
    ModelTier.STANDARD: ModelConfig(
        provider="openai", model_id="gpt-4o-mini",
        cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
        max_tokens=16384,
    ),
    ModelTier.REASONING: ModelConfig(
        provider="anthropic", model_id="claude-sonnet-4-5-20250929",
        cost_per_1k_input=0.003, cost_per_1k_output=0.015,
        max_tokens=64000, supports_vision=True,
    ),
}


@dataclass
class UsageRecord:
    task_type: str
    tier: str
    model_id: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    latency_ms: float


class ModelRouter:
    """Routes LLM calls to optimal model based on task type."""
    
    def __init__(self, models: dict[ModelTier, ModelConfig] = None):
        self.models = models or DEFAULT_MODELS
        self.usage_log: list[UsageRecord] = []
    
    def route(self, task_type: TaskType, input_tokens: int = 0) -> ModelConfig:
        """Select the best model for a task."""
        tier = TASK_TO_TIER.get(task_type, ModelTier.STANDARD)
        
        # Auto-upgrade if input is very large (>4K tokens, FAST can't handle well)
        if tier == ModelTier.FAST and input_tokens > 4000:
            tier = ModelTier.STANDARD
            logger.info(f"Auto-upgraded {task_type} from FAST to STANDARD (input: {input_tokens} tokens)")
        
        model = self.models.get(tier)
        if not model:
            model = self.models[ModelTier.STANDARD]  # fallback
        
        return model
    
    def record_usage(self, task_type: TaskType, model: ModelConfig,
                     input_tokens: int, output_tokens: int, latency_ms: float):
        """Record usage for cost tracking."""
        cost = (
            (input_tokens / 1000) * model.cost_per_1k_input +
            (output_tokens / 1000) * model.cost_per_1k_output
        )
        record = UsageRecord(
            task_type=task_type.value,
            tier=self._get_tier(model).value,
            model_id=model.model_id,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=round(cost, 6),
            latency_ms=latency_ms,
        )
        self.usage_log.append(record)
        return record
    
    def get_cost_summary(self) -> dict:
        """Get cost breakdown by tier and task type."""
        by_tier = {}
        by_task = {}
        total = 0.0
        
        for r in self.usage_log:
            by_tier[r.tier] = by_tier.get(r.tier, 0) + r.cost_usd
            by_task[r.task_type] = by_task.get(r.task_type, 0) + r.cost_usd
            total += r.cost_usd
        
        return {
            "total_usd": round(total, 4),
            "by_tier": {k: round(v, 4) for k, v in by_tier.items()},
            "by_task": {k: round(v, 4) for k, v in by_task.items()},
            "total_calls": len(self.usage_log),
        }
    
    def _get_tier(self, model: ModelConfig) -> ModelTier:
        for tier, m in self.models.items():
            if m.model_id == model.model_id:
                return tier
        return ModelTier.STANDARD
```

### `src/sentinel/llm/prompt_cache.py`
```python
"""
Prompt Cache — Caches static prompt prefixes to reduce tokens and cost.

Claude's prompt caching gives 85% latency reduction and 90% cost savings
on cached prefixes. This module manages cache keys for system prompts,
tool schemas, and other static content.
"""
import hashlib
from dataclasses import dataclass
from sentinel.logging import get_logger

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
        logger.debug(f"Cached prompt prefix '{label}': {cached.token_count} est. tokens")
        return cached
    
    def build_messages(self, cached_prefix: CachedPrompt, user_content: str) -> list[dict]:
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
    
    def stats(self) -> dict:
        return {
            "cached_prefixes": len(self._cache),
            "total_cached_tokens": sum(c.token_count for c in self._cache.values()),
        }
```

---

## Files to Modify

### All agent files that call LLM
Replace direct LLM calls with router-aware calls. Pattern:
```python
# Before:
response = await self.llm_client.complete(prompt)

# After:
model = self.router.route(TaskType.VERIFY_FINDING, input_tokens=len(prompt)//4)
response = await self.llm_client.complete(prompt, model=model.model_id, provider=model.provider)
self.router.record_usage(TaskType.VERIFY_FINDING, model, len(prompt)//4, len(response)//4, latency_ms)
```

### `src/sentinel/api/` — Add cost endpoint
```python
@app.get("/api/v1/costs")
async def get_costs():
    return router.get_cost_summary()
```

---

## Tests

### `tests/llm/test_model_router.py`
```python
import pytest
from sentinel.llm.model_router import ModelRouter, TaskType, ModelTier

class TestModelRouter:
    def setup_method(self):
        self.router = ModelRouter()
    
    def test_fast_task_routes_to_cerebras(self):
        model = self.router.route(TaskType.LOG_PARSE)
        assert model.provider == "cerebras"
    
    def test_reasoning_task_routes_to_claude(self):
        model = self.router.route(TaskType.EXPLOIT_CHAIN)
        assert model.provider == "anthropic"
    
    def test_auto_upgrade_large_input(self):
        model = self.router.route(TaskType.LOG_PARSE, input_tokens=5000)
        assert model.provider != "cerebras"  # Should upgrade
    
    def test_cost_tracking(self):
        model = self.router.route(TaskType.LOG_PARSE)
        self.router.record_usage(TaskType.LOG_PARSE, model, 100, 50, 200.0)
        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 1
        assert summary["total_usd"] > 0
    
    def test_all_tasks_have_tier(self):
        from sentinel.llm.model_router import TASK_TO_TIER
        for task in TaskType:
            assert task in TASK_TO_TIER
```

---

## Acceptance Criteria
- [ ] ModelRouter routes FAST/STANDARD/REASONING tasks to correct providers
- [ ] Auto-upgrade kicks in for oversized inputs
- [ ] Cost tracking calculates per-call USD correctly
- [ ] PromptCache generates cache_control metadata for Anthropic API
- [ ] `/api/v1/costs` endpoint returns cost breakdown
- [ ] All tests pass