"""
Model Router — Routes LLM calls to the optimal model based on task complexity.

Tiers:
  FAST: Cerebras (1000+ tok/s) — recon summaries, simple classification, log parsing
  STANDARD: GPT-4o-mini / Claude Haiku — hypothesis generation, tool selection
  REASONING: Claude Sonnet / GPT-4o — exploit chain planning, code analysis, report writing

Routes based on:
  1. Task type (explicit label from caller)
  2. Input token count (proxy for complexity)
"""

from dataclasses import dataclass
from enum import Enum

from sentinel.core import get_logger

logger = get_logger(__name__)


class ModelTier(str, Enum):
    FAST = "fast"           # Cerebras, Groq — speed over quality
    STANDARD = "standard"   # GPT-4o-mini, Haiku — balanced
    REASONING = "reasoning"  # Claude Sonnet, GPT-4o — max quality


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


TASK_TO_TIER: dict[TaskType, ModelTier] = {
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
DEFAULT_MODELS: dict[ModelTier, ModelConfig] = {
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

    def __init__(self, models: dict[ModelTier, ModelConfig] | None = None):
        self.models = models or dict(DEFAULT_MODELS)
        self.usage_log: list[UsageRecord] = []

    def route(self, task_type: TaskType, input_tokens: int = 0) -> ModelConfig:
        """Select the best model for a task."""
        tier = TASK_TO_TIER.get(task_type, ModelTier.STANDARD)

        # Auto-upgrade if input is very large (>4K tokens, FAST can't handle well)
        if tier == ModelTier.FAST and input_tokens > 4000:
            tier = ModelTier.STANDARD
            logger.info(
                "auto_upgrade",
                task_type=task_type.value,
                from_tier="fast",
                to_tier="standard",
                input_tokens=input_tokens,
            )

        model = self.models.get(tier)
        if not model:
            model = self.models[ModelTier.STANDARD]  # fallback
        return model

    def record_usage(
        self,
        task_type: TaskType,
        model: ModelConfig,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float,
    ) -> UsageRecord:
        """Record usage for cost tracking."""
        cost = (
            (input_tokens / 1000) * model.cost_per_1k_input
            + (output_tokens / 1000) * model.cost_per_1k_output
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
        by_tier: dict[str, float] = {}
        by_task: dict[str, float] = {}
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
