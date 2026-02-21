"""Tests for LLM model router."""

import pytest
from sentinel.llm.model_router import (
    ModelRouter,
    TaskType,
    ModelTier,
    ModelConfig,
    TASK_TO_TIER,
    DEFAULT_MODELS,
)


class TestModelRouter:
    def setup_method(self):
        self.router = ModelRouter()

    def test_fast_task_routes_to_cerebras(self):
        model = self.router.route(TaskType.LOG_PARSE)
        assert model.provider == "cerebras"

    def test_classify_routes_to_fast(self):
        model = self.router.route(TaskType.CLASSIFY)
        assert model.provider == "cerebras"

    def test_summarize_short_routes_to_fast(self):
        model = self.router.route(TaskType.SUMMARIZE_SHORT)
        assert model.provider == "cerebras"

    def test_standard_task_routes_to_openai(self):
        model = self.router.route(TaskType.HYPOTHESIS_GEN)
        assert model.provider == "openai"

    def test_tool_select_routes_to_standard(self):
        model = self.router.route(TaskType.TOOL_SELECT)
        assert model.provider == "openai"

    def test_result_triage_routes_to_standard(self):
        model = self.router.route(TaskType.RESULT_TRIAGE)
        assert model.provider == "openai"

    def test_reasoning_task_routes_to_anthropic(self):
        model = self.router.route(TaskType.EXPLOIT_CHAIN)
        assert model.provider == "anthropic"

    def test_code_analysis_routes_to_reasoning(self):
        model = self.router.route(TaskType.CODE_ANALYSIS)
        assert model.provider == "anthropic"

    def test_report_write_routes_to_reasoning(self):
        model = self.router.route(TaskType.REPORT_WRITE)
        assert model.provider == "anthropic"

    def test_verify_finding_routes_to_reasoning(self):
        model = self.router.route(TaskType.VERIFY_FINDING)
        assert model.provider == "anthropic"

    def test_patch_generate_routes_to_reasoning(self):
        model = self.router.route(TaskType.PATCH_GENERATE)
        assert model.provider == "anthropic"

    def test_auto_upgrade_large_input(self):
        model = self.router.route(TaskType.LOG_PARSE, input_tokens=5000)
        assert model.provider != "cerebras"

    def test_no_upgrade_below_threshold(self):
        model = self.router.route(TaskType.LOG_PARSE, input_tokens=3000)
        assert model.provider == "cerebras"

    def test_upgrade_at_boundary(self):
        model = self.router.route(TaskType.LOG_PARSE, input_tokens=4001)
        assert model.provider == "openai"

    def test_standard_not_upgraded_on_large_input(self):
        model = self.router.route(TaskType.HYPOTHESIS_GEN, input_tokens=10000)
        assert model.provider == "openai"

    def test_cost_tracking(self):
        model = self.router.route(TaskType.EXPLOIT_CHAIN)  # anthropic, higher cost
        self.router.record_usage(TaskType.EXPLOIT_CHAIN, model, 1000, 500, 200.0)
        summary = self.router.get_cost_summary()
        assert summary["total_calls"] == 1
        assert summary["total_usd"] > 0

    def test_cost_calculation_correct(self):
        model = self.router.route(TaskType.LOG_PARSE)  # cerebras
        record = self.router.record_usage(TaskType.LOG_PARSE, model, 1000, 1000, 100.0)
        expected = (1000 / 1000) * model.cost_per_1k_input + (1000 / 1000) * model.cost_per_1k_output
        assert record.cost_usd == round(expected, 6)

    def test_cost_summary_by_tier(self):
        fast_model = self.router.route(TaskType.LOG_PARSE)
        reasoning_model = self.router.route(TaskType.EXPLOIT_CHAIN)
        self.router.record_usage(TaskType.LOG_PARSE, fast_model, 100, 50, 50.0)
        self.router.record_usage(TaskType.EXPLOIT_CHAIN, reasoning_model, 500, 200, 300.0)
        summary = self.router.get_cost_summary()
        assert "fast" in summary["by_tier"]
        assert "reasoning" in summary["by_tier"]
        assert summary["total_calls"] == 2

    def test_cost_summary_by_task(self):
        model = self.router.route(TaskType.LOG_PARSE)
        self.router.record_usage(TaskType.LOG_PARSE, model, 100, 50, 50.0)
        self.router.record_usage(TaskType.LOG_PARSE, model, 200, 100, 60.0)
        summary = self.router.get_cost_summary()
        assert "log_parse" in summary["by_task"]
        assert summary["total_calls"] == 2

    def test_all_tasks_have_tier(self):
        for task in TaskType:
            assert task in TASK_TO_TIER

    def test_custom_models(self):
        custom = {
            ModelTier.FAST: ModelConfig(
                provider="groq", model_id="llama-3.1-70b",
                cost_per_1k_input=0.0005, cost_per_1k_output=0.001,
                max_tokens=8192,
            ),
            ModelTier.STANDARD: ModelConfig(
                provider="openai", model_id="gpt-4o-mini",
                cost_per_1k_input=0.00015, cost_per_1k_output=0.0006,
                max_tokens=16384,
            ),
            ModelTier.REASONING: ModelConfig(
                provider="anthropic", model_id="claude-sonnet-4-5-20250929",
                cost_per_1k_input=0.003, cost_per_1k_output=0.015,
                max_tokens=64000,
            ),
        }
        router = ModelRouter(models=custom)
        model = router.route(TaskType.LOG_PARSE)
        assert model.provider == "groq"

    def test_empty_usage_log(self):
        summary = self.router.get_cost_summary()
        assert summary["total_usd"] == 0
        assert summary["total_calls"] == 0
        assert summary["by_tier"] == {}
        assert summary["by_task"] == {}

    def test_usage_record_fields(self):
        model = self.router.route(TaskType.CLASSIFY)
        record = self.router.record_usage(TaskType.CLASSIFY, model, 500, 200, 150.0)
        assert record.task_type == "classify"
        assert record.tier == "fast"
        assert record.model_id == model.model_id
        assert record.input_tokens == 500
        assert record.output_tokens == 200
        assert record.latency_ms == 150.0

    def test_default_models_all_tiers(self):
        assert ModelTier.FAST in DEFAULT_MODELS
        assert ModelTier.STANDARD in DEFAULT_MODELS
        assert ModelTier.REASONING in DEFAULT_MODELS

    def test_reasoning_model_supports_vision(self):
        model = DEFAULT_MODELS[ModelTier.REASONING]
        assert model.supports_vision is True

    def test_fast_model_no_tools(self):
        model = DEFAULT_MODELS[ModelTier.FAST]
        assert model.supports_tools is False
