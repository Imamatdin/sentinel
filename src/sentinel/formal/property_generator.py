"""
LLM Property Generator — Generates formal properties from code analysis.

PropertyGPT pattern:
1. Parse function/contract code
2. LLM generates candidate properties: preconditions, postconditions, invariants
3. Classify: reachability, arithmetic bounds, access control, state transitions
4. Format as Z3-compatible assertions

Falls back to rule-based generation when no LLM client is available.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum

from sentinel.core import get_logger

logger = get_logger(__name__)


class PropertyType(str, Enum):
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    INVARIANT = "invariant"
    REACHABILITY = "reachability"
    ARITHMETIC = "arithmetic"
    ACCESS_CONTROL = "access_control"
    STATE_TRANSITION = "state_transition"


@dataclass
class FormalProperty:
    property_id: str
    property_type: PropertyType
    description: str
    z3_expression: str
    source_function: str
    confidence: float
    counterexample: dict = field(default_factory=dict)
    verified: bool | None = None


class PropertyGenerator:
    """Generate formal properties from code using LLM analysis with rule-based fallback."""

    PROPERTY_PROMPT_TEMPLATE = (
        "Analyze the following function and generate formal properties "
        "(preconditions, postconditions, invariants).\n\n"
        "Function:\n```\n{code}\n```\n\n"
        "For each property, provide:\n"
        "1. Type: precondition | postcondition | invariant | access_control\n"
        "2. Description: what the property checks\n"
        "3. Z3 expression: Python code using z3 library\n"
        "4. Confidence: 0.0-1.0\n\n"
        "Output as JSON array of properties."
    )

    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.generated_properties: list[FormalProperty] = []

    async def generate_properties(
        self, code: str, function_name: str = ""
    ) -> list[FormalProperty]:
        """Use LLM to generate formal properties, falling back to rules."""
        if not self.llm_client:
            return self._rule_based_properties(code, function_name)

        prompt = self.PROPERTY_PROMPT_TEMPLATE.format(code=code)
        try:
            response = await self.llm_client.complete(prompt)
            properties = self._parse_llm_response(response, function_name)
            self.generated_properties.extend(properties)
            return properties
        except Exception as e:
            logger.error("property_generation_failed", error=str(e))
            return self._rule_based_properties(code, function_name)

    def _rule_based_properties(
        self, code: str, function_name: str
    ) -> list[FormalProperty]:
        """Fallback: generate basic properties from code patterns."""
        properties: list[FormalProperty] = []
        prop_id = 0

        if re.search(r"[/](?!=)", code):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.ARITHMETIC,
                description="Division operand must not be zero",
                z3_expression="z3.And(divisor != 0)",
                source_function=function_name,
                confidence=0.9,
            ))

        if re.search(r"\[.*\]", code):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.PRECONDITION,
                description="Array index must be within bounds",
                z3_expression="z3.And(index >= 0, index < length)",
                source_function=function_name,
                confidence=0.85,
            ))

        if re.search(r"(?:is_admin|role|permission|authorize|auth)", code, re.IGNORECASE):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.ACCESS_CONTROL,
                description="Only authorized users can execute this function",
                z3_expression="z3.Implies(action_executed, user_authorized == True)",
                source_function=function_name,
                confidence=0.8,
            ))

        if re.search(r"(?:state|status)\s*=", code):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.STATE_TRANSITION,
                description="State transitions must follow valid paths",
                z3_expression=(
                    "z3.Or(z3.And(old_state == 'pending', new_state == 'active'), "
                    "z3.And(old_state == 'active', new_state == 'completed'))"
                ),
                source_function=function_name,
                confidence=0.7,
            ))

        return properties

    def _parse_llm_response(
        self, response: str, function_name: str
    ) -> list[FormalProperty]:
        """Parse LLM JSON response into FormalProperty objects."""
        properties: list[FormalProperty] = []
        try:
            start = response.find("[")
            end = response.rfind("]") + 1
            if start >= 0 and end > start:
                data = json.loads(response[start:end])
                for i, item in enumerate(data):
                    properties.append(FormalProperty(
                        property_id=f"llm_prop_{i}",
                        property_type=PropertyType(item.get("type", "invariant")),
                        description=item.get("description", ""),
                        z3_expression=item.get("z3_expression", ""),
                        source_function=function_name,
                        confidence=float(item.get("confidence", 0.5)),
                    ))
        except (json.JSONDecodeError, ValueError) as e:
            logger.warning("llm_property_parse_failed", error=str(e))
        return properties
