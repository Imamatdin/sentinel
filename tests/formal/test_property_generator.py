"""Tests for PropertyGenerator."""

from sentinel.formal.property_generator import PropertyGenerator, PropertyType


class TestRuleBasedProperties:
    def setup_method(self):
        self.gen = PropertyGenerator()

    def test_detects_division(self):
        code = "def calc(a, b): return a / b"
        props = self.gen._rule_based_properties(code, "calc")
        assert any(p.property_type == PropertyType.ARITHMETIC for p in props)

    def test_detects_array_access(self):
        code = "def get(items, i): return items[i]"
        props = self.gen._rule_based_properties(code, "get")
        assert any(p.property_type == PropertyType.PRECONDITION for p in props)

    def test_detects_auth_pattern(self):
        code = "def admin_action(user): if user.is_admin: delete_all()"
        props = self.gen._rule_based_properties(code, "admin_action")
        assert any(p.property_type == PropertyType.ACCESS_CONTROL for p in props)

    def test_detects_state_change(self):
        code = "def process(order): order.state = 'completed'"
        props = self.gen._rule_based_properties(code, "process")
        assert any(p.property_type == PropertyType.STATE_TRANSITION for p in props)

    def test_no_false_properties_on_simple_code(self):
        code = "def hello(): return 'world'"
        props = self.gen._rule_based_properties(code, "hello")
        assert len(props) == 0

    def test_properties_have_z3_expressions(self):
        code = "def risky(a, b): return a / b + items[i]"
        props = self.gen._rule_based_properties(code, "risky")
        for p in props:
            assert p.z3_expression
            assert p.confidence > 0

    def test_properties_have_unique_ids(self):
        code = "def complex(): x = a / b; y = items[i]; if is_admin: pass; state = 'done'"
        props = self.gen._rule_based_properties(code, "complex")
        ids = [p.property_id for p in props]
        assert len(ids) == len(set(ids))


class TestLLMResponseParsing:
    def setup_method(self):
        self.gen = PropertyGenerator()

    def test_parse_valid_json(self):
        response = '''Here are the properties:
[{"type": "precondition", "description": "x must be positive", "z3_expression": "x > 0", "confidence": 0.9}]'''
        props = self.gen._parse_llm_response(response, "test_fn")
        assert len(props) == 1
        assert props[0].property_type == PropertyType.PRECONDITION

    def test_parse_invalid_json(self):
        props = self.gen._parse_llm_response("not json at all", "test_fn")
        assert len(props) == 0

    def test_parse_empty_array(self):
        props = self.gen._parse_llm_response("[]", "test_fn")
        assert len(props) == 0
