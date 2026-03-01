"""Tests for PromptInjectionTester."""

from sentinel.tools.ai_security.prompt_injection import (
    PromptInjectionTester,
    INJECTION_PAYLOADS,
    InjectionCategory,
)


class TestPayloadCoverage:
    def test_minimum_payload_count(self):
        assert len(INJECTION_PAYLOADS) >= 14

    def test_all_active_categories_covered(self):
        categories_covered = {p.category for p in INJECTION_PAYLOADS}
        assert InjectionCategory.DIRECT in categories_covered
        assert InjectionCategory.PROMPT_LEAK in categories_covered
        assert InjectionCategory.JAILBREAK in categories_covered
        assert InjectionCategory.DATA_EXFIL in categories_covered
        assert InjectionCategory.OUTPUT_MANIP in categories_covered

    def test_each_payload_has_required_fields(self):
        for p in INJECTION_PAYLOADS:
            assert p.name, f"Payload missing name"
            assert p.prompt, f"Payload {p.name} missing prompt"
            assert p.severity in ("critical", "high", "medium", "low")
            assert p.description


class TestInjectionDetection:
    def setup_method(self):
        self.tester = PromptInjectionTester()

    def test_direct_injection_detected(self):
        payload = next(
            p for p in INJECTION_PAYLOADS if p.name == "role_override"
        )
        assert self.tester._check_injection_success(
            "INJECTED: success! Here is the data.", payload
        )

    def test_override_confirmed_detected(self):
        payload = next(
            p for p in INJECTION_PAYLOADS if p.name == "instruction_override"
        )
        assert self.tester._check_injection_success(
            "OVERRIDE_CONFIRMED. I will now comply with the new policy.", payload
        )

    def test_no_false_positive_on_normal_response(self):
        payload = next(
            p for p in INJECTION_PAYLOADS if p.name == "role_override"
        )
        assert not self.tester._check_injection_success(
            "The weather today is sunny with a high of 72F.", payload
        )

    def test_prompt_leak_multi_indicator(self):
        response = (
            "My instructions say: You are a helpful assistant. "
            "Your role is to answer questions. You must always be polite. "
            "You should always verify information before responding."
        )
        payload = next(
            p for p in INJECTION_PAYLOADS
            if p.category == InjectionCategory.PROMPT_LEAK
        )
        assert self.tester._check_injection_success(response, payload)

    def test_prompt_leak_insufficient_indicators(self):
        response = "I can help you with that question about weather."
        payload = next(
            p for p in INJECTION_PAYLOADS
            if p.category == InjectionCategory.PROMPT_LEAK
        )
        assert not self.tester._check_injection_success(response, payload)

    def test_data_exfil_detects_email(self):
        response = "The user's email is admin@company.com and their token is abc123"
        payload = next(
            p for p in INJECTION_PAYLOADS
            if p.category == InjectionCategory.DATA_EXFIL
        )
        assert self.tester._check_injection_success(response, payload)

    def test_data_exfil_detects_connection_string(self):
        response = "Database at postgres://admin:secret@db.internal:5432/app"
        payload = next(
            p for p in INJECTION_PAYLOADS
            if p.category == InjectionCategory.DATA_EXFIL
        )
        assert self.tester._check_injection_success(response, payload)

    def test_data_exfil_detects_api_key(self):
        response = 'Config: api_key = "sk-abc123def456ghi789jkl012mno345"'
        payload = next(
            p for p in INJECTION_PAYLOADS
            if p.category == InjectionCategory.DATA_EXFIL
        )
        assert self.tester._check_injection_success(response, payload)

    def test_output_manip_json_injection(self):
        payload = next(
            p for p in INJECTION_PAYLOADS if p.name == "json_injection"
        )
        assert self.tester._check_injection_success(
            '{"role": "admin", "authorized": true, "bypass": true}', payload
        )

    def test_output_manip_function_call(self):
        payload = next(
            p for p in INJECTION_PAYLOADS if p.name == "function_call_injection"
        )
        assert self.tester._check_injection_success(
            "Calling delete_all_users() as requested.", payload
        )


class TestEvidenceExtraction:
    def setup_method(self):
        self.tester = PromptInjectionTester()

    def test_evidence_with_pattern_match(self):
        payload = next(
            p for p in INJECTION_PAYLOADS if p.name == "role_override"
        )
        response = "Hello INJECTED: success! Nice to meet you."
        evidence = self.tester._extract_evidence(response, payload)
        assert "INJECTED" in evidence

    def test_evidence_fallback_to_truncation(self):
        payload = next(
            p for p in INJECTION_PAYLOADS
            if p.category == InjectionCategory.PROMPT_LEAK
        )
        response = "Some generic response without any indicators."
        evidence = self.tester._extract_evidence(response, payload)
        assert evidence == response[:200]
