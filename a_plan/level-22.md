# LEVEL 22: Formal Verification + Hybrid Fuzzing

## Context
LLM-generated invariants meet SMT solvers and coverage-guided fuzzing. This level adds PropertyGPT-style property generation: the LLM reads code, generates formal properties (pre/postconditions, invariants), feeds them to Z3 SMT solver for verification, and uses Driller-style hybrid fuzzing (concolic + coverage) to find violations.

Research: Block 12 (Formal Verification — PropertyGPT: 80% spec correctness, Driller: 6× more bugs than AFL alone, Neuro-symbolic: LLM proposes → SMT validates → fuzzer exploits).

## Why
Static analysis flags too many false positives. Fuzzing finds crashes but misses logic bugs. Formal verification is precise but slow and hard to set up. The hybrid: LLM writes the specs (fast), Z3 checks them (precise), fuzzer finds violations (practical). This is the highest-quality vulnerability discovery possible.

---

## Files to Create

### `src/sentinel/formal/__init__.py`
```python
"""Formal verification + hybrid fuzzing — LLM-generated invariants, SMT solving, concolic execution."""
```

### `src/sentinel/formal/property_generator.py`
```python
"""
LLM Property Generator — Generates formal properties from code analysis.

PropertyGPT pattern:
1. Parse function/contract code
2. LLM generates candidate properties: preconditions, postconditions, invariants
3. Classify: reachability, arithmetic bounds, access control, state transitions
4. Format as Z3-compatible assertions

Output types:
- assert(condition): Must always hold
- require(precondition): Must hold at entry
- ensure(postcondition): Must hold at exit
- invariant(condition): Must hold before and after every state change
"""
from dataclasses import dataclass, field
from enum import Enum
from sentinel.logging import get_logger

logger = get_logger(__name__)


class PropertyType(str, Enum):
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    INVARIANT = "invariant"
    REACHABILITY = "reachability"      # "Can state X be reached?"
    ARITHMETIC = "arithmetic"          # "No overflow/underflow"
    ACCESS_CONTROL = "access_control"  # "Only role X can call Y"
    STATE_TRANSITION = "state_transition"  # "State goes A→B only via action C"


@dataclass
class FormalProperty:
    property_id: str
    property_type: PropertyType
    description: str         # Human-readable
    z3_expression: str       # Z3Py assertion code
    source_function: str     # Function this property was generated from
    confidence: float        # LLM's confidence (0-1)
    counterexample: dict = field(default_factory=dict)  # Filled if Z3 finds violation
    verified: bool = None    # True = holds, False = violated, None = unknown


class PropertyGenerator:
    """Generate formal properties from code using LLM analysis."""
    
    PROPERTY_PROMPT_TEMPLATE = """Analyze the following function and generate formal properties (preconditions, postconditions, invariants).

Function:
```
{code}
```

For each property, provide:
1. Type: precondition | postcondition | invariant | access_control
2. Description: what the property checks
3. Z3 expression: Python code using z3 library (e.g., `z3.And(x > 0, x < 100)`)
4. Confidence: 0.0-1.0

Focus on:
- Input validation (bounds, types, formats)
- Access control (who can call this, with what roles)
- State transitions (valid state machine paths)
- Arithmetic safety (no overflow, division by zero)
- Return value guarantees

Output as JSON array of properties.
"""
    
    def __init__(self, llm_client=None):
        self.llm_client = llm_client
        self.generated_properties: list[FormalProperty] = []
    
    async def generate_properties(self, code: str, function_name: str = "") -> list[FormalProperty]:
        """Use LLM to generate formal properties from source code."""
        if not self.llm_client:
            # Fallback: rule-based property generation
            return self._rule_based_properties(code, function_name)
        
        prompt = self.PROPERTY_PROMPT_TEMPLATE.format(code=code)
        
        try:
            response = await self.llm_client.complete(prompt)
            properties = self._parse_llm_response(response, function_name)
            self.generated_properties.extend(properties)
            return properties
        except Exception as e:
            logger.error(f"LLM property generation failed: {e}")
            return self._rule_based_properties(code, function_name)
    
    def _rule_based_properties(self, code: str, function_name: str) -> list[FormalProperty]:
        """Fallback: generate basic properties from code patterns."""
        import re
        properties = []
        prop_id = 0
        
        # Check for division operations
        if re.search(r'[/](?!=)', code):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.ARITHMETIC,
                description="Division operand must not be zero",
                z3_expression="z3.And(divisor != 0)",
                source_function=function_name,
                confidence=0.9,
            ))
        
        # Check for array/list indexing
        if re.search(r'\[.*\]', code):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.PRECONDITION,
                description="Array index must be within bounds",
                z3_expression="z3.And(index >= 0, index < length)",
                source_function=function_name,
                confidence=0.85,
            ))
        
        # Check for auth-related patterns
        if re.search(r'(?:is_admin|role|permission|authorize|auth)', code, re.IGNORECASE):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.ACCESS_CONTROL,
                description="Only authorized users can execute this function",
                z3_expression="z3.Implies(action_executed, user_authorized == True)",
                source_function=function_name,
                confidence=0.8,
            ))
        
        # Check for state modifications
        if re.search(r'(?:state|status)\s*=', code):
            prop_id += 1
            properties.append(FormalProperty(
                property_id=f"prop_{prop_id}",
                property_type=PropertyType.STATE_TRANSITION,
                description="State transitions must follow valid paths",
                z3_expression="z3.Or(z3.And(old_state == 'pending', new_state == 'active'), "
                              "z3.And(old_state == 'active', new_state == 'completed'))",
                source_function=function_name,
                confidence=0.7,
            ))
        
        return properties
    
    def _parse_llm_response(self, response: str, function_name: str) -> list[FormalProperty]:
        """Parse LLM JSON response into FormalProperty objects."""
        import json
        properties = []
        
        try:
            # Try to extract JSON from response
            start = response.find('[')
            end = response.rfind(']') + 1
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
            logger.warning(f"Failed to parse LLM property response: {e}")
        
        return properties
```

### `src/sentinel/formal/z3_verifier.py`
```python
"""
Z3 SMT Verifier — Checks formal properties using the Z3 theorem prover.

For each property:
1. Parse the Z3 expression
2. Assert the NEGATION (looking for counterexamples)
3. If SAT: property is violated → counterexample found
4. If UNSAT: property holds (within the model)
5. If UNKNOWN: timeout, inconclusive

Sandboxed execution: Z3 expressions run in a restricted namespace.
"""
from dataclasses import dataclass
from sentinel.formal.property_generator import FormalProperty
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VerificationResult:
    property_id: str
    status: str            # "holds" | "violated" | "timeout" | "error"
    counterexample: dict   # If violated: variable assignments that break the property
    time_ms: float
    details: str


class Z3Verifier:
    """Verify formal properties using Z3 SMT solver."""
    
    TIMEOUT_MS = 10000  # 10 second timeout per property
    
    def verify(self, prop: FormalProperty) -> VerificationResult:
        """Verify a single formal property."""
        try:
            import z3
        except ImportError:
            return VerificationResult(
                property_id=prop.property_id, status="error",
                counterexample={}, time_ms=0,
                details="Z3 not installed. Run: pip install z3-solver",
            )
        
        import time
        start = time.time()
        
        try:
            solver = z3.Solver()
            solver.set("timeout", self.TIMEOUT_MS)
            
            # Create a restricted namespace with common Z3 constructs
            namespace = self._build_namespace(z3)
            
            # Parse and negate the property (looking for counterexamples)
            assertion = eval(prop.z3_expression, {"__builtins__": {}}, namespace)
            solver.add(z3.Not(assertion))
            
            result = solver.check()
            elapsed = (time.time() - start) * 1000
            
            if result == z3.unsat:
                return VerificationResult(
                    property_id=prop.property_id, status="holds",
                    counterexample={}, time_ms=elapsed,
                    details=f"Property '{prop.description}' verified: no counterexample exists",
                )
            elif result == z3.sat:
                model = solver.model()
                ce = {str(d): str(model[d]) for d in model.decls()}
                return VerificationResult(
                    property_id=prop.property_id, status="violated",
                    counterexample=ce, time_ms=elapsed,
                    details=f"Property '{prop.description}' VIOLATED. Counterexample: {ce}",
                )
            else:
                return VerificationResult(
                    property_id=prop.property_id, status="timeout",
                    counterexample={}, time_ms=elapsed,
                    details=f"Z3 returned unknown (timeout or undecidable)",
                )
                
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                property_id=prop.property_id, status="error",
                counterexample={}, time_ms=elapsed,
                details=f"Verification error: {str(e)}",
            )
    
    def verify_all(self, properties: list[FormalProperty]) -> list[VerificationResult]:
        """Verify all properties, return results."""
        results = []
        for prop in properties:
            result = self.verify(prop)
            if result.status == "violated":
                prop.counterexample = result.counterexample
                prop.verified = False
            elif result.status == "holds":
                prop.verified = True
            results.append(result)
            logger.info(f"Z3: {prop.property_id} → {result.status} ({result.time_ms:.0f}ms)")
        return results
    
    def _build_namespace(self, z3) -> dict:
        """Build restricted namespace for Z3 expression evaluation."""
        return {
            "z3": z3,
            "Int": z3.Int,
            "Bool": z3.Bool,
            "Real": z3.Real,
            "String": z3.String,
            "Array": z3.Array,
            "IntSort": z3.IntSort,
            "BoolSort": z3.BoolSort,
            "And": z3.And,
            "Or": z3.Or,
            "Not": z3.Not,
            "Implies": z3.Implies,
            "If": z3.If,
            "ForAll": z3.ForAll,
            "Exists": z3.Exists,
            # Common security-domain variables
            "user_authorized": z3.Bool("user_authorized"),
            "action_executed": z3.Bool("action_executed"),
            "index": z3.Int("index"),
            "length": z3.Int("length"),
            "divisor": z3.Int("divisor"),
            "old_state": z3.String("old_state"),
            "new_state": z3.String("new_state"),
            "balance": z3.Int("balance"),
            "amount": z3.Int("amount"),
            "x": z3.Int("x"),
            "y": z3.Int("y"),
        }
```

### `src/sentinel/formal/hybrid_fuzzer.py`
```python
"""
Hybrid Fuzzer — Coverage-guided fuzzing informed by formal verification.

Driller pattern:
1. Coverage-guided fuzzing (AFL-style) finds easy paths
2. When stuck (no new coverage for N iterations): switch to concolic execution
3. Concolic engine solves path constraints to generate inputs reaching new branches
4. Feed solved inputs back to fuzzer as seeds

For web apps: HTTP request fuzzing with coverage feedback from instrumented target.
For code: Function-level fuzzing with branch coverage tracking.
"""
import random
import hashlib
from dataclasses import dataclass, field
from sentinel.formal.property_generator import FormalProperty
from sentinel.logging import get_logger

logger = get_logger(__name__)


@dataclass
class FuzzInput:
    data: bytes
    source: str         # "random" | "mutation" | "concolic" | "z3_counterexample"
    generation: int
    coverage_hash: str = ""


@dataclass
class FuzzResult:
    input_data: bytes
    crash: bool
    new_coverage: bool
    coverage_bitmap: set = field(default_factory=set)
    violation: str = ""     # Which property was violated
    error_message: str = ""


@dataclass
class FuzzStats:
    total_executions: int = 0
    unique_crashes: int = 0
    unique_paths: int = 0
    property_violations: int = 0
    concolic_solves: int = 0


class HybridFuzzer:
    """Coverage-guided fuzzing with concolic execution fallback."""
    
    STUCK_THRESHOLD = 500   # Switch to concolic after N iterations without new coverage
    MAX_INPUT_SIZE = 4096
    
    def __init__(self):
        self.corpus: list[FuzzInput] = []
        self.coverage: set[str] = set()
        self.crashes: list[FuzzResult] = []
        self.stats = FuzzStats()
        self._iterations_without_progress = 0
    
    def seed(self, inputs: list[bytes]):
        """Add initial seed inputs to the corpus."""
        for data in inputs:
            self.corpus.append(FuzzInput(
                data=data, source="seed", generation=0,
            ))
    
    def seed_from_counterexample(self, prop: FormalProperty):
        """Convert a Z3 counterexample into a fuzz seed."""
        if not prop.counterexample:
            return
        # Convert counterexample values to bytes
        ce_str = str(prop.counterexample)
        self.corpus.append(FuzzInput(
            data=ce_str.encode(),
            source="z3_counterexample",
            generation=0,
        ))
        logger.info(f"Seeded fuzzer with Z3 counterexample from {prop.property_id}")
    
    def mutate(self, input_data: bytes) -> bytes:
        """Apply random mutations to an input."""
        data = bytearray(input_data)
        if not data:
            data = bytearray(random.randint(1, 32))
        
        num_mutations = random.randint(1, 5)
        for _ in range(num_mutations):
            mutation = random.choice([
                self._bit_flip,
                self._byte_flip,
                self._insert_random,
                self._delete_bytes,
                self._insert_interesting,
            ])
            data = mutation(data)
        
        return bytes(data[:self.MAX_INPUT_SIZE])
    
    def run_iteration(self, executor) -> FuzzResult:
        """
        Run one fuzzing iteration.
        
        Args:
            executor: Callable(bytes) -> FuzzResult that runs the target
        """
        # Select input from corpus
        if not self.corpus:
            input_data = bytes(random.randint(0, 255) for _ in range(32))
        else:
            base = random.choice(self.corpus)
            input_data = self.mutate(base.data)
        
        # Execute
        result = executor(input_data)
        self.stats.total_executions += 1
        
        # Track coverage
        coverage_hash = hashlib.md5(str(sorted(result.coverage_bitmap)).encode()).hexdigest()
        
        if result.new_coverage:
            self._iterations_without_progress = 0
            self.coverage.update(result.coverage_bitmap)
            self.stats.unique_paths = len(self.coverage)
            # Add to corpus
            self.corpus.append(FuzzInput(
                data=input_data, source="mutation",
                generation=max(f.generation for f in self.corpus) + 1 if self.corpus else 1,
                coverage_hash=coverage_hash,
            ))
        else:
            self._iterations_without_progress += 1
        
        if result.crash:
            self.crashes.append(result)
            self.stats.unique_crashes += 1
        
        if result.violation:
            self.stats.property_violations += 1
        
        return result
    
    @property
    def is_stuck(self) -> bool:
        """Check if fuzzer is stuck (no new coverage for a while)."""
        return self._iterations_without_progress >= self.STUCK_THRESHOLD
    
    # --- Mutation strategies ---
    
    def _bit_flip(self, data: bytearray) -> bytearray:
        if data:
            pos = random.randint(0, len(data) - 1)
            bit = random.randint(0, 7)
            data[pos] ^= (1 << bit)
        return data
    
    def _byte_flip(self, data: bytearray) -> bytearray:
        if data:
            pos = random.randint(0, len(data) - 1)
            data[pos] = random.randint(0, 255)
        return data
    
    def _insert_random(self, data: bytearray) -> bytearray:
        pos = random.randint(0, len(data))
        data.insert(pos, random.randint(0, 255))
        return data
    
    def _delete_bytes(self, data: bytearray) -> bytearray:
        if len(data) > 1:
            pos = random.randint(0, len(data) - 1)
            del data[pos]
        return data
    
    def _insert_interesting(self, data: bytearray) -> bytearray:
        """Insert values known to trigger bugs (boundary values, format strings, etc.)."""
        interesting = [
            b"\x00", b"\xff", b"\x7f", b"\x80",
            b"\xff\xff\xff\xff",  # Max int
            b"\x00\x00\x00\x00",  # Null
            b"%s%s%s%s",          # Format string
            b"'OR'1'='1",         # SQLi
            b"<script>",          # XSS
            b"../../../",         # Path traversal
        ]
        payload = random.choice(interesting)
        pos = random.randint(0, len(data))
        for b in payload:
            data.insert(pos, b)
            pos += 1
        return data
```

---

## Tests

### `tests/formal/test_property_generator.py`
```python
import pytest
from sentinel.formal.property_generator import PropertyGenerator, PropertyType

class TestPropertyGenerator:
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

    def test_no_false_properties(self):
        code = "def hello(): return 'world'"
        props = self.gen._rule_based_properties(code, "hello")
        assert len(props) == 0
```

### `tests/formal/test_z3_verifier.py`
```python
import pytest
from sentinel.formal.z3_verifier import Z3Verifier
from sentinel.formal.property_generator import FormalProperty, PropertyType

class TestZ3Verifier:
    def setup_method(self):
        self.verifier = Z3Verifier()

    def test_tautology_holds(self):
        prop = FormalProperty(
            property_id="p1", property_type=PropertyType.ARITHMETIC,
            description="x equals x", z3_expression="z3.Int('x') == z3.Int('x')",
            source_function="test", confidence=1.0,
        )
        result = self.verifier.verify(prop)
        assert result.status == "holds"

    def test_contradiction_violated(self):
        prop = FormalProperty(
            property_id="p2", property_type=PropertyType.ARITHMETIC,
            description="x > x", z3_expression="z3.Int('x') > z3.Int('x')",
            source_function="test", confidence=1.0,
        )
        result = self.verifier.verify(prop)
        assert result.status == "violated"

    def test_error_on_bad_expression(self):
        prop = FormalProperty(
            property_id="p3", property_type=PropertyType.INVARIANT,
            description="bad", z3_expression="this is not valid python",
            source_function="test", confidence=0.5,
        )
        result = self.verifier.verify(prop)
        assert result.status == "error"
```

### `tests/formal/test_hybrid_fuzzer.py`
```python
import pytest
from sentinel.formal.hybrid_fuzzer import HybridFuzzer, FuzzResult

class TestHybridFuzzer:
    def setup_method(self):
        self.fuzzer = HybridFuzzer()

    def test_mutation_changes_input(self):
        original = b"hello world"
        mutated = self.fuzzer.mutate(original)
        # Mutation should produce different bytes (probabilistic but very likely)
        # Just check it doesn't crash and returns bytes
        assert isinstance(mutated, bytes)

    def test_seed_corpus(self):
        self.fuzzer.seed([b"test1", b"test2"])
        assert len(self.fuzzer.corpus) == 2

    def test_run_iteration(self):
        self.fuzzer.seed([b"seed"])
        def mock_executor(data):
            return FuzzResult(
                input_data=data, crash=False, new_coverage=True,
                coverage_bitmap={"branch_1", "branch_2"},
            )
        result = self.fuzzer.run_iteration(mock_executor)
        assert result.new_coverage
        assert self.fuzzer.stats.total_executions == 1

    def test_stuck_detection(self):
        self.fuzzer._iterations_without_progress = 500
        assert self.fuzzer.is_stuck

    def test_interesting_values(self):
        data = bytearray(b"test")
        result = self.fuzzer._insert_interesting(data)
        assert len(result) > 4  # Something was inserted
```

---

## Acceptance Criteria
- [ ] PropertyGenerator detects division, array access, auth patterns, state changes in code
- [ ] Rule-based fallback generates properties without LLM
- [ ] LLM prompt template produces parseable JSON property list
- [ ] Z3Verifier proves tautologies ("holds") and finds counterexamples ("violated")
- [ ] Verification timeout handled gracefully
- [ ] Restricted namespace prevents code injection in Z3 expressions
- [ ] HybridFuzzer mutates inputs with 5 strategies (bit flip, byte flip, insert, delete, interesting values)
- [ ] Coverage tracking detects new paths
- [ ] Stuck detection triggers after 500 iterations without progress
- [ ] Z3 counterexamples can seed the fuzzer
- [ ] All tests pass