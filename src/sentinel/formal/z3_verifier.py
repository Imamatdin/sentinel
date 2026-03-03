"""
Z3 SMT Verifier — Checks formal properties using the Z3 theorem prover.

For each property:
1. Parse the Z3 expression
2. Assert the NEGATION (looking for counterexamples)
3. SAT → property violated, counterexample found
4. UNSAT → property holds
5. UNKNOWN → timeout / inconclusive

Z3 expressions run in a restricted namespace to prevent code injection.
"""

import time
from dataclasses import dataclass

from sentinel.formal.property_generator import FormalProperty
from sentinel.core import get_logger

logger = get_logger(__name__)


@dataclass
class VerificationResult:
    property_id: str
    status: str  # "holds" | "violated" | "timeout" | "error"
    counterexample: dict
    time_ms: float
    details: str


class Z3Verifier:
    """Verify formal properties using Z3 SMT solver."""

    TIMEOUT_MS = 10000

    def verify(self, prop: FormalProperty) -> VerificationResult:
        """Verify a single formal property. Returns result with status."""
        try:
            import z3
        except ImportError:
            return VerificationResult(
                property_id=prop.property_id, status="error",
                counterexample={}, time_ms=0,
                details="Z3 not installed. Run: pip install z3-solver",
            )

        start = time.time()
        try:
            solver = z3.Solver()
            solver.set("timeout", self.TIMEOUT_MS)

            namespace = self._build_namespace(z3)
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
                    details="Z3 returned unknown (timeout or undecidable)",
                )
        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return VerificationResult(
                property_id=prop.property_id, status="error",
                counterexample={}, time_ms=elapsed,
                details=f"Verification error: {e}",
            )

    def verify_all(
        self, properties: list[FormalProperty]
    ) -> list[VerificationResult]:
        """Verify all properties, updating their verified/counterexample fields."""
        results: list[VerificationResult] = []
        for prop in properties:
            result = self.verify(prop)
            if result.status == "violated":
                prop.counterexample = result.counterexample
                prop.verified = False
            elif result.status == "holds":
                prop.verified = True
            results.append(result)
            logger.info(
                "z3_verify", prop=prop.property_id,
                status=result.status, time_ms=f"{result.time_ms:.0f}",
            )
        return results

    def _build_namespace(self, z3) -> dict:
        """Build restricted namespace for Z3 expression evaluation."""
        return {
            "z3": z3,
            "Int": z3.Int, "Bool": z3.Bool, "Real": z3.Real,
            "String": z3.String, "Array": z3.Array,
            "IntSort": z3.IntSort, "BoolSort": z3.BoolSort,
            "And": z3.And, "Or": z3.Or, "Not": z3.Not,
            "Implies": z3.Implies, "If": z3.If,
            "ForAll": z3.ForAll, "Exists": z3.Exists,
            "user_authorized": z3.Bool("user_authorized"),
            "action_executed": z3.Bool("action_executed"),
            "index": z3.Int("index"),
            "length": z3.Int("length"),
            "divisor": z3.Int("divisor"),
            "old_state": z3.String("old_state"),
            "new_state": z3.String("new_state"),
            "balance": z3.Int("balance"),
            "amount": z3.Int("amount"),
            "x": z3.Int("x"), "y": z3.Int("y"),
        }
