"""Deduplicate vulnerability patterns using string-tuple identity.

Two patterns are considered duplicates if their (attack_vector, payload_family,
root_cause) tuple matches exactly. This is deterministic, fast, and sufficient
for hackathon scope where a single engagement produces 5-20 findings.

The class structure is maintained so embedding-based dedup can be swapped in
post-hackathon by overriding the `_identity_key` method.

Why NOT embeddings for the hackathon:
- sentence-transformers adds ~2GB of torch/transformers dependencies
- Embedding similarity thresholds require tuning per domain
- For <20 patterns per engagement, string matching catches the real duplicates
  (same SQLi found on /search and /api/search)
- Deterministic = no false positives in dedup = more reliable demo
"""

import logging
from sentinel.genome.models import VulnPattern

logger = logging.getLogger("sentinel.genome.deduplicator")


class PatternDeduplicator:
    """Deduplicate patterns by their identity tuple.

    Usage:
        dedup = PatternDeduplicator()
        unique_patterns = dedup.deduplicate(patterns)
    """

    def deduplicate(self, patterns: list[VulnPattern]) -> list[VulnPattern]:
        """Remove duplicate patterns. Keeps the first occurrence.

        Args:
            patterns: List of VulnPattern objects (possibly with duplicates)

        Returns:
            Deduplicated list, preserving order of first occurrence
        """
        if not patterns:
            return []

        seen: set[tuple[str, str, str]] = set()
        unique: list[VulnPattern] = []

        for pattern in patterns:
            key = self._identity_key(pattern)
            if key not in seen:
                seen.add(key)
                unique.append(pattern)
            else:
                logger.debug(
                    "duplicate_removed",
                    pattern_id=pattern.id,
                    attack_vector=pattern.attack_vector,
                )

        logger.info(
            "dedup_complete",
            input_count=len(patterns),
            output_count=len(unique),
            duplicates_removed=len(patterns) - len(unique),
        )
        return unique

    def _identity_key(self, pattern: VulnPattern) -> tuple[str, str, str]:
        """Compute the identity tuple for a pattern.

        Normalizes to lowercase for case-insensitive matching.
        Override this method to implement embedding-based similarity.
        """
        return (
            pattern.attack_vector.lower().strip(),
            pattern.payload_family.lower().strip(),
            pattern.root_cause.lower().strip(),
        )
