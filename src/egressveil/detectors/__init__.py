"""Sensitive-data detectors.

Phase 0 defines the detector interface and the set of detector categories
that configuration may reference. Concrete detectors (secrets, tokens, PII,
internal hostnames) are planned for a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

__all__ = ["DETECTOR_CATEGORIES", "Detector", "Finding"]

DETECTOR_CATEGORIES: frozenset[str] = frozenset(
    {"secrets", "tokens", "pii", "internal_hostnames"},
)


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected sensitive span.

    A finding deliberately stores only offsets and metadata, never the matched
    text, so it is always safe to log.
    """

    detector: str
    rule_id: str
    start: int
    end: int
    confidence: float


class Detector(Protocol):
    """Interface every detector implements."""

    category: str

    def scan(self, text: str) -> list[Finding]:
        """Return all findings in ``text``."""
        ...
