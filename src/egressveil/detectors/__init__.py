"""Sensitive-data detectors.

A detector scans text and returns :class:`Finding` objects. A finding holds
only offsets and metadata, never the matched text, so findings are always safe
to log, print or put in an error message.

Implemented categories: ``secrets`` and ``tokens``. The ``pii`` and
``internal_hostnames`` categories are accepted by configuration but have no
detector yet (planned for Phase 2); :data:`IMPLEMENTED_CATEGORIES` lists what
actually runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable

__all__ = [
    "DETECTOR_CATEGORIES",
    "IMPLEMENTED_CATEGORIES",
    "Detector",
    "Finding",
    "build_detectors",
    "merge_spans",
]

DETECTOR_CATEGORIES: frozenset[str] = frozenset(
    {"secrets", "tokens", "pii", "internal_hostnames"},
)
IMPLEMENTED_CATEGORIES: frozenset[str] = frozenset({"secrets", "tokens"})


@dataclass(frozen=True, slots=True)
class Finding:
    """A detected sensitive span ``text[start:end]``. Never stores the text."""

    detector: str
    rule_id: str
    start: int
    end: int
    confidence: float


class Detector(Protocol):
    """Interface every detector implements."""

    @property
    def category(self) -> str: ...

    def scan(self, text: str) -> list[Finding]:
        """Return all findings in ``text``."""
        ...


def merge_spans(findings: Iterable[Finding]) -> list[tuple[int, int, Finding]]:
    """Merge overlapping findings into disjoint ``(start, end, representative)`` spans.

    The representative is the finding with the highest confidence (longest span
    on ties). Used by the redactor so overlapping matches are replaced once.
    """
    ordered = sorted(findings, key=lambda f: (f.start, -f.end))
    merged: list[tuple[int, int, Finding]] = []
    for f in ordered:
        if merged and f.start < merged[-1][1]:
            start, end, rep = merged[-1]
            better = (f.confidence, f.end - f.start) > (rep.confidence, rep.end - rep.start)
            merged[-1] = (start, max(end, f.end), f if better else rep)
        else:
            merged.append((f.start, f.end, f))
    return merged


def build_detectors(enabled: Iterable[str]) -> list[Detector]:
    """Instantiate the implemented detectors for the enabled categories."""
    from egressveil.detectors.patterns import SECRET_RULES, TOKEN_RULES, PatternDetector

    wanted = set(enabled)
    detectors: list[Detector] = []
    if "secrets" in wanted:
        detectors.append(PatternDetector("secrets", SECRET_RULES))
    if "tokens" in wanted:
        detectors.append(PatternDetector("tokens", TOKEN_RULES))
    return detectors
