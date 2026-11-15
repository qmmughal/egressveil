"""Sensitive-data detectors.

A detector scans text and returns :class:`Finding` objects. A finding holds
only offsets and metadata, never the matched text, so findings are always safe
to log, print or put in an error message.

Categories: ``secrets`` and ``tokens`` (:mod:`.patterns`), ``pii``
(:mod:`.pii`) and ``internal_hostnames`` (:mod:`.hostnames`).
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
    "known_rule_ids",
    "merge_spans",
]

DETECTOR_CATEGORIES: frozenset[str] = frozenset(
    {"secrets", "tokens", "pii", "internal_hostnames"},
)
IMPLEMENTED_CATEGORIES: frozenset[str] = DETECTOR_CATEGORIES


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


def build_detectors(
    enabled: Iterable[str],
    *,
    internal_domains: Iterable[str] = (),
    include_common_internal_suffixes: bool = True,
    include_private_ips: bool = False,
) -> list[Detector]:
    """Instantiate the detectors for the enabled categories."""
    from egressveil.detectors.hostnames import HostnameDetector
    from egressveil.detectors.patterns import SECRET_RULES, TOKEN_RULES, PatternDetector
    from egressveil.detectors.pii import make_pii_detector

    wanted = set(enabled)
    detectors: list[Detector] = []
    if "secrets" in wanted:
        detectors.append(PatternDetector("secrets", SECRET_RULES))
    if "tokens" in wanted:
        detectors.append(PatternDetector("tokens", TOKEN_RULES))
    if "pii" in wanted:
        detectors.append(make_pii_detector())
    if "internal_hostnames" in wanted:
        detectors.append(
            HostnameDetector(
                internal_domains,
                include_common_internal_suffixes=include_common_internal_suffixes,
                include_private_ips=include_private_ips,
            )
        )
    return detectors


def known_rule_ids() -> frozenset[str]:
    """Every rule ID any detector can emit (used to validate allowlist entries)."""
    from egressveil.detectors.patterns import SECRET_RULES, TOKEN_RULES
    from egressveil.detectors.pii import PII_RULES

    ids = {r.rule_id for r in (*SECRET_RULES, *TOKEN_RULES, *PII_RULES)}
    return frozenset(ids | {"internal_domain", "internal_suffix", "private_ipv4"})
