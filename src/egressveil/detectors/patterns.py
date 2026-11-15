"""Pattern-based detectors for secrets and tokens.

Design notes:

* Vendor-specific rules (known key prefixes) are high-confidence and are not
  filtered for placeholders, except AWS's documented ``EXAMPLE`` keys.
* Generic rules (``password = "..."``) only fire on quoted or ``.env``-style
  values that contain a digit, have reasonable entropy and do not look like a
  placeholder. This keeps false positives on ordinary source code low.
* All patterns are linear-time friendly (no nested unbounded quantifiers) and
  every quantifier that could span large inputs is bounded.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from egressveil.detectors import Finding

__all__ = [
    "SECRET_RULES",
    "TOKEN_RULES",
    "PatternDetector",
    "PatternRule",
    "looks_like_placeholder",
    "shannon_entropy",
]


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


_PLACEHOLDER_MARKERS = (
    "example",
    "xxxx",
    "your_",
    "your-",
    "yourkey",
    "changeme",
    "change_me",
    "placeholder",
    "dummy",
    "redacted",
    "egressveil:",
    "<",
    ">",
    "${",
    "{{",
    "****",
    "....",
)


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(marker in lowered for marker in _PLACEHOLDER_MARKERS):
        return True
    if value.startswith(("$", "%")):
        return True
    # A single repeated character ("aaaaaaaaaaaa", "000000000000").
    return len(set(value)) <= 2


def _not_aws_example(value: str) -> bool:
    return "EXAMPLE" not in value


def _has_letter_and_digit(value: str) -> bool:
    return any(c.isdigit() for c in value) and any(c.isalpha() for c in value)


def _generic_value(value: str) -> bool:
    return (
        not looks_like_placeholder(value)
        and any(c.isdigit() for c in value)
        and shannon_entropy(value) >= 3.0
    )


def _url_password(value: str) -> bool:
    lowered = value.lower()
    if lowered in {"password", "pass", "passwd", "pwd", "secret"}:
        return False
    # Template syntax: f"{password}", "%(pw)s", "%s", "$PW".
    if any(c in value for c in "{}%"):
        return False
    return not looks_like_placeholder(value)


@dataclass(frozen=True, slots=True)
class PatternRule:
    rule_id: str
    pattern: re.Pattern[str]
    group: int = 0
    """Capture group that holds the sensitive span (0 = whole match)."""
    confidence: float = 0.9
    validator: Callable[[str], bool] | None = None


def _rule(
    rule_id: str,
    pattern: str,
    *,
    group: int = 0,
    confidence: float = 0.9,
    validator: Callable[[str], bool] | None = None,
    flags: int = 0,
) -> PatternRule:
    return PatternRule(rule_id, re.compile(pattern, flags), group, confidence, validator)


_KEY_NAMES = (
    r"api[_\-]?key|apikey|secret[_\-]?key|client[_\-]?secret|access[_\-]?token"
    r"|auth[_\-]?token|private[_\-]?key|secret|password|passwd|pwd|token"
)

SECRET_RULES: tuple[PatternRule, ...] = (
    _rule("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9][A-Za-z0-9_\-]{30,300}"),
    _rule(
        "openai_api_key",
        r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,300}",
        validator=_has_letter_and_digit,
    ),
    _rule(
        "aws_access_key_id",
        r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        validator=_not_aws_example,
    ),
    _rule(
        "aws_secret_access_key",
        r"aws_?secret_?access_?key[\"']?\s{0,8}[:=]\s{0,8}[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
        group=1,
        validator=_not_aws_example,
        flags=re.IGNORECASE,
    ),
    _rule("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    _rule("github_fine_grained_pat", r"\bgithub_pat_[A-Za-z0-9_]{50,255}\b"),
    _rule("gitlab_token", r"\bglpat-[A-Za-z0-9_\-]{20,64}\b"),
    _rule("slack_token", r"\bxox[abposr]-[A-Za-z0-9\-]{10,250}"),
    _rule(
        "slack_webhook",
        r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9/_\-]{20,200}",
    ),
    _rule("stripe_secret_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,200}\b"),
    _rule("google_api_key", r"\bAIza[0-9A-Za-z_\-]{35}(?![0-9A-Za-z_\-])"),
    _rule("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("huggingface_token", r"\bhf_[A-Za-z0-9]{34,64}\b"),
    _rule(
        "private_key",
        r"-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----"
        r"(?:[\s\S]{0,16384}?-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----"
        r"|[A-Za-z0-9+/=\s]{0,16384})",
        confidence=0.99,
    ),
    _rule(
        "url_credentials",
        r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s:/@\"'<>]{1,128}:([^\s@/\"'<>]{3,256})@[^\s/\"'<>]{1,253}",
        group=1,
        confidence=0.8,
        validator=_url_password,
    ),
    _rule(
        "generic_secret_assignment",
        rf"(?<![A-Za-z0-9])(?:{_KEY_NAMES})[\"']?\s{{0,8}}(?:=|:|=>)\s{{0,8}}[\"'`]([^\"'`\s]{{12,256}})[\"'`]",
        group=1,
        confidence=0.6,
        validator=_generic_value,
        flags=re.IGNORECASE,
    ),
    _rule(
        "env_file_assignment",
        r"^[ \t]{0,16}(?:export[ \t]+)?[A-Z0-9_]{0,64}"
        r"(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?)[A-Z0-9_]{0,32}"
        # The value must run to end-of-line/whitespace and contain no code
        # punctuation, so `API_KEY = os.environ.get("X")` is not a match.
        r"[ \t]{0,4}=[ \t]{0,4}([^\s\"'#()\[\]{},;]{12,256})(?=[ \t]*(?:#.*)?$)",
        group=1,
        confidence=0.6,
        validator=_generic_value,
        flags=re.MULTILINE,
    ),
)

TOKEN_RULES: tuple[PatternRule, ...] = (
    _rule(
        "jwt",
        r"\beyJ[A-Za-z0-9_\-]{8,4096}\.eyJ[A-Za-z0-9_\-]{8,8192}\.[A-Za-z0-9_\-]{8,4096}",
        confidence=0.95,
    ),
    _rule(
        "bearer_token",
        r"\bbearer[ \t]{1,4}([A-Za-z0-9\-._~+/]{20,4096}=*)",
        group=1,
        confidence=0.7,
        validator=lambda v: (
            _has_letter_and_digit(v) and not looks_like_placeholder(v) and shannon_entropy(v) >= 3.0
        ),
        flags=re.IGNORECASE,
    ),
    _rule(
        "basic_auth_header",
        r"\bauthorization:[ \t]{0,4}basic[ \t]{1,4}([A-Za-z0-9+/]{12,1024}={0,2})",
        group=1,
        confidence=0.85,
        flags=re.IGNORECASE,
    ),
)


class PatternDetector:
    """Runs a set of :class:`PatternRule` over text."""

    def __init__(self, category: str, rules: Sequence[PatternRule]) -> None:
        self._category = category
        self._rules = tuple(rules)

    @property
    def category(self) -> str:
        return self._category

    @property
    def rule_ids(self) -> tuple[str, ...]:
        return tuple(r.rule_id for r in self._rules)

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self._rules:
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.group)
                if start < 0 or start == end:
                    continue
                if rule.validator is not None and not rule.validator(text[start:end]):
                    continue
                findings.append(Finding(self._category, rule.rule_id, start, end, rule.confidence))
        return findings
