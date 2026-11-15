"""Redaction engine.

Replaces sensitive spans with stable placeholders of the form
``[EGRESSVEIL:<rule_id>:<8 hex>]``. The hex suffix is a keyed hash (HMAC) of
the original value, so:

* the same secret always gets the same placeholder for a given key. That
  keeps the conversation consistent for the model across turns and keeps
  provider prompt caching effective, and
* the placeholder reveals nothing about the value without the local key.

By design there is **no** un-redaction: EgressVeil never restores an
original value into model output, so a model or a prompt injection cannot
trick the gateway into putting a real credential into an executable tool call.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable

from egressveil.detectors import Finding, merge_spans

__all__ = ["PLACEHOLDER_PREFIX", "Redactor"]

PLACEHOLDER_PREFIX = "[EGRESSVEIL:"


class Redactor:
    def __init__(self, key: bytes) -> None:
        if len(key) < 16:
            raise ValueError("redaction key must be at least 16 bytes")
        self._key = key

    def placeholder(self, rule_id: str, value: str) -> str:
        mac = hmac.new(
            self._key, b"placeholder\x00" + value.encode("utf-8", "surrogatepass"), hashlib.sha256
        ).hexdigest()
        return f"{PLACEHOLDER_PREFIX}{rule_id}:{mac[:8]}]"

    def redact(self, text: str, findings: Iterable[Finding]) -> str:
        """Return ``text`` with every finding span replaced (overlaps merged)."""
        spans = merge_spans(findings)
        if not spans:
            return text
        out: list[str] = []
        cursor = 0
        for start, end, rep in spans:
            out.append(text[cursor:start])
            out.append(self.placeholder(rep.rule_id, text[start:end]))
            cursor = end
        out.append(text[cursor:])
        return "".join(out)
