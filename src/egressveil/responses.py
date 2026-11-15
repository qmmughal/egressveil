"""Optional response inspection (``gateway.inspect_responses``).

Model responses are scanned with the same detectors, allowlist and policy as
requests, and findings are written to the audit log. Responses are **never
modified**: the bytes the agent receives are exactly the upstream's.

Streaming (SSE) responses spread text over many small ``delta`` events, so a
value can be split across events. The scanner parses each ``data:`` event and
concatenates delta text before scanning, in bounded windows with an overlap,
so memory stays bounded however long the stream runs.
"""

from __future__ import annotations

import codecs
import json
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from egressveil.inspection import Inspector

__all__ = ["RESPONSE_LOCATION", "ResponseScanner"]

RESPONSE_LOCATION: Final = "$response"
WINDOW: Final = 64 * 1024
OVERLAP: Final = 4 * 1024
MAX_FINDINGS: Final = 200
_SKIP_KEYS: Final = frozenset(
    {"type", "id", "model", "role", "object", "signature", "encrypted_content", "stop_reason",
     "finish_reason", "system_fingerprint", "created", "index", "event"}
)  # fmt: skip


def _extract(node: Any, in_delta: bool, out: list[tuple[str, bool]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _SKIP_KEYS and isinstance(value, str):
                continue
            _extract(value, in_delta or key == "delta", out)
    elif isinstance(node, list):
        for value in node:
            _extract(value, in_delta, out)
    elif isinstance(node, str):
        out.append((node, in_delta))


class ResponseScanner:
    def __init__(self, inspector: Inspector, content_type: str | None, max_bytes: int) -> None:
        media = (content_type or "").split(";", 1)[0].strip().lower()
        self.mode = (
            "sse"
            if media == "text/event-stream"
            else "json"
            if media == "application/json" or media.endswith("+json")
            else None
        )
        self._inspector = inspector
        self._max_bytes = max_bytes
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._line = ""
        self._text = ""
        self._offset = 0
        self._json = bytearray()
        self._seen: set[tuple[int, str]] = set()
        self.findings: list[dict[str, object]] = []
        self.truncated = False

    @property
    def active(self) -> bool:
        return self.mode is not None

    # ------------------------------------------------------------------ input

    def feed(self, chunk: bytes) -> None:
        if self.mode == "json":
            if len(self._json) + len(chunk) > self._max_bytes:
                self.truncated = True
                self.mode = None  # too large to parse; stop inspecting
                self._json.clear()
                return
            self._json.extend(chunk)
        elif self.mode == "sse":
            self._line += self._decoder.decode(chunk)
            *lines, self._line = self._line.split("\n")
            for line in lines:
                self._sse_line(line.rstrip("\r"))
            if len(self._line) > self._max_bytes:  # absurd line without newline
                self._line = ""
                self.truncated = True

    def _sse_line(self, line: str) -> None:
        if not line.startswith("data:"):
            return
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            return
        try:
            event = json.loads(payload)
        except ValueError:
            self._append(payload, delta=False)
            return
        parts: list[tuple[str, bool]] = []
        _extract(event, False, parts)
        for text, delta in parts:
            self._append(text, delta)

    def _append(self, text: str, delta: bool) -> None:
        self._text += text if delta else f"\n{text}\n"
        if len(self._text) >= WINDOW:
            self._scan(final=False)

    # ------------------------------------------------------------------ scanning

    def _scan(self, *, final: bool) -> None:
        text = self._text
        cut = len(text) if final else max(0, len(text) - OVERLAP)
        for f, action, digest in self._inspector.evaluate_text(text):
            if not final and f.start >= cut:
                continue  # re-examined with more context in the next window
            key = (self._offset + f.start, f.rule_id)
            if key in self._seen or len(self.findings) >= MAX_FINDINGS:
                continue
            self._seen.add(key)
            self.findings.append(
                {
                    "detector": f.detector,
                    "rule_id": f.rule_id,
                    "location": RESPONSE_LOCATION,
                    "action": "LOG_ONLY",
                    "policy_action": action.value,
                    "digest": digest,
                }
            )
        self._text = text[cut:]
        self._offset += cut

    def finish(self) -> list[dict[str, object]]:
        if self.mode == "sse":
            self._line += self._decoder.decode(b"", final=True)
            if self._line:
                self._sse_line(self._line.rstrip("\r"))
        elif self.mode == "json" and self._json:
            try:
                document = json.loads(bytes(self._json).decode("utf-8", errors="replace"))
            except ValueError:
                document = None
            parts: list[tuple[str, bool]] = []
            _extract(document, False, parts)
            for text, _ in parts:
                self._append(text, delta=False)
        self._scan(final=True)
        return self.findings
