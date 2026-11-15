"""Anthropic Messages API request parsing.

Rather than extracting a fixed list of fields, the parser walks **every**
string in the JSON body. A new API field added by the provider therefore cannot
carry text past the detectors unnoticed. Exceptions:

* control keys whose values are identifiers rather than content (``model``,
  ``type``, ``role``, ``id``, ``tool_use_id``, ``media_type``) are skipped;
* ``signature`` values and ``redacted_thinking`` data are provider-issued,
  encrypted or signed blobs and are skipped;
* base64 ``source`` payloads (images, PDFs) are reported as **opaque**: they
  cannot be inspected, and the gateway's strict mode blocks them by default;
* strings inside ``thinking`` blocks are scanned but marked **signed**: they
  carry a provider signature, so they cannot be modified. A finding there that
  would require redaction escalates to ``BLOCK``.

JSON parsing is hardened against request smuggling: duplicate object keys,
``NaN``/``Infinity`` literals and excessive nesting are rejected, so the
gateway never inspects a different document than the upstream parses.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "MAX_JSON_DEPTH",
    "OpaqueItem",
    "RouteKind",
    "TextField",
    "UninspectableError",
    "classify_route",
    "parse_json_body",
    "walk_body",
]

MAX_JSON_DEPTH: Final = 64

INSPECTED_JSON_ROUTES: Final = frozenset({"/v1/messages", "/v1/messages/count_tokens"})

_SKIP_KEYS: Final = frozenset({"model", "type", "role", "id", "tool_use_id", "media_type"})
_OPAQUE_SOURCE_TYPES: Final = frozenset({"base64"})


class RouteKind(StrEnum):
    JSON_INSPECT = "json_inspect"
    """A JSON request whose body EgressVeil understands and inspects."""
    BODYLESS = "bodyless"
    """GET/HEAD without a body. Only the URL is inspected."""
    UNSUPPORTED = "unsupported"
    """Anything else. Strict mode blocks it."""


def classify_route(method: str, path: str, has_body: bool) -> RouteKind:
    method = method.upper()
    normalized = path.rstrip("/") or "/"
    if method == "POST" and normalized in INSPECTED_JSON_ROUTES:
        return RouteKind.JSON_INSPECT
    if method in {"GET", "HEAD"} and not has_body:
        return RouteKind.BODYLESS
    return RouteKind.UNSUPPORTED


class UninspectableError(Exception):
    """The request cannot be inspected. ``reason`` is a stable machine code."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message


@dataclass(slots=True)
class TextField:
    """A string leaf in the body, addressable so it can be rewritten in place."""

    location: str
    container: dict[str, Any] | list[Any]
    key: str | int
    text: str
    signed: bool = False

    def replace(self, new_text: str) -> None:
        self.container[self.key] = new_text  # type: ignore[index]


@dataclass(frozen=True, slots=True)
class OpaqueItem:
    location: str
    kind: str


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise UninspectableError("duplicate_key", "JSON body contains a duplicate key")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise UninspectableError("invalid_json", f"JSON body contains non-standard literal {name}")


def parse_json_body(raw: bytes) -> dict[str, Any]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise UninspectableError("invalid_json", "request body is not valid UTF-8") from None
    try:
        value = json.loads(
            text, object_pairs_hook=_reject_duplicates, parse_constant=_reject_constant
        )
    except UninspectableError:
        raise
    except RecursionError:
        raise UninspectableError("nesting_too_deep", "JSON body is nested too deeply") from None
    except ValueError:
        raise UninspectableError("invalid_json", "request body is not valid JSON") from None
    if not isinstance(value, dict):
        raise UninspectableError("invalid_json", "request body must be a JSON object")
    return value


def _child(location: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{location}[{key}]"
    return f"{location}.{key}" if location else key


def walk_body(body: dict[str, Any]) -> tuple[list[TextField], list[OpaqueItem]]:
    """Collect every inspectable string field and every opaque payload."""
    fields: list[TextField] = []
    opaque: list[OpaqueItem] = []
    # (node, location, depth, signed)
    stack: list[tuple[Any, str, int, bool]] = [(body, "", 0, False)]
    while stack:
        node, location, depth, signed = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise UninspectableError("nesting_too_deep", "JSON body is nested too deeply")
        if isinstance(node, dict):
            block_type = node.get("type")
            if block_type == "redacted_thinking":
                continue  # provider-encrypted; not user content
            child_signed = signed or block_type == "thinking"
            source = node.get("source")
            for key, value in node.items():
                child_loc = _child(location, key)
                if key == "signature" or (key in _SKIP_KEYS and isinstance(value, str)):
                    continue
                if (
                    key == "source"
                    and value is source
                    and isinstance(value, dict)
                    and value.get("type") in _OPAQUE_SOURCE_TYPES
                ):
                    kind = value.get("media_type")
                    opaque.append(
                        OpaqueItem(child_loc, kind if isinstance(kind, str) else "binary")
                    )
                    continue
                if isinstance(value, str):
                    fields.append(TextField(child_loc, node, key, value, child_signed))
                elif isinstance(value, dict | list):
                    stack.append((value, child_loc, depth + 1, child_signed))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                child_loc = _child(location, index)
                if isinstance(value, str):
                    fields.append(TextField(child_loc, node, index, value, signed))
                elif isinstance(value, dict | list):
                    stack.append((value, child_loc, depth + 1, signed))
    fields.sort(key=lambda f: f.location)
    return fields, opaque
