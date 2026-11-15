"""Provider-independent request parsing.

Each supported API is described by a :class:`ProviderAdapter`: which routes
carry inspectable JSON, how its content blocks mark opaque/signed/encrypted
data, and what its error responses look like. The walker itself is shared.

The walker visits **every** string in a JSON body, so a new API field cannot
carry text past the detectors unnoticed. JSON parsing is hardened against
request smuggling: duplicate object keys, ``NaN``/``Infinity`` and excessive
nesting are rejected, so the gateway never inspects a different document than
the upstream parses.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

__all__ = [
    "MAX_JSON_DEPTH",
    "OpaqueItem",
    "ProviderAdapter",
    "RouteKind",
    "TextField",
    "UninspectableError",
    "WalkProfile",
    "data_uri_kind",
    "parse_json_body",
    "walk_body",
]

MAX_JSON_DEPTH: Final = 64


class RouteKind(StrEnum):
    JSON_INSPECT = "json_inspect"
    """A JSON request whose body EgressVeil understands and inspects."""
    BODYLESS = "bodyless"
    """GET/HEAD without a body. Only the URL is inspected."""
    UNSUPPORTED = "unsupported"
    """Anything else. Strict mode blocks it."""


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


OpaqueRule = Callable[[str, str, dict[str, Any]], "str | None"]
"""``(key, string value, parent object) -> kind`` when the string is binary content.

Rules only ever classify a *string*: objects and lists are always walked, so no
text can hide inside a structure that merely looks like a blob."""


def data_uri_kind(value: str) -> str | None:
    """Media type of a base64 ``data:`` URI, or ``None`` for ordinary text."""
    if value.startswith("data:"):
        head = value[:256]
        marker = head.find(";base64,")
        if marker != -1:
            return head[5:marker].split(";", 1)[0] or "binary"
    return None


@dataclass(frozen=True, slots=True)
class WalkProfile:
    skip_keys: frozenset[str] = frozenset()
    """String values under these keys are identifiers, not content (``model``, ``role``...)."""
    skip_value_keys: frozenset[str] = frozenset()
    """*String* values under these keys are provider-issued blobs (signatures, encrypted
    reasoning). Non-string values under the same keys are still inspected."""
    skip_block_types: frozenset[str] = frozenset()
    """In objects with this ``type``, the encrypted ``data`` string is skipped; every
    other field is still inspected."""
    signed_block_types: frozenset[str] = frozenset()
    """Objects with this ``type`` carry a provider signature and cannot be modified."""
    opaque_rules: tuple[OpaqueRule, ...] = ()


ErrorBody = Callable[[str, str], dict[str, Any]]


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    name: str
    mount: str
    """Path prefix on the gateway ("" for the root)."""
    inspected_routes: frozenset[str]
    profile: WalkProfile
    error_body: ErrorBody
    base_url_env: tuple[str, ...] = field(default=())
    """Environment variables agents read for this provider's base URL."""

    def classify(self, method: str, path: str, has_body: bool) -> RouteKind:
        method = method.upper()
        normalized = path.rstrip("/") or "/"
        if method == "POST" and normalized in self.inspected_routes:
            return RouteKind.JSON_INSPECT
        if method in {"GET", "HEAD"} and not has_body:
            return RouteKind.BODYLESS
        return RouteKind.UNSUPPORTED


# --------------------------------------------------------------------------- JSON


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


def walk_body(
    body: dict[str, Any], profile: WalkProfile
) -> tuple[list[TextField], list[OpaqueItem]]:
    """Collect every inspectable string field and every opaque payload."""
    fields: list[TextField] = []
    opaque: list[OpaqueItem] = []

    def visit_string(
        container: dict[str, Any] | list[Any],
        key: str | int,
        value: str,
        location: str,
        signed: bool,
    ) -> None:
        kind = data_uri_kind(value)
        if kind is not None:
            opaque.append(OpaqueItem(location, kind))
        else:
            fields.append(TextField(location, container, key, value, signed))

    stack: list[tuple[Any, str, int, bool]] = [(body, "", 0, False)]
    while stack:
        node, location, depth, signed = stack.pop()
        if depth > MAX_JSON_DEPTH:
            raise UninspectableError("nesting_too_deep", "JSON body is nested too deeply")
        if isinstance(node, dict):
            block_type = node.get("type")
            encrypted_block = isinstance(block_type, str) and block_type in profile.skip_block_types
            child_signed = signed or (
                isinstance(block_type, str) and block_type in profile.signed_block_types
            )
            for key, value in node.items():
                child_loc = _child(location, key)
                if isinstance(value, str):
                    if key in profile.skip_value_keys or key in profile.skip_keys:
                        continue
                    if encrypted_block and key == "data":
                        continue
                    kind = next(
                        (k for rule in profile.opaque_rules if (k := rule(key, value, node))),
                        None,
                    )
                    if kind is not None:
                        opaque.append(OpaqueItem(child_loc, kind))
                        continue
                    visit_string(node, key, value, child_loc, child_signed)
                elif isinstance(value, dict | list):
                    stack.append((value, child_loc, depth + 1, child_signed))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                child_loc = _child(location, index)
                if isinstance(value, str):
                    visit_string(node, index, value, child_loc, signed)
                elif isinstance(value, dict | list):
                    stack.append((value, child_loc, depth + 1, signed))
    fields.sort(key=lambda f: f.location)
    return fields, opaque
