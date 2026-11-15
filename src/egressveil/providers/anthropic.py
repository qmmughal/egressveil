"""Anthropic Messages API adapter (Claude Code; Aider with Anthropic models)."""

from __future__ import annotations

from typing import Any

from egressveil.providers.base import ProviderAdapter, WalkProfile

__all__ = ["ADAPTER"]


def _base64_source(key: str, value: str, parent: dict[str, Any]) -> str | None:
    """The ``data`` string of a ``{"type": "base64", ...}`` image/document source."""
    if key == "data" and parent.get("type") == "base64":
        kind = parent.get("media_type")
        return kind if isinstance(kind, str) else "binary"
    return None


def _error_body(error_type: str, message: str) -> dict[str, Any]:
    return {"type": "error", "error": {"type": error_type, "message": message}}


ADAPTER = ProviderAdapter(
    name="anthropic",
    mount="",
    inspected_routes=frozenset({"/v1/messages", "/v1/messages/count_tokens"}),
    profile=WalkProfile(
        skip_keys=frozenset({"model", "type", "role", "id", "tool_use_id", "media_type"}),
        skip_value_keys=frozenset({"signature"}),
        skip_block_types=frozenset({"redacted_thinking"}),
        signed_block_types=frozenset({"thinking"}),
        opaque_rules=(_base64_source,),
    ),
    error_body=_error_body,
    base_url_env=("ANTHROPIC_BASE_URL",),
)
