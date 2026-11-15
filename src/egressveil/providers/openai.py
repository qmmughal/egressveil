"""OpenAI-compatible API adapter (Aider via LiteLLM, OpenAI SDK based agents).

Mounted under ``/openai`` on the gateway, so the agent's base URL is
``http://127.0.0.1:<port>/openai/v1``.

Opaque content: base64 ``data:`` URIs (images in ``image_url``,
``input_image``), ``input_audio`` and inline ``file_data``. Encrypted
reasoning (``encrypted_content``) is provider-issued and skipped.
"""

from __future__ import annotations

from typing import Any

from egressveil.providers.base import ProviderAdapter, WalkProfile

__all__ = ["ADAPTER"]


_AUDIO_FORMATS = frozenset({"wav", "mp3", "flac", "opus", "pcm16", "aac", "m4a", "ogg"})


def _audio_or_file(key: str, value: str, parent: dict[str, Any]) -> str | None:
    """Inline audio (``input_audio.data``) and inline files (``file_data``)."""
    fmt = parent.get("format")
    if key == "data" and isinstance(fmt, str) and fmt in _AUDIO_FORMATS:
        return f"audio/{fmt}"
    if key == "file_data":
        return "file"
    return None


def _error_body(error_type: str, message: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": error_type, "param": None, "code": "egressveil"}}


ADAPTER = ProviderAdapter(
    name="openai",
    mount="/openai",
    inspected_routes=frozenset(
        {"/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/embeddings"}
    ),
    profile=WalkProfile(
        skip_keys=frozenset({"model", "type", "role", "id", "tool_call_id", "call_id", "object"}),
        skip_value_keys=frozenset({"encrypted_content"}),
        opaque_rules=(_audio_or_file,),
    ),
    error_body=_error_body,
    base_url_env=("OPENAI_BASE_URL", "OPENAI_API_BASE"),
)
