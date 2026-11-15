"""LLM provider definitions.

``KNOWN_PROVIDERS`` holds the static facts used by configuration validation
(official endpoints for allowlisting). Request parsing lives in one adapter
per API (:mod:`.anthropic`, :mod:`.openai`), built on :mod:`.base`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from egressveil.providers.base import ProviderAdapter

__all__ = ["KNOWN_PROVIDERS", "ProviderSpec", "adapter_for_path", "adapters"]


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Static description of a supported upstream API."""

    name: str
    default_upstream_url: str
    allowed_hosts: frozenset[str]
    description: str


KNOWN_PROVIDERS: dict[str, ProviderSpec] = {
    "anthropic": ProviderSpec(
        name="anthropic",
        default_upstream_url="https://api.anthropic.com",
        allowed_hosts=frozenset({"api.anthropic.com"}),
        description="Anthropic Messages API (used by Claude Code and Aider).",
    ),
    "openai": ProviderSpec(
        name="openai",
        default_upstream_url="https://api.openai.com",
        allowed_hosts=frozenset({"api.openai.com"}),
        description="OpenAI Chat Completions / Responses API (used by Aider).",
    ),
}


def adapters() -> dict[str, ProviderAdapter]:
    """All request adapters, keyed by provider name."""
    from egressveil.providers import anthropic, openai

    return {"anthropic": anthropic.ADAPTER, "openai": openai.ADAPTER}


def adapter_for_path(path: str) -> tuple[ProviderAdapter, str]:
    """Pick the adapter for a gateway path and return the upstream path.

    ``/openai/...`` goes to the OpenAI adapter with the prefix removed;
    everything else goes to the Anthropic adapter unchanged.
    """
    table = adapters()
    for adapter in table.values():
        mount = adapter.mount
        if mount and (path == mount or path.startswith(mount + "/")):
            return adapter, path[len(mount) :] or "/"
    return table["anthropic"], path
