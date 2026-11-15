"""LLM provider definitions.

A provider describes an upstream LLM API that EgressVeil knows how to parse.
Phase 0 ships only the registry of known providers and their official
endpoints, which configuration validation uses for endpoint allowlisting.
Request/response parsers are planned for a later phase.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["KNOWN_PROVIDERS", "ProviderSpec"]


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
