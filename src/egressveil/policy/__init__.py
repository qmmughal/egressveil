"""Policy engine.

Phase 0 defines only the policy vocabulary used by configuration. Rule
evaluation is planned for a later phase (see ``docs/roadmap.md``).
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["GatewayMode", "PolicyAction"]


class PolicyAction(StrEnum):
    """What the gateway does when a detector produces a finding."""

    ALLOW = "ALLOW"
    """Forward the request unchanged and do not record the finding."""

    REDACT = "REDACT"
    """Replace the sensitive span with a placeholder, then forward."""

    BLOCK = "BLOCK"
    """Reject the request locally; nothing is sent upstream."""

    LOG_ONLY = "LOG_ONLY"
    """Forward unchanged but record a (secret-free) audit event."""


class GatewayMode(StrEnum):
    """How the gateway treats traffic it cannot fully inspect."""

    STRICT = "strict"
    """Fail closed: unsupported or uninspectable requests are blocked."""

    PERMISSIVE = "permissive"
    """Fail open with an audit event. Intended for evaluation only."""
