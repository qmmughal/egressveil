"""Redaction engine.

Not implemented in Phase 0. The redactor will replace detected spans with
stable placeholders. By design it will never automatically restore original
secrets into model output that becomes an executable tool call. See
``docs/security-design.md``.
"""

from __future__ import annotations
