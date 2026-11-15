"""Audit logging.

Not implemented in Phase 0. Audit events will record detector, rule, policy
action, offsets and a keyed hash for correlation, but never the raw
sensitive value. Configuration validation already rejects settings that
would log raw values.
"""

from __future__ import annotations
