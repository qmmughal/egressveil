"""Local HTTP gateway.

Not implemented in Phase 0. The gateway will listen on loopback only by
default, forward supported provider API calls to allowlisted upstreams, and
enforce bounded request bodies and streaming buffers. See
``docs/architecture.md``.
"""

from __future__ import annotations
