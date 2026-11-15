"""Internal-hostname detector.

Matches hostnames under:

* the organisation's ``internal_domains`` from configuration (and the bare
  domains themselves), and
* conventional private suffixes (``.internal``, ``.corp``, ``.intranet``,
  ``.lan``, ``.home.arpa``) unless ``include_common_internal_suffixes`` is
  false. Well-known public development names such as
  ``host.docker.internal`` are ignored.

Optionally (``include_private_ips``) RFC 1918 IPv4 addresses are reported as
``private_ipv4``. That is off by default because example code is full of them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Final

from egressveil.detectors import Finding

__all__ = ["COMMON_INTERNAL_SUFFIXES", "HostnameDetector"]

COMMON_INTERNAL_SUFFIXES: Final = ("internal", "corp", "intranet", "lan", "home.arpa")
_PUBLIC_DEV_NAMES: Final = frozenset(
    {
        "host.docker.internal",
        "gateway.docker.internal",
        "kubernetes.docker.internal",
        "metadata.google.internal",
    }
)
_LABEL: Final = r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
_PRIVATE_IPV4: Final = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2})(?![\d.]|\.\d)"
)


class HostnameDetector:
    def __init__(
        self,
        internal_domains: Iterable[str] = (),
        *,
        include_common_internal_suffixes: bool = True,
        include_private_ips: bool = False,
    ) -> None:
        configured = sorted(
            {d.lower().strip(".") for d in internal_domains if d}, key=len, reverse=True
        )
        suffixes = list(configured)
        if include_common_internal_suffixes:
            suffixes += list(COMMON_INTERNAL_SUFFIXES)
        self._configured = frozenset(configured)
        self._pattern: re.Pattern[str] | None = None
        if suffixes:
            alternation = "|".join(re.escape(s) for s in suffixes)
            # Labels before the suffix are optional only for configured domains
            # (the bare domain itself is internal); bare "lan"/"corp" are words.
            self._pattern = re.compile(
                # Underscores never occur in hostnames: "detectors.internal_x" or
                # "obj._internal" are code, not hosts.
                rf"(?<![A-Za-z0-9.\-_])((?:{_LABEL}\.){{0,10}})({alternation})"
                rf"(?![A-Za-z0-9\-_]|\.[A-Za-z0-9])",
                re.IGNORECASE,
            )
        self._private_ips = include_private_ips

    @property
    def category(self) -> str:
        return "internal_hostnames"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if self._pattern is not None:
            for m in self._pattern.finditer(text):
                prefix, suffix = m.group(1), m.group(2).lower()
                host = m.group(0).lower()
                if not prefix and suffix not in self._configured:
                    continue
                if host in _PUBLIC_DEV_NAMES:
                    continue
                rule = "internal_domain" if suffix in self._configured else "internal_suffix"
                findings.append(Finding("internal_hostnames", rule, m.start(), m.end(), 0.85))
        if self._private_ips:
            for m in _PRIVATE_IPV4.finditer(text):
                if all(int(o) <= 255 for o in m.group(0).split(".")):
                    findings.append(
                        Finding("internal_hostnames", "private_ipv4", m.start(), m.end(), 0.6)
                    )
        return findings
