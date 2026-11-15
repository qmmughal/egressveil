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
_HOST_CHARS: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
_LABEL_RE: Final = re.compile(_LABEL)
_PRIVATE_IPV4: Final = re.compile(
    r"(?<![\d.])(?:10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r"|192\.168(?:\.\d{1,3}){2})(?![\d.]|\.\d)"
)


def _is_python_import(text: str, begin: int) -> bool:
    line_start = text.rfind("\n", 0, begin) + 1
    head = text[line_start:begin].lstrip()
    return head in {"from ", "import "} or (head.startswith("import ") and head.endswith(", "))


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
        self._suffix: re.Pattern[str] | None = None
        if suffixes:
            # Find the suffix first (fast literal alternation), then walk left
            # over hostname characters. Underscores never occur in hostnames,
            # so "detectors.internal_x" or "obj._internal" are code, not hosts.
            alternation = "|".join(re.escape(x) for x in suffixes)
            # Case-sensitive on lower-cased text: much faster than IGNORECASE.
            self._suffix = re.compile(
                rf"(?<![A-Za-z0-9\-_])(?:{alternation})(?![A-Za-z0-9\-_]|\.[A-Za-z0-9])"
            )
        self._private_ips = include_private_ips

    @property
    def category(self) -> str:
        return "internal_hostnames"

    def scan(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        if self._suffix is not None:
            lower = text.lower()
            if len(lower) != len(text):  # non-ASCII case folding changed offsets
                lower = "".join(c if len(c.lower()) != 1 else c.lower() for c in text)
            for m in self._suffix.finditer(lower):
                suffix = m.group(0)
                begin = m.start()
                while begin > 0 and m.start() - begin < 253 and text[begin - 1] in _HOST_CHARS:
                    begin -= 1
                while begin < m.start() and text[begin] in ".-":
                    begin += 1
                prefix = text[begin : m.start()]
                if prefix and not prefix.endswith("."):
                    continue  # "-corp" or similar: not a label boundary
                labels = prefix.rstrip(".").split(".") if prefix else []
                if labels and not all(_LABEL_RE.fullmatch(label) for label in labels):
                    continue
                if not prefix and suffix not in self._configured:
                    continue  # bare "lan"/"corp" are words, not hosts
                if _is_python_import(text, begin):
                    continue  # "from librt.internal import x" is a module path
                host = text[begin : m.end()].lower()
                if host in _PUBLIC_DEV_NAMES:
                    continue
                rule = "internal_domain" if suffix in self._configured else "internal_suffix"
                findings.append(Finding("internal_hostnames", rule, begin, m.end(), 0.85))
        if self._private_ips:
            for m in _PRIVATE_IPV4.finditer(text):
                if all(int(o) <= 255 for o in m.group(0).split(".")):
                    findings.append(
                        Finding("internal_hostnames", "private_ipv4", m.start(), m.end(), 0.6)
                    )
        return findings
