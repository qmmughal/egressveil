"""Personal-data (PII) detector.

Rules: email addresses, phone numbers (international ``+`` format and
North-American ``(555) 123-4567`` style), US Social Security numbers, payment
card numbers (Luhn-validated, known issuer prefixes) and IBANs (mod-97).

False-positive control: example/test/no-reply email domains, file names such
as ``icon@2x.png`` and service accounts such as ``git@github.com`` are
ignored; numbers must pass checksums or structural checks.
"""

from __future__ import annotations

import re
from typing import Final

from egressveil.detectors.patterns import PatternDetector, PatternRule

__all__ = ["PII_RULES", "iban_valid", "luhn_valid", "make_pii_detector"]

_EXAMPLE_DOMAINS: Final = frozenset(
    {"example.com", "example.org", "example.net", "localhost", "users.noreply.github.com"}
)
_RESERVED_TLDS: Final = frozenset({"example", "test", "invalid", "localhost", "local"})
_SERVICE_LOCALPARTS: Final = frozenset({"git", "noreply", "no-reply", "donotreply", "do-not-reply"})
_FILE_TLDS: Final = frozenset(
    {
        "png", "jpg", "jpeg", "gif", "svg", "webp", "ico", "bmp", "js", "mjs", "ts", "tsx",
        "jsx", "css", "scss", "py", "rb", "go", "rs", "md", "txt", "json", "yaml", "yml",
        "toml", "lock", "map", "html", "xml", "pdf", "zip", "gz", "tar", "whl", "so", "dll",
    }
)  # fmt: skip


def _email_ok(value: str) -> bool:
    local, _, domain = value.rpartition("@")
    domain = domain.lower()
    tld = domain.rsplit(".", 1)[-1]
    if tld in _FILE_TLDS or tld in _RESERVED_TLDS:
        return False
    if domain in _EXAMPLE_DOMAINS or any(domain.endswith("." + d) for d in _EXAMPLE_DOMAINS):
        return False
    return local.lower() not in _SERVICE_LOCALPARTS


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def luhn_valid(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card_ok(value: str) -> bool:
    separators = {c for c in value if not c.isdigit()}
    if len(separators) > 1:
        return False
    digits = _digits(value)
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    two, four = int(digits[:2]), int(digits[:4])
    issuer = (
        digits[0] == "4"
        or 51 <= two <= 55
        or 2221 <= four <= 2720
        or two in {34, 37, 36, 38, 30, 35, 65}
        or four == 6011
        or 644 <= int(digits[:3]) <= 649
        or digits.startswith("62")
    )
    return issuer and luhn_valid(digits)


def iban_valid(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


def _phone_ok(value: str) -> bool:
    return 8 <= len(_digits(value)) <= 15


def _ssn_ok(value: str) -> bool:
    area, group, serial = value.split("-")
    return area not in {"000", "666"} and area[0] != "9" and group != "00" and serial != "0000"


PII_RULES: tuple[PatternRule, ...] = (
    PatternRule(
        "email",
        re.compile(
            r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]{1,64}@"
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}"
            r"(?![A-Za-z0-9\-])"
        ),
        confidence=0.9,
        validator=_email_ok,
    ),
    PatternRule(
        "phone_international",
        re.compile(r"(?<![\w+])\+[1-9]\d{0,2}(?:[ .\-]?\(?\d{1,4}\)?){1,5}(?![\d])"),
        confidence=0.7,
        validator=_phone_ok,
    ),
    PatternRule(
        "phone_nanp",
        re.compile(r"(?<![\w(])\(?[2-9]\d{2}\)?[ .\-][2-9]\d{2}[ .\-]\d{4}(?![\d])"),
        confidence=0.6,
    ),
    PatternRule(
        "us_ssn",
        re.compile(r"(?<![\d\-])\d{3}-\d{2}-\d{4}(?![\d\-])"),
        confidence=0.75,
        validator=_ssn_ok,
    ),
    PatternRule(
        "payment_card",
        re.compile(r"(?<![\d\-])\d(?:[ \-]?\d){12,18}(?![\d\-])"),
        confidence=0.85,
        validator=_card_ok,
    ),
    PatternRule(
        "iban",
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b"),
        confidence=0.9,
        validator=iban_valid,
    ),
)


def make_pii_detector() -> PatternDetector:
    return PatternDetector("pii", PII_RULES)
