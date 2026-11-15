"""Detection quality gates: recall, false positives on real code, adversarial timing."""

from __future__ import annotations

import sys
import sysconfig
import time
from pathlib import Path

import pytest

from egressveil.detectors.patterns import SECRET_RULES, TOKEN_RULES
from egressveil.detectors.pii import PII_RULES
from tests.helpers import make_inspector

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import benchmark

INSPECTOR = make_inspector({"detectors": {"internal_hostnames": {"include_private_ips": True}}})


def test_recall_is_complete_for_every_rule() -> None:
    covered: dict[str, list[bool]] = {}
    for rule, text in benchmark.positive_cases():
        hit = any(f.rule_id == rule for f, _, _ in INSPECTOR.evaluate_text(text))
        covered.setdefault(rule, []).append(hit)
    missed = {r: hits.count(False) for r, hits in covered.items() if not all(hits)}
    assert missed == {}
    all_rules = {r.rule_id for r in (*SECRET_RULES, *TOKEN_RULES, *PII_RULES)}
    assert all_rules <= set(covered) | {"internal_domain"}, all_rules - set(covered)


def test_no_secret_or_token_false_positives_on_stdlib() -> None:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    hits: list[str] = []
    for path in sorted(stdlib.glob("*.py")):
        text = path.read_text(encoding="utf-8", errors="replace")
        hits += [
            f"{path.name}:{f.rule_id}"
            for f, _, _ in INSPECTOR.evaluate_text(text)
            if f.detector in {"secrets", "tokens"}
        ]
    assert hits == []


# Inputs designed to make a naive regex backtrack: long runs of characters the
# pattern accepts, without the terminator it needs.
ADVERSARIAL = {
    "key prefixes": "sk-ant-" + "a" * 60_000 + " ghp_" + "b" * 60_000 + " xoxb-" + "-" * 60_000,
    "private key header": "-----BEGIN RSA PRIVATE KEY-----\n" + "A" * 120_000,
    "url credentials": "postgres://" + "u" * 30_000 + ":" + "p" * 30_000 + " " + "://" * 20_000,
    "assignments": "password = '" + "x" * 50_000 + "\n" + "API_KEY=" + "y" * 50_000,
    "email": "a" * 70_000 + "@" + "b." * 30_000,
    "phones": "+1 " + "2 " * 40_000 + " (" * 20_000,
    "digits": "1 " * 60_000 + "4" * 60_000,
    "iban": "GB82 " + "ABCD " * 30_000,
    "hostnames": "a." * 60_000 + "internal " + "x-" * 30_000 + "corp",
    "jwt": "eyJ" + "a" * 50_000 + ".eyJ" + "b" * 50_000 + ".",
    "bearer": "Bearer " + "A" * 100_000,
    "private ips": "10." * 40_000 + "192.168." * 10_000,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_adversarial_input_scans_quickly(name: str) -> None:
    text = ADVERSARIAL[name]
    started = time.perf_counter()
    INSPECTOR.evaluate_text(text)
    elapsed = time.perf_counter() - started
    assert elapsed < 3.0, f"{name}: {elapsed:.2f}s for {len(text)} chars"
