"""Detection benchmark: recall on a labelled positive corpus, false positives on real code.

Usage:
    python scripts/benchmark.py              # print a report
    python scripts/benchmark.py --markdown   # print the docs/benchmark.md body
    python scripts/benchmark.py --json       # machine-readable results

Positive corpus: every rule, embedded in several realistic contexts (config
files, shell exports, JSON, logs, code). Values are generated at run time
(tests/fakes.py), so the repository contains no real or real-looking secrets.

Negative corpus: real-world source code that should contain no live secrets
or personal data: the Python standard library (test directories excluded)
and widely used third-party packages installed in this environment. Every
finding there is counted as a false positive, which overstates the rate a
little, because some files contain deliberate example data.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import secrets
import sys
import sysconfig
import time
from collections import Counter
from collections.abc import Callable, Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests import fakes  # noqa: E402

from egressveil.audit import AuditLogger  # noqa: E402
from egressveil.config import parse_config  # noqa: E402
from egressveil.inspection import Inspector  # noqa: E402
from egressveil.redactor import Redactor  # noqa: E402

THIRD_PARTY = ("aiohttp", "yaml", "typer", "rich", "pip", "jsonschema", "mypy", "_pytest")
TEXT_SUFFIXES = (".py", ".pyi", ".txt", ".md", ".rst", ".cfg", ".toml", ".ini", ".json")
MAX_FILE = 2 * 1024 * 1024

CONTEXTS: tuple[Callable[[str], str], ...] = (
    lambda v: f"value = {v}\n",
    lambda v: f'{{"credential": "{v}", "enabled": true}}',
    lambda v: f"2026-11-16T10:00:00Z INFO connecting with {v} to upstream\n",
    lambda v: f"# TODO rotate\nexport SERVICE_TOKEN_VALUE={v}\n",
    lambda v: f"  - name: deploy\n    run: ./deploy.sh '{v}'\n",
)

# rule_id -> value factory. Context-sensitive rules get their own wrappers.
POSITIVES: dict[str, Callable[[], str]] = {
    "anthropic_api_key": fakes.anthropic_key,
    "openai_api_key": fakes.openai_key,
    "aws_access_key_id": fakes.aws_access_key_id,
    "github_token": fakes.github_token,
    "github_fine_grained_pat": fakes.github_fine_grained,
    "gitlab_token": fakes.gitlab_token,
    "slack_token": fakes.slack_token,
    "slack_webhook": fakes.slack_webhook,
    "stripe_secret_key": fakes.stripe_key,
    "google_api_key": fakes.google_api_key,
    "npm_token": fakes.npm_token,
    "huggingface_token": fakes.huggingface_token,
    "private_key": fakes.private_key_block,
    "jwt": fakes.jwt,
}
WRAPPED: dict[str, list[str]] = {
    "aws_secret_access_key": [
        f"aws_secret_access_key = {fakes.aws_secret()}\n",
        f'AWS_SECRET_ACCESS_KEY="{fakes.aws_secret()}"\n',
    ],
    "url_credentials": [
        f"DATABASE_URL=postgres://app:{fakes.db_password()}@db:5432/app\n",
        f"redis://default:{fakes.db_password()}@cache.example.net:6379/0",
    ],
    "generic_secret_assignment": [
        f'client_secret = "{fakes.db_password()}"\n',
        f"{{'api_key': '{fakes.db_password()}'}}",
    ],
    "env_file_assignment": [
        f"STRIPE_WEBHOOK_SECRET={fakes.db_password()}\n",
        f"export DB_PASSWORD={fakes.db_password()}  # prod\n",
    ],
    "bearer_token": [f"Authorization: Bearer Q9{fakes.rand(30)}\n"],
    "basic_auth_header": [f"Authorization: Basic {fakes.rand(24)}==\n"],
    "email": ["Contact jane.doe@acme-corp.io for access.", "From: Ann <ann@mail.acme.co.uk>"],
    "phone_international": ["call +44 20 7946 0958", "tel +1-415-555-0132"],
    "phone_nanp": ["office (212) 555-0147", "fax 415.555.0199"],
    "us_ssn": ["ssn: 123-45-6789"],
    "payment_card": ["card 4111 1111 1111 1111", "5500-0000-0000-0004"],
    "iban": ["IBAN GB82 WEST 1234 5698 7654 32", "DE89370400440532013000"],
    "internal_suffix": ["curl http://billing.svc.internal/health", "ssh jenkins.corp"],
}


def make_inspector() -> Inspector:
    config, issues = parse_config({})
    assert config is not None, issues
    key = secrets.token_bytes(32)
    return Inspector.from_config(config, redactor=Redactor(key), audit=AuditLogger(None, key))


def positive_cases() -> Iterator[tuple[str, str]]:
    for rule, factory in POSITIVES.items():
        for ctx in CONTEXTS:
            yield rule, ctx(factory())
    for rule, samples in WRAPPED.items():
        for sample in samples:
            yield rule, sample


def negative_files() -> Iterator[tuple[str, Path]]:
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    for path in stdlib.rglob("*.py"):
        parts = {p.lower() for p in path.relative_to(stdlib).parts}
        if parts & {"test", "tests", "idlelib", "site-packages", "__pycache__"}:
            continue
        yield "stdlib", path
    for name in THIRD_PARTY:
        spec = importlib.util.find_spec(name)
        if spec is None or spec.origin is None:
            continue
        base = Path(spec.origin).parent
        for path in base.rglob("*"):
            if path.suffix in TEXT_SUFFIXES and "tests" not in path.parts and path.is_file():
                yield name, path


def run() -> dict[str, object]:
    inspector = make_inspector()

    per_rule: dict[str, list[int]] = {}
    for rule, text in positive_cases():
        hit = any(f.rule_id == rule for f, _, _ in inspector.evaluate_text(text))
        total, found = per_rule.setdefault(rule, [0, 0])
        per_rule[rule] = [total + 1, found + int(hit)]
    cases = sum(t for t, _ in per_rule.values())
    found = sum(f for _, f in per_rule.values())

    fp_rules: Counter[str] = Counter()
    fp_detectors: Counter[str] = Counter()
    bytes_scanned = 0
    files = 0
    genuine_emails = 0
    started = time.perf_counter()
    for _, path in negative_files():
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > MAX_FILE:
            continue
        text = data.decode("utf-8", errors="replace")
        bytes_scanned += len(data)
        files += 1
        for f, _, _ in inspector.evaluate_text(text):
            if f.rule_id == "email":
                # Real addresses (author credits, maintainers): correct detections,
                # reported separately instead of as false positives.
                genuine_emails += 1
                continue
            fp_rules[f"{f.detector}/{f.rule_id}"] += 1
            fp_detectors[f.detector] += 1
    elapsed = time.perf_counter() - started
    mb = bytes_scanned / 1_000_000

    return {
        "positive_cases": cases,
        "positive_found": found,
        "recall": found / cases if cases else 0.0,
        "missed_rules": sorted(r for r, (t, f) in per_rule.items() if f < t),
        "per_rule": {r: {"cases": t, "found": f} for r, (t, f) in sorted(per_rule.items())},
        "negative_files": files,
        "negative_mb": round(mb, 1),
        "scan_seconds": round(elapsed, 1),
        "throughput_mb_s": round(mb / elapsed, 1) if elapsed else 0.0,
        "genuine_emails_in_corpus": genuine_emails,
        "false_positives_by_detector": dict(fp_detectors.most_common()),
        "false_positives_by_rule": dict(fp_rules.most_common()),
        "false_positives_per_mb": {d: round(n / mb, 3) for d, n in fp_detectors.most_common()}
        if mb
        else {},
        "python": sys.version.split()[0],
    }


def markdown(r: dict[str, object]) -> str:
    per_rule = r["per_rule"]
    assert isinstance(per_rule, dict)
    fps = r["false_positives_by_rule"]
    assert isinstance(fps, dict)
    rate = r["false_positives_per_mb"]
    assert isinstance(rate, dict)
    lines = [
        f"- Recall: **{r['positive_found']}/{r['positive_cases']} "
        f"({float(r['recall']):.1%})** across {len(per_rule)} rules",
        f"- False-positive corpus: **{r['negative_files']} files, {r['negative_mb']} MB** "
        f"(Python {r['python']} standard library plus {', '.join(THIRD_PARTY)})",
        f"- Scan throughput: **{r['throughput_mb_s']} MB/s** (all four detectors, one core)",
        "",
        "| Detector | False positives | Per MB of code |",
        "| --- | --- | --- |",
    ]
    by_det = r["false_positives_by_detector"]
    assert isinstance(by_det, dict)
    for det in ("secrets", "tokens", "pii", "internal_hostnames"):
        lines.append(f"| `{det}` | {by_det.get(det, 0)} | {rate.get(det, 0)} |")
    lines += [
        "",
        f"Not counted above: **{r['genuine_emails_in_corpus']} real email addresses** "
        "(author and maintainer credits in the source). They are correct `pii/email` "
        "detections; allow them with a `pattern` entry if you don't need them redacted.",
        "",
        "| Rule | False positives |",
        "| --- | --- |",
    ]
    lines += [f"| `{rule}` | {n} |" for rule, n in fps.items()] or ["| (none) | 0 |"]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    args = parser.parse_args()
    result = run()
    if args.json:
        print(json.dumps(result, indent=2))
    elif args.markdown:
        print(markdown(result))
    else:
        print(markdown(result))
        if result["missed_rules"]:
            print(f"\nMISSED: {result['missed_rules']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
