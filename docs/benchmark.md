# Detection benchmark

Measured with `python scripts/benchmark.py` on EgressVeil 0.7.0 (Windows 11, Python 3.12). Re-run it to reproduce. CI enforces the key results on every change (`tests/test_quality.py`): 100% recall on the labelled corpus, and zero secret or token false positives on the Python standard library.

## Method

- **Recall.** All 27 rules are tested against 93 labelled cases. Vendor keys appear in five realistic contexts each: config line, JSON, log line, shell export and CI YAML. Context-specific rules (URL credentials, `.env` lines, PII) have their own samples. Values are generated at run time, so the repository contains no real secrets.
- **False positives.** Every finding in real source code is counted as a false positive. The corpus is the Python standard library (test directories excluded) plus aiohttp, PyYAML, Typer, Rich, pip, jsonschema, mypy and pytest. That code contains no live credentials or customer data.
- The default policy and detectors are used, with `include_private_ips` off.

## Results

- Recall: **93/93 (100.0%)** across 27 rules
- False-positive corpus: **2344 files, 29.0 MB** (Python 3.12.2 standard library plus aiohttp, yaml, typer, rich, pip, jsonschema, mypy, _pytest)
- Scan throughput: **4.3 MB/s** (all four detectors, one core)

| Detector | False positives | Per MB of code |
| --- | --- | --- |
| `secrets` | 0 | 0 |
| `tokens` | 0 | 0 |
| `pii` | 0 | 0 |
| `internal_hostnames` | 4 | 0.138 |

Not counted above: **172 real email addresses** (author and maintainer credits in the source). They are correct `pii/email` detections; allow them with a `pattern` entry if you don't need them redacted.

| Rule | False positives |
| --- | --- |
| `internal_hostnames/internal_suffix` | 4 |


## Reading the numbers

- **Secrets and tokens: 0 false positives in 29 MB** of real code. This is the category that blocks requests by default, so it is the one that must not misfire.
- **The 4 remaining `internal_suffix` hits** are prose and dotted names that end in `.internal`, such as `non-localized.internal token`. Python import paths such as `from librt.internal import ...` are recognised and skipped. You can turn the generic suffixes off with `include_common_internal_suffixes: false` and list your real domains in `internal_domains` instead.
- **Recall on a labelled corpus is an upper bound.** Secrets that are encoded, split or in an unknown vendor format can still get through. See the README's Security limitations.

## Changes found by this benchmark (0.7.0)

- Scanning got **about 5x faster** (from 0.9 MB/s): cheap substring pre-checks per rule, regexes that start with a character class instead of a lookbehind, and case-folded matching instead of `IGNORECASE`.
- `phone_international` no longer matches decimals such as `Decimal('+35236450.6')`.
- `internal_hostnames` skips Python import paths (17 to 4 false positives).
