# Roadmap

The phases are ordered by dependency. Each phase ships only when its tests,
documentation and threat-model review are complete. There are no dates.

## Phase 0: Foundation (done)

- [x] `src/` package layout, Hatchling build, MIT license
- [x] CLI: `version`, `config validate`, `doctor`
- [x] Strict config schema with secure defaults that validation enforces
- [x] CI: Ruff, strict mypy, pytest on Python 3.11 and 3.12 across Linux,
      macOS and Windows, plus dependency auditing
- [x] Architecture, threat model, security design and integration docs

## Phase 1: Claude Code gateway (done, v0.2.0)

- [x] `egressveil serve`: an async aiohttp gateway on loopback with body and
      stream limits
- [x] An Anthropic Messages API parser that walks every string field (system,
      messages, tool_use, tool_result, tools, unknown fields), with streaming
      SSE passthrough
- [x] Secret and token detectors: vendor key patterns, private keys, URL
      credentials, generic and `.env` assignments, JWTs, bearer and Basic auth
      headers, with positive and false-positive test sets
- [x] Policy engine with most-restrictive-wins evaluation
- [x] Redactor with stable keyed placeholders (stable across requests, not
      just within one, so prompt caching keeps working)
- [x] JSONL audit log with keyed digests and restrictive file permissions
- [x] Strict-mode fail-closed paths, each covered by tests
- [x] Provider-shaped error responses for `BLOCK`
- [x] End-to-end tests against a local mock upstream (no real API calls in CI)
- [x] Host-header (DNS-rebinding) and browser-`Origin` protection
- [x] `egressveil scan` for files and stdin
- [x] Doctor detects a running gateway

Known gaps carried forward:

- [ ] Validate against a wider range of real Claude Code sessions and record
      any endpoints that are blocked as `unsupported_route` (moved to Phase 3)
- [x] Optional support for an upstream HTTPS proxy, for corporate networks
      (v0.3.0: `gateway.upstream_proxy`)

## Phase 2: Aider and broader detection (done, v0.3.0)

- [x] OpenAI-compatible parser, mounted at `/openai`: Chat Completions,
      Responses, Completions and Embeddings
- [x] PII detectors: email, international and North-American phone, US SSN,
      payment card (Luhn), IBAN (mod-97). Locale coverage is international
      formats plus the US; more national ID formats are welcome as
      contributions
- [x] Internal-hostname detector driven by `internal_domains`, with private
      suffixes and optional private IPv4 addresses
- [x] `egressveil run -- <agent> [args]`: launches the agent with base URLs set
- [x] Doctor verifies end to end that routing works (canary self-test)
- [x] Verified with real clients: Aider 0.86.2 and the OpenAI and Anthropic
      Python SDKs, against the live APIs

## Phase 3: More agents and operational maturity (done, v0.4.0)

- [x] OpenClaw integration: researched, with `egressveil setup openclaw`
      and a doctor check. Not yet verified end to end with a running
      OpenClaw
- [x] Cursor assessed: not technically possible, because model requests
      come from Cursor's servers. Documented, and reported by `setup` and
      `doctor`
- [x] Shareable policy packs (`balanced`, `redact`, `strict`, `audit`),
      `extends`, and per-project overrides (`extends: user`)
- [x] Allowlists by keyed digest, pattern or rule
- [x] Optional response-side inspection, audit-only, with streaming deltas
      reassembled
- [x] Live validation with Claude Code 2.1.325 (routes used, block
      message, redact pack)
- [x] Signed GitHub releases with build provenance (v0.2.0)
- [x] PyPI release via Trusted Publishing (`pip install egressveil`, v0.2.0)

## Path to 1.0

A 1.0 release is a promise. The config, CLI and audit formats won't break
without a major version, and the protection claims are measured, not
assumed.

### 0.6: Frozen contracts (done)

- [x] Audit events carry `schema_version`, and the published JSON Schema
      ships in the package. Tests validate real gateway output against it
- [x] Versioned health endpoint schema
- [x] Configuration and CLI references (`docs/configuration.md`,
      `docs/cli.md`), with tests that fail if a key or command is
      undocumented
- [x] Versioning and deprecation policy (`docs/versioning.md`)

### 0.7: Measured quality

- [ ] A detection benchmark: recall on a labelled positive corpus and
      false-positive rate on real-world code, with the numbers published
- [ ] Property-based fuzzing of the request parser and the inspector
- [ ] Regex timing tests on adversarial input for every rule
- [ ] Performance and soak numbers: latency overhead and memory during long
      streams

### 0.8: Hardening

- [ ] CodeQL and OpenSSF Scorecard in CI, and an SBOM with every release
- [ ] HTTP edge-case tests: request smuggling, malformed chunked bodies,
      oversized headers
- [ ] Optional background service: Windows Task Scheduler, macOS launchd,
      Linux systemd `--user`

### 1.0.0-rc: Live validation

- [ ] A live Claude Code session with a real key, covering the tool-result
      path. Needs the maintainer's API key
- [ ] OpenClaw end to end
- [ ] Re-validate on the latest Claude Code and Aider releases

### 1.0.0

- [ ] An rc feedback window, with no open critical or high-severity issues

## Future ideas

These are not scheduled. Contributions are welcome.

- More national ID formats for the `pii` detector
- Optional redaction of streamed responses (currently audit-only)
- Packaged policy packs that are shared and versioned like dependencies

## Non-goals

- TLS interception or installing a root CA
- A system-wide firewall or egress control for every process
- Any telemetry
