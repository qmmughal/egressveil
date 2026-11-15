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

## Phase 1: Claude Code gateway (current)

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
      any endpoints that are blocked as `unsupported_route`
- [ ] Optional support for an upstream HTTPS proxy, for corporate networks

## Phase 2: Aider and broader detection

- [ ] OpenAI-compatible Chat Completions parser
- [ ] PII detectors (email, phone, national ID formats) with locale awareness
- [ ] Internal-hostname detector driven by `internal_domains`
- [ ] `egressveil run -- <agent> [args]`: launches the agent with base URLs set
- [ ] Doctor verifies end to end that routing works

## Phase 3: More agents and operational maturity

- [ ] OpenClaw integration (research first)
- [ ] Experimental Cursor support where technically possible, with its
      coverage documented
- [ ] Shareable policy packs and per-project overrides
- [ ] Optional response-side inspection
- [x] Signed GitHub releases with build provenance (v0.2.0)
- [ ] PyPI release via Trusted Publishing (workflow ready; needs the one-time
      PyPI setup in docs/releasing.md)

## Non-goals

- TLS interception or installing a root CA
- A system-wide firewall or egress control for every process
- Any telemetry
