# Roadmap

The phases are ordered by dependency. Each phase ships only when its tests,
documentation and threat-model review are complete. There are no dates.

## Phase 0: Foundation (current)

- [x] `src/` package layout, Hatchling build, MIT license
- [x] CLI: `version`, `config validate`, `doctor`
- [x] Strict config schema with secure defaults that validation enforces
- [x] CI: Ruff, strict mypy, pytest on Python 3.11 and 3.12 across Linux,
      macOS and Windows, plus dependency auditing
- [x] Architecture, threat model, security design and integration docs

## Phase 1: Claude Code gateway

- [ ] `egressveil serve`: an async gateway on loopback with body and stream limits
- [ ] An Anthropic Messages API parser covering system, messages, tool_use,
      tool_result and streaming SSE passthrough
- [ ] Secret and token detectors: provider key patterns, private keys, JWTs,
      high-entropy strings in context, with fixtures and a false-positive
      corpus
- [ ] Policy engine with most-restrictive-wins evaluation
- [ ] Redactor with stable per-request placeholders
- [ ] JSONL audit log with keyed digests and restrictive file permissions
- [ ] Strict-mode fail-closed paths, each covered by tests
- [ ] Provider-shaped error responses for `BLOCK`
- [ ] End-to-end tests against a local mock upstream (no real API calls in CI)

## Phase 2: Aider and broader detection

- [ ] OpenAI-compatible Chat Completions parser
- [ ] PII detectors (email, phone, national ID formats) with locale awareness
- [ ] Internal-hostname detector driven by `internal_domains`
- [ ] `egressveil run -- <agent> [args]`: launches the agent with base URLs set
- [ ] Doctor checks that the gateway is running and that routing works

## Phase 3: More agents and operational maturity

- [ ] OpenClaw integration (research first)
- [ ] Experimental Cursor support where technically possible, with its
      coverage documented
- [ ] Shareable policy packs and per-project overrides
- [ ] Optional response-side inspection
- [ ] PyPI release with signed provenance, once the name is confirmed

## Non-goals

- TLS interception or installing a root CA
- A system-wide firewall or egress control for every process
- Any telemetry
