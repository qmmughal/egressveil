# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
intends to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-11-16

First public release. EgressVeil is free and open source under the MIT
License. This release protects Claude Code's Anthropic API traffic from
leaking secrets and tokens. It is pre-alpha: see the README for coverage
limitations.

### Added: release and community

- A release workflow builds and smoke-tests each release, attaches signed
  build provenance, and creates the GitHub release. PyPI Trusted Publishing
  is ready but turned off until the project is registered on PyPI (see
  `docs/releasing.md`).
- Official support for Python 3.13 and 3.14. CI tests Python 3.11 to 3.14 on
  Linux, macOS and Windows.
- `SUPPORT.md`, `CODEOWNERS`, and install instructions using pipx or pip with
  the release wheel.

### Added: Phase 1, the Claude Code gateway

- `egressveil serve`: a local aiohttp gateway for the Anthropic Messages API
  (`/v1/messages`, `/v1/messages/count_tokens`), with streaming passthrough,
  bounded request bodies and stream chunks, verified TLS to an allowlisted
  upstream, no redirect following, and no use of environment proxies.
- An Anthropic request parser that inspects every string field, hardened
  against duplicate keys, `NaN` and deep nesting.
- `secrets` and `tokens` detectors with vendor, private-key, URL-credential,
  generic-assignment, JWT, bearer and Basic auth rules.
- A policy engine (the most restrictive action wins), keyed stable
  redaction placeholders, and escalation to `BLOCK` for signed `thinking`
  content and for URLs.
- Strict-mode fail-closed handling for unsupported routes, content types and
  encodings, invalid JSON, opaque images and PDFs, and detector errors.
  Permissive mode forwards these and flags them.
- A JSONL audit log with keyed digests and a `0600` key file. It never
  records bodies, headers, query strings or raw values.
- Host-header (DNS-rebinding) and browser-`Origin` rejection, and a local
  `/_egressveil/health` endpoint.
- `egressveil scan`: runs the detectors and policy over files or stdin.
- `doctor` detects a running gateway and lists the active detectors.
- Config option `gateway.allow_opaque_content`.
- Runtime dependency: `aiohttp`.

### Added: Phase 0, the foundation

- Project scaffold: `src/` layout, Hatchling packaging, MIT license.
- CLI commands: `egressveil version`, `egressveil config validate` and
  `egressveil doctor`.
- A strict YAML configuration schema with secure defaults enforced at
  validation: loopback-only listener, https allowlisted upstreams, strict
  mode, no raw-value audit logging, and no telemetry.
- Secret-safe validation output, and rejection of config files that contain
  credential-shaped values.
- Documentation: architecture, threat model, security design, integrations
  and roadmap.
- CI: Ruff, strict mypy, and pytest on Python 3.11 and 3.12 across Linux,
  macOS and Windows; a build check; and pip-audit dependency auditing.

[Unreleased]: https://github.com/qmmughal/egressveil/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/qmmughal/egressveil/releases/tag/v0.2.0
