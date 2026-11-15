# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
intends to follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.3.0] - 2026-11-16

Phase 2: Aider and broader detection.

### Added

- An OpenAI-compatible API adapter, mounted at `/openai`, covering Chat
  Completions, Responses, Completions and Embeddings. Blocks use OpenAI's
  error format. Base64 `data:` URIs, inline audio and files are treated as
  opaque, and `encrypted_content` is skipped.
- A `pii` detector: email, international and North-American phone numbers,
  US SSNs, payment cards (Luhn) and IBANs (mod-97), with false-positive
  filters for example and no-reply addresses and file names.
- An `internal_hostnames` detector: configured `internal_domains`, the
  private suffixes `.internal`, `.corp`, `.intranet`, `.lan` and
  `.home.arpa`, and optional RFC 1918 IPv4 addresses.
- `egressveil run -- <agent>`: starts the gateway if needed, sets
  `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL` and `OPENAI_API_BASE` (and
  `NO_PROXY` for loopback), runs the agent, passes back its exit code, and
  stops the gateway it started.
- `doctor`: an end-to-end self-test that sends a random canary credential
  which must be blocked locally, plus checks for the enabled providers and
  the proxy mode.
- `gateway.upstream_proxy`: `none` (the default), `env`, or an explicit proxy
  URL. Credentials in the config file are rejected.
- Verified with real clients: Aider 0.86.2 and the OpenAI and Anthropic
  Python SDKs, run against the live APIs.

### Changed

- Findings in provider-signed `thinking` content are now recorded as
  `LOG_ONLY` (`"signed": true`) instead of escalating to `BLOCK`. This content
  is provably provider-generated, and blocking it wedged sessions.
- `build_detectors()` takes hostname options, `Inspector.inspect_request()`
  takes a provider `adapter`, and `providers.anthropic` now exposes an
  `ADAPTER`. `providers.base` holds the shared parsing.
- EgressVeil is now on PyPI: `pip install egressveil` (or `pipx install egressveil`).

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

[Unreleased]: https://github.com/qmmughal/egressveil/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/qmmughal/egressveil/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/qmmughal/egressveil/releases/tag/v0.2.0
