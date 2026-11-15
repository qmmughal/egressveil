# Contributing to EgressVeil

Thank you for helping. EgressVeil is a security tool, so correctness and
clear scope matter more than adding features fast.

## Ground rules

- **Never commit real credentials, tokens or personal data.** That includes
  tests and fixtures. Build credential-shaped test strings at runtime from
  pieces (see `tests/conftest.py`) so the source tree contains no real-looking
  secrets.
- **Don't overstate coverage.** Docs and CLI output must keep implemented
  features separate from planned ones, and supported traffic separate from
  unsupported traffic.
- **Secure defaults.** A change that weakens a default needs an explicit
  opt-in and a warning.
- **Keep dependencies few.** A new runtime dependency needs a stated reason.

## Development setup

These commands work on Windows, macOS and Linux:

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Running checks

To run everything CI runs:

```bash
python scripts/check.py
```

Or run the checks one at a time:

```bash
python -m pytest -q
python -m ruff check .
python -m ruff format --check .
python -m mypy --strict src/egressveil
python -m build
```

A `Makefile` with the same targets is provided for people who use `make`.
It is optional.

## Pull requests

1. Open an issue first for anything bigger than a small fix.
2. Keep each PR focused, and add tests for any change in behavior.
3. Fill in the PR template, including the security considerations section.
4. Use [Conventional Commits](https://www.conventionalcommits.org/) for
   commit messages (`feat:`, `fix:`, `docs:`, `chore:`, ...).

## Adding a detector (Phase 1 and later)

- Implement the `egressveil.detectors.Detector` protocol.
- A `Finding` must never contain the matched text.
- Include tests that should match and tests that should not, with a
  realistic false-positive corpus.

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Releases

Maintainers: see [docs/releasing.md](docs/releasing.md). Releases are built,
signed and published only by GitHub Actions.
