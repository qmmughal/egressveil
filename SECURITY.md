# Security Policy

## Supported versions

EgressVeil is pre-alpha. Only the latest commit on `main` gets security
fixes. **The current release (Phase 0) does not intercept or protect any
traffic.** See the README for what is implemented.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/qmmughal/egressveil/security/advisories/new)**.

Please include:

- the affected version or commit,
- the steps to reproduce,
- the impact, for example a bypass, a leak in logs, or exposure on the
  network.

Do **not** include real credentials. Use fabricated values that have the
same shape.

We aim to acknowledge reports within 7 days and to agree on a disclosure
timeline with you. This is a volunteer project, so we can't guarantee
response times.

## Scope

In scope:

- ways to make EgressVeil forward data its policy should block or redact,
- raw secrets appearing in logs, CLI output or error messages,
- the gateway being reachable from other hosts despite the default
  configuration,
- unsafe parsing of configuration or request data.

Out of scope: limitations that the documentation already describes, such as
traffic that never goes through the gateway. See
[docs/threat-model.md](docs/threat-model.md).
