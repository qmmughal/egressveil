# Getting help

EgressVeil is free, community-supported open-source software. There is no
paid support tier.

- **Questions, ideas, "is this expected?"**: use
  [GitHub Discussions](https://github.com/qmmughal/egressveil/discussions).
- **Bugs**: [open an issue](https://github.com/qmmughal/egressveil/issues/new/choose)
  and include the output of `egressveil doctor`. That output is designed to
  be safe to share and contains no secrets or URLs.
- **Security vulnerabilities**: please **don't** open a public issue. Report
  them privately as described in [SECURITY.md](SECURITY.md).

Before posting, please:

1. Check the [README](README.md) and [docs/integrations.md](docs/integrations.md),
   especially the coverage limitations.
2. Run `egressveil doctor` and `egressveil config validate`.
3. If a request was blocked, look up its request ID in the audit log. The
   `reason` field explains why.

**Never paste real credentials, tokens or API keys** into issues or
discussions. EgressVeil's own output never contains them, so it is safe to
share.
