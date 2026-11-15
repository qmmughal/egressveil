# Versioning and compatibility policy

EgressVeil follows [Semantic Versioning](https://semver.org/). From 1.0.0 on:

- **Major** (`2.0.0`): may break the public contract below. Breaking changes
  are announced in the changelog with migration steps.
- **Minor** (`1.1.0`): new features and new optional fields. It never breaks
  the public contract.
- **Patch** (`1.0.1`): bug fixes and detection-quality fixes.

Before 1.0.0, minor versions may still change behaviour, and every such
change is called out in the changelog.

## Public contract

| Surface | Guarantee |
| --- | --- |
| **Config schema `version: 1`** ([configuration.md](configuration.md)) | Keys aren't removed or renamed within a major version. New keys are optional and default to existing behaviour. Security defaults are never weakened in a minor release |
| **CLI** ([cli.md](cli.md)) | Commands, flags and documented exit codes are stable. New commands and flags may be added |
| **Audit log `schema_version: 1`** ([audit-log.md](audit-log.md)) | Fields aren't removed or renamed, and their meanings don't change. New optional fields may be added, so consumers must ignore unknown fields |
| **Health endpoint `schema_version: 1`** | The same rules as the audit log |
| **Agent routing** | `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`, `/openai/v1` for OpenAI-compatible clients, and the block error formats |

## Not part of the contract

- **The Python API.** Modules under `egressveil.*` are internal and may
  change in any release. Use the CLI, the config file and the audit log
  instead.
- **Detection results.** Rules are tuned in patch and minor releases to catch
  more and to reduce false positives. A value detected today might not be
  detected tomorrow, or the other way round. Pin a version if you need
  reproducible results, and use allowlists for known false positives.
- **Log, banner and error message wording**, except the machine fields in
  error responses (`type`/`error.type`) and the reason codes in the audit
  schema.

## Deprecation

When a contract surface has to change, the old form keeps working and
produces a warning (in `config validate` or on stderr) for at least one
minor release before the next major release removes it.

## Security fixes

The latest minor release gets security fixes (see [SECURITY.md](../SECURITY.md)).
