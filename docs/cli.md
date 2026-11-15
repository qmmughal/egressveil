# CLI reference

Command names, flags and exit codes are part of the public contract (see
[versioning.md](versioning.md)).

Every command that reads configuration accepts `--config PATH` (`-c PATH`).
Without it, configuration is discovered as described in
[configuration.md](configuration.md), and `$EGRESSVEIL_CONFIG` is honoured.
No command ever prints configuration values, environment values or matched
sensitive values.

| Command | What it does | Exit codes |
| --- | --- | --- |
| `egressveil version` | Prints the version | 0 |
| `egressveil config validate` | Validates configuration and prints the effective settings | 0 valid · 1 invalid |
| `egressveil doctor` | Checks the environment, the gateway, a canary self-test and integrations | 0 no failures · 1 at least one failure |
| `egressveil serve` | Runs the gateway in the foreground until Ctrl+C | 0 stopped · 1 invalid config, or can't start or listen |
| `egressveil run [--start/--no-start] -- <agent> [args...]` | Runs an agent through the gateway, starting the gateway if needed (unless `--no-start`) | the agent's own exit code · 1 invalid config · 2 launcher error, such as the agent not being found or the gateway not running with `--no-start` |
| `egressveil scan <paths...>` | Scans files, or stdin with `-`, using the configured detectors and policy. Prints `path:line:col: ACTION category/rule  digest=...` | 0 nothing found · 1 findings · 2 a file couldn't be read |
| `egressveil setup <agent>` | Prints setup steps for `claude-code`, `aider`, `openclaw` or `cursor` | 0 · 2 unknown agent |

## `egressveil run` environment

The agent's process is started with these environment variables:

| Variable | Value |
| --- | --- |
| `ANTHROPIC_BASE_URL` | `http://127.0.0.1:<port>`, when the Anthropic provider is enabled |
| `OPENAI_BASE_URL`, `OPENAI_API_BASE` | `http://127.0.0.1:<port>/openai/v1`, when the OpenAI provider is enabled |
| `NO_PROXY` (and `no_proxy` outside Windows) | Existing entries plus `127.0.0.1,localhost,::1` |
| `EGRESSVEIL_GATEWAY` | `http://127.0.0.1:<port>` |

A gateway started by `run` writes its output to `gateway.log`, next to the
audit log, and is stopped when the agent exits.

## Health endpoint

`GET /_egressveil/health` is answered by the gateway itself and is never
forwarded. Its JSON format is defined in
[`health-v1.schema.json`](../src/egressveil/schemas/health-v1.schema.json).
