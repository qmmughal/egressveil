# Audit log format

The gateway appends one JSON object per line to `audit.path` (by default
`~/.egressveil/audit.jsonl`), one per request. The format is versioned by the
`schema_version` field, and the full machine-readable definition ships with
the package as
[`egressveil/schemas/audit-event-v1.schema.json`](../src/egressveil/schemas/audit-event-v1.schema.json).

## Guarantees

- **No sensitive content.** Request bodies, header values (including API
  keys), query strings and raw matched values are never written. Findings
  carry a 16-hex keyed digest (HMAC-SHA256 under the local `egressveil.key`)
  instead of the value.
- **Stable within a schema version.** Within `schema_version: 1`, fields
  aren't removed or renamed and their meaning doesn't change. Minor releases
  may add new **optional** fields, so consumers must ignore fields they don't
  know. A breaking change means a new `schema_version` and a new major
  release (see [versioning.md](versioning.md)).

## Fields

| Field | Always present | Meaning |
| --- | --- | --- |
| `schema_version` | yes | `1` |
| `ts` | yes | UTC timestamp, ISO 8601 with milliseconds |
| `request_id` | yes | `ev_` plus 16 hex characters. The same ID appears in the `x-egressveil-request-id` response header and in block messages |
| `provider` | yes | `anthropic` or `openai` |
| `method`, `path` | yes | The HTTP method and the gateway path, without the query string |
| `duration_ms` | yes | Time spent in the gateway, including the upstream round trip |
| `outcome` | yes | `forward`, `redact`, `block` or `error` |
| `reason` | no | Why a request was blocked, errored or forwarded uninspected. The codes are listed in the schema |
| `route` | no | `json_inspect`, `bodyless` or `unsupported` |
| `inspected` | no | `false` when permissive mode forwarded a request it couldn't inspect |
| `bytes_in` | no | Size of the request body |
| `upstream_status`, `stream_complete` | no | The upstream HTTP status, and whether the response was relayed completely |
| `findings` | no | Request findings: `detector`, `rule_id`, `location`, `action` and `digest`, plus optionally `escalated: true` or `signed: true` |
| `opaque` | no | Content that couldn't be inspected: `location` and `kind` (for example `image/png`) |
| `response_findings` | no | With `inspect_responses` on: `detector`, `rule_id`, `location: "$response"`, `action: "LOG_ONLY"`, `policy_action` and `digest` |
| `response_inspection` | no | `truncated` or `skipped` when a response couldn't be inspected |

## Example

```json
{"schema_version":1,"ts":"2026-11-16T09:12:03.512+00:00","request_id":"ev_3c1f0a9e2b7d4c11","provider":"anthropic","method":"POST","path":"/v1/messages","duration_ms":2.4,"outcome":"block","reason":"policy","route":"json_inspect","inspected":true,"bytes_in":48211,"findings":[{"detector":"secrets","rule_id":"aws_access_key_id","location":"messages[4].content[0].content[0].text","action":"BLOCK","digest":"9f2c4be01a7d33e8"}]}
```

## Validating

```python
import json, importlib.resources, jsonschema

schema = json.loads(
    importlib.resources.files("egressveil.schemas")
    .joinpath("audit-event-v1.schema.json")
    .read_text()
)
for line in open("audit.jsonl"):
    jsonschema.validate(json.loads(line), schema)
```
