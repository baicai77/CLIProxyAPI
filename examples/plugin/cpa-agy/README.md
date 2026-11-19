# cpa-agy Antigravity Adapter Plugin

This Go plugin ports the closed [archyqx/sub2api](https://github.com/archyqx/sub2api) Antigravity adaptations that can live outside the CPA core:

1. Built-in compatibility rewrites for client harness prompts. The default rules do not remove security authorization requirements.
2. Optional JSON rule file reloaded on demand, at most once every 5 seconds.

Empty-stream failover and Gemini reasoning `maxOutputTokens` flooring are implemented in the CPA Antigravity executor itself. Plugins cannot convert a committed HTTP 200 empty Claude SSE into a retryable 502. This plugin rewrites system/developer prompts only on `request.intercept_after` when `ToFormat` is `antigravity`, so before-auth intercepts (empty `ToFormat`) and other providers are left unchanged.

## Configuration

```yaml
plugins:
  enabled: true
  configs:
    cpa-agy:
      enabled: true
      priority: 50
      rules_file: "./antigravity-sanitize-rules.json"
```

`rules_file` defaults to `CPA_AGY_RULES_FILE`, then `antigravity-sanitize-rules.json` in the working directory.

`merge` (the default) adds file rules to the built-in rules. `replace` uses only file rules, without built-in rewrites or invisible character cleanup. If a file cannot be read or its rules are invalid, the last valid rules stay active. A missing file falls back to built-in rules.

Each request uses one rule snapshot. Unknown JSON fields, including fields inside individual rules, invalidate the file. Literal and regex replacement rules require an explicit `replace` string: use `""` to intentionally delete a match. A missing or `null` value invalidates the file. Built-in identity rules require a complete declaration at the start of a line; a name followed by an arbitrary comma clause or possessive suffix does not match. Custom `identity_openers` still only apply to non-empty matches at the start of the text.

External JSON schema:

```json
{
  "mode": "merge",
  "identity_openers": ["(?i)^[ \\t\\r\\n]*You\\s+are\\s+MyAgent\\b\\.?"],
  "literals": [{"name": "example", "find": "TRIGGER", "replace": "SAFE"}],
  "replacements": [{"name": "example-re", "pattern": "(?i)fingerprint", "replace": "rewritten"}]
}
```

## Verify request rewriting

For each after-auth Antigravity interception, the plugin emits an INFO `[cpa-agy] sanitize request` line. The event includes only these fields:

- `executions`: cumulative eligible callback count for this loaded plugin instance; not a count of unique client requests.
- `checked_text_fields`: non-empty eligible text fields passed through the rule engine. User messages are not counted.
- `matched_rules`: distinct rules that changed text in this callback (invisible-character cleanup counts as one rule).
- `replacements`: changed occurrences across those rules, including removals. Sequential rules can cancel one another's changes.
- `body_modified`: whether the plugin returned a modified body to CPA. Use this field to confirm a net rewrite.
- `status`: `empty_body` (zero bytes), `invalid_json`, `no_eligible_text` (valid JSON, zero checked fields), `unchanged` (text checked, no modified body returned), or `modified`.

Search the service logs for `cpa-agy` and `sanitize request`. For a zero-rewrite event, use `status` and `checked_text_fields` to distinguish skipped bodies, missing eligible text, and checked text that was not rewritten. Before-auth and other upstream formats do not emit this event. The event contains no request body, headers, credentials, or rule text. It does not verify upstream delivery or rate-limit behavior.

### Local end-to-end smoke test

Run `python3 smoke_local.py /out/cpa-agy-server /out/cpa-agy.so` inside a Linux amd64 container started with `--network none`. Mount the script and the two build outputs into the container. It launches CPA with temporary credentials and a loopback mock, and checks that a synthetic system-text rewrite survives translation, unmatched system text stays unchanged, and user text is never rewritten.

## Build

From the repository root in PowerShell (Windows amd64; requires Go 1.26.10 or newer and a C compiler supported by cgo on `PATH`):

```powershell
$out = Join-Path (Get-Location).Path 'plugins/windows/amd64'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$env:CGO_ENABLED = '1'
go -C ./examples/plugin/cpa-agy/go build -buildmode=c-shared -o (Join-Path $out 'cpa-agy.dll') .
```

On Linux/macOS, run the same Go build from the plugin module (or use `go -C`), with cgo enabled and an absolute output path under `plugins/<os>/<arch>/`. Use `cpa-agy.so` on Linux and `cpa-agy.dylib` on macOS; the file stem is the plugin ID.
