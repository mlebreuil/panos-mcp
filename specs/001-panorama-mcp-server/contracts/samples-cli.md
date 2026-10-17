# Contract: Sample Library CLI (`panos-mcp-samples`)

**Feature**: `001-panorama-mcp-server` | Research: R7–R9 | Models: [data-model.md §C](../data-model.md)

Developer/maintainer tool for building and maintaining the sample library under `samples/`.
All sub-commands are offline except `capture`, which is opt-in.

Exit codes: `0` success, `1` validation/leak failure, `2` usage error, `3` live safety check
failed (config changed or live mode not enabled).

## `panos-mcp-samples add`
Register a response body as a sample (typically copied from the API documentation).
```
panos-mcp-samples add --version 11.1 --type op --cmd '<show><devices><all/></devices></show>' \
  --variant baseline --source documentation --url <doc-url> \
  --description "Two connected firewalls, one disconnected" path/to/response.xml
```
- Sanitizes the body (same rules as `sanitize`), runs the leak check, writes
  `<variant>.xml` + `<variant>.meta.json` in the canonical location, refuses to overwrite
  without `--force`.

## `panos-mcp-samples sanitize`
```
panos-mcp-samples sanitize [--mapping-dir DIR] [--check-only] FILE|DIR...
```
- Replaces sensitive values with forged values of the same type (research R8) using the
  local HMAC key + mapping in `--mapping-dir` (default `~/.config/panos-mcp/sanitize/`,
  created on first use, never inside the repo unless git-ignored).
- `--check-only`: report what would change; non-zero if anything sensitive is found.

## `panos-mcp-samples validate`
```
panos-mcp-samples validate [samples/]
```
Offline checks run in CI:
- every `.xml` is well-formed and has a `.meta.json` valid against
  [sample-metadata.schema.json](./sample-metadata.schema.json); `id` matches the path;
- sanitization lint (public IPs only in documentation ranges, `example.*`/`.test` domains,
  documentation MACs, serials start with `9`, secret elements contain only `REDACTED`);
- every scenario references existing samples and is internally consistent.

## `panos-mcp-samples index`
Regenerates `samples/INDEX.md`: coverage table of commands × versions × provenance ×
status, highlighting tools whose requests have no `documentation`/`lab-capture` sample.

## `panos-mcp-samples generate`
```
panos-mcp-samples generate large-estate --devices 500 --rules 10000 --seed 42
```
Deterministically generates synthetic samples/scenarios for scale tests (R13).

## `panos-mcp-samples capture` (opt-in, live)

Offline helper (no live access, no `PANOS_MCP_LIVE` needed):
```
panos-mcp-samples capture --write-plan capture-plans/baseline.json
```
Generates the capture plan from `commands.TOOL_REQUESTS`, with placeholders for device-group
names and serials that are resolved at capture time.

Live capture:
```
PANOS_MCP_LIVE=1 PANOS_MCP_HOST=... PANOS_MCP_API_KEY=... \
  panos-mcp-samples capture --plan capture-plans/baseline.json --version 11.2 --variant lab-baseline
```
- Refuses to run unless `PANOS_MCP_LIVE=1`.
- Uses the server's XML API client and allow-list (read-only by construction).
- Records pending-changes state and latest commit job before and after; exits `3` if they
  differ.
- Sanitizes in memory and runs the leak check before writing; writes with
  `provenance.source = "lab-capture"` and `status = "unverified"` (promote with
  `--mark-verified` once compared with the web interface).
