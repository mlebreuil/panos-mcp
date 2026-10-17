# Research: Panorama MCP Server

**Feature**: `001-panorama-mcp-server` | **Date**: 2026-10-16 | **Plan**: [plan.md](./plan.md)

All Technical Context unknowns are resolved below. Items marked **Verify at implementation**
are facts about third-party software that may have moved since this research and must be
re-checked when the related task starts (no live Panorama is available to confirm them).

---

## R1. Language and runtime

- **Decision**: Python ≥ 3.12, managed with `uv` (lockfile committed).
- **Rationale**: Mandated by the constitution (Python). 3.12 is a supported release with
  modern typing (`type` aliases, PEP 695 generics) and is widely available on engineer laptops.
  `uv` gives a fast, reproducible setup and lets the MCP client launch the server with one
  command (`uvx` / `uv run`).
- **Alternatives considered**: 3.10/3.11 (older typing; shorter remaining support);
  Poetry/pip-tools (slower, more moving parts).

## R2. MCP framework and transport

- **Decision**: Official MCP Python SDK (`mcp` package) using its `FastMCP` server API, **stdio
  transport only**. Every tool is registered with `ToolAnnotations(readOnlyHint=True,
  destructiveHint=False, idempotentHint=True, openWorldHint=True)` and returns Pydantic models
  so clients receive structured content plus a text rendering.
- **Rationale**: stdio means the server is a child process of the engineer's AI client and
  opens no network listener (FR-006, constitution Security constraints). The official SDK
  tracks the protocol, supports tool annotations (FR-050) and structured output (FR-051).
- **Alternatives considered**: Streamable HTTP transport (opens a listener — rejected for v1);
  third-party `fastmcp` 2.x (extra dependency with features we do not need).
- **Verify at implementation**: current major version of `mcp` and the exact import path /
  structured-output API; pin a compatible range in `pyproject.toml`.

## R3. Talking to Panorama: own XML API client vs. `pan-os-python`

- **Decision**: A small, purpose-built async XML API client on `httpx`, with a **request
  allow-list** enforced before any request is sent.
- **Rationale**:
  - Principle I requires that only allow-listed read requests can leave the process. A
    generic SDK exposes create/commit/push methods and makes "nothing else is possible" hard to
    prove; a thin client with ~4 request shapes is auditable in one file.
  - Async `httpx` integrates with the MCP SDK event loop (anyio) and supports injecting a
    transport — which is exactly how offline sample replay works (R6).
  - `pan-os-python` is synchronous and object-model-heavy; we only need read paths.
- **Alternatives considered**: `pan-os-python` (write capabilities, sync, heavy);
  `pan-python` (`pan.xapi`, sync, low-level but no allow-list); PAN-OS REST API (covers
  policies/objects but not operational commands, logs, or policy-match tests — XML API is
  needed anyway, so one API keeps the client simple).

## R4. XML API request shapes used (read-only allow-list)

All requests are `POST https://<panorama>/api/` with the key in the `X-PAN-KEY` header (keeps
secrets out of URLs and access logs). Allowed shapes:

| Purpose | `type` | Other params | Allow-list rule |
|---|---|---|---|
| Key generation (only if username/password configured) | `keygen` | `user`, `password` | Startup only, never callable from a tool |
| Operational read | `op` | `cmd` (XML), optional `target` (firewall serial) | Parsed `cmd` root path must match an allow-listed command (see below) |
| Config read | `config` | `action` ∈ {`get`, `show`}, `xpath` | `action` must be `get` (candidate) or `show` (running); xpath must start with `/config/` |
| Log query | `log` | `log-type`, `query`, `nlogs`, `skip` | Start query; `log-type` ∈ {traffic, threat, url, system, config} |
| Log job retrieval | `log` | `action=get`, `job-id` | Only for job IDs this process started |

Allow-listed operational commands (root → leaf path of the parsed `cmd` XML):

- `show/system/info`
- `show/high-availability/state`
- `show/devices/all` (managed firewalls with status)
- `show/devicegroups`
- `show/dg-hierarchy`
- `show/templates`
- *(none for template stacks: membership is read from config, `/config/devices/entry[@name='localhost.localdomain']/template-stack`; **verify at implementation**: element names per version)*
- `show/jobs/all`, `show/jobs/id`
- `check/pending-changes` (read-only status check)
- `show/object/dynamic-address-group` (with `target`, resolves DAG members on a firewall)
- `test/security-policy-match` (with `target`; evaluates a flow, changes nothing)
- `request/license/info` — **exact path only**. Despite the `request` verb it only displays
  installed licenses (needed for FR-013) and changes nothing. Every other `request/*` command
  stays blocked (`license/fetch|install|deactivate`, `system/*`, `batch/*`, …). **Verify at
  implementation** whether a `show`-based equivalent exists; if so, use it and drop this
  exception.

Anything else — including every `set`, `edit`, `delete`, `move`, `rename`, `commit`,
`commit-all`, `request` (other than the exact `request/license/info` path), `clear`, `debug` — is rejected by the allow-list with a
`ReadOnlyViolation` error before a socket is opened.

- **Rationale**: Covers FR-010…FR-031 with the minimum surface. Config reads via xpath give
  rules/objects for any scope; candidate vs. running is explicit (FR-026).
- **Verify at implementation**: exact op command element names and response shapes per
  supported Panorama release (11.1, 11.2, 12.1) using the API documentation; record any
  version differences as separate samples (R7).

## R5. Panorama-specific behaviors computed client-side

- **Effective (inherited) rulebase (FR-021)**: Panorama has no single "effective rulebase"
  call. Compute: walk `dg-hierarchy` from `shared` to the target device group; evaluation
  order is shared pre → ancestor pre (top-down) → DG pre → [firewall local] → DG post →
  ancestor post (bottom-up) → shared post → default rules. Each rule is labeled with its
  source scope and position.
- **Object references / "where used" (FR-024)**: no API call exists; scan rules and groups in
  the relevant scopes (object's scope plus all descendants, since children can reference
  parent objects) and report matches with location.
- **Name resolution with overrides**: when an object name exists in several scopes, the
  nearest scope wins (DG → ancestors → shared); responses state which definition applied.
- **Static address group expansion (FR-025)**: recursive expansion with cycle detection.
  Dynamic groups: show the match filter from config; resolve current members via
  `show/object/dynamic-address-group` with `target=<serial>` when a firewall is specified.

## R6. Offline development: sample replay transport

- **Decision**: An `httpx.MockTransport`-based **sample replay transport** that answers
  allow-listed requests from the sample library. It is used by tests and by an explicit
  **offline demo mode** (`PANOS_MCP_SAMPLES_SCENARIO=<name>`) so the full server can be driven
  from Claude Code without any Panorama. No HTTP server/socket is involved.
- **Rationale**: The production client code path is exercised unchanged (only the transport is
  swapped), satisfying Principle IV with zero network access, and the allow-list is still
  applied before the transport so tests also prove read-only behavior.
- **Alternatives considered**: `respx` (extra dependency; `MockTransport` suffices); a local
  fake HTTP Panorama (opens a socket, more code, no added fidelity).

## R7. Sample library: sources, structure, provenance

- **Decision**: Samples live in `samples/` at the repo root, organized by
  `<panos-version>/<api-type>/<command-slug>/<variant>.xml`, each with a sidecar
  `<variant>.meta.json` validated by a JSON Schema
  ([contracts/sample-metadata.schema.json](./contracts/sample-metadata.schema.json)).
  Named **scenarios** (`samples/scenarios/<name>.json`) map requests to sample variants so a
  test or demo can say "use the `disconnected-device` world".
- **Sources, in priority order**:
  1. `documentation` — response examples from the Palo Alto Networks *PAN-OS and Panorama XML
     API Usage* guide and related admin guides (record doc URL and Panorama version).
  2. `synthetic` — hand-authored responses that follow the documented schema to fill gaps
     (e.g., hierarchies, large rulebases, error responses). Generated large datasets are built
     by a script from a small seed so they stay reproducible.
  3. `lab-capture` — opt-in captures from a live lab Panorama (R9), always sanitized.
- **Rationale**: Documentation alone does not cover every command, version, or edge case
  (disconnected devices, 10,000 rules, errors); provenance in metadata makes the gaps visible
  and tells us which samples must be re-validated once a real Panorama is reachable.
- **Every sample, whatever its source, passes through the sanitizer** (R8) — documentation
  examples sometimes contain realistic-looking data.
- **Licensing note**: store doc-derived samples as normalized, sanitized response bodies with
  a source URL; do not copy surrounding prose.

## R8. Sanitization: replacing real data with forged data of the same type

- **Decision**: A deterministic, type-preserving sanitizer (`panos-mcp-samples sanitize`).
  Each sensitive value is classified, then replaced through a keyed HMAC mapping so the same
  real value always maps to the same forged value across all samples (references between
  rules, groups, and objects stay consistent). The HMAC key and the real→forged mapping table
  live only on the capturing machine (git-ignored, outside the repo by default) and are never
  committed.

| Value type | Detection | Forged replacement (same type) |
|---|---|---|
| Public IPv4 / prefix / range | `ipaddress` parse, not private | Address in RFC 5737 TEST-NETs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) or 198.18.0.0/15 for larger prefixes; prefix length and range width preserved |
| Private IPv4 (RFC 1918) | `ipaddress.is_private` | Address in the same RFC 1918 block, remapped; subnet membership and prefix length preserved |
| CGNAT / loopback / link-local / multicast | `ipaddress` flags | Same special range, remapped |
| IPv6 global / ULA | `ipaddress` | 2001:db8::/32 (documentation) / fd00::/8 remapped; prefix preserved |
| FQDN / domain | element context + regex | `<word>.example.com` / `.example.net` / `.test`, label count preserved |
| Object, rule, device-group, template, zone*, tag, profile names | element context (`entry/@name`, member text) | Generated name preserving shape: prefix/separator pattern, case, digit runs, approx. length (e.g., `PAR-DC1-web-srv-01` → `KTO-DC4-app-node-07`) |
| Hostnames (firewall/Panorama) | `hostname`, `devicename` | `fw-<site>-NN`, `panorama-NN` |
| Serial numbers | `serial` elements/attrs | Same length, digits only, prefixed `9` (never a valid issued range) |
| MAC addresses | regex | RFC 7042 documentation range `00:00:5e:00:53:xx` |
| Usernames / admins | `admin`, `user`, `src-user` | `user-NNN`, domain prefix preserved as `EXAMPLE\` |
| Email addresses | regex | `user-NNN@example.com` |
| Free text: comments, descriptions | `description`, `comment` elements | Neutral generated sentence of similar length |
| URLs | regex/context | `https://site-NN.example.com/<path shape>` |
| Secrets: API keys, password hashes, PSKs, private keys, certificate bodies, SNMP communities | element allow/deny list (`phash`, `key`, `password`, `private-key`, `pre-shared-key`, …) | Dropped or replaced with fixed placeholder `REDACTED`; never mapped |
| Timestamps, versions, counters, model names | — | Kept (not sensitive, needed for realism) |

\*Well-known built-in values are preserved via a keep-list: `any`, `application-default`,
predefined applications and services (`ssl`, `web-browsing`, `service-http`), built-in
profile names (`default`, `strict`), action/enum values, and PAN-OS defaults.

- **Leak checks** (two layers):
  1. At capture/sanitize time, every original sensitive value collected is searched for in the
     output; any hit aborts the write.
  2. In CI (no mapping available), a lint asserts: public IPs only in documentation ranges,
     emails/domains only `example.*`/`.test`, MACs only in the documentation range, serials
     start with `9`, no secret-bearing element contains anything but `REDACTED`.
- **Rationale**: Satisfies the user requirement ("forged ones of similar type") and the
  constitution (fixtures contain no real hostnames, IPs, serials, or secrets) while keeping
  samples realistic enough to exercise parsing, hierarchy, and reference logic.
- **Alternatives considered**: blanket `REDACTED` everywhere (breaks references and type
  validation); random replacement without a key (inconsistent across samples, references
  break); mapping private IPs to documentation ranges (loses private/public distinction that
  the tools reason about).

## R9. Opt-in live lab capture

- **Decision**: `panos-mcp-samples capture` runs only when explicitly invoked **and**
  `PANOS_MCP_LIVE=1` is set. It reuses the server's client and allow-list (read-only by
  construction), executes the request set defined by a scenario or a capture plan, sanitizes
  in memory, runs the leak check, and only then writes samples with
  `provenance.source = "lab-capture"`. Before and after capture it records the Panorama
  configuration state (pending changes + latest commit job) and fails if anything changed.
- Live integration tests (`pytest -m live`) are skipped unless `PANOS_MCP_LIVE=1`.
- **Rationale**: Lets anyone with a lab refresh/extend samples later without changing code,
  and without risk to the lab or to the repository.

## R10. XML parsing safety

- **Decision**: Parse all XML with `defusedxml.ElementTree`.
- **Rationale**: Protects against entity-expansion and external-entity attacks from a
  malicious or compromised endpoint (cheap, small dependency).
- **Alternatives considered**: `lxml` (faster, richer XPath, but heavier; stdlib ElementTree's
  limited XPath is sufficient for response parsing).

## R11. Configuration and secrets

- **Decision**: Settings from environment variables (optionally a `.env` file referenced by
  path) via `pydantic-settings`; `SecretStr` for the key/password. Supported: API key
  (preferred) or username/password (exchanged once for a key at startup via `keygen`).
  `PANOS_MCP_VERIFY_TLS` defaults to `true`; `false` logs a warning at startup and appends a
  warning to `get_panorama_info` output. A custom CA bundle path is supported.
- **Rationale**: MCP clients pass env vars in their server configuration; `SecretStr` prevents
  accidental logging (FR-002). `pydantic-settings` is already a dependency of the MCP SDK
  (**verify at implementation**).

## R12. Logging

- **Decision**: stdlib `logging` to **stderr** only (stdout is the MCP stdio channel), with a
  redaction filter that masks the API key, password, and `X-PAN-KEY` header values. Log
  payload data only at DEBUG when explicitly enabled.

## R13. Performance strategy

- **Decision**: One shared `httpx.AsyncClient` (connection reuse); bounded concurrency
  (semaphore, default 4) for multi-call operations; a small in-memory TTL cache (default 30 s,
  `0` disables) for config subtree reads keyed by (`action`, `xpath`), so an effective-rulebase
  or where-used computation fetches each scope once. Responses include `retrieved_at` so
  cached data is visible. Log queries poll the job with backoff until done or until
  `PANOS_MCP_QUERY_TIMEOUT` (default 60 s).
- **Rationale**: Meets SC-003 (< 5 s for typical lookups at 500 devices / 10,000 rules) without
  hammering the management plane (constitution: bounded concurrency, no unbounded retries).
- **Validation without Panorama**: a synthetic scenario `large-estate` (500 devices, 10,000
  rules) generated by script; parse+filter time is measured in a benchmark test. Network
  latency of a real Panorama remains unverified until a lab is available (documented gap).

## R14. Testing and quality tooling

- **Decision**: `pytest` with the `anyio` plugin (anyio is already a transitive dependency —
  no `pytest-asyncio` needed); `ruff` (format + lint); `mypy --strict`; `jsonschema` (dev only)
  for sample metadata validation. Test layers: `unit`, `contract` (tool schemas + outputs per
  scenario, incl. "no non-allow-listed request" assertions), `samples` (library validity +
  sanitization lint), `integration/live` (opt-in).
- **Rationale**: Minimal dependency set (Principle V), all offline (Principle IV).

## R15. Supported Panorama versions

- **Decision**: Target currently supported Panorama releases; start the sample library with
  **11.1** and **11.2**, add **12.1** samples where documentation exists. The supported list is
  maintained in `samples/README.md` and re-checked against Palo Alto's end-of-life table at
  each release.
- **Verify at implementation**: current end-of-life dates.

## Known gaps (cannot be closed without a live Panorama)

- Exact response shapes for commands whose documentation examples are missing or partial
  (samples marked `synthetic` until confirmed).
- SC-002 (95% match with the Panorama web interface) and the network-latency part of SC-003
  need a lab Panorama; they are validated through the opt-in live test suite when available.
