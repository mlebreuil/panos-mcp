# Implementation Plan: Panorama MCP Server

**Branch**: `001-panorama-mcp-server` | **Date**: 2026-10-16 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-panorama-mcp-server/spec.md`

## Summary

Build a read-only MCP server in Python that runs locally over stdio. It lets an AI assistant
answer questions about a Panorama-managed firewall estate: inventory and health, security and
NAT policy (including inherited rules), objects and their usages, logs, and policy-match tests.

The server talks to Panorama through a small async XML API client. That client has a request
allow-list, so only read requests can ever be sent (Principle I).

**No live Panorama is available**, so development runs entirely against a **sample library**:
- XML API responses gathered from the Palo Alto API documentation and filled out with
  synthetic samples.
- Stored in a structured layout with provenance metadata.
- Sanitized so every real name, IP address, serial, comment, etc. is replaced by a forged
  value of the same type.

A replay transport serves these samples to the unchanged client code in tests and in an
offline demo mode. A live lab Panorama is **opt-in only**. It is used to refresh or extend the
samples through a sanitizing, read-only capture tool and to run live integration tests.

Building the sample library and its tooling is a first-class workstream of this feature.

## Technical Context

**Language/Version**: Python ≥ 3.12 (constitution: Python mandated), packaged with `uv`

**Primary Dependencies**:
- Runtime:
  - `mcp`: official SDK, FastMCP, stdio
  - `httpx`: async HTTP client
  - `pydantic` v2 and `pydantic-settings`
  - `defusedxml`
- Dev:
  - `pytest` with the anyio plugin
  - `ruff`
  - `mypy` (strict)
  - `jsonschema`
  - `psutil` (test-only, for the no-listener check)

**Storage**: None at runtime. The sample library is files in the repo (`samples/`: XML plus
JSON metadata). Sanitization keys and mappings are local files outside the repo.

**Testing**:
- Unit and contract tests use the offline replay of the sample library; scenario-based
  contract tests assert the read-only allow-list.
- Sample-library validation and sanitization lint run in CI.
- Live tests are opt-in (`PANOS_MCP_LIVE=1`, `pytest -m live`).

**Target Platform**:
- The engineer's workstation (macOS, Linux, Windows).
- Launched by an MCP client (Claude Code etc.) over stdio.

**Project Type**: Single Python package. It provides an MCP server (CLI entry `panos-mcp`) and
a maintainer CLI for the sample library (`panos-mcp-samples`).

**Performance Goals**: Typical lookups return in < 5 s for 500 firewalls and 10,000 rules
(SC-003). Log queries are bounded by a 60 s default timeout.

**Constraints**:
- Read-only (allow-list enforced before transport).
- No network listener.
- No secrets in output or logs.
- TLS verification on by default.
- Bounded concurrency (default 4).
- No unbounded retries.
- Offline-capable development and CI.

**Scale/Scope**:
- 13 MCP tools ([contracts/mcp-tools.md](./contracts/mcp-tools.md)).
- 5 log types.
- Targets Panorama 11.1 and 11.2 (12.1 where documented).
- One Panorama per server instance.

All Technical Context items were resolved in [research.md](./research.md). There are no open
NEEDS CLARIFICATION items. Items marked *verify at implementation* there are confirmations of
third-party details, not open design questions.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle / Constraint | How the design complies | Pre-research | Post-design |
|---|---|---|---|
| **I. Read-Only Safety** | <ul><li>Client allow-list (R4) applies to `op`, `config` (`get`/`show` only) and `log`, rejecting anything else before a socket is opened. The one `request` command allowed is the exact path `request/license/info`, which only displays data (see Complexity Tracking).</li><li>No write tools exist.</li><li>The capture tool reuses the same client.</li><li>Contract tests assert that every transported request is allow-listed.</li><li>The live suite checks config is unchanged.</li></ul> | PASS | PASS |
| **II. Credential & Data Protection** | <ul><li>`SecretStr` settings.</li><li>The key is sent in the `X-PAN-KEY` header over POST.</li><li>Logging has a redaction filter and goes to stderr.</li><li>TLS verification is on by default, with warnings when off.</li><li>Inputs are validated (FR-053).</li><li>The `cmd` XML is built from typed parameters, not string concatenation.</li><li>XML is parsed with `defusedxml`.</li><li>A read-only role is recommended.</li></ul> | PASS | PASS |
| **III. Clear, Bounded Tool Contracts** | <ul><li>13 tools, each annotated read-only, with typed Pydantic inputs and outputs.</li><li>`ToolResult` envelope with pagination, a truncation flag and a narrowing hint.</li><li>`config_source` and `scope` are on every config result.</li><li>`ToolError` carries a plain-language message and a hint.</li><li>Names and schemas are documented as the public contract.</li></ul> | PASS | PASS |
| **IV. Test-First Against Recorded Behavior** | <ul><li>A replay transport over the sample library, so CI runs with no network.</li><li>Samples are sanitized with forged values of the same type; leak check plus CI lint.</li><li>Live tests are opt-in and include a no-change check.</li><li>Each tool is tested for success, not-found, permission-denied and truncation (scenarios `baseline`, `auth-failure`, `large-estate`, …).</li></ul> | PASS | PASS |
| **V. Fidelity & Simplicity** | <ul><li>Every tool traces to an FR.</li><li>Computed views (effective rulebase, where-used) label their sources.</li><li>Unknown or unavailable data is reported as such.</li><li>Dependencies are limited to the runtime and dev lists in Technical Context.</li><li>No `pan-os-python` and no mock HTTP server.</li><li>The small TTL cache (R13) is justified by SC-003 and can be disabled.</li></ul> | PASS | PASS |
| Security & Operational Constraints | <ul><li>stdio only.</li><li>One Panorama per instance.</li><li>Configurable timeouts and limits.</li><li>Concurrency semaphore.</li><li>Polling with backoff and a cap.</li><li>Payloads are logged only at DEBUG.</li><li>Supported versions are listed.</li></ul> | PASS | PASS |
| Development Workflow | <ul><li>Python with strict typing.</li><li>CI runs ruff, mypy and pytest offline.</li><li>Docs (README, configuration, tools, role) are updated with code.</li></ul> | PASS | PASS |

Two documented deviations are listed in Complexity Tracking (both within the principles, not violations).

## Project Structure

### Documentation (this feature)

```text
specs/001-panorama-mcp-server/
├── plan.md                 # This file
├── research.md             # Phase 0: decisions R1–R15, known gaps
├── data-model.md           # Phase 1: domain models, envelope/errors, sample library model
├── quickstart.md           # Phase 1: validation scenarios (offline + opt-in live)
├── contracts/
│   ├── mcp-tools.md                    # 13 tools: inputs, outputs, requests, errors
│   ├── configuration.md                # environment variables, client config, role
│   ├── samples-cli.md                  # panos-mcp-samples sub-commands
│   └── sample-metadata.schema.json     # JSON Schema for sample sidecars
├── checklists/requirements.md
└── tasks.md                # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

```text
pyproject.toml                  # uv project; scripts: panos-mcp, panos-mcp-samples
src/panos_mcp/
├── __main__.py                 # entry: load settings, build client, run FastMCP over stdio
├── server.py                   # FastMCP app; registers tools with read-only annotations
├── config.py                   # pydantic-settings Settings (SecretStr), validation, warnings
├── logging.py                  # stderr logging + secret redaction filter
├── client/
│   ├── xmlapi.py               # async XML API client (op/config/log), keygen at startup
│   ├── allowlist.py            # request allow-list (the read-only guarantee)
│   ├── commands.py             # typed builders for allow-listed op commands and xpaths; TOOL_REQUESTS registry
│   ├── errors.py               # Panorama/transport errors → ToolError codes
│   ├── cache.py                # small TTL cache for config reads
│   └── replay.py               # httpx MockTransport serving samples by scenario
├── models/                     # Pydantic models from data-model.md (A + B)
│   ├── common.py               # ToolResult, ToolError, Scope, ConfigSource, pagination
│   ├── inventory.py            # PanoramaInfo, ManagedFirewall, DeviceGroup, Template, Job
│   ├── policy.py               # SecurityRule, NatRule
│   ├── objects.py              # object kinds, ObjectReference, ResolvedAddressGroup
│   └── logs.py                 # LogEntry, PolicyMatchResult
├── parsers/                    # XML response → models (one module per area)
├── services/                   # domain logic
│   ├── inventory.py            # devices, device groups, templates, jobs, system info
│   ├── hierarchy.py            # dg tree, ancestry, name resolution with overrides
│   ├── policy.py               # rulebases, effective rulebase, rule filters
│   ├── objects.py              # objects, where-used, address-group expansion
│   └── logs.py                 # log query job lifecycle, filter builder/validator, policy match
├── tools/                      # thin MCP tool handlers (validate → service → ToolResult)
│   ├── inventory.py
│   ├── policy.py
│   ├── objects.py
│   └── troubleshooting.py
└── samples/                    # sample library tooling (panos-mcp-samples CLI)
    ├── cli.py                  # add, sanitize, validate, index, generate, capture
    ├── layout.py               # paths, ids, canonical request keys
    ├── metadata.py             # sidecar models + JSON Schema validation
    ├── sanitize/
    │   ├── classify.py         # value-type detection by element context + parsing
    │   ├── forge.py            # type-preserving forged value generators (HMAC-keyed)
    │   ├── keeplist.py         # built-in values never replaced
    │   └── leakcheck.py        # original-value search + CI lint rules
    ├── generate.py             # deterministic synthetic datasets (large-estate)
    └── capture.py              # opt-in live capture (PANOS_MCP_LIVE=1) with no-change check

samples/
├── README.md                   # how samples are gathered, provenance rules, supported versions
├── INDEX.md                    # generated coverage table
├── 11.1/
│   ├── op/<command-slug>/<variant>.xml + .meta.json
│   ├── config/<command-slug>/...
│   └── log/<command-slug>/...
├── 11.2/...
├── any/...                     # version-independent (e.g. error responses)
└── scenarios/                  # baseline, disconnected-device, auth-failure,
                                # candidate-differs, large-estate, log-timeout, ...
capture-plans/                  # request sets for opt-in live capture

tests/
├── conftest.py                 # replay fixtures; network guard (fail on real transport)
├── unit/                       # parsers, allowlist, hierarchy, filters, sanitizer, config
├── contract/                   # each MCP tool × scenarios; schema snapshots; allow-list audit
├── samples/                    # library validity + sanitization lint (wraps `validate`)
├── benchmark/                  # large-estate timing (marker: benchmark)
└── integration/live/           # opt-in (marker: live, PANOS_MCP_LIVE=1)

.github/workflows/ci.yml        # ruff, mypy, pytest (offline), samples validate
```

**Structure Decision**: one Python package (`src/panos_mcp`) with two entry points. The
production server and the sample tooling share the XML API client and allow-list, so live
capture is read-only by construction. Dependencies point one way: tools → services →
client/parsers → models, which keeps services testable with the replay transport.
`samples/` is data at the repo root, not package code, so non-developers can review and add
samples in PRs.

### Workstreams (input for `/speckit-tasks`)

1. **Foundation**: project setup, settings, logging and redaction, models, client, allow-list,
   error mapping, replay transport, network-guard test fixture.
2. **Sample library**, requested by the user as its own deliverable:
   - Directory layout, metadata schema and sanitizer (forged values of the same type, keyed and
     consistent).
   - Leak check and CI lint.
   - `add`, `validate` and `index` commands.
   - **Gathering samples from the XML API documentation** for every request used by the 13
     tools, for 11.1 first and then 11.2.
   - Synthetic fill-ins and error samples.
   - Scenarios.
3. **US1: Inventory**, P1: `get_panorama_info`, `list_managed_devices`, `list_device_groups`,
   `list_templates`, `list_jobs`, `get_job`.
4. **US2: Policy and objects**, P1: `get_security_rules`, `get_nat_rules`, `get_objects`,
   `find_object_references`, `resolve_address_group`.
5. **US3: Troubleshooting**, P2: `query_logs`, `test_security_policy_match`.
6. **Scale and live**: the `generate large-estate` command and benchmarks; opt-in `capture`,
   capture plans and the live test suite.
7. **Docs**: README (install, Claude Code setup, offline demo, configuration, read-only role)
   and `samples/README.md`.

## Complexity Tracking

| Deviation | Why needed | Simpler alternative rejected because |
|---|---|---|
| Not-found / truncation test cases N/A for `get_panorama_info` (both), `list_jobs` (not-found) and `test_security_policy_match` (truncation) | They return one record, or take only filters and no lookup input | Inventing artificial not-found or truncation paths would add input parameters that serve no user need |
| One `request` command allowed: exact path `request/license/info` | FR-013 needs license data and it is only exposed through this display command | Dropping licenses loses a field auditors rely on; the exact-path rule keeps every other `request/*` command blocked (tested in the allow-list tests) |
