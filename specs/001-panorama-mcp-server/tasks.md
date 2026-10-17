---

description: "Task list for the Panorama MCP Server (read-only, offline-first)"
---

# Tasks: Panorama MCP Server

**Input**: Design documents from `/specs/001-panorama-mcp-server/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: REQUIRED. Constitution Principle IV (Test-First Against Recorded Panorama Behavior) mandates tests written before implementation, run offline against the sample library. Every tool needs success, not-found, permission-denied, and truncation tests.

**Organization**: Tasks are grouped by user story so each story can be implemented and tested on its own. Sample gathering, which the user asked for as its own deliverable, has two parts:
- The tooling and layout are foundational (Phase 2).
- The **sample content** for each story is gathered inside that story's phase.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on incomplete tasks)
- **[Story]**: US1 = Inventory & health, US2 = Policy & objects, US3 = Troubleshooting (logs, policy match)

## Path Conventions

- Package code: `src/panos_mcp/`
- Sample library (data): `samples/`
- Tests: `tests/`

These follow plan.md → Project Structure.

## Global rules for every task (read before starting any task)

- **Read-only**: never write code that sends a Panorama request outside the allow-list in research.md R4.
- **No network in tests**: tests use the replay transport (`src/panos_mcp/client/replay.py`). The fixture in `tests/conftest.py` fails any test that reaches a real transport.
- **Sanitize every sample**: every sample under `samples/` MUST be added with `panos-mcp-samples add`, which sanitizes it and runs the leak check. Never hand-edit real data into a sample.
  - Forged values follow research.md R8:
    - Public IPs: RFC 5737 / 198.18.0.0/15.
    - Private IPs: stay in the same RFC 1918 block.
    - Domains: `example.*` / `.test`.
    - Serials: digits only, starting with `9`.
    - MACs: `00:00:5e:00:53:xx`.
    - Secrets: `REDACTED`.
- **Samples from documentation**: use the Palo Alto Networks *PAN-OS and Panorama XML API Usage* guide for the stated version. Record its URL in `provenance.url`.
  - If no documented example exists, author a schema-conformant response with `provenance.source = "synthetic"` and say in `provenance.notes` what it was derived from.
  - All new samples get `status = "unverified"`.
- **Typing and checks**: all public functions and tool handlers carry type hints. `uv run ruff check . && uv run mypy && uv run pytest` must pass at each checkpoint.
- **Stderr only**: logging goes to stderr only; stdout is the MCP channel.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and tooling

- [X] T001 Create `pyproject.toml` for a `uv` project named `panos-mcp`:
  - `requires-python = ">=3.12"`.
  - Runtime deps: `mcp`, `httpx`, `pydantic>=2`, `pydantic-settings`, `defusedxml`. Pin `mcp` to the current compatible major after checking its import path for `FastMCP` and `ToolAnnotations` (research.md R2).
  - Dev extra: `pytest`, `anyio`, `ruff`, `mypy`, `jsonschema`, `psutil`, `types-defusedxml` if available.
  - Scripts: `panos-mcp = "panos_mcp.__main__:main"`, `panos-mcp-samples = "panos_mcp.samples.cli:main"`.
  - src layout with package `src/panos_mcp`.
- [X] T002 Create the package skeleton with empty `__init__.py` files:
  - `src/panos_mcp/` and its subpackages `client/`, `models/`, `parsers/`, `services/`, `tools/`, `samples/`, `samples/sanitize/`.
  - Test directories: `tests/unit/`, `tests/contract/`, `tests/samples/`, `tests/benchmark/`, `tests/integration/live/`.
- [X] T003 [P] Configure tooling in `pyproject.toml`:
  - ruff: line length 100; rule sets `E,F,I,B,UP,S,ASYNC,RUF`.
  - mypy: `strict = true`, `files = ["src", "tests"]`.
  - pytest: `testpaths = ["tests"]`; markers `live`, `benchmark`; `addopts = "-m 'not live and not benchmark'"`; anyio backend `asyncio`.
- [X] T004 [P] Create `.github/workflows/ci.yml`:
  - Runs on push/PR with Python 3.12 and 3.13: `uv sync --all-extras`, `uv run ruff format --check .`, `uv run ruff check .`, `uv run mypy`, `uv run pytest`, `uv run panos-mcp-samples validate samples/`.
  - No secrets and no live tests in CI.
- [X] T005 [P] Update `.gitignore`:
  - Add `.env`, `*.env`, `.panos-mcp-sanitize/`, `sanitize-mapping*.json`, `sanitize.key`, `.venv/`, `.mypy_cache/`, `.ruff_cache/`.
  - Keep the existing `.claude/` entry.
- [X] T006 [P] Create the sample library skeleton:
  - `samples/README.md`. Explain:
    - The layout `samples/<panos-version>/<api-type>/<command-slug>/<variant>.xml` + `.meta.json`.
    - Provenance values `documentation | synthetic | lab-capture`.
    - The status values `unverified | verified`.
    - The forged-data rules (research.md R8).
    - Supported versions 11.1, 11.2, 12.1.
    - How to add a sample with `panos-mcp-samples add`.
  - Empty dirs `samples/11.1/`, `samples/11.2/`, `samples/any/`, `samples/scenarios/`, `capture-plans/` with `.gitkeep`.
- [X] T007 [P] Copy `specs/001-panorama-mcp-server/contracts/sample-metadata.schema.json` to `src/panos_mcp/samples/sample-metadata.schema.json` and include it as package data in `pyproject.toml`.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core client, read-only guarantee, models envelope, sample library tooling, replay transport, MCP server skeleton.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### 2a. Tests first (write, run, confirm they FAIL)

- [X] T008 [P] Write `tests/conftest.py`:
  - An autouse fixture that monkeypatches `httpx.AsyncHTTPTransport.handle_async_request` to raise `AssertionError("network access in tests")`.
  - A `replay_client(scenario: str)` fixture that builds the XML API client on the replay transport.
  - A `settings_offline` fixture.
- [X] T009 [P] Write `tests/unit/test_allowlist.py`. It asserts that the allow-list:
  - **Accepts**: each op command in research.md R4 (`show/system/info`, `show/high-availability/state`, `show/devices/all`, `show/devicegroups`, `show/dg-hierarchy`, `show/templates`, `show/jobs/all`, `show/jobs/id`, `check/pending-changes`, `show/object/dynamic-address-group`, `test/security-policy-match`, `request/license/info` (exact path only)); `config` with `action` `get` and `show` and an xpath starting `/config/`; `log` start for `traffic|threat|url|system|config`; and `log` `action=get` only for job IDs started by this process.
  - **Rejects with `ReadOnlyViolation`**: `set`, `edit`, `delete`, `move`, `rename`, `clone`, `override`, `multi-move`, `commit`, `commit-all`, `revert`, every other `request ...` (explicitly `request/license/fetch`, `request/license/install`, `request/license/deactivate`, `request/system/...`, `request/batch/...`), `clear ...`, `debug ...`, `type=import`, `type=export`, `type=user-id`, `type=report`, xpaths not starting `/config/`, and op `cmd` that is not well-formed XML or has multiple roots.
- [X] T010 [P] Write `tests/unit/test_config.py`:
  - Covers every env var in `contracts/configuration.md`: host required unless `PANOS_MCP_SAMPLES_SCENARIO` is set; an API key or username/password pair is required; `PANOS_MCP_VERIFY_TLS` defaults to `true`.
  - Numeric defaults: `TIMEOUT=30`, `QUERY_TIMEOUT=60`, `LOG_LIMIT_MAX=1000`, `CACHE_TTL=30`, `MAX_CONCURRENCY=4`.
  - Secrets never appear in `repr()`, `str()` or `model_dump()` output.
- [X] T011 [P] Write `tests/unit/test_logging_redaction.py`:
  - Log records containing the API key, the password, or an `X-PAN-KEY: <value>` header are masked as `***`.
  - Handlers write to stderr only.
- [X] T012 [P] Write `tests/unit/test_errors.py` for the Panorama/transport → `ToolError.code` mapping (data-model.md §B):
  - 403 from `keygen`, or a response whose message says the key is invalid or expired → `auth_failed`. Any other 403 or `<response status="error" code="403">` → `permission_denied`.
  - Codes 7/12 → `not_found` / `invalid_input`.
  - `httpx.ConnectError` → `unreachable`.
  - SSL errors → `tls_error`.
  - `httpx.TimeoutException` → `timeout`.
  - Other error responses → `panorama_error`.
  - In every case `message` and `hint` are non-empty and contain no secret.
- [X] T013 [P] Write `tests/unit/test_xmlapi_client.py` against the replay transport:
  - Every request is `POST /api/` with header `X-PAN-KEY` and form params.
  - The key never appears in URL or params.
  - The allow-list check runs before the transport.
  - XML is parsed with defusedxml: a billion-laughs payload is rejected.
  - At most `MAX_CONCURRENCY` requests are in flight at once.
  - `keygen` is used once at startup when username/password are configured.
- [X] T014 [P] Write `tests/unit/test_cache.py`:
  - The TTL cache keyed by (`action`, `xpath`) returns a cached value within TTL and refetches after it.
  - `CACHE_TTL=0` disables caching.
  - `retrieved_at` reflects the original fetch time.
- [X] T015 [P] Write `tests/unit/test_sanitize.py`, one test per row of research.md R8. The table below gives each value type and the expected forged value:

  | Value type | Expected forged value |
  |---|---|
  | public IPv4 / prefix / range | RFC 5737 or 198.18.0.0/15; prefix length and range width preserved |
  | RFC 1918 | same block, subnet membership preserved |
  | CGNAT / loopback / link-local / multicast | same special range |
  | IPv6 global / ULA | `2001:db8::/32` / `fd00::/8` |
  | FQDN | `example.*` / `.test`, label count preserved |
  | names | shape preserved: prefix/separators/case/digit runs |
  | hostnames | `fw-<site>-NN` |
  | serials | same length, digits, starting with `9` |
  | MAC | `00:00:5e:00:53:xx` |
  | usernames | `user-NNN`, domain prefix `EXAMPLE\` |
  | emails | `user-NNN@example.com` |
  | descriptions/comments | neutral text of similar length |
  | URLs | `https://site-NN.example.com/...` |
  | secrets (`phash`, `key`, `password`, `private-key`, `pre-shared-key`, `community`) | `REDACTED` |

  The tests also assert:
  - Keep-list values (`any`, `application-default`, `ssl`, `web-browsing`, `service-http`, `default`, `strict`, action enums) are unchanged.
  - Mapping is deterministic for the same HMAC key and different for a different key.
  - The same real value maps to the same forged value across two files.
- [X] T016 [P] Write `tests/unit/test_leakcheck.py`:
  - Layer 1: an output still containing any original value fails.
  - Layer 2: the CI lint flags a public IP outside the documentation ranges, a non-`example.*` domain, a non-documentation MAC, a serial not starting with `9`, and a secret element containing anything but `REDACTED`.
- [X] T017 [P] Write `tests/unit/test_samples_layout.py`:
  - `id` ↔ path round-trip.
  - Canonical request key: op `cmd` with whitespace between elements stripped; config `(action, xpath)`; log `(log_type, log_phase)` with job-id placeholder.
  - Metadata validates against `sample-metadata.schema.json`: `documentation` requires `url`; `lab-capture` requires `captured_at`; `leak_check` must be `"passed"`.
- [X] T018 [P] Write `tests/unit/test_replay.py`:
  - The replay transport serves the sample mapped by a scenario.
  - A miss returns an error response when `default_on_miss = "error_not_found"` and raises when it is `"fail_test"`.
  - The allow-list is still enforced in front of replay.
  - Log job IDs are matched through placeholders.
  - Lookup order (data-model.md §C): own `responses` → parent chain via `extends` (nearest first) → nearest `default_response` → `default_on_miss`.
  - A scenario with only `default_response` answers every allow-listed request with that sample.
  - An `extends` cycle (A → B → A) or an unknown parent is a load error.
- [X] T019 [P] Write `tests/samples/test_library.py`. It runs `panos-mcp-samples validate samples/` in-process and asserts exit code 0, so it covers schema, well-formedness, the sanitization lint and scenario consistency.
- [X] T020 [P] Write `tests/unit/test_commands.py`:
  - `xpath_literal` handles `'`, `"` and both.
  - Injection-style names such as `x' or '1'='1`, `]/..` and `a"b` are **not** rejected: the resulting xpath selects only an entry with that exact literal name (assert by parsing the xpath predicate). Names that are empty, longer than 63 characters, or contain newlines/control characters are rejected as `invalid_input`.
  - A name starting with `_` is accepted.
  - Every builder output parses as XML.
  - Device-group names with spaces and dots round-trip correctly.
  - Every tool in `TOOL_REQUESTS` has at least one request template, and every template passes the allow-list.
- [X] T021 [P] Write `tests/unit/test_server_errors.py`. A tool that raises `KeyError` returns `isError=true` with code `panorama_error`. The client output has no `Traceback`, no file paths and no exception text, while stderr contains the traceback.

### 2b. Implementation

- [X] T022 [P] Implement `src/panos_mcp/models/common.py`:
  - `ConfigSource` enum `running | candidate` (default `running`).
  - `Scope` type (`"shared"` or device-group name).
  - `ToolResult[T]` (generic Pydantic model) with fields: `items`, `total: int | None`, `returned: int`, `truncated: bool`, `next_offset: int | None`, `narrowing_hint: str | None` (required when `truncated`), `config_source: ConfigSource | None`, `retrieved_at: datetime`, `warnings: list[str]`.
  - `ToolError` with `code` enum `not_found | invalid_input | permission_denied | auth_failed | unreachable | tls_error | timeout | panorama_error | read_only_violation | device_unavailable`, `message`, `hint`, `suggestions: list[str]`.
  - Pagination params: `limit: int = 50` constrained `1..500`, `offset: int = 0` constrained `>= 0`.
  - Helper `paginate(items, limit, offset, hint)` that sets `truncated`, `next_offset` and `narrowing_hint`.
- [X] T023 [P] Implement `src/panos_mcp/config.py`:
  - `Settings` (pydantic-settings, prefix `PANOS_MCP_`, optional `PANOS_MCP_ENV_FILE`) with all fields from `contracts/configuration.md`.
  - `SecretStr` for the API key and password.
  - Validation errors are rendered as plain-language messages to stderr, with exit code 2.
  - `tls_warning()` returns the warning text when verification is disabled.
- [X] T024 [P] Implement `src/panos_mcp/logging.py`:
  - `configure_logging(settings)`: a stderr `StreamHandler`, with the level from `PANOS_MCP_LOG_LEVEL`.
  - `RedactionFilter`: masks the configured secrets and the `X-PAN-KEY` header values.
  - Response payloads are logged only at DEBUG.
- [X] T025 Implement `src/panos_mcp/client/allowlist.py` (makes T009 pass):
  - `ReadOnlyViolation(Exception)`.
  - `check_request(params: Mapping[str, str], started_log_jobs: set[int]) -> None`. It implements research.md R4 exactly and parses `cmd` with defusedxml to extract the root→leaf path.
  - A module docstring stating that this file is the read-only guarantee and that changes require review under constitution Principle I.
- [X] T026 [P] Implement `src/panos_mcp/client/commands.py`:
  - Typed builders returning the `cmd` XML for each allow-listed op command (`show_system_info()`, `show_ha_state()`, `show_devices_all()`, `show_devicegroups()`, `show_dg_hierarchy()`, `show_templates()`, `show_jobs_all()`, `show_job(job_id: int)`, `check_pending_changes()`, `show_dynamic_address_group(name: str | None)`, `test_security_policy_match(...)`).
  - Typed builder `show_license_info()` for `request/license/info`.
  - Xpath builders `shared_xpath(...)`, `device_group_xpath(dg, ...)` and `template_stack_xpath(...)`.
  - Values placed inside `cmd` XML are XML-escaped (`xml.sax.saxutils.escape`, plus quote escaping for attributes).
  - Values placed inside xpath predicates go through `xpath_literal(value)`. It returns `'v'` when there is no `'`, `"v"` when there is no `"`, and otherwise `concat('a', "'", 'b')`.
  - Safety comes from `xpath_literal` alone, not from restricting names. Names are only checked for what PAN-OS can never contain: empty, longer than 63 characters (verify per object type in the docs), control characters or newlines. Anything else is quoted safely and passed through, so existing objects with unusual names (leading `_`, other punctuation PAN-OS allows) can still be looked up. Violations → `invalid_input`.
  - Never format user input into an xpath or command string directly.
  - Define `TOOL_REQUESTS: dict[str, list[RequestTemplate]]`, mapping each of the 13 tool names to the request shapes it can issue (type + cmd path or xpath pattern). This one registry is used by `samples index` (T035) for coverage, by `capture-plans/baseline.json` generation (T085) and by the allow-list audit (T090).
- [X] T027 [P] Implement `src/panos_mcp/client/errors.py`. It maps exceptions and Panorama error responses to `ToolError` per T012, with plain-language messages and hints (e.g. "Check that the API key is valid and the admin role allows XML API config read").
- [X] T028 [P] Implement `src/panos_mcp/client/cache.py`: an async-safe TTL cache keyed by `(action, xpath)` that stores `(retrieved_at, element)`. A TTL of 0 means disabled.
- [X] T029 Implement `src/panos_mcp/client/xmlapi.py` (makes T013 pass). This is `PanoramaClient`:
  - Holds one `httpx.AsyncClient`, with an injectable transport.
  - `verify` comes from settings, or the CA bundle path.
  - Per-request timeout `PANOS_MCP_TIMEOUT`.
  - An `asyncio.Semaphore(MAX_CONCURRENCY)` bounds concurrent requests.
  - Methods:
    - `op(cmd, target=None)`
    - `config_get(xpath)` (candidate)
    - `config_show(xpath)` (running)
    - `config(xpath, source: ConfigSource)`
    - `log_start(log_type, query, nlogs, skip)`
    - `log_get(job_id)`
    - `keygen()`, startup only
  - Every request calls `allowlist.check_request` first.
  - Responses are parsed with `defusedxml.ElementTree`.
  - `status="error"` responses raise mapped errors.
  - Bounded retry: one retry only, on connect errors.
- [X] T030 Implement sample library core:
  - `src/panos_mcp/samples/layout.py`: paths, ids, `canonical_request_key()`.
  - `src/panos_mcp/samples/metadata.py`: Pydantic models for the meta sidecar, plus JSON Schema validation using the packaged schema.
  - Together these make T017 pass.
- [X] T031 [P] Implement `src/panos_mcp/samples/sanitize/keeplist.py`. It holds the built-in values that are never replaced (research.md R8 footnote), extensible by a `samples/keeplist.txt` file.
- [X] T032 [P] Implement `src/panos_mcp/samples/sanitize/classify.py`. It classifies values by XML element/attribute context (`entry/@name`, `member`, `ip-netmask`, `ip-range`, `fqdn`, `serial`, `hostname`, `devicename`, `description`, `comment`, `admin`, `user`, `src-user`, MAC-bearing fields, secret elements) and by parsing (`ipaddress`, regexes for email/URL/MAC).
- [X] T033 Implement `src/panos_mcp/samples/sanitize/forge.py` (makes T015 pass):
  - Type-preserving forged-value generators driven by `hmac.new(key, value, sha256)`.
  - A persistent mapping store (default `~/.config/panos-mcp/sanitize/`: `sanitize.key`, `mapping.json`). The store refuses a directory inside the repo unless it is git-ignored.
  - `sanitize_tree(element) -> (element, originals: set[str])`.
- [X] T034 Implement `src/panos_mcp/samples/sanitize/leakcheck.py` (makes T016 pass): `check_originals(text, originals)` and `lint(text) -> list[Finding]` (research.md R8 leak checks).
- [X] T035 Implement `src/panos_mcp/samples/cli.py` with `argparse` sub-commands `add`, `sanitize`, `validate` and `index`, as specified in `contracts/samples-cli.md`:
  - Exit codes `0/1/2/3`.
  - `add` refuses to overwrite without `--force`.
  - `index` writes `samples/INDEX.md` (commands × versions × provenance × status, with uncovered requests from `commands.TOOL_REQUESTS` flagged).
  - `generate` and `capture` are stubs that exit 2 with "not yet implemented"; T083 and T087 implement them.
  - Together this makes T019 pass on an empty library.
- [X] T036 Implement `src/panos_mcp/client/replay.py` (makes T018 pass):
  - `ReplayTransport(httpx.AsyncBaseTransport)`. It loads `samples/scenarios/<name>.json`, canonicalizes each incoming form request with `layout.canonical_request_key`, and returns the mapped sample XML with HTTP 200.
  - Log job IDs are assigned deterministically.
  - Supports `extends` and `default_response` with the lookup order in data-model.md §C; the same resolver is used by `samples validate` (scenario consistency, inheritance cycles).
  - Misses are handled according to `default_on_miss`.
- [X] T037 Add version-independent error samples via `panos-mcp-samples add` in `samples/any/`:
  - `op/error-403/invalid-key`
  - `op/error-403/role-denied`
  - `config/error-not-present/code-7`
  - `config/error-invalid-object/code-12`
  - `op/error-generic/unknown-command`

  Source each from the documented XML API error format, using `documentation` provenance where the docs show an example and `synthetic` otherwise. Create `samples/scenarios/auth-failure.json`, which maps every request to `invalid-key` through `default_response`.

  Also create `samples/scenarios/permission-denied.json`, which maps **every** request to `role-denied` through `default_response` (no `responses`). This mimics an admin role that may log in but has no XML API read rights. The server makes no Panorama call at startup in offline mode, so it still starts.
- [X] T038 Implement `src/panos_mcp/server.py`:
  - `build_server(client, settings) -> FastMCP` with server name `panorama`.
  - Instructions text: read-only, one Panorama, how to scope queries.
  - A helper `readonly_tool()` decorator that registers tools with `ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)`. It converts raised `ToolError` into an MCP error result with `isError=true` and structured `{code, message, hint, suggestions}`.
  - Global warnings: TLS verification disabled; connected to a passive HA peer.
  - Any other exception raised in a tool is caught, logged with its traceback to **stderr only**, and returned as `ToolError(code=panorama_error, message="Unexpected error while processing the Panorama response", hint="Retry; if it persists, run with PANOS_MCP_LOG_LEVEL=DEBUG and report the log (it contains no secrets)")`. No exception text or traceback is sent to the client.
- [X] T039 Implement `src/panos_mcp/__main__.py` `main()`:
  - Load settings; configure logging.
  - Build the client: `ReplayTransport` when `PANOS_MCP_SAMPLES_SCENARIO` is set (log "offline demo mode: scenario <name>" to stderr), otherwise HTTPS, running `keygen` if needed.
  - Build the server and `run(transport="stdio")`. Never open a network listener.
- [X] T040 Implement `src/panos_mcp/services/hierarchy.py`, shared by US1 and US2, with matching tests in `tests/unit/test_hierarchy.py` written first:
  - `DeviceGroupTree` built from the `show/dg-hierarchy` response: `ancestors(dg) -> list[str]` ending with `"shared"`, `descendants(dg)`, `exists(dg)`.
  - `close_matches(name)` using `difflib`.
  - `resolve_scope(name)` raising `ToolError(not_found, suggestions=...)`.

**Checkpoint**: `uv run pytest` is green. `panos-mcp-samples validate samples/` passes. `PANOS_MCP_SAMPLES_SCENARIO=auth-failure uv run panos-mcp` starts and lists zero tools without error.

---

## Phase 3: User Story 1 - Inventory and health of managed firewalls (Priority: P1) 🎯 MVP

**Goal**: An engineer can list managed firewalls with status, device groups (hierarchy), templates/stacks, Panorama info, and jobs (FR-010…FR-014).

**Independent Test**: With `PANOS_MCP_SAMPLES_SCENARIO=baseline`, ask Claude Code "Which firewalls are disconnected?" and "Show the device group hierarchy". The answers must match `samples/scenarios/baseline.json` (quickstart.md Scenario 3, rows 1–2). The contract tests in `tests/contract/test_inventory_tools.py` must pass.

### Sample gathering for User Story 1

- [X] T041 [P] [US1] Gather and add 11.1 samples for `show/system/info` (variants `baseline`, `passive-ha`) and `show/high-availability/state` (variants `standalone`, `active`, `passive`) under `samples/11.1/op/`, via `panos-mcp-samples add`, sourced from the XML API Usage guide 11.1. Also add `request/license/info` (variant `baseline`, one expired license).
- [X] T042 [P] [US1] Gather and add 11.1 samples for `show/devices/all` under `samples/11.1/op/show-devices-all/`. Variants:
  - `baseline`: 4 firewalls across 3 device groups, all connected and in sync, one HA pair, one multi-vsys.
  - `one-disconnected`: same estate, one firewall `connected=no`.
  - `out-of-sync`: two firewalls out of sync.
  - `empty`: no managed firewalls.
- [X] T043 [P] [US1] Gather and add 11.1 samples under `samples/11.1/`, consistent with the `baseline` devices (same forged serials and names):
  - `show/devicegroups` (variant `baseline`).
  - `show/dg-hierarchy` (variant `baseline`: `shared` → `Global-DG` → {`Region-A-DG` → `Branch-DG`, `Region-B-DG`}).
  - `show/templates` (variant `baseline`).
  - Config xpath for template stacks (variants `baseline-running`, `baseline-candidate`).
- [X] T044 [P] [US1] Gather and add 11.1 samples for `show/jobs/all` (variants `baseline` with commit, commit-all/push, content jobs in states pending/active/finished with ok/fail; and `empty`) and `show/jobs/id` (variants `push-ok` with per-device results, `push-partial-fail` with at least 3 firewall results including 1 failure, and `not-found`) under `samples/11.1/op/`.
- [X] T045 [US1] Repeat T041–T044 for Panorama 11.2 under `samples/11.2/`. Wherever the 11.2 documentation shows no difference, add one 11.2 sample per command noting "identical to 11.1 per documentation" in `provenance.notes`. Record any element-name differences, especially for template stacks and `show/devices/all` (the research.md R4 verify item).
- [X] T046 [US1] Create the inventory scenarios in `samples/scenarios/`: `baseline.json` (inventory requests → baseline variants) and `disconnected-device.json` (`extends: "baseline"`; overrides `show/devices/all` → `one-disconnected`), and `license-denied.json` (`extends: "baseline"`; overrides `request/license/info` → `samples/any/op/error-403/role-denied`, used to test that `get_panorama_info` still returns its other data with a warning). Run `panos-mcp-samples validate` and `index`.

### Tests for User Story 1 (write first, confirm they FAIL)

- [X] T047 [P] [US1] Write `tests/unit/test_parsers_inventory.py`. It parses each US1 sample (11.1 and 11.2) into models and asserts field values for:
  - `serial`, `hostname`, `model`, `mgmt_ip`, `sw_version`, `device_group`, `template_stack`;
  - `connected`, `config_sync` (`in_sync | out_of_sync | unknown`), HA, `vsys` list;
  - device-group children/members, template stack members, job states;
  - `PanoramaInfo.ha_state` (`standalone | active | passive | suspended | unknown`).
- [X] T048 [P] [US1] Write `tests/contract/test_inventory_tools.py`. For each US1 tool it asserts:
  - tool registered, with read-only annotations;
  - input schema matches `contracts/mcp-tools.md` §1–6;
  - success on `baseline`;
  - `list_managed_devices(connected=False)` on `disconnected-device` returns exactly one firewall (US1-2);
  - `list_managed_devices(config_sync="out_of_sync")` (US1-4);
  - `not_found` with suggestions for: `list_managed_devices(device_group=<unknown>)`, `list_managed_devices(template_stack=<unknown>)`, `list_device_groups(root=<unknown>)` and `list_templates(name=<unknown>)`;
  - `list_jobs` not-found N/A (no lookup input): assert an empty `items` list with `total=0` when no job matches its filters;
  - `auth_failed` on `auth-failure`;
  - permission-denied scenario → every US1 tool returns code `permission_denied` with a hint naming the missing XML API permission;
  - truncation with `limit=2` (`truncated=true`, `next_offset=2`, non-empty `narrowing_hint`);
  - `list_device_groups(limit=2)`, `list_templates(limit=1)` and `list_jobs(limit=2)` → truncation;
  - `get_job(job_id=0)` → `invalid_input` (`job_id: int (>0)`);
  - `get_job(job_id=999999)` → `not_found`;
  - `get_job(<push-partial-fail job>, max_devices=2)` → `devices` has 2 entries with failures first, `truncated=true`, `total` = full count, non-empty `narrowing_hint`;
  - `get_panorama_info` not-found/truncation N/A: assert the output is a single object with no `next_offset` (contracts/mcp-tools.md, required test cases);
  - `get_panorama_info` on `baseline` includes licenses from `request/license/info`;
  - `get_panorama_info` on `license-denied` succeeds with `licenses` empty and a warning that the admin role cannot read license information;
  - every request seen by the transport passes the allow-list.

### Implementation for User Story 1

- [X] T049 [P] [US1] Implement `src/panos_mcp/models/inventory.py` per data-model.md §A:
  - `PanoramaInfo` (with `License`), `ManagedFirewall` (with `HAStatus`), `DeviceGroup`, `Template` (`kind: template | template_stack`), `Job` (with `JobDeviceResult`; `status: pending | active | finished`, `result: ok | fail | pending | unknown`, `progress: int 0..100`).
  - Serial input validator `^[0-9A-Za-z]{8,20}$`.
- [X] T050 [US1] Implement `src/panos_mcp/parsers/inventory.py` (makes T047 pass). It provides functions that turn each US1 response element into models and tolerates missing optional elements and version differences recorded in T045.
- [X] T051 [US1] Implement `src/panos_mcp/services/inventory.py`:
  - `get_panorama_info()`: system info + HA state; adds the passive-peer and TLS warnings.
  - `list_devices(filters)`: `show/devices/all`, joined with device groups and templates for membership. Filters: `device_group`, `template_stack`, `connected`, `config_sync`, `model`, and `sw_version` as a prefix match. Unknown device groups and stacks are validated through `hierarchy.resolve_scope` and the template list.
  - `list_device_groups(root, include_members)`, depth-first from `shared`.
  - `list_templates(kind, name)`.
  - `list_jobs(status, job_type, limit=20)`, newest first.
  - `get_job(job_id)`.
- [X] T052 [US1] Implement `src/panos_mcp/tools/inventory.py` (makes T048 pass). It contains the six handlers `get_panorama_info`, `list_managed_devices`, `list_device_groups`, `list_templates`, `list_jobs` and `get_job`:
  - Input schemas follow `contracts/mcp-tools.md` §1–6.
  - Descriptions are written for an AI assistant: purpose, when to use, read-only.
  - Each handler returns `ToolResult` plus a concise text summary such as "4 firewalls, 1 disconnected: fw-site-03 (9000000000003)".
  - Register the handlers in `src/panos_mcp/server.py`.

**Checkpoint**: US1 is fully functional offline. Quickstart Scenario 3 rows 1–2 work in Claude Code with `baseline` and `disconnected-device`.

---

## Phase 4: User Story 2 - Inspect security policy and objects (Priority: P1)

**Goal**: Engineers can retrieve security/NAT rules per scope or the effective inherited rulebase, filter them, list objects, find where an object is used, and expand address groups, always labeled running/candidate (FR-020…FR-026).

**Independent Test**: With `baseline`, ask for the effective security policy of `Branch-DG`, where an address object is used, and the expansion of a nested address group. Answers must match the scenario samples (quickstart.md Scenario 3, rows 3–5). `tests/contract/test_policy_tools.py` and `tests/contract/test_object_tools.py` must pass.

### Sample gathering for User Story 2

- [X] T053 [P] [US2] Gather and add 11.1 config samples (`action=show`, running) for security pre- and post-rulebases in `shared`, `Global-DG`, `Region-A-DG` and `Branch-DG`, under `samples/11.1/config/security-rules-*`:
  - At least 3 rules per scope.
  - Cover: disabled rules, negate source, tags, multiple zones, application-default, profile group, and target devices.
  - Rules reference the objects added in T055 so references resolve.
- [X] T054 [P] [US2] Gather and add 11.1 config samples (running) for NAT pre- and post-rulebases in `shared` and `Branch-DG` under `samples/11.1/config/nat-rules-*`. Cover: dynamic-ip-and-port, static bidirectional, destination translation with port, and nat64 if documented.
- [X] T055 [P] [US2] Gather and add 11.1 config samples (running) for objects in `shared`, `Global-DG` and `Branch-DG` under `samples/11.1/config/<kind>-*`. Include:
  - `address`: all four types `ip-netmask | ip-range | ip-wildcard | fqdn`.
  - `address-group`: static with nested groups; one dynamic with a tag filter; one cycle (A→B→A) in a dedicated variant.
  - `service`, `service-group`, `application-group`, `tag`, `profile-group`.
  - One object name defined in both `shared` and `Branch-DG` (override case).
  - One tag used on two addresses and in one dynamic-group filter.
  - One address object referenced at least 3 times (rules + groups) and one nested static group that expands to at least 3 addresses (needed by the truncation tests in T065).
- [X] T056 [P] [US2] Add `action=get` (candidate) variants for `Branch-DG` security pre-rules and `shared` address objects under `samples/11.1/config/`. In them, one rule is added and one address changed versus running. Add a `check/pending-changes` sample (variants `none`, `pending`).
- [X] T057 [P] [US2] Gather and add an 11.1 sample for `show/object/dynamic-address-group` with `target` (variant `baseline`, members for the dynamic group from T055) under `samples/11.1/op/`.
- [X] T058 [US2] Repeat T053–T057 for 11.2 under `samples/11.2/config/`. Where the 11.2 documentation shows no difference, keep one variant per command with an "identical to 11.1 per documentation" note.
- [X] T059 [US2] Extend `samples/scenarios/baseline.json` with all US2 requests. Create `samples/scenarios/candidate-differs.json` (`extends: "baseline"`; overrides the candidate requests) and `samples/scenarios/address-group-cycle.json` (`extends: "baseline"`; overrides the address-group requests with the cycle variant). Then run `panos-mcp-samples validate` and `index`.

### Tests for User Story 2 (write first, confirm they FAIL)

- [X] T060 [P] [US2] Write `tests/unit/test_parsers_policy.py`. It parses security and NAT samples into `SecurityRule`/`NatRule` (all fields in data-model.md §A, including `action` enum `allow | deny | drop | reset-client | reset-server | reset-both` and `nat_type` enum `ipv4 | nat64 | nptv6`). It also parses each object kind, with address `type` enum `ip-netmask | ip-range | ip-wildcard | fqdn` and service `protocol` enum `tcp | udp | sctp`.
- [X] T061 [P] [US2] Write `tests/unit/test_effective_rulebase.py`:
  - For `Branch-DG` the order is: `shared` pre → `Global-DG` pre → `Region-A-DG` pre → `Branch-DG` pre → `Branch-DG` post → `Region-A-DG` post → `Global-DG` post → `shared` post.
  - Each rule carries `scope`, `position` and a 1-based `order`.
- [X] T062 [P] [US2] Write `tests/unit/test_rule_filters.py`:
  - Covers filters `name_contains`, `tag`, `from_zone`, `to_zone`, `source`, `destination`, `application`, `service`, `action`, `disabled`, AND-combined.
  - An IP/CIDR `destination` filter matches rules whose resolved addresses contain it (US2 scenario 1: `10.20.0.0/16`), including through nested groups.
  - `any` matches everything.
- [X] T063 [P] [US2] Write `tests/unit/test_objects_service.py`:
  - Name resolution picks the nearest scope (`Branch-DG` override beats `shared`) and reports the resolved scope.
  - Where-used finds references in the defining scope and all descendants, excluding shadowed references, which are listed in warnings.
  - Static group expansion flattens nested groups and de-duplicates.
  - The cycle is reported in `cycles_detected` without infinite recursion.
  - A dynamic group without `device_serial` returns `dynamic_filter` and a hint to supply a serial.
  - A dynamic group *with* `device_serial` returns members from the `show/object/dynamic-address-group` sample.
  - Where-used for a **tag** finds rules, objects and dynamic-group filters that use it.
  - Where-used for a **security profile** name finds profile groups and rules.
- [X] T064 [P] [US2] Write `tests/contract/test_policy_tools.py` for `get_security_rules` and `get_nat_rules`:
  - Annotations and input schema per `contracts/mcp-tools.md` §7–8.
  - `effective=true` on `baseline` (US2-1).
  - Filters (US2-4).
  - `config_source="candidate"` on `candidate-differs` shows the extra rule and `config_source="candidate"` in the result (US2-5, FR-026).
  - Unknown scope → `not_found` with suggestions.
  - `auth-failure` → `auth_failed`.
  - permission-denied scenario → `permission_denied` for both tools.
  - `limit=2` → truncation with a narrowing hint.
  - Allow-list audit of all transported requests.
- [X] T065 [P] [US2] Write `tests/contract/test_object_tools.py` for `get_objects`, `find_object_references` and `resolve_address_group`, covering:
  - schemas per §9–11;
  - US2-2 (references) and US2-3 (nested expansion) on `baseline`;
  - the override flagged `effective`;
  - `address-group-cycle`;
  - `not_found` and `auth_failed` cases;
  - truncation: `get_objects(kind="address", limit=2)` and `find_object_references(<object used ≥3 times>, limit=2)` → `truncated=true`, `next_offset=2`; `resolve_address_group(<nested group with ≥3 addresses>, max_addresses=2)` → 2 addresses, `truncated=true`, `total` = full count, non-empty `narrowing_hint`;
  - permission-denied scenario → `permission_denied` for all three tools;
  - the allow-list audit.

### Implementation for User Story 2

- [X] T066 [P] [US2] Implement `src/panos_mcp/models/policy.py`: `Rule` base (`rule_type: security | nat`, `position: pre | post | default`, `order: int`), `SecurityRule`, `NatRule`, `RuleTarget`, `SourceTranslation` (`kind: dynamic-ip-and-port | dynamic-ip | static-ip`) and `DestinationTranslation`, per data-model.md §A.
- [X] T067 [P] [US2] Implement `src/panos_mcp/models/objects.py`:
  - `ObjectBase` with `kind: address | address_group | service | service_group | application_group | tag | security_profile_group`, plus subclasses `Address`, `AddressGroup` (`static_members` **or** `dynamic_filter`, validator enforcing exactly one), `Service`, `ServiceGroup`, `ApplicationGroup`, `Tag` and `SecurityProfileGroup`.
  - `ObjectReference` (`referrer_kind: security_rule | nat_rule | address_group | service_group | application_group`).
  - `ResolvedAddressGroup` (`kind: static | dynamic`).
- [X] T068 [US2] Implement `src/panos_mcp/parsers/policy.py` and `src/panos_mcp/parsers/objects.py` (makes T060 pass).
- [X] T069 [US2] Implement `src/panos_mcp/services/policy.py` (makes T061, T062 pass):
  - `get_rules(rule_type, scope, rulebase, effective, filters, config_source)`. It fetches per-scope rulebases through the client cache with bounded concurrency and builds the effective order via `hierarchy.ancestors`.
  - Filter matching, including IP/CIDR containment against resolved addresses, using `services/objects.py` resolution.
- [X] T070 [US2] Implement `src/panos_mcp/services/objects.py` (makes T063 pass): `get_objects(...)` with `include_inherited` and the `effective` flag, `resolve_name(name, kind, scope)`, `find_references(...)`, and `resolve_address_group(name, scope, device_serial)`. Dynamic membership comes from op `show/object/dynamic-address-group` with `target=device_serial`; its sample is added in T057.
- [X] T071 [US2] Implement `src/panos_mcp/tools/policy.py` with `get_security_rules` and `get_nat_rules`, and `src/panos_mcp/tools/objects.py` with `get_objects`, `find_object_references` and `resolve_address_group`:
  - Schemas per `contracts/mcp-tools.md` §7–11.
  - Every result sets `config_source` and labels `scope`.
  - The text summary states "running" or "candidate".
  - Register all five in `src/panos_mcp/server.py`.
  - Together this makes T064 and T065 pass.

**Checkpoint**: US1 and US2 both work independently on `baseline`. Quickstart Scenario 3 rows 3–5 behave as expected.

---

## Phase 5: User Story 3 - Troubleshoot traffic with logs and policy matching (Priority: P2)

**Goal**: Engineers can query traffic, threat, URL, system and config logs with filters and limits, and test which rule matches a flow on a firewall (FR-030…FR-032).

**Independent Test**: With `baseline`, ask for denied traffic to a given IP in the last hour and which rule matches tcp/443 between two hosts on a firewall. Answers must match the samples (quickstart.md Scenario 3, rows 6–7). With `log-timeout`, the user gets a clear timeout message. `tests/contract/test_troubleshooting_tools.py` must pass.

### Sample gathering for User Story 3

- [X] T072 [P] [US3] Gather and add 11.1 log samples under `samples/11.1/log/`. Each type gets one query-start response (job enqueued, `log_phase=start`) and result responses (`log_phase=result`) for:
  - `traffic` (allow + deny entries, ≥ 5 entries);
  - `threat` (≥ 3, varied severity);
  - `url` (≥ 3);
  - `system` (≥ 3);
  - `config` (≥ 3).

  Also add a `pending` (job still running) result variant for traffic. Entries reference forged devices, IPs and rules consistent with `baseline`.
- [X] T073 [P] [US3] Gather and add 11.1 samples for `test/security-policy-match` with `target=<baseline serial>` under `samples/11.1/op/test-security-policy-match/`. Variants:
  - `match-allow`
  - `match-deny`
  - `no-match` (default rule applies)
  - `device-disconnected` (error response)
- [X] T074 [US3] Repeat T072–T073 for 11.2 under `samples/11.2/`, with "identical per documentation" notes where applicable.
- [X] T075 [US3] Extend `samples/scenarios/baseline.json` with the US3 requests. Create `samples/scenarios/log-timeout.json` (`extends: "baseline"`), where every log result returns the `pending` variant. Then run `panos-mcp-samples validate` and `index`.

### Tests for User Story 3 (write first, confirm they FAIL)

- [X] T076 [P] [US3] Write `tests/unit/test_log_filters.py`:
  - The structured filters (`since` as datetime or relative `1h|24h`, `until`, `source`/`destination` IP or CIDR, `port` int `1..65535`, `application`, `action`, `rule`, `device_serial`, `severity`) build correct PAN-OS query syntax.
  - `advanced_filter` validation accepts balanced parentheses/quotes and allowed fields and operators (`eq`, `neq`, `in`, `notin`, `geq`, `leq`, `and`, `or`, `not`). It rejects unbalanced quotes, unknown fields and control characters.
  - `limit` defaults to 100, accepts `1..PANOS_MCP_LOG_LIMIT_MAX`, and is rejected above the max.
- [X] T077 [P] [US3] Write `tests/unit/test_parsers_logs.py`. It parses every log sample into `LogEntry` with the type-specific fields from data-model.md §A, puts unknown fields in a bounded `extra`, and parses policy-match responses into `PolicyMatchResult`.
- [X] T078 [P] [US3] Write `tests/contract/test_troubleshooting_tools.py` for `query_logs` and `test_security_policy_match`, covering:
  - schemas per `contracts/mcp-tools.md` §12–13;
  - US3-1: `query_logs(log_type="traffic", destination="192.0.2.10", action="deny", since="1h")`:
    - the **outgoing** `query` param recorded by the replay transport equals `( addr.dst in 192.0.2.10 ) and ( action eq deny ) and ( receive_time geq '<now-1h>' )` (fixed clock);
    - the returned entries are newest first;
    - `returned <= limit`, and `truncated=true` when the sample holds more than `limit` entries;
  - US3-2: rule name returned, plus "no match / default deny" wording;
  - US3-3: `log-timeout` → `timeout` with a hint to narrow the time range, finishing within `PANOS_MCP_QUERY_TIMEOUT` (set to 2 s in the test with a fake clock);
  - `device-disconnected` → `device_unavailable`;
  - invalid IP or port → `invalid_input`;
  - `query_logs(device_serial=<unknown serial>)` and `test_security_policy_match(device_serial=<unknown serial>)` → `not_found` with close-match suggestions;
  - `auth-failure`;
  - permission-denied scenario → `permission_denied` for `query_logs` and `test_security_policy_match` (truncation N/A for the latter: single result, no `next_offset`);
  - the allow-list audit, including that `log_get` is only used for job IDs started in the same call.

### Implementation for User Story 3

- [X] T079 [P] [US3] Implement `src/panos_mcp/models/logs.py`: `LogEntry` (with `log_type: traffic | threat | url | system | config` and the type-specific optional fields plus `extra: dict[str, str]` capped at 50 keys) and `PolicyMatchResult`, per data-model.md §A.
- [X] T080 [US3] Implement `src/panos_mcp/parsers/logs.py` (makes T077 pass).
- [X] T081 [US3] Implement `src/panos_mcp/services/logs.py` (makes T076 pass):
  - `build_query(filters)` and `validate_advanced_filter(text)`.
  - `query_logs(...)`. It starts the job, then polls `log_get` with exponential backoff (0.5 s → 4 s cap) until finished or `QUERY_TIMEOUT`, and returns entries newest first, truncated to `limit` with a narrowing hint.
  - `test_policy_match(...)`. It checks via `services/inventory.list_devices` that the device exists (`not_found` with suggestions otherwise) and is connected (`device_unavailable` otherwise).
  - When `query_logs` gets a `device_serial` filter, it checks it the same way (`not_found` if unknown) before starting the log job.
- [X] T082 [US3] Implement `src/panos_mcp/tools/troubleshooting.py` with `query_logs` and `test_security_policy_match` (schemas per `contracts/mcp-tools.md` §12–13) and register them in `src/panos_mcp/server.py` (makes T078 pass).

**Checkpoint**: All three user stories work independently. Quickstart Scenario 3 is complete, including the "create an address object" row, where no tool exists and the assistant reports read-only.

---

## Phase 6: Scale & Opt-in Live Lab (Cross-Cutting)

**Purpose**: SC-003 synthetic scale validation, and the opt-in live path to refresh samples (research.md R9, R13).

- [X] T083 Implement `src/panos_mcp/samples/generate.py` and wire `panos-mcp-samples generate large-estate --devices N --rules M --seed S` in `src/panos_mcp/samples/cli.py`:
  - Deterministically produces `samples/11.1/.../large-estate` variants (500 devices, 10,000 rules spread across the baseline device groups, matching objects) and `samples/scenarios/large-estate.json`.
  - `provenance.source = "synthetic"` with `provenance.generator` set to `"generate.py seed=<S>"`.
  - Generated output passes the sanitization lint.
- [X] T084 [P] Write `tests/benchmark/test_large_estate.py` (marker `benchmark`). It runs `list_managed_devices`, `get_security_rules(effective=true, destination=<ip>)` and `find_object_references` on `large-estate` and asserts each completes in < 5 s locally (SC-003, network excluded). It also asserts truncation hints appear.
- [X] T085 [P] Generate `capture-plans/baseline.json` from `commands.TOOL_REQUESTS` (`panos-mcp-samples capture --write-plan`), listing every allow-listed request used by the 13 tools with placeholder parameters (device group names and serials resolved at capture time from `show/devicegroups` and `show/devices/all`).
- [X] T086 Write `tests/unit/test_capture_guard.py`:
  - `capture` exits 3 when `PANOS_MCP_LIVE` is unset.
  - It exits 3 when the before/after state (`check/pending-changes` + latest commit job id from `show/jobs/all`) differs. Simulate this with the replay transport.
  - Nothing is written when the leak check fails.
- [X] T087 Implement `src/panos_mcp/samples/capture.py` and wire `capture` in `src/panos_mcp/samples/cli.py` per `contracts/samples-cli.md` (makes T086 pass):
  - Reuse `PanoramaClient` (allow-list enforced).
  - Snapshot state before and after.
  - Sanitize in memory, run the leak check, then write with `provenance.source = "lab-capture"`, `captured_at` and `status = "unverified"`.
  - `--mark-verified` promotes reviewed samples.
- [X] T088 [P] Write `tests/integration/live/test_live_readonly.py` (marker `live`, skipped unless `PANOS_MCP_LIVE=1`):
  - Calls each of the 13 tools once against the configured lab Panorama.
  - Asserts structured results and no `read_only_violation`.
  - Asserts the pending-changes and commit-job state are unchanged before and after the session.

- [X] T089 Create `tests/integration/live/questions.yaml` with 30+ entries across inventory (10), policy (10) and objects (10). Each entry has `question`, `tool` and `expected_args`, plus `expected_answer`, which is filled in from the Panorama web interface during the lab session. Add `tests/integration/live/test_questions.py` (marker `live`). It calls the tools directly and reports the match rate; SC-002 needs at least 95%.

**Checkpoint**: `uv run pytest -m benchmark` passes. Live tests are skipped by default. `capture` is safe by construction.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [X] T090 [P] Write `tests/contract/test_allowlist_audit.py`:
  - Iterates every scenario in `samples/scenarios/` and invokes every tool with representative inputs.
  - Records every request the transport sees and asserts 100% pass `allowlist.check_request` (constitution I, SC-005).
  - Asserts every request seen matches an entry in `TOOL_REQUESTS` for the tool that issued it.
  - Asserts no tool lacks `readOnlyHint=True`.
- [X] T091 [P] Write `tests/contract/test_no_secrets.py`:
  - Runs all tools on all scenarios with a recognizable fake key `TESTKEY-DO-NOT-LEAK` and password.
  - Captures tool outputs, error messages and stderr logs at DEBUG.
  - Asserts the secrets never appear (FR-002, SC-004).
- [X] T092 [P] Write `tests/contract/test_tool_schemas_snapshot.py`. It snapshots the 13 tool names and input JSON schemas to `tests/contract/snapshots/tools.json`, so any change fails until intentionally updated (constitution III: public contract).
- [X] T093 [P] Write `tests/unit/test_no_listener.py`. It starts the server in offline mode in a subprocess, lists its sockets with `psutil` (dev dependency) or `lsof`, and asserts there are no LISTEN sockets. It skips if neither tool is available (FR-006).
- [X] T094 [P] Write `README.md`, covering:
  - what the server does and that it is read-only;
  - install with `uv`;
  - Claude Code setup (from `contracts/configuration.md`);
  - offline demo mode with scenarios;
  - all env vars;
  - the recommended read-only Panorama admin role (FR-007);
  - the tool list with one-line descriptions;
  - the sample library workflow and the opt-in live capture;
  - known gaps (research.md).
- [X] T095 [P] Create `CHANGELOG.md` with a `0.1.0` entry listing the 13 tools and the sample library tooling.
- [X] T096 Run `uv run panos-mcp-samples index` and check `samples/INDEX.md` lists every request used by the 13 tools for 11.1 and 11.2 with at least one sample. Add any missing samples via `panos-mcp-samples add`.
- [X] T097 Run the full quickstart.md validation (Scenarios 1–4) on a clean checkout with the network disabled, and record the results in `specs/001-panorama-mcp-server/checklists/quickstart-validation.md`.
  - Manual checks, recorded in the same file:
    - SC-007: time a fresh install and first answer by following README only (goal: under 15 min).
    - SC-001: in the offline demo, time "Which firewalls are disconnected?" from asking to answer (goal: under 30 s).

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup and BLOCKS all user stories.
  - The 2a tests come before 2b implementation.
  - T025 (allow-list) → T029 (client) → T036 (replay) → T038/T039 (server).
  - T030 → T031/T032 → T033 → T034 → T035 (samples CLI) → T037 (error samples).
  - T040 depends on T029 and T036.
- **US1 (Phase 3)**: depends on Phase 2.
- **US2 (Phase 4)**: depends on Phase 2.
  - It reuses `services/hierarchy.py` (T040) only, not US1 code.
  - Its scenarios extend `baseline.json` (T046). If US1 is not done, create `baseline.json` in T059 instead.
- **US3 (Phase 5)**: depends on Phase 2.
  - `test_policy_match` uses `services/inventory.list_devices` (T051). If US1 is not done, implement a minimal device-status lookup in `services/logs.py`.
- **Scale & Live (Phase 6)**: after the stories whose tools it exercises (T084 needs US1 and US2; T088 needs all).
- **Polish (Phase 7)**: after all desired stories.

### User Story Dependencies

- **US1 (P1)**: independent after Foundational.
- **US2 (P1)**: independent after Foundational; shares scenario files with US1.
- **US3 (P2)**: independent after Foundational; optional reuse of US1's inventory service.

### Within Each User Story

Gather samples → scenarios → tests (FAIL) → models → parsers → services → tools → register in server → checkpoint.

### Parallel Opportunities

- Phase 1: T003–T007 in parallel after T001–T002.
- Phase 2: all 2a tests (T008–T019, T020, T021) in parallel; then T022, T023, T024, T026, T027, T028, T031 and T032 in parallel.
- Sample gathering tasks inside each story ([P]) in parallel, since each writes a different `samples/` directory.
- After Phase 2: US1, US2 and US3 can be worked on in parallel by different people.

---

## Parallel Example: User Story 1

```bash
# Gather samples in parallel (different sample directories):
Task: "T041 [US1] show/system/info + show/high-availability/state samples in samples/11.1/op/"
Task: "T042 [US1] show/devices/all samples in samples/11.1/op/show-devices-all/"
Task: "T043 [US1] devicegroups / dg-hierarchy / templates samples in samples/11.1/"
Task: "T044 [US1] jobs samples in samples/11.1/op/"

# Then write tests in parallel:
Task: "T047 [US1] tests/unit/test_parsers_inventory.py"
Task: "T048 [US1] tests/contract/test_inventory_tools.py"
```

## Parallel Example: User Story 2

```bash
Task: "T053 [US2] security rulebase samples"   Task: "T054 [US2] NAT samples"
Task: "T055 [US2] object samples"              Task: "T056 [US2] candidate samples"
Task: "T066 [US2] models/policy.py"            Task: "T067 [US2] models/objects.py"
```

## Parallel Example: User Story 3

```bash
Task: "T072 [US3] log samples"   Task: "T073 [US3] policy-match samples"
Task: "T076 [US3] test_log_filters.py"   Task: "T077 [US3] test_parsers_logs.py"   Task: "T078 [US3] contract tests"
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phase 1 Setup → Phase 2 Foundational. This gives the read-only client, the sample tooling and the replay transport.
2. Phase 3 US1: inventory samples and the six inventory tools.
3. **STOP and VALIDATE**: offline demo in Claude Code with `baseline` and `disconnected-device`.

### Incremental Delivery

1. Foundation → US1 (MVP demo) → US2 (policy and objects: largest productivity gain) → US3 (troubleshooting).
2. Phase 6 when scale numbers are needed or a lab Panorama becomes available.
3. Phase 7 before the first release (`0.1.0`).

### When a lab Panorama becomes available

Run T087 `capture` with `capture-plans/baseline.json` for each supported version and diff the new samples against the documentation-based ones. Fix parsers where shapes differ. Promote reviewed samples to `verified`. Run T088 and close the SC-002 / SC-003 gaps.

---

## Notes

- [P] tasks touch different files and do not depend on incomplete tasks.
- Commit after each task or logical group. Sample additions and the code that uses them can go in the same PR.
- Never commit `sanitize.key` or `mapping.json`. They live in `~/.config/panos-mcp/sanitize/`.
- Any change to `src/panos_mcp/client/allowlist.py` needs explicit reviewer sign-off (constitution I).
