# Quickstart & Validation Guide: Panorama MCP Server

**Feature**: `001-panorama-mcp-server` | Contracts: [mcp-tools](./contracts/mcp-tools.md),
[configuration](./contracts/configuration.md), [samples-cli](./contracts/samples-cli.md)

This guide proves the feature works end to end. Scenarios 1–4 need **no Panorama**; scenario 5
is opt-in for whoever has a lab.

## Prerequisites

- Python ≥ 3.12 and `uv`
- Claude Code (or another MCP client) for the interactive scenarios
- Repository checked out on branch `001-panorama-mcp-server`

```bash
uv sync --all-extras          # install runtime + dev dependencies
```

## Scenario 1 — Quality gates pass offline

```bash
uv run ruff format --check . && uv run ruff check .
uv run mypy
uv run pytest                  # unit + contract + samples; live tests auto-skipped
```

**Expected**: all green, no network access attempted (tests fail if any request reaches a real
transport). Output reports `live` tests as skipped.

## Scenario 2 — Sample library is valid and sanitized

```bash
uv run panos-mcp-samples validate samples/
uv run panos-mcp-samples index && git diff --stat samples/INDEX.md
```

**Expected**: `validate` exits 0; `INDEX.md` lists every tool's requests with at least one
sample for 11.1 and the provenance (documentation / synthetic / lab-capture).

Negative check — sanitizer catches real-looking data:

```bash
printf '<response status="success"><result><entry name="x"><ip-netmask>8.8.8.8/32</ip-netmask><description>Contact jane.doe@corp.com</description></entry></result></response>' > /tmp/leak.xml
uv run panos-mcp-samples sanitize --check-only /tmp/leak.xml   # exit 1, lists 2 findings
```

## Scenario 3 — Offline demo in Claude Code (no Panorama)

Register the server in replay mode:

```bash
claude mcp add panorama-demo \
  -e PANOS_MCP_SAMPLES_SCENARIO=baseline \
  -- uv run --directory "$PWD" panos-mcp
```

Ask in Claude Code and check against the scenario files in `samples/scenarios/baseline.json`:

| Ask | Expected (from the scenario) |
|---|---|
| "Which firewalls are disconnected from Panorama?" | Only the firewall marked disconnected in the scenario (US1-2) |
| "Show the device group hierarchy" | Parent/child tree with members (US1-3) |
| "Show the effective security policy for device group `<child DG>`" | Shared → parent → child pre-rules, then post-rules, each labeled with scope and position; states `running` (US2-1, FR-026) |
| "Where is address object `<name>` used?" | All referencing rules/groups with location (US2-2) |
| "Expand address group `<nested group>`" | Flattened addresses (US2-3) |
| "Show traffic logs denied to `<ip>` in the last hour" | Matching entries newest first, bounded (US3-1) |
| "Which rule matches tcp/443 from `<src>` to `<dst>` on `<serial>`?" | Rule name from the sample (US3-2) |
| "Create an address object…" | Assistant reports the server is read-only; no tool performs it |

Switch scenario to exercise edge cases: `disconnected-device`, `auth-failure`,
`permission-denied`, `license-denied`, `candidate-differs`, `address-group-cycle`,
`large-estate`, `log-timeout`. Expected outcomes for each are listed in the
scenario's `description` and asserted by contract tests.

## Scenario 4 — Scale budget (synthetic)

```bash
uv run panos-mcp-samples generate large-estate --devices 500 --rules 10000 --seed 42
uv run pytest -m benchmark
```

**Expected**: parse + filter + effective-rulebase computation for the `large-estate` scenario
completes well under the 5 s budget of SC-003 (network latency excluded; see research gaps).

## Scenario 5 — Opt-in live lab (only with a lab Panorama)

Use a **lab** Panorama and a read-only admin role.

```bash
export PANOS_MCP_LIVE=1 PANOS_MCP_HOST=lab-panorama.example.net PANOS_MCP_API_KEY=...
uv run pytest -m live                                         # live read tests + no-change check
uv run panos-mcp-samples capture --plan capture-plans/baseline.json --version 11.2 --variant lab-baseline
uv run panos-mcp-samples validate samples/
git diff samples/                                             # review: only forged data present
```

**Expected**: live tests pass and report "configuration unchanged"; captured samples are
written with `provenance.source = "lab-capture"`, pass the leak check, and contain only forged
names/IPs/serials/comments.

## Done when

- Scenarios 1–4 pass on a clean checkout with no network access.
- Every row of Scenario 3 behaves as expected.
- `samples/INDEX.md` shows no tool without at least one sample.
