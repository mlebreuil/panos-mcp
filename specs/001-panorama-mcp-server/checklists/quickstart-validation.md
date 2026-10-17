# Quickstart Validation: Panorama MCP Server

**Run**: 2026-10-17
**Where**: the working tree on branch `001-panorama-mcp-server` (macOS, Python 3.14, uv 0.12)
**Guide**: [quickstart.md](../quickstart.md)

**Not a clean checkout:** the work is not committed yet, so the run used the working tree.
**Network:** tests run with network access blocked by the autouse fixture in
`tests/conftest.py`. `uv sync` had already been run, which is the only step that needs
network access.

## Results

| Scenario | Command(s) | Result |
|---|---|---|
| 1. Quality gates offline | `ruff format --check .` / `ruff check .` / `mypy` / `pytest` | PASS: 110 files formatted, lint clean, strict mypy clean (90 files), **309 passed**, 6 deselected (live + benchmark) |
| 2. Sample library valid | `panos-mcp-samples validate samples/` / `index` | PASS: 0 problems; INDEX.md lists 123 committed samples, **0 uncovered** request/version combinations (11.1 and 11.2) |
| 2. Negative sanitizer check | `sanitize --check-only leak.xml` | PASS: exit 1, 2 findings (`public-ipv4-not-documentation` 8.8.8.8, `email-not-example` jane.doe@corp.com) |
| 3. Offline demo over stdio | real MCP stdio client, `PANOS_MCP_SAMPLES_SCENARIO` | PASS: see table below; 13 tools listed, none can write |
| 4. Scale budget | `generate large-estate` + `pytest -m benchmark` | PASS: effective rulebase with IP filter 0.45 s; where-used 0.23 s; device list < 0.1 s (budget 5 s; 504 firewalls, 10,000 rules; network latency excluded) |

### Scenario 3 rows

Each row is the tool call an assistant makes for the quickstart question, run through a real
MCP stdio session.

| Question | Scenario | Tool result | Latency |
|---|---|---|---|
| Which firewalls are disconnected? (US1-2) | disconnected-device | 1 firewall: fw-branch-01 (900000000003) | 29 ms |
| Device-group hierarchy (US1-3) | baseline | 4 device groups | 6 ms |
| Effective policy for Branch-DG (US2-1) | baseline | 15 rules, shared → … → shared post, running config | 12 ms |
| Where is web-srv-01 used? (US2-2) | baseline | 4 references (+ Branch-DG override warning) | 12 ms |
| Expand all-servers (US2-3) | baseline | 3 addresses, nested web-servers | 7 ms |
| Denied traffic to 192.0.2.10, last hour (US3-1) | baseline | 6 entries, newest first | 13 ms |
| Rule for tcp/443 10.10.1.5 → 10.20.1.10 (US3-2) | baseline | Allow-Admin-Web (allow) | 6 ms |
| "Create an address object…" | any | No tool can do it: none of the 13 tools writes; server instructions tell the assistant it is read-only | n/a |

## Manual checks (need a person)

| Check | Goal | Status |
|---|---|---|
| SC-001: time from asking "Which firewalls are disconnected?" to the answer, in the offline demo | < 30 s | **Partly measured**: the tool answers in 29 ms; end-to-end time in Claude Code (model reasoning) still needs to be timed by a person |
| SC-007: fresh install to first correct answer by following README only | < 15 min | **Not yet performed**: needs a person who has not seen the project |

## Not covered offline

- SC-002 (answers match the Panorama web interface in ≥ 95% of cases): needs a lab Panorama.
  The question set is ready in `tests/integration/live/questions.json`.
- The network-latency part of SC-003: needs a lab Panorama.
- Live read-only session (`pytest -m live`): skipped (no `PANOS_MCP_LIVE`).
