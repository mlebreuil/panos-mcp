# panos-mcp

Read-only MCP server for Palo Alto Networks Panorama (Python ≥ 3.12, uv, MCP SDK 2.x).
Governing documents: `.specify/memory/constitution.md` (non-negotiable) and
`specs/001-panorama-mcp-server/` (spec, plan, research, data model, contracts).

## Commands

```bash
uv sync --all-extras
uv run ruff format --check . && uv run ruff check . && uv run mypy   # mypy is strict
uv run pytest                          # offline; excludes live + benchmark
uv run pytest -m benchmark             # scale budget (< 5 s per lookup)
uv run panos-mcp-samples validate      # sample schema + sanitization lint
uv run panos-mcp-samples index         # refresh samples/INDEX.md after adding samples
```

All of these must pass before a commit (they are the CI gates).

## Rules

- **Read-only, always.** No tool may create, edit, delete, commit, push, revert, reboot,
  install or clear. Every Panorama request goes through `src/panos_mcp/client/allowlist.py`.
  Changing the allow-list needs explicit reviewer sign-off (constitution Principle I).
- **New Panorama request:** add a typed builder in `client/commands.py` and declare it in
  `TOOL_REQUESTS` for the tool that issues it. The contract tests fail on undeclared requests.
- **User input never reaches XML or an xpath raw.** Use the builders, `xpath_literal` and
  `validate_name`/`validate_serial`.
- **Secrets:** never in tool output, errors or logs. Logs go to stderr only; stdout is the
  MCP channel.
- **Errors:** raise `ToolError(ErrorCode..., message, hint)`, with a plain-language message
  and a next step. Results use `ToolResult` and must bound large lists (pagination or
  `max_*` with `truncated` and `narrowing_hint`).
- **Tests first, offline only.** Tests replay `samples/` through `ReplayTransport`, and a
  fixture blocks real network access. Each tool needs success, not-found, permission-denied
  and truncation tests (or a documented N/A).
- **Tool names and input schemas are a public contract.** Regenerate
  `tests/contract/snapshots/tools.json` (`PANOS_MCP_UPDATE_SNAPSHOTS=1`) only for an intended
  change, and treat it as a MAJOR version bump.

## Sample library

- Add samples with `panos-mcp-samples add` (or `samples.library.add_sample`), which sanitizes
  them and runs the leak check. Never hand-edit real data into `samples/`.
- Never commit the sanitization key or mapping (`~/.config/panos-mcp/sanitize/`).
- All current samples are `synthetic` and `unverified`: no live Panorama was available.
  Treat response shapes as assumptions until confirmed by a lab capture
  (`PANOS_MCP_LIVE=1 panos-mcp-samples capture`).
- Scenarios (`samples/scenarios/*.json`) support `extends` and `default_response`.
  `large-estate` is generated on demand and git-ignored.

## Gotchas

- MCP SDK 2.x: the server class is `MCPServer`, not `FastMCP`. Arguments that violate a
  tool's schema are rejected by the SDK before the tool runs (in-process `call_tool` raises).
- A tool's real data (names, IPs, rules, logs) goes to the model provider; see
  `docs/how-it-works.md`.

## Workflow

- New features go through Spec Kit: `/speckit-specify` → `/speckit-plan` →
  `/speckit-tasks` → `/speckit-implement`.
- Update `README.md` and `CHANGELOG.md` in the same change as user-visible behavior.
