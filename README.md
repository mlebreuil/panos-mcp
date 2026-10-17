# panos-mcp

A **read-only** [Model Context Protocol](https://modelcontextprotocol.io) server for Palo Alto
Networks **Panorama**. It lets an AI assistant (Claude Code, or any MCP client) answer questions
about your firewall estate: inventory and health, security/NAT policy (including inherited
rules), objects and where they are used, logs, and "which rule matches this flow?".

**It cannot change anything.**
- No tool can create, edit, delete, commit, push, revert or reboot.
- Every request to Panorama passes a strict allow-list of read operations
  ([`client/allowlist.py`](src/panos_mcp/client/allowlist.py)).
- If you ask for a change, the assistant is told the server is read-only.

The server runs locally, launched by your MCP client over stdio. It opens no network listener.

## Install

Requires Python ≥ 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/mlebreuil/panos-mcp.git
cd panos-mcp
uv sync
```

## Use with Claude Code

```bash
claude mcp add panorama \
  -e PANOS_MCP_HOST=panorama.example.com \
  -e PANOS_MCP_API_KEY="$PANOS_API_KEY" \
  -- uv run --directory "$PWD" panos-mcp
```

Or in your MCP client configuration:

```json
{
  "mcpServers": {
    "panorama": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/panos-mcp", "panos-mcp"],
      "env": { "PANOS_MCP_HOST": "panorama.example.com", "PANOS_MCP_API_KEY": "<from your secret store>" }
    }
  }
}
```

Then ask, for example:
- "Which firewalls are disconnected from Panorama?"
- "Show the effective security policy for device group Branch-DG that allows traffic to 10.20.0.0/16."
- "Where is address object web-srv-01 used?"
- "Was traffic from 10.10.1.5 to 192.0.2.10 blocked in the last hour?"

### Try it without a Panorama (offline demo)

The server can replay the bundled [sample library](samples/README.md) instead of contacting
Panorama:

```bash
claude mcp add panorama-demo -e PANOS_MCP_SAMPLES_SCENARIO=baseline \
  -- uv run --directory "$PWD" panos-mcp
```

| Scenario | What it represents |
|---|---|
| `baseline` | Four firewalls (one HA pair, one multi-vsys) in three device groups; rules, objects, logs |
| `baseline-11-2` | Same estate on Panorama 11.2 |
| `disconnected-device` | One firewall disconnected |
| `out-of-sync` | Two firewalls out of sync |
| `ha-passive` | Connected to the passive Panorama HA peer |
| `candidate-differs` | Uncommitted candidate changes |
| `address-group-cycle` | Address groups referencing each other |
| `log-timeout` | Log queries never finish |
| `license-denied` | The admin role cannot read licenses |
| `auth-failure` / `permission-denied` | Invalid key / role without XML API rights |
| `large-estate` | 500 firewalls, 10,000 rules. Not committed: generate it first with `uv run panos-mcp-samples generate large-estate` |

## Configuration

Environment variables (or a dotenv file named by `PANOS_MCP_ENV_FILE`):

| Variable | Default | Description |
|---|---|---|
| `PANOS_MCP_HOST` | required | Panorama hostname/IP (HTTPS) |
| `PANOS_MCP_API_KEY` | — | API key (preferred) |
| `PANOS_MCP_USERNAME` / `PANOS_MCP_PASSWORD` | — | Exchanged once for an API key at startup |
| `PANOS_MCP_VERIFY_TLS` | `true` | `false` disables certificate checks; every result then carries a warning |
| `PANOS_MCP_CA_BUNDLE` | system | CA bundle for a private PKI |
| `PANOS_MCP_TIMEOUT` | `30` | Per-request timeout (s) |
| `PANOS_MCP_QUERY_TIMEOUT` | `60` | Maximum wait for log queries (s) |
| `PANOS_MCP_LOG_LIMIT_MAX` | `1000` | Upper bound for `query_logs.limit` |
| `PANOS_MCP_CACHE_TTL` | `30` | Config read cache (s); `0` disables |
| `PANOS_MCP_MAX_CONCURRENCY` | `4` | Parallel requests to Panorama |
| `PANOS_MCP_LOG_LEVEL` | `INFO` | Logging to stderr. Secrets are always masked |
| `PANOS_MCP_SAMPLES_SCENARIO` | — | Offline demo: replay this scenario (no host or key needed) |
| `PANOS_MCP_SAMPLES_DIR` | `samples/` | Sample library location |

Secrets are never returned, logged or included in errors.

### Recommended Panorama account

Create a dedicated admin with a **custom read-only role**:
- XML API: **configuration**, **operational requests** and **log** read access.
- **No** commit, export or import rights.

The server works within that role. If the role lacks a right, the tools answer with
`permission_denied` and say which kind of access is missing.

## Tools

All 13 tools are annotated read-only. Large results are paginated or truncated with a hint on
how to narrow the query. Configuration results state whether they come from the **running**
or **candidate** configuration.

| Tool | What it answers |
|---|---|
| `get_panorama_info` | Panorama version, HA state, uptime, licenses |
| `list_managed_devices` | Firewalls with status, versions, device group, template stack, HA, sync; filterable |
| `list_device_groups` | Device-group hierarchy with member firewalls |
| `list_templates` | Templates and template stacks |
| `list_jobs` / `get_job` | Commits, pushes and content installs, with per-firewall results |
| `get_security_rules` | Rules per scope, or the effective inherited rulebase in evaluation order; filters incl. IP/CIDR |
| `get_nat_rules` | Same for NAT, with translations |
| `get_objects` | Addresses, groups, services, application groups, tags, profile groups; override resolution |
| `find_object_references` | Where an object is used (rules, groups, tags, dynamic-group filters) |
| `resolve_address_group` | Flatten a group (nested, cycles reported); dynamic members on a firewall |
| `query_logs` | Traffic, threat, URL, system, config logs with filters and a bounded result |
| `test_security_policy_match` | Which rule a firewall would apply to a flow |

The full contract is in
[`specs/001-panorama-mcp-server/contracts/mcp-tools.md`](specs/001-panorama-mcp-server/contracts/mcp-tools.md).

## Development

```bash
uv sync --all-extras
uv run ruff format --check . && uv run ruff check . && uv run mypy
uv run pytest                      # offline; live and benchmark tests are excluded
uv run pytest -m benchmark         # 500 firewalls / 10,000 rules, < 5 s per lookup
uv run panos-mcp-samples validate  # sample library schema + sanitization lint
```

Tests never touch the network. They replay the sample library through the real client, and
every request is checked against the read-only allow-list.

### Sample library

- Development runs against Panorama XML API responses stored in [`samples/`](samples/README.md).
- Each sample has provenance metadata and is sanitized: real names, IPs, serials and comments
  are replaced with forged values of the same type.
- The current samples are hand-authored from the API documentation, so they are marked
  `synthetic` and `unverified`.

To add or refresh samples from a **lab** Panorama (opt-in):

```bash
uv run panos-mcp-samples capture --write-plan capture-plans/baseline.json
PANOS_MCP_LIVE=1 PANOS_MCP_HOST=... PANOS_MCP_API_KEY=... \
  uv run panos-mcp-samples capture --plan capture-plans/baseline.json --version 11.2 --variant lab
PANOS_MCP_LIVE=1 PANOS_MCP_HOST=... PANOS_MCP_API_KEY=... uv run pytest -m live
```

Capture stops without writing anything if Panorama's configuration changes during the run, or
if any original value would remain after sanitizing.

## Known gaps

- No live Panorama was available during development. Response shapes come from the
  documentation and are unverified until compared with a lab capture. This applies especially
  to: template stacks, job errors, log fields, and the policy-match output.
- SC-002 (answers match the web interface) needs the live question set
  (`tests/integration/live/questions.json`).
- The network-latency part of SC-003 also needs a lab Panorama.
- `test_security_policy_match` evaluates in the firewall's default target vsys; the `vsys`
  argument is recorded but not applied.
- Relative log times (`1h`, `24h`) use this machine's clock; Panorama applies its own time zone.
- Arguments that violate a tool's JSON schema (for example `limit` > 500) are rejected by the
  MCP SDK before the tool runs, with a message naming the argument.

## License

MIT — see [LICENSE](LICENSE).
