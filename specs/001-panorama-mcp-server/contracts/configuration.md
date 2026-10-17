# Contract: Server Configuration

**Feature**: `001-panorama-mcp-server`

Configuration is read from environment variables (set in the MCP client's server entry), or
from a dotenv file given by `PANOS_MCP_ENV_FILE`. Secrets are held as secret strings and never
printed, logged, or returned (FR-002).

| Variable | Required | Default | Description |
|---|---|---|---|
| `PANOS_MCP_HOST` | yes* | — | Panorama hostname or IP (HTTPS, port 443 unless `host:port`) |
| `PANOS_MCP_API_KEY` | one of* | — | API key (preferred) |
| `PANOS_MCP_USERNAME` / `PANOS_MCP_PASSWORD` | one of* | — | Exchanged once for an API key at startup; password then discarded |
| `PANOS_MCP_VERIFY_TLS` | no | `true` | `false` disables certificate verification and emits warnings (FR-003) |
| `PANOS_MCP_CA_BUNDLE` | no | system | Path to a CA bundle for private PKI |
| `PANOS_MCP_TIMEOUT` | no | `30` | Per-request timeout, seconds |
| `PANOS_MCP_QUERY_TIMEOUT` | no | `60` | Max wait for log query jobs, seconds (FR-032) |
| `PANOS_MCP_LOG_LIMIT_MAX` | no | `1000` | Upper bound for `query_logs.limit` |
| `PANOS_MCP_CACHE_TTL` | no | `30` | Config read cache TTL, seconds; `0` disables |
| `PANOS_MCP_MAX_CONCURRENCY` | no | `4` | Parallel requests to Panorama |
| `PANOS_MCP_LOG_LEVEL` | no | `INFO` | stderr logging; `DEBUG` may include response payloads (never secrets) |
| `PANOS_MCP_SAMPLES_SCENARIO` | no | — | **Offline demo mode**: replay the named scenario from the sample library instead of contacting Panorama; host/credentials not required |
| `PANOS_MCP_SAMPLES_DIR` | no | `<repo>/samples` | Sample library location for offline mode |

\* Not required when `PANOS_MCP_SAMPLES_SCENARIO` is set.

Startup validation errors are reported on stderr in plain language and the process exits
non-zero; nothing is sent to Panorama until configuration is valid.

### Example MCP client entry (Claude Code)

```json
{
  "mcpServers": {
    "panorama": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/panos-mcp", "panos-mcp"],
      "env": {
        "PANOS_MCP_HOST": "panorama.example.com",
        "PANOS_MCP_API_KEY": "<from your secret store>"
      }
    }
  }
}
```

Recommended Panorama role: a custom admin role with read-only access to XML API
(configuration, operational requests, logs) and no commit/export/import rights (FR-007).
