# How It Works: Data Flow and Data Handling

This page explains what happens when you ask your AI assistant a question that uses
panos-mcp, which component talks to which, and where your data goes.

Nothing in the cloud talks to Panorama directly. The server runs on your machine, holds the
API key and makes the HTTPS calls. The model only sees tool descriptions and tool results.

## Overview

```
 You                Claude Code            Claude model            panos-mcp               Panorama
 (terminal)         (your machine)         (model provider API)    (child process,         (HTTPS :443)
                                                                    your machine)
   │ "Which firewalls    │                       │                      │                       │
   │  are disconnected?" │                       │                      │                       │
   │────────────────────▶│  question + tool list │                      │                       │
   │                     │──────────────────────▶│                      │                       │
   │                     │  call list_managed_devices(connected=false)  │                       │
   │                     │◀──────────────────────│                      │                       │
   │                     │  JSON-RPC over stdin/stdout                  │                       │
   │                     │─────────────────────────────────────────────▶│  allow-list check     │
   │                     │                       │                      │  POST /api/ (X-PAN-KEY)
   │                     │                       │                      │──────────────────────▶│
   │                     │                       │                      │◀──────── XML ─────────│
   │                     │◀─────────────── result (summary + JSON) ─────│                       │
   │                     │  tool result          │                      │                       │
   │                     │──────────────────────▶│                      │                       │
   │                     │  written answer       │                      │                       │
   │◀────────────────────│◀──────────────────────│                      │                       │
```

## Step by step

Example question: **"Which firewalls are disconnected?"**

1. **Startup.** The MCP client (e.g. Claude Code) launches `panos-mcp` as a local process and
   talks to it over stdin/stdout. The server:
   - reads its settings from environment variables (see [Configuration](../README.md#configuration));
   - lists its 13 tools, each with a name, a description, an input schema and a read-only label;
   - opens no network listener.
2. **The model picks a tool.** The client sends your question and the tool list to the model.
   The model replies with a tool call, here `list_managed_devices` with `connected=false`.
3. **Arguments are checked.** The client passes the call to the server. The MCP SDK checks the
   arguments against the tool's schema; for example, `limit` must be between 1 and 500.
4. **The tool runs.** The tool asks the inventory service
   ([`services/inventory.py`](../src/panos_mcp/services/inventory.py)) for the data. The service
   sends three reads to Panorama in parallel, at most `PANOS_MCP_MAX_CONCURRENCY` (default 4)
   at a time:
   - `show devices all`: the firewalls and their status;
   - `show devicegroups`: which device group each firewall belongs to;
   - a configuration read of the template stacks. Configuration reads are cached for
     `PANOS_MCP_CACHE_TTL` seconds (default 30).
5. **Every request passes the read-only gate.** Before anything leaves the machine,
   [`allowlist.check_request`](../src/panos_mcp/client/allowlist.py) checks the request.
   Anything that is not a listed read (commit, set, delete, …) raises an error and never
   reaches the network. Allowed requests are sent as `POST https://<panorama>/api/` with:
   - the API key in the `X-PAN-KEY` header, never in the URL;
   - TLS certificate verification on, unless the operator turned it off.
6. **The response is processed.** The server:
   - reads Panorama's XML safely (`defusedxml`, which protects against malicious XML);
   - turns Panorama errors (403, code 7, …) into plain-language messages such as
     `permission_denied` or `not_found`, with a suggested next step;
   - converts the data into typed records and applies your filters;
   - pages or truncates long results, saying so and suggesting how to narrow the query;
   - adds warnings where relevant, for example when TLS verification is off or when connected
     to the passive Panorama HA peer.
7. **The result goes back.** The server returns a short summary (e.g. "1 firewall(s) match…
   Disconnected: fw-branch-01") plus the full data as JSON. The client sends that to the model,
   which writes the answer you read.

## Variations by tool

| Tools | What differs |
|---|---|
| `get_security_rules`, `get_nat_rules`, `get_objects`, `find_object_references`, `resolve_address_group` | The server reads the device-group tree and the rulebases and objects of each scope. It then works out inheritance, name overrides and IP matching locally, because Panorama has no single call for an effective rulebase or a where-used search. |
| `query_logs` | The server starts a log query on Panorama, which searches its log collectors. It then polls for the result with increasing waits (0.5 s up to 4 s) until the query finishes or `PANOS_MCP_QUERY_TIMEOUT` is reached. |
| `test_security_policy_match`, `resolve_address_group` with `device_serial` | The server sends the request to Panorama with `target=<serial>`, and Panorama forwards it to that firewall. The server never connects to firewalls directly. |
| Offline demo (`PANOS_MCP_SAMPLES_SCENARIO`) | Only the last hop changes: instead of HTTPS, the replay component answers from [`samples/`](../samples/README.md). Everything else, including the read-only gate, is identical. |

## Where your data goes

| Data | Where it goes |
|---|---|
| API key or password | Stays on your machine: environment of the server process only. Never sent to the model, never in tool results, never logged. |
| Requests to Panorama | Only between the server and Panorama, over HTTPS. |
| Server logs | Your machine (stderr): startup messages, blocked requests and tracebacks of unexpected errors. Panorama responses are not logged. Secrets are always masked. |
| Your question | Sent to the model provider by your MCP client. |
| **Tool results** | **Sent to the model provider**, including real firewall names, IP addresses, rule names, object values and log entries. |

> **Before using it on production data:** the sanitizer applies only to the sample library,
> not to live answers. If sending real configuration and log data to your model provider's
> API is a concern for your organization, check it against your data-handling policy first.
> The read-only admin role keeps Panorama safe from changes. It does not limit what the model
> sees.

Ways to reduce what is shared:
- Use an admin role that can only read the parts of the configuration and logs you are
  willing to share.
- Ask narrow questions (a scope, a filter, a time range); results are bounded by `limit`.
- Use the offline demo (`PANOS_MCP_SAMPLES_SCENARIO`) for demonstrations and training.
