# Sample Library

Recorded or authored Panorama XML API responses. The server is developed and tested against
these files; no test ever contacts a real Panorama.

## Layout

```
samples/<panos-version>/<api-type>/<command-slug>/<variant>.xml
samples/<panos-version>/<api-type>/<command-slug>/<variant>.meta.json
samples/scenarios/<name>.json
```

- `<panos-version>`: `11.1`, `11.2`, or `any` for version-independent responses (errors).
- `<api-type>`: `op`, `config` or `log`.
- Each `.meta.json` follows
  [`sample-metadata.schema.json`](../src/panos_mcp/samples/sample-metadata.schema.json):
  the request it answers, a description, provenance, sanitization record and status.

## Provenance

| `provenance.source` | Meaning |
|---|---|
| `documentation` | Response body taken from the Palo Alto Networks API documentation (`url` required) |
| `synthetic` | Hand-authored (or generated) response following the documented structure; `url` points to the page consulted |
| `lab-capture` | Captured from a lab Panorama with `panos-mcp-samples capture` (opt-in) |

`status` is `unverified` until a sample has been compared with a real Panorama, then
`verified`.

The documentation pages show request formats and only abbreviated response examples. So
all current samples are `synthetic`: they follow the documented structure, cite the page
used, and are unverified. Capturing from a lab Panorama (see below) is how they become
verified.

## Supported versions

Panorama **11.1** and **11.2** (12.1 where documented). Check Palo Alto Networks' end-of-life
table at each release.

## Forged data rules

Every sample is passed through the sanitizer (`panos-mcp-samples add` does this
automatically). Real values are replaced by forged values of the same type, and the same real
value always maps to the same forged value:

| Value | Forged as |
|---|---|
| Public IPv4 | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` or `198.18.0.0/15`; prefix length kept |
| Private IPv4 | Same RFC 1918 block; subnet membership kept |
| IPv6 | `2001:db8::/32` (global) or `fd00::/8` (ULA) |
| Domains / FQDNs | `*.example.com`, `*.example.net`, `*.test`; label count kept |
| Names (objects, rules, groups, zones) | Same shape (separators, case, digit runs) |
| Hostnames | `fw-<site>-NN`, `panorama-NN` |
| Serial numbers | Digits only, same length, starting with `9` |
| MAC addresses | `00:00:5e:00:53:xx` |
| Users / emails | `user-NNN`, `EXAMPLE\user-NNN`, `user-NNN@example.com` |
| Comments / descriptions | Neutral text of similar length |
| Secrets (keys, password hashes, PSKs, certificates) | `REDACTED` |

PAN-OS built-ins (`any`, `application-default`, predefined apps and services, default
profiles, enums) are kept. Add project-specific values to keep in `samples/keeplist.txt`.

**Synthetic samples** are fictional by construction. They are sanitized in `synthetic` mode:
names, comments and private addresses are kept so tests can refer to them. Secrets are still
redacted, and public IPs, MACs, serials, emails and domains are still forged. Documentation
and lab captures always use `full` mode.

The HMAC key and the real→forged mapping live in `~/.config/panos-mcp/sanitize/` and must
never be committed. The tool refuses a mapping directory inside the repository unless it is
git-ignored.

Two leak checks protect the repository:

1. When sanitizing, every replaced original value is searched for in the output. Any hit
   aborts the write.
2. In CI, `panos-mcp-samples validate` lints every sample: public IPs only in documentation
   ranges, `example.*`/`.test` domains, documentation MACs, serials starting with `9`, secrets
   only `REDACTED`.

## Scenarios

A scenario maps requests to samples to form a consistent "world":

```json
{
  "name": "disconnected-device",
  "description": "Baseline with fw-branch-01 disconnected.",
  "panos_version": "11.1",
  "extends": "baseline",
  "responses": [{"request": {"type": "op", "cmd": "<show><devices><all></all></devices></show>"},
                 "sample": "11.1/op/show-devices-all/one-disconnected"}],
  "default_response": null,
  "default_on_miss": "error_not_found"
}
```

A request is answered from, in order: the scenario's own responses, then its `extends` chain
(nearest parent first), then the nearest `default_response`, then the `default_on_miss` rule.

## Adding a sample

```bash
uv run panos-mcp-samples add --version 11.1 --type op \
  --cmd '<show><devices><all/></devices></show>' --variant my-case \
  --source documentation --url <doc-url> \
  --description "What this sample represents" response.xml
uv run panos-mcp-samples validate
uv run panos-mcp-samples index      # refresh INDEX.md coverage
```

## Live lab capture (opt-in)

With a lab Panorama and a read-only admin role:

```bash
PANOS_MCP_LIVE=1 PANOS_MCP_HOST=... PANOS_MCP_API_KEY=... \
  uv run panos-mcp-samples capture --plan capture-plans/baseline.json --version 11.2 --variant lab
```

Capture uses the server's read-only client, refuses to run without `PANOS_MCP_LIVE=1`,
checks that Panorama's configuration did not change, and sanitizes in full mode before
writing anything.
