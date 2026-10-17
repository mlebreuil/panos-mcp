# Changelog

All notable changes to this project are documented here. The project follows
[Semantic Versioning](https://semver.org/); tool names and input schemas are a public
contract (a breaking change is a MAJOR release).

## [0.1.0] - 2026-10-17

### Added

- Read-only MCP server for Palo Alto Networks Panorama (stdio, no network listener) with
  13 tools:
  - **Inventory:** `get_panorama_info`, `list_managed_devices`, `list_device_groups`,
    `list_templates`, `list_jobs`, `get_job`.
  - **Policy:** `get_security_rules` and `get_nat_rules`, per scope or as the effective
    inherited rulebase in evaluation order, with IP/CIDR filters.
  - **Objects:** `get_objects` (with override resolution), `find_object_references`,
    `resolve_address_group` (nested groups, cycles, dynamic members).
  - **Troubleshooting:** `query_logs` (traffic, threat, URL, system, config; bounded and
    with a timeout) and `test_security_policy_match`.
- **Read-only guarantee:** a request allow-list enforced before any transport, plus tool
  annotations. Structured, plain-language errors. Secrets are redacted from output and logs.
  TLS verification is on by default.
- **Sample library tooling (`panos-mcp-samples`):**
  - `add`, `sanitize` (forged values of the same type, keyed and consistent), `validate`
    (schema + leak lint) and `index` (coverage).
  - `generate large-estate`, a synthetic scale dataset.
  - Opt-in `capture` from a lab Panorama, with a configuration-unchanged check.
- 123 synthetic samples for Panorama 11.1 and 11.2 and 11 committed scenarios, plus the
  generated `large-estate` scenario. Offline demo mode via `PANOS_MCP_SAMPLES_SCENARIO`.
