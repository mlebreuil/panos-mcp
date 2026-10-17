# Contract: MCP Tools

**Feature**: `001-panorama-mcp-server` | Models: [data-model.md](../data-model.md)

Public contract exposed to MCP clients over **stdio**. Tool names and input schemas are a
public contract (constitution III): breaking changes require a MAJOR release.

**Every tool**:
- is annotated `readOnlyHint=true`, `destructiveHint=false`, `idempotentHint=true`,
  `openWorldHint=true`;
- returns a `ToolResult[T]` (structured) plus a concise text summary;
- on failure returns a `ToolError` (`isError=true`) with `code`, `message`, `hint`;
- validates all inputs before any Panorama request (FR-053). Arguments that violate the
  tool's JSON input schema (types, ranges such as `limit` 1..500 or `job_id > 0`) are rejected
  by the MCP SDK before the tool runs, as an `isError` result naming the argument. Semantic
  checks (names, IPs, serials, filters) return a structured `invalid_input` `ToolError`;
- issues only allow-listed requests (research R4).

Common pagination inputs (list tools): `limit: int = 50 (1..500)`, `offset: int = 0`.
Common config inputs: `config_source: "running" | "candidate" = "running"`.

**Required test cases per tool (constitution IV).** Every tool is tested for success and
permission-denied. Not-found and truncation apply to every tool except where marked N/A:
`get_panorama_info` (not-found N/A because it has no lookup input; truncation N/A because it
returns a single record), `list_jobs` (not-found N/A because it has only filters, no lookup
input; an empty match returns `items=[]`, `total=0`) and `test_security_policy_match`
(truncation N/A because it returns a single result).

If the admin role can read system info but not licenses, `get_panorama_info` returns its other
data with `licenses=[]` and a warning instead of failing. For N/A cases, the test checks that the output schema can't express them
(single object, no `next_offset`).

Tools that return one object with an inner list (`get_job` devices, `resolve_address_group`
addresses) bound that list with a `max_*` input. They report truncation through `truncated`,
`total` and `narrowing_hint`; `next_offset` is not used.

---

## 1. `get_panorama_info`
Panorama system information, HA state, licenses, content versions. (FR-013)
- **Input**: none
- **Output**: `ToolResult[PanoramaInfo]`
- **Requests**: op `show/system/info`, op `show/high-availability/state`, op `request/license/info`
  (the only allow-listed `request` command; research R4)
- **Notes**: adds a warning when TLS verification is disabled or connected to a passive peer.

## 2. `list_managed_devices`
Managed firewalls with status. (FR-010, FR-011)
- **Input**: `device_group?: str`, `template_stack?: str`,
  `connected?: bool`, `config_sync?: "in_sync" | "out_of_sync"`, `model?: str`,
  `sw_version?: str` (prefix match, e.g. `11.1`), `limit`, `offset`
- **Output**: `ToolResult[list[ManagedFirewall]]`
- **Requests**: op `show/devices/all` (+ `show/devicegroups`, `show/templates` to fill membership)
- **Errors**: `not_found` for unknown device group / stack (with suggestions)

## 3. `list_device_groups`
Device-group hierarchy with member firewalls. (FR-012)
- **Input**: `root?: str` (subtree), `include_members: bool = true`, `limit`, `offset`
- **Output**: `ToolResult[list[DeviceGroup]]` ordered depth-first from `shared`
- **Requests**: op `show/dg-hierarchy`, op `show/devicegroups`

## 4. `list_templates`
Templates and template stacks with members. (FR-012)
- **Input**: `kind?: "template" | "template_stack"`, `name?: str`, `limit`, `offset`
- **Output**: `ToolResult[list[Template]]`
- **Requests**: op `show/templates`, config `get|show` on template-stack xpath

## 5. `list_jobs`
Recent/pending Panorama jobs. (FR-014)
- **Input**: `status?: "pending" | "active" | "finished"`, `job_type?: str`, `limit: int = 20 (1..500)`, `offset`
- **Output**: `ToolResult[list[Job]]` newest first
- **Requests**: op `show/jobs/all`

## 6. `get_job`
One job with per-device results. (FR-014)
- **Input**: `job_id: int (>0)`, `max_devices: int = 200 (1..1000)`
- **Output**: `ToolResult[Job]`; when the job has more per-firewall results than `max_devices`,
  `devices` is cut to that many (failures listed first), `truncated=true`, and `narrowing_hint`
  suggests raising `max_devices` or checking a specific firewall
- **Requests**: op `show/jobs/id`
- **Errors**: `not_found` when Panorama reports no job with that id

## 7. `get_security_rules`
Security rules for a scope, or the effective inherited rulebase. (FR-020, FR-021, FR-022, FR-026)
- **Input**:
  - `scope: str = "shared"` (`shared` or device-group name)
  - `rulebase: "pre" | "post" | "both" = "both"`
  - `effective: bool = false` — include shared + ancestor rules in evaluation order
  - filters (all optional, AND-combined; list fields match if any element equals/contains):
    `name_contains`, `tag`, `from_zone`, `to_zone`, `source`, `destination`
    (object name or IP/CIDR — IP matches rules whose resolved addresses contain it),
    `application`, `service`, `action`, `disabled: bool`
  - `config_source`, `limit`, `offset`
- **Output**: `ToolResult[list[SecurityRule]]`, each with `scope`, `position`, `order`
- **Requests**: config `get|show` on `…/pre-rulebase/security/rules` and
  `…/post-rulebase/security/rules` per scope in the ancestry; op `show/dg-hierarchy`

## 8. `get_nat_rules`
Same contract as `get_security_rules` for NAT. (FR-020, FR-021, FR-026)
- **Input**: `scope`, `rulebase`, `effective`, filters: `name_contains`, `tag`, `from_zone`,
  `to_zone`, `source`, `destination`, `service`, `disabled`; `config_source`, `limit`, `offset`
- **Output**: `ToolResult[list[NatRule]]`

## 9. `get_objects`
Objects of one kind in a scope. (FR-023, FR-026)
- **Input**: `kind: "address" | "address_group" | "service" | "service_group" |
  "application_group" | "tag" | "security_profile_group"`, `scope: str = "shared"`,
  `name?: str` (exact), `name_contains?: str`, `value_contains?: str` (address/service values),
  `include_inherited: bool = false`, `config_source`, `limit`, `offset`
- **Output**: `ToolResult[list[Object]]` with defining `scope`; when the same name exists in
  several scopes, each is listed and the one that applies for `scope` is flagged `effective`.

## 10. `find_object_references`
Where an object is used. (FR-024)
- **Input**: `name: str`, `kind: <object kind>`, `scope: str = "shared"`, `config_source`,
  `limit`, `offset`
- **Output**: `ToolResult[list[ObjectReference]]`
- **Behavior**: searches the defining scope and all descendant device groups (rules + groups);
  references shadowed by a nearer same-name object are excluded and listed in `warnings`.

## 11. `resolve_address_group`
Expand an address group to concrete addresses. (FR-025)
- **Input**: `name: str`, `scope: str = "shared"`, `device_serial?: str` (required to resolve
  dynamic membership), `config_source`, `max_addresses: int = 200 (1..1000)`
- **Output**: `ToolResult[ResolvedAddressGroup]`; when the expansion has more addresses than
  `max_addresses`, `addresses` is cut to that many, `truncated=true`, `total` is the full count,
  and `narrowing_hint` suggests expanding a nested group or passing `device_serial`
- **Requests**: config reads; for dynamic groups with `device_serial`: op
  `show/object/dynamic-address-group` with `target`

## 12. `query_logs`
Search logs collected by Panorama. (FR-030, FR-032)
- **Input**: `log_type: "traffic" | "threat" | "url" | "system" | "config"`,
  `since?: datetime | relative ("1h", "24h")`, `until?: datetime`,
  `source?: ip|cidr`, `destination?: ip|cidr`, `port?: int (1..65535)`, `application?: str`,
  `action?: str`, `rule?: str`, `device_serial?: str`, `severity?: str`,
  `advanced_filter?: str` (PAN-OS log filter syntax; validated: balanced parentheses/quotes,
  allowed operators and field names only), `limit: int = 100 (1..configured max)`
- **Output**: `ToolResult[list[LogEntry]]` newest first
- **Requests**: log query start → poll `action=get&job-id` with backoff until done or timeout
- **Errors**: `timeout` with hint to narrow the time range

## 13. `test_security_policy_match`
Which rule would match a flow on a firewall. (FR-031)
- **Input**: `device_serial: str`, `vsys: str = "vsys1"`, `from_zone: str`, `to_zone: str`,
  `source: ip`, `destination: ip`, `protocol: int | "tcp" | "udp" | "icmp"`,
  `destination_port?: int`, `application?: str`, `source_user?: str`
- **Output**: `ToolResult[PolicyMatchResult]`
- **Requests**: op `test/security-policy-match` with `target=<serial>`
- **Errors**: `device_unavailable` if the firewall is disconnected

---

## Prohibited (contract-level guarantee)
No tool exists — and the client refuses — any request that creates, edits, deletes, moves,
renames, commits, pushes, reverts, reboots, installs, or clears. Attempts surface as
`read_only_violation`. Contract tests assert that, across all scenarios, every request reaching
the transport matches the allow-list.
