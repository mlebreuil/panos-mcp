# Data Model: Panorama MCP Server

**Feature**: `001-panorama-mcp-server` | **Date**: 2026-10-16 | **Plan**: [plan.md](./plan.md)

These are the normalized, read-only models the server builds from Panorama XML API responses
and returns to MCP clients (as Pydantic models → structured tool output). Nothing here is
persisted by the server; the only on-disk data is the **sample library** (section C).

Notation: `?` = optional, `[]` = list. All names are case-sensitive as in PAN-OS.

---

## A. Domain entities (Panorama)

### PanoramaInfo
| Field | Type | Notes |
|---|---|---|
| hostname | str | |
| model | str | e.g. `Panorama`, `M-600` |
| serial | str | |
| sw_version | str | |
| ha_state | enum `standalone \| active \| passive \| suspended \| unknown` | Passive → read still allowed; noted in output |
| uptime | str | As reported |
| licenses | `[License]` | feature, expires, expired: bool |
| content_versions | `dict[str, str]` | app/threat, antivirus, wildfire… |
| tls_verification | bool | `false` → warning included (FR-003) |

### ManagedFirewall
| Field | Type | Notes |
|---|---|---|
| serial | str | **Identity** |
| hostname | str | |
| model | str | |
| mgmt_ip | IPvAnyAddress? | |
| sw_version | str | |
| content_versions | `dict[str, str]` | |
| device_group | str? | Name; `None` if unassigned |
| template_stack | str? | |
| connected | bool | |
| config_sync | enum `in_sync \| out_of_sync \| unknown` | FR-010 |
| ha | `HAStatus?` | mode, local_state, peer_serial |
| vsys | `[str]` | Multi-vsys support |

Validation: `serial` must match `^[0-9A-Za-z]{8,20}$` when accepted as user input (FR-053).

### DeviceGroup
| Field | Type | Notes |
|---|---|---|
| name | str | **Identity** (unique per Panorama) |
| parent | str | `shared` for top-level |
| children | `[str]` | Derived from hierarchy |
| members | `[str]` | Firewall serials |
| description | str? | |

Relationships: tree rooted at the pseudo-scope `shared`. Ancestry list
`ancestors(dg) = [parent, …, shared]` drives inheritance (R5).

### Template / TemplateStack
| Field | Type | Notes |
|---|---|---|
| name | str | **Identity** |
| kind | enum `template \| template_stack` | |
| templates | `[str]` | Stack only: ordered member templates |
| members | `[str]` | Firewall serials (stacks) |

### Scope (value object)
`Scope = "shared" | DeviceGroupName`. Validated against the known device-group list before
any request (unknown → `NotFound` with close-match suggestions).

### ConfigSource (value object)
enum `running | candidate`. Every config-derived response carries it (FR-026). Default:
`running`.

### Rule (base for SecurityRule and NatRule)
| Field | Type | Notes |
|---|---|---|
| name | str | Unique within a rulebase scope |
| uuid | str? | When present (PAN-OS 9.0+) |
| rule_type | enum `security \| nat` | |
| scope | Scope | Where defined |
| position | enum `pre \| post \| default` | |
| order | int | 1-based evaluation order in the returned list |
| disabled | bool | |
| description | str? | |
| tags | `[str]` | |
| target | `RuleTarget?` | devices / negate (Panorama targeting) |

**SecurityRule** adds: `from_zones`, `to_zones`, `sources`, `destinations`, `source_users`,
`applications`, `services`, `categories` (all `[str]`), `negate_source`, `negate_destination`
(bool), `action` (enum `allow | deny | drop | reset-client | reset-server | reset-both`),
`profile_group` (str?), `profiles` (`dict[str, str]`?), `log_start`, `log_end` (bool),
`log_setting` (str?), `schedule` (str?).

**NatRule** adds: `from_zones`, `to_zone`, `to_interface`, `sources`, `destinations`
(`[str]`), `service` (str), `nat_type` (enum `ipv4 | nat64 | nptv6`),
`source_translation` (`SourceTranslation?`: kind dynamic-ip-and-port | dynamic-ip | static-ip,
addresses/interface, bidirectional), `destination_translation` (`DestinationTranslation?`:
address, port, dynamic: bool).

### ObjectBase and object kinds
| Field | Type | Notes |
|---|---|---|
| name | str | **Identity within scope** |
| kind | enum `address \| address_group \| service \| service_group \| application_group \| tag \| security_profile_group` | FR-023 |
| scope | Scope | Defining scope |
| description | str? | |
| tags | `[str]` | |

Kind-specific fields:
- **Address**: `type` (`ip-netmask | ip-range | ip-wildcard | fqdn`), `value` (str)
- **AddressGroup**: `static_members` (`[str]`) **or** `dynamic_filter` (str)
- **Service**: `protocol` (`tcp | udp | sctp`), `destination_port` (str), `source_port` (str?)
- **ServiceGroup / ApplicationGroup**: `members` (`[str]`)
- **Tag**: `color` (str?), `comments` (str?)
- **SecurityProfileGroup**: `profiles` (`dict[str, str]`)

Resolution rule: a name referenced from scope S resolves to the nearest definition in
`[S, ancestors(S)…, shared]`; the resolved scope is reported.

### ObjectReference (output of where-used, FR-024)
| Field | Type | Notes |
|---|---|---|
| referrer_kind | enum `security_rule \| nat_rule \| address_group \| service_group \| application_group \| security_profile_group \| address \| service \| dynamic_address_group_filter` | |
| referrer_name | str | |
| scope | Scope | |
| position | `pre \| post`? | For rules |
| field | str | e.g. `destination`, `members`; `tag` when an object carries the tag; `filter` when a dynamic group's tag filter mentions it |

### ResolvedAddressGroup (FR-025)
`group`, `scope`, `kind` (`static | dynamic`), `addresses` (`[Address]`, flattened, de-duplicated),
`nested_groups` (`[str]`, traversal path), `dynamic_filter` (str?), `resolved_on` (serial? —
only for dynamic groups resolved against a firewall), `cycles_detected` (`[str]`).
`addresses` is bounded by the tool's `max_addresses` (default 200); `ToolResult.truncated` and
`total` report a cut.

### LogEntry (FR-030)
Common: `log_type` (enum `traffic | threat | url | system | config`), `receive_time`
(datetime), `device_serial`, `device_name`, `vsys` (str?). Type-specific normalized fields:
- traffic: `src`, `dst`, `sport`, `dport`, `proto`, `app`, `rule`, `action`, `from_zone`,
  `to_zone`, `src_user`, `bytes`, `session_end_reason`
- threat: traffic fields + `threat_name`, `threat_id`, `severity`, `direction`
- url: traffic fields + `url`, `category`
- system: `event_id`, `severity`, `description`
- config: `admin`, `command`, `path`, `result`

Raw fields not normalized are kept in `extra: dict[str, str]` (bounded).

### PolicyMatchResult (FR-031)
`device_serial`, `vsys`, `query` (echo of validated inputs), `matched` (bool), `rule_name`
(str?), `action` (str?), `note` (str — e.g. "no match: interzone/intrazone default applies").

### Job (FR-014)
| Field | Type | Notes |
|---|---|---|
| id | int | **Identity** |
| type | str | `Commit`, `CommitAll`, `Content`, … as reported |
| status | enum `pending \| active \| finished` | |
| result | enum `ok \| fail \| pending \| unknown` | |
| progress | int | 0–100 |
| user | str? | |
| queued_at / started_at / finished_at | datetime? | |
| details | `[str]` | Messages |
| devices | `[JobDeviceResult]` | serial, status, result, messages; bounded by `get_job.max_devices` (default 200), failures first |

State transitions (observed, never caused by this server):
`pending → active → finished(result ok|fail)`.

---

## B. Response envelope and errors (shared by all tools)

### ToolResult[T]
| Field | Type | Notes |
|---|---|---|
| items | `[T]` or `T` | |
| total | int? | Total matching before pagination |
| returned | int | |
| truncated | bool | |
| next_offset | int? | Present when more data exists |
| narrowing_hint | str? | Required when truncated (FR-051) |
| config_source | ConfigSource? | Required on config-derived results (FR-026) |
| retrieved_at | datetime | Cache-aware timestamp |
| warnings | `[str]` | e.g. TLS verification disabled, passive HA peer, unreachable devices |

### ToolError
| Field | Type | Notes |
|---|---|---|
| code | enum | `not_found`, `invalid_input`, `permission_denied`, `auth_failed`, `unreachable`, `tls_error`, `timeout`, `panorama_error`, `read_only_violation`, `device_unavailable` |
| message | str | Plain language, never contains secrets (FR-002, FR-052) |
| hint | str | Suggested next step |
| suggestions | `[str]` | Close matches for `not_found` |

Mapping from Panorama: 403 from `keygen`, or a response whose message says the key is invalid or
expired → `auth_failed`; any other HTTP 403 / `<response status="error" code="403">` →
`permission_denied`; codes 7/12 ("object not present"/"invalid object") → `not_found` or
`invalid_input`; connect/TLS exceptions → `unreachable` / `tls_error`.

---

## C. Sample library (on disk, repository)

### Sample
One XML response body plus a metadata sidecar.

Path: `samples/<panos-version>/<api-type>/<command-slug>/<variant>.xml` and
`<variant>.meta.json` (schema: [contracts/sample-metadata.schema.json](./contracts/sample-metadata.schema.json)).

| Meta field | Type | Notes |
|---|---|---|
| id | str | `<panos-version>/<api-type>/<command-slug>/<variant>` (derived from path; must match) |
| request | `SampleRequest` | Canonical request this sample answers |
| panos_version | str | e.g. `11.1` or `any` |
| description | str | What situation the sample represents |
| provenance | `Provenance` | source `documentation \| synthetic \| lab-capture`, url?, captured_at?, notes? |
| sanitization | `SanitizationRecord` | tool_version, sanitized_at, leak_check `passed` |
| status | enum `unverified \| verified` | `verified` only after comparison with a real Panorama |
| tags | `[str]` | e.g. `error`, `large`, `multi-vsys` |

### SampleRequest (canonical key)
`type` (`op | config | log`), plus `cmd` (normalized XML, whitespace-stripped) **or**
`action` + `xpath` **or** `log_type` + `query`/`job` placeholders, plus `target` (serial?).
Matching: the replay transport canonicalizes the outgoing request the same way and looks it up.
Log query text is not part of the matching key. The replay transport records it so tests can
assert on it.
Dynamic parts (log job IDs, timestamps in queries) are matched by declared placeholders.

### Scenario
`samples/scenarios/<name>.json`: `name`, `description`, `panos_version`, `extends?`
(name of a parent scenario), `responses`: `[ { request: SampleRequest, sample: <sample id> } ]`,
`default_response?` (sample id returned for any request not matched), `default_on_miss`
(`error_not_found` | `fail_test`).

Lookup order for an incoming request: the scenario's own `responses` → the parent chain's
`responses` (via `extends`, nearest first) → the nearest `default_response` in the chain →
`default_on_miss`. Inheritance cycles are a validation error.

Examples: `auth-failure` and `permission-denied` have no responses and a `default_response`
(`invalid-key` / `role-denied`); `disconnected-device`, `license-denied` and `candidate-differs`
`extends: "baseline"` and override only the requests that differ. Scenarios compose samples into a coherent "world"
(e.g. `baseline`, `disconnected-device`, `large-estate`, `auth-failure`, `candidate-differs`).
Validation: every referenced sample exists; device serials/names are consistent across the
samples of a scenario (checked by a test).

### SanitizationMapping (never committed)
Stored on the capturing machine only (default `~/.config/panos-mcp/sanitize/`):
`key` (HMAC secret), `mapping` (`{type: {real: forged}}`). Used for leak checks and for
consistent re-sanitization of later captures. Git-ignored if placed in the repo by mistake.
