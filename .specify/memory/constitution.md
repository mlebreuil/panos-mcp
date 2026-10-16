# panos-mcp Constitution

## Core Principles

### I. Read-Only Safety (NON-NEGOTIABLE)

- The server MUST NOT expose any capability that creates, modifies, deletes, commits, pushes,
  or reverts configuration on Panorama or managed firewalls, or that changes system state
  (reboots, software/content/license installs, HA failover, session clearing).
- Every request sent to Panorama MUST be a read or a read-only operational command. Commands
  are allow-listed; anything not on the allow-list is rejected before it leaves the server.
- Adding any state-changing capability requires a MAJOR amendment of this constitution and a
  dedicated feature spec defining explicit opt-in, confirmation, and audit controls.

Rationale: engineers point this server at production security infrastructure and let an AI
assistant drive it. A single unintended change can cause an outage or open a security hole.

### II. Credential & Data Protection

- Credentials (passwords, API keys) MUST come only from the operator's local configuration and
  MUST NEVER appear in tool output, error messages, logs, or exception traces.
- TLS certificate verification MUST be enabled by default; disabling it requires an explicit
  operator setting and MUST emit a visible warning.
- The server MUST operate with the least privilege of the configured Panorama account and MUST
  NOT attempt to work around role-based access restrictions. Documentation MUST recommend a
  read-only admin role.
- Every user-supplied input (names, scopes, IPs, ports, filters) MUST be validated before use;
  inputs MUST NOT be concatenated into queries or commands without escaping.

Rationale: the server holds keys to the firewall estate; leaking them or enabling injection is
equivalent to compromising the firewalls themselves.

### III. Clear, Bounded Tool Contracts

- Every tool MUST have a precise description written for an AI assistant (purpose, when to use
  it, inputs, output shape), a typed input schema, and a read-only annotation.
- Outputs MUST be structured and bounded: large result sets are paginated or truncated, and
  truncation is always stated together with how to narrow the query.
- Configuration results MUST state their scope (shared / device group / template) and whether
  they reflect the running or candidate configuration.
- Errors MUST be returned as plain-language messages with a cause and a suggested next step,
  never as raw stack traces or untranslated Panorama error payloads.
- Tool names and input schemas are a public contract: breaking changes require a MAJOR release.

Rationale: the consumer is a language model; ambiguous or unbounded tools lead to wrong
answers, wasted context, and misplaced user trust.

### IV. Test-First Against Recorded Panorama Behavior

- Tests MUST be written before or alongside implementation and MUST fail before the code that
  makes them pass is written.
- Unit and contract tests MUST run against recorded or fixture Panorama responses, with no
  network access, so CI never requires a live Panorama.
- Fixtures MUST be sanitized: no real hostnames, IPs, serials, or secrets from production.
- Integration tests against a live lab Panorama MUST be opt-in (explicitly enabled) and MUST
  include a check that no configuration change occurred.
- Every tool MUST have tests for success, not-found, permission-denied, and truncation paths.

Rationale: Panorama access is scarce and sensitive; recorded behavior keeps tests fast,
reproducible, and safe while still covering real response shapes.

### V. Fidelity & Simplicity

- Answers MUST reflect what Panorama reports. The server MUST NOT invent, guess, or silently
  merge data; if something is unknown or unavailable (e.g., a disconnected firewall), it says so.
- Prefer the smallest set of tools that covers the specified user stories; new tools require a
  user scenario in a spec. No speculative features or abstraction layers without a present need.
- Dependencies MUST be justified, actively maintained, and kept to a minimum.

Rationale: accuracy is the product's entire value; complexity is the main source of inaccuracy.

## Security & Operational Constraints

- Deployment model: each engineer runs the server locally, launched by their AI assistant
  client. The server MUST NOT open network listeners reachable from other machines.
- One server instance connects to exactly one Panorama.
- The server MUST respect operator-configurable timeouts and result limits and MUST NOT poll
  or query Panorama in ways that could degrade its management plane (bounded concurrency,
  no unbounded retries).
- Logs written by the server MUST exclude secrets and SHOULD exclude log/traffic payload data
  unless debugging is explicitly enabled.
- Support targets currently supported Panorama releases; end-of-life releases are out of scope.

## Development Workflow & Quality Gates

- Features follow the Spec Kit flow: specify → (clarify) → plan → tasks → implement. Each plan
  MUST include a Constitution Check against all five principles.
- Implementation language: the server MUST be written in Python, targeting a currently
  supported Python 3 release. Introducing another language for runtime code requires a MAJOR
  amendment. Public functions and tool handlers MUST carry type hints.
- All changes land through pull requests. CI MUST pass formatting, linting, static type checks,
  and the full offline test suite before merge.
- Reviewers MUST verify that no state-changing Panorama operation was introduced (Principle I)
  and that no secret can reach output or logs (Principle II).
- Releases use semantic versioning with a changelog entry for every user-visible change.
- User documentation (installation, configuration, available tools, required Panorama role)
  MUST be updated in the same PR as the change it describes.

## Governance

- This constitution supersedes other project practices. Where a spec, plan, or PR conflicts
  with it, the constitution wins until amended.
- Amendments are made by pull request that updates this file, includes a Sync Impact Report,
  and states the version bump rationale.
- Versioning: MAJOR for removing or redefining a principle (including relaxing Principle I);
  MINOR for adding a principle or section or materially expanding guidance; PATCH for
  clarifications and wording.
- Compliance is reviewed in every plan (Constitution Check) and every PR review. Any justified
  deviation MUST be recorded in the plan's Complexity Tracking section.

**Version**: 1.1.0 | **Ratified**: 2026-10-16 | **Last Amended**: 2026-10-16
