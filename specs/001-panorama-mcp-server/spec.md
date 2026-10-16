# Feature Specification: Panorama MCP Server

**Feature Branch**: `001-panorama-mcp-server`

**Created**: 2026-10-16

**Status**: Draft

**Input**: User description: "create an mcp server for Palo Alto Panorama"

## Overview

Network and security engineers who manage Palo Alto Networks firewalls through Panorama want to use an AI assistant to answer questions about and troubleshoot their firewall estate in natural language. This feature delivers a strictly read-only Model Context Protocol (MCP) server, run locally by each engineer, that exposes Panorama's managed devices, configuration, operational state, and logs to any MCP-compatible AI assistant as a set of well-described, safe capabilities. It never modifies Panorama or firewall configuration.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Inventory and health of managed firewalls (Priority: P1)

A security engineer asks their AI assistant "Which firewalls are disconnected from Panorama?" or "List all firewalls in the EMEA device group with their software versions and HA state." The assistant uses the server to retrieve the list of managed firewalls, their device-group and template-stack membership, connection status, software/content versions, HA state, and configuration sync status, and answers accurately.

**Why this priority**: Visibility into the managed estate is the foundation for every other use case, is read-only (low risk), and on its own delivers immediate value for daily operations and audits.

**Independent Test**: Connect an AI assistant to the server pointed at a Panorama with at least two managed firewalls; ask for the device list and connection status; verify the answer matches what the Panorama web interface shows.

**Acceptance Scenarios**:

1. **Given** the server is connected to a Panorama managing several firewalls, **When** the user asks for all managed firewalls, **Then** the assistant returns each firewall's name, serial number, model, management address, software version, device group, template stack, and connection status.
2. **Given** one firewall has lost its connection to Panorama, **When** the user asks which devices are disconnected, **Then** only that firewall is returned.
3. **Given** a device group hierarchy exists, **When** the user asks for the device-group structure, **Then** the parent/child relationships and member firewalls are returned.
4. **Given** some firewalls have configuration out of sync with Panorama, **When** the user asks which devices have pending changes, **Then** those firewalls are identified.

---

### User Story 2 - Inspect security policy and objects (Priority: P1)

An engineer asks "Show me the pre-rules in device group Branch-Offices that allow traffic to 10.20.0.0/16" or "Where is address object web-srv-01 used?" The assistant retrieves security rules, NAT rules, and the objects they reference (addresses, address groups, services, service groups, applications, tags, security profiles) from the correct scope (shared, a device group, or inherited from a parent), and explains the result.

**Why this priority**: Policy review and object lookup are the most frequent and time-consuming tasks in Panorama administration; doing them conversationally yields the largest productivity gain while staying read-only.

**Independent Test**: Against a Panorama with known rules and objects, ask for the rulebase of a specific device group and for the usages of a specific object; compare with the Panorama web interface.

**Acceptance Scenarios**:

1. **Given** a device group with pre-rules and post-rules, **When** the user asks for its security policy, **Then** rules are returned in evaluation order, labeled as pre-rule or post-rule, with the scope (shared, parent device group, or this device group) each rule comes from.
2. **Given** an address object referenced by rules and groups, **When** the user asks where it is used, **Then** every referencing rule and group is returned with its location.
3. **Given** an address group, **When** the user asks what it contains, **Then** nested group members are expanded to their underlying addresses.
4. **Given** a rulebase with hundreds of rules, **When** the user asks for rules matching a filter (e.g., a destination zone, tag, or application), **Then** only matching rules are returned.
5. **Given** a candidate configuration with uncommitted changes, **When** the user asks for policy, **Then** the response clearly states whether it reflects the running or candidate configuration.

---

### User Story 3 - Troubleshoot traffic with logs and policy matching (Priority: P2)

An engineer investigating an incident asks "Was traffic from 10.1.1.5 to 192.168.50.10 on port 443 blocked in the last hour, and by which rule?" The assistant queries traffic, threat, and system logs collected by Panorama, and can ask which security rule would match a given traffic flow on a specific firewall.

**Why this priority**: Troubleshooting is high-value but depends on the inventory and policy views from P1 stories to be interpreted correctly.

**Independent Test**: Generate known traffic through a managed firewall, then ask the assistant for matching log entries and for the rule that would match that flow; verify against the Panorama log viewer and the firewall's policy-match test.

**Acceptance Scenarios**:

1. **Given** logs are forwarded to Panorama, **When** the user asks for traffic logs filtered by source, destination, port, action, and time range, **Then** matching entries are returned, newest first, limited to a bounded number of results.
2. **Given** a source, destination, protocol, port, and target firewall, **When** the user asks which rule would match, **Then** the matching rule name (or "no match / default deny") is returned.
3. **Given** a log query that takes time to complete, **When** results are not yet ready, **Then** the server waits for completion within a bounded time and either returns results or a clear timeout message.

---

### Edge Cases

- Panorama is unreachable, times out, or returns a certificate that cannot be validated: the user receives a clear, actionable error rather than a hang or a silent failure.
- Credentials are invalid, expired, or lack the role permissions for a requested operation: the error states the operation was denied by Panorama and which permission is likely missing.
- Very large results (thousands of rules, objects, or log entries): results are paginated or truncated with an explicit indication that more data exists and how to narrow the query.
- Device group, template, firewall, or object named by the user does not exist: the server reports "not found" and, where possible, suggests close matches.
- Objects with the same name exist in multiple scopes (shared vs. device group overrides): the response identifies which scope's definition applies.
- A managed firewall is disconnected when operational data is requested for it: that firewall is reported as unavailable while other results are still returned.
- Multiple virtual systems (vsys) on a managed firewall: results identify the vsys.
- Panorama is in an HA pair: the server reports which peer (active or passive) it is connected to.
- The candidate configuration contains uncommitted changes by administrators: responses state whether they reflect running or candidate configuration.
- The user asks the assistant to change configuration: the server has no capability to do so, and the assistant is told the server is read-only.
- Requests containing input that could be interpreted as injected query syntax: inputs are validated and rejected if malformed.

## Requirements *(mandatory)*

### Functional Requirements

**Connection and security**

- **FR-001**: The server MUST connect to one Panorama instance per configured server instance, using credentials supplied by the operator at startup and never requested from or exposed to the AI assistant.
- **FR-002**: The server MUST never include passwords, API keys, or other secrets in any response, log, or error message.
- **FR-003**: The server MUST verify the Panorama TLS certificate by default; disabling verification MUST require an explicit operator setting and MUST produce a visible warning.
- **FR-004**: The server MUST operate within the permissions of the Panorama administrator account it uses; it MUST NOT attempt to bypass role-based restrictions.
- **FR-005**: The server MUST be read-only: it MUST NOT expose any capability that creates, modifies, deletes, commits, pushes, or reverts configuration, or that changes system state (e.g., reboots, software or content installs). Operational queries that only read state are allowed.
- **FR-006**: The server MUST run locally on the engineer's own machine as a process launched by their AI assistant client, using that engineer's own Panorama credentials; it MUST NOT accept connections from other machines on the network.
- **FR-007**: The documentation MUST recommend using a Panorama administrator account with a read-only role.

**Inventory and status (User Story 1)**

- **FR-010**: Users MUST be able to list managed firewalls with name, serial, model, management IP, software version, content versions, device group, template stack, connection status, HA state, and config sync status.
- **FR-011**: Users MUST be able to filter firewalls by device group, template stack, connection status, model, or software version.
- **FR-012**: Users MUST be able to list device groups (with hierarchy), templates, and template stacks with their member firewalls.
- **FR-013**: Users MUST be able to retrieve Panorama's own system information (version, HA state, uptime, licenses).
- **FR-014**: Users MUST be able to list recent and pending jobs (commits, pushes, content updates) with their status and results.

**Policy and objects (User Story 2)**

- **FR-020**: Users MUST be able to retrieve security and NAT rules for the shared scope or any device group, distinguishing pre-rules and post-rules and preserving evaluation order.
- **FR-021**: Users MUST be able to view the effective (inherited) rulebase for a device group, including rules from ancestor device groups and shared, each labeled with its source scope.
- **FR-022**: Users MUST be able to filter rules by name, tag, zone, source/destination address, application, service, action, and disabled state.
- **FR-023**: Users MUST be able to retrieve address objects, address groups, service objects, service groups, application groups, tags, and security profile groups from any scope.
- **FR-024**: Users MUST be able to find all places where a given object is referenced (rules, groups, and other objects).
- **FR-025**: Users MUST be able to resolve an address group (static or dynamic) to its effective member addresses.
- **FR-026**: Every configuration response MUST state whether it reflects the running or the candidate configuration.

**Logs and troubleshooting (User Story 3)**

- **FR-030**: Users MUST be able to query traffic, threat, URL filtering, system, and configuration logs collected by Panorama using filters (time range, source, destination, port, application, action, rule, device) and a result limit.
- **FR-031**: Users MUST be able to ask which security rule would match a specified traffic flow on a specified managed firewall.
- **FR-032**: Long-running queries MUST complete or fail with a clear timeout message within an operator-configurable limit.

**General behavior**

- **FR-050**: Every capability exposed to AI assistants MUST include a clear description of its purpose and inputs, and MUST be marked as read-only, so assistants can choose correctly.
- **FR-051**: Responses MUST be structured and concise, summarizing large datasets and indicating truncation with guidance on narrowing the query.
- **FR-052**: Errors from Panorama MUST be translated into plain-language messages that identify the cause and a suggested next step.
- **FR-053**: All user-supplied inputs MUST be validated (names, IP addresses, ports, scopes) before being sent to Panorama.

### Key Entities

- **Panorama**: The central management server; has version, HA state, licenses, and a running and candidate configuration.
- **Managed Firewall**: A firewall under Panorama management; identified by serial; belongs to one device group and one template stack; has connection, sync, HA, and version status; may host multiple virtual systems.
- **Device Group**: A hierarchical container for policy and objects; has a parent (or shared), child groups, and member firewalls.
- **Template / Template Stack**: Containers for network and device settings applied to firewalls.
- **Security Rule / NAT Rule**: Ordered policy entries in a scope, with pre/post position and match criteria referencing objects.
- **Object**: Reusable configuration element (address, address group, service, service group, application group, tag, security profile group) defined in shared or a device group.
- **Log Entry**: A record of traffic, threat, URL, system, or configuration activity, attributed to a firewall and time.
- **Job**: An asynchronous Panorama operation (commit, push, log query, content install) with ID, status, progress, and per-device results; the server can view jobs but never start configuration jobs.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An engineer can obtain the list of disconnected or out-of-sync firewalls in under 30 seconds from asking the question, versus several minutes of navigation in the management interface.
- **SC-002**: For a defined test suite of at least 30 common inventory, policy, and object questions, the assistant's answers match the Panorama web interface in at least 95% of cases.
- **SC-003**: Typical inventory and configuration lookups return results in under 5 seconds for a Panorama managing up to 500 firewalls and 10,000 rules.
- **SC-004**: Zero secrets (passwords, API keys) appear in any response, error, or log across the full test suite.
- **SC-005**: Zero configuration changes, commits, or pushes are made on Panorama or any managed firewall across the full test suite, including tests that explicitly ask the assistant to make changes.
- **SC-006**: 100% of errors in the test suite produce a plain-language message with a cause and suggested next step (no raw stack traces or unexplained failures).
- **SC-007**: A new user can install, configure, and get a first correct answer from the server in under 15 minutes by following the documentation.

## Assumptions

- Target users are network/security engineers who already have a Panorama administrator account and understand Panorama concepts (device groups, templates, pre/post rules).
- The server targets currently supported Panorama software releases; end-of-life releases are out of scope.
- Each server instance connects to a single Panorama; users managing multiple Panoramas run multiple instances.
- Direct connections to individual firewalls (bypassing Panorama), Strata Cloud Manager, and Prisma Access management are out of scope for this feature.
- Making configuration changes (objects, policy, templates), committing, and pushing are out of scope for this version; they may be added in a later feature.
- Each engineer runs their own server instance locally; a shared network-hosted server for a team is out of scope.
- Log querying depends on logs being forwarded to Panorama or its Log Collectors; data not available in Panorama is out of scope.
- Software upgrades, content/license installation, and device onboarding/offboarding are out of scope for this version.
- Credentials are supplied by the engineer through local configuration (e.g., environment or a local config file) and are protected by the engineer's own machine security.
- Default limits: log queries return at most 100 entries unless the user asks for more (capped at an operator-configured maximum); long-running queries time out after 60 seconds by default.
