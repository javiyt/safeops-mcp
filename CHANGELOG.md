# Changelog

## Unreleased

## 0.5.0

- Added advanced read-only host diagnostics for CPU, memory, disk health, network, time, configured processes, and aggregate host health summaries.
- Added diagnostic threshold configuration with safe defaults and configured connectivity targets.
- Added closed executor operations and MCP tools for `cpu_status`, `memory_status`, `disk_health`, `network_status`, `time_status`, `configured_process_status`, and `host_health_summary`.
- Added `safeopsctl diagnostics` commands with human-readable and JSON output.
- Audited diagnostic reads and documented metadata exposure mitigations, IP redaction, configured disk aliases, configured process matching, and network target restrictions.

## 0.4.0

- Added `safeops-telegram`, an optional private Telegram long-polling adapter for OpenClaw.
- Added Telegram configuration validation for token environment variables, allowlisted numeric users, single administrator identity, rate limiting, message limits, confirmation settings, and OpenClaw command settings.
- Added Telegram channel handling for private-chat enforcement, unauthorized-user rejection, per-user rate limiting, message splitting, redaction, callback parsing, and confirmation/cancellation buttons.
- Bound Telegram deployments to `identity.administrator_id: telegram:<admin_id>` so approvals and mutable audit rows remain tied to the configured administrator.
- Documented Telegram setup, OpenClaw channel metadata, security threats, operations, troubleshooting, and manual E2E checks.

## 0.3.0

- Added OpenClaw Phase 3 integration assets: locked-down MCP config, SafeOps agent prompt, optional installer, and E2E checklist.
- Documented OpenClaw stdio MCP registration, tool policy, approval flow, agent prompt behavior, audit expectations, and final security checks.
- Hardened MCP tool descriptions with configured-alias, untrusted-log, sensitive-field, and approval warnings.
- Filtered `list_containers` responses to configured aliases as defense in depth.
- Added MCP surface tests for unsafe tool exclusion, Podman-optional container tools, untrusted log flags, and OpenClaw-style command denial.

## 0.2.1

- Hardened Podman configuration validation for existing absolute binaries, invalid container names, invalid permissions, and Quadlet units.
- Propagated process-output byte truncation to `container_logs` responses.
- Documented and tested sanitized Podman inspect handling so status responses omit environment variables, command arguments, mounts, and credentials.
- Tightened container restart health handling for `not_configured`, `unhealthy`, and `require_healthy_after_restart` behavior.
- Added tests for persistent resource locks, TOCTOU revalidation, strict executor JSON decoding, Quadlet systemd scope usage, and Podman diagnostics.
- Updated Podman, Quadlet, OpenClaw, operations, architecture, and security documentation.

## 0.2.0

- Added configured Podman container status, logs, and confirmed restart support.
- Added Quadlet workload restart support through configured systemd units.
- Generalized approvals for service and container restart actions.
- Added native Podman health-state handling.
- Added read-only `safeopsctl podman check` and `safeopsctl containers` diagnostics.
- Added SQLite migration support for generic action metadata.
- Updated documentation for rootless Podman, Quadlets, OpenClaw, and security boundaries.

## 0.1.0

- Initial project scaffold.
