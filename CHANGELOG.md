# Changelog

## Unreleased

## 0.9.0

- Added configured `backups` resources with Restic and predefined command backends.
- Added MCP tools: `list_backups`, `backup_status`, `backup_history`, `request_backup`, and `request_restore_plan`.
- Added SQLite backup metadata persistence with snapshot IDs, timestamps, durations, size, status, integrity state, redacted errors, and metadata.
- Added confirmed backup execution through the existing approval and audit flow, with resource locks for backup aliases.
- Added Restic integrity checks, retention hooks, and password-file validation requiring absolute paths outside the repository with `0600` permissions.
- Added restore-plan generation without restore execution.
- Added `safeopsctl backups list|status|history|create|restore-plan|verify`.
- Updated README, architecture, security model, operations, OpenClaw, and example configuration documentation for backups and recovery planning.

## 0.8.0

- Added deployable `applications` configuration for controlled service and container updates while preserving existing cache cleanup configuration.
- Added MCP tools: `application_version`, `check_application_update`, `request_application_update`, and `request_application_rollback`.
- Added safe update execution for configured Git service applications and configured container image applications, with fixed branches/channels, separated process arguments, optional predefined post-update commands, health checks, and automatic rollback attempts on update failure.
- Added SQLite `deployment_history` persistence with version, digest or commit, previous/next version, status, triggering user, and per-application pruning through `rollback.versions_to_keep`.
- Added security restrictions for per-application Git repository whitelists, Podman registry whitelist validation, digest-required container deployments, configured commands only, and rollback only to recorded versions.
- Added `safeopsctl app version|check-update|update|rollback|history`.
- Updated README, architecture, security model, operations, OpenClaw configuration, and OpenClaw agent prompt documentation for controlled deployments.

## 0.7.0

- Added controlled maintenance MCP tools: `request_group_restart`, `rotate_configured_logs`, `cleanup_application_cache`, `remove_expired_safeops_records`, `reset_resource_failure_state`, and `request_host_reboot`.
- Added `groups` configuration for ordered service/container stack restarts.
- Added configured log rotation and application cache cleanup with alias-only paths, dry-run support, and bounded retention settings.
- Added SafeOps audit and approval record cleanup with retention age and minimum-record limits.
- Added systemd `reset-failed` support for configured service aliases; container failure-state reset returns `not_applicable`.
- Added opt-in host reboot with longer confirmation codes, operation-lock checks, configurable confirmation window, and restricted executor command documentation.
- Added executor protocol operations and `safeopsctl groups|logs|cache|records|reset-failed|reboot` maintenance commands.
- Updated README, architecture, security, operations, OpenClaw, and example configuration documentation for controlled maintenance.

## 0.6.0

- Added `safeops-monitor`, a separate proactive alert monitor that runs scheduled read-only checks and can send direct Telegram notifications.
- Added SQLite alert persistence with `new`, `active`, `acknowledged`, `resolved`, and `suppressed` states.
- Added checks for configured services, configured Podman/Quadlet containers, executor availability, SQLite alert state, disk usage, memory pressure/OOM events, CPU load/temperature, and repeated application log errors. Certificate and backup checks are configurable placeholders and remain disabled by default.
- Added antispam controls for cooldown, grouping, persistence threshold, resolution notifications, temporary silences, and silence schedules.
- Added MCP alert tools: `list_alerts`, `acknowledge_alert`, and `silence_alert`.
- Added `safeopsctl alerts list|acknowledge|silence|resolve|check`.
- Added optional `alerts` configuration and a systemd service example for `safeops-monitor`.
- Updated architecture, security, operations, OpenClaw, README, and example configuration documentation for proactive alerts.

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
