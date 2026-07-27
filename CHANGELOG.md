# Changelog

## Unreleased

## 0.4.0

- Added OpenClaw Phase 3 integration assets: locked-down MCP config, SafeOps agent prompt, optional installer, and E2E checklist.
- Documented OpenClaw stdio MCP registration, tool policy, approval flow, agent prompt behavior, audit expectations, and final security checks.
- Hardened MCP tool descriptions with configured-alias, untrusted-log, sensitive-field, and approval warnings.
- Filtered `list_containers` responses to configured aliases as defense in depth.
- Added MCP surface tests for unsafe tool exclusion, Podman-optional container tools, untrusted log flags, and OpenClaw-style command denial.

## 0.3.0

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
