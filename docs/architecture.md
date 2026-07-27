# Architecture

SafeOps MCP has three separate binaries.

`safeops-mcp` runs without administrative privileges and speaks MCP over stdio. It validates tool inputs, applies policy, creates approvals, records audit events, redacts secrets, and calls the local executor through a Unix socket.

`safeops-executor` listens only on a local Unix socket. It resolves configured aliases to systemd units or filesystem paths, validates requests again, and performs only closed operations.

`safeopsctl` is an operator CLI for configuration validation, database migrations, audit and approval listing, and read-only Podman diagnostics.

The trust boundary is the Unix socket. The MCP process never receives a free shell, never calls `sudo`, and never accepts arbitrary commands. The executor never talks to the LLM and never interprets natural language.

Read flow:

1. The MCP client calls a typed tool.
2. `safeops-mcp` validates arguments and policy.
3. `safeops-mcp` calls the executor over `/run/safeops/safeops.sock`.
4. The executor resolves the alias from its own configuration.
5. The executor returns structured JSON.

Action model:

1. Mutable tools create a generic approval with a closed action type, resource kind, configured resource alias, normalized arguments, an arguments hash, risk, human summary, expected effect, approval ID, and operation ID.
2. Initial action types are `restart_service` and `restart_container`.
3. Initial resource kinds are `service` and `container`.
4. Confirmation revalidates user, status, expiration, code, action type, resource kind, alias, current configuration, permissions, dry-run mode, arguments hash, and executor availability.

Service restart flow:

1. `request_service_restart` creates a persistent approval and returns a short confirmation code.
2. `confirm_action` verifies the owner, state, expiration, code, policy, and current configuration.
3. The approval is atomically marked as executing.
4. The executor restarts the configured unit or simulates it in dry-run mode.
5. The final result is audited and the approval cannot be reused.

Podman container flow:

1. Read tools accept only configured container aliases.
2. The executor resolves each alias to a configured container name.
3. The Podman adapter invokes `exec.CommandContext(ctx, podmanBinary, argument1, argument2, ...)` with closed argument lists.
4. Status uses structured `podman inspect` JSON and maps native health to `healthy`, `unhealthy`, `starting`, `not_configured`, or `unknown`.
5. Logs use bounded `podman logs` calls, closed `since` values, output limits, redaction, and untrusted-content marking.

Quadlet workload flow:

1. A `management: quadlet` container is treated as a systemd-managed workload.
2. Container state still comes from Podman inspection of the configured container name.
3. Unit state comes from the configured Quadlet unit.
4. Restart uses the configured systemd scope and unit. It does not call Podman restart for Quadlet workloads.

SafeOps never talks to the Podman REST socket. It does not expose a generic Podman runner, shell, or arbitrary argument field.

Mutable operations are intended to be serialized by resource key `resource_kind + resource_alias`; the database schema includes a persistent lock table for cross-process ownership and recovery.

Add a tool by defining a use case in `internal/application`, adding a closed executor operation if needed, exposing it in `internal/adapters/inbound/mcpstdio`, and testing validation at both boundaries.
