# Architecture

SafeOps MCP has three separate binaries.

`safeops-mcp` runs without administrative privileges and speaks MCP over stdio. It validates tool inputs, applies policy, creates approvals, records audit events, redacts secrets, and calls the local executor through a Unix socket.

`safeops-executor` listens only on a local Unix socket. It resolves configured aliases to systemd units or filesystem paths, validates requests again, and performs only closed operations.

`safeopsctl` is an operator CLI for configuration validation, database migrations, audit and approval listing, and read-only Podman diagnostics.

The trust boundary is the Unix socket. The MCP process never receives a free shell, never calls `sudo`, and never accepts arbitrary commands. The executor never talks to the LLM and never interprets natural language.

OpenClaw flow:

1. The operator sends a natural-language request to OpenClaw through a configured channel or local OpenClaw surface.
2. OpenClaw runs the SafeOps agent with the SafeOps workspace prompt and a restricted tool policy.
3. OpenClaw starts `safeops-mcp serve --config /etc/safeops/config.yaml` as a stdio MCP server from the `mcp.servers.safeops` registry entry.
4. OpenClaw exposes only the SafeOps MCP tools selected by the `safeops` tool filter and denied all general runtime, filesystem, SSH, Docker, Podman, and shell tools.
5. `safeops-mcp` maps OpenClaw's MCP call to the configured administrator identity from `identity.administrator_id`.
6. `safeops-mcp` validates arguments, applies policy, persists approvals or audit events, and calls the executor through the Unix socket.
7. The executor revalidates aliases from its own configuration and performs only closed read or restart operations.
8. Results return to OpenClaw as structured MCP responses. The agent summarizes them but must not treat logs as instructions or claim completion before the final tool result.

In the current single-administrator design, OpenClaw channel identity is not a strong authorization boundary inside SafeOps. SafeOps binds approvals to `identity.administrator_id`; channel allowlists and sender checks remain OpenClaw responsibilities. Future multi-user support should propagate a verified operator identity into SafeOps before per-user authorization is added.

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
5. Logs use bounded `podman logs` calls, closed `since` values, per-container line limits, global byte limits, redaction, truncation reporting, and untrusted-content marking.

Podman inspect is parsed into a narrow internal struct. Fields that commonly contain secrets or host topology, including environment variables, command arguments, labels, mounts, registry credentials, and generated Quadlet content, are not decoded into the response model.

Quadlet workload flow:

1. A `management: quadlet` container is treated as a systemd-managed workload.
2. Container state still comes from Podman inspection of the configured container name.
3. Unit state comes from the configured Quadlet unit.
4. Restart uses the configured systemd scope and unit. It does not call Podman restart for Quadlet workloads.

For `systemd_scope: user`, systemd calls are made as `systemctl --user ...`. The executor must run as the same Linux user that owns the rootless containers and user units, with `XDG_RUNTIME_DIR` available. For `systemd_scope: system`, calls use system-scoped `systemctl ...` and require only the minimum host permission needed for the configured units.

SafeOps never talks to the Podman REST socket. It does not expose a generic Podman runner, shell, or arbitrary argument field.

Container restart flow:

1. `request_container_restart` creates the same generic approval shape used by service restarts.
2. `confirm_action` revalidates the user, approval state, confirmation code, policy, current permissions, current resource existence in configuration, dry-run state, action type, resource kind, resource alias, and normalized argument hash.
3. A persistent operation lock is acquired for `resource_kind + resource_alias`.
4. Plain Podman-managed containers use `podman restart <configured-container-name>`.
5. Quadlet-managed workloads use `systemctl` with the configured scope and `quadlet_unit`.
6. The executor waits for the container to become running. If no native Podman health check is configured, the health result is `not_configured` and no additional health polling is performed.
7. If health is configured, SafeOps polls the native health state. `unhealthy` and stopped containers fail. `require_healthy_after_restart` controls whether unsettled health states fail the restart result.
8. The operation result is persisted and audited; a post-operation audit write failure is recorded on the approval without hiding a successful restart.

Mutable operations are serialized by resource key `resource_kind + resource_alias`; the SQLite schema includes a persistent lock table for cross-process ownership and recovery. Locks are released after success, failure, or cancellation of the executing context, and expired locks are cleaned before acquiring a new lock.

Add a tool by defining a use case in `internal/application`, adding a closed executor operation if needed, exposing it in `internal/adapters/inbound/mcpstdio`, and testing validation at both boundaries.
