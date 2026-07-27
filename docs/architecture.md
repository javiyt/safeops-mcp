# Architecture

SafeOps MCP has four core binaries and one optional channel adapter.

`safeops-mcp` runs without administrative privileges and speaks MCP over stdio. It validates tool inputs, applies policy, creates approvals, records audit events, redacts secrets, and calls the local executor through a Unix socket.

`safeops-executor` listens only on a local Unix socket. It resolves configured aliases to systemd units or filesystem paths, validates requests again, and performs only closed operations.

`safeopsctl` is an operator CLI for configuration validation, database migrations, audit and approval listing, read-only Podman diagnostics, and read-only host diagnostics.

`safeops-telegram` is an optional channel adapter. It is not a privileged executor and does not expose SafeOps tools directly to Telegram. It accepts private Telegram messages from allowlisted users, calls the configured OpenClaw command, and sends the response back to Telegram.

`safeops-monitor` is an optional proactive alert monitor. It runs as a separate process, calls the existing closed executor API for read-only status and diagnostics, persists alert state in SQLite, applies notification suppression rules, and sends Telegram notifications directly through the Bot API when configured. It does not execute mutable actions.

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

Telegram flow:

1. The operator sends a private Telegram message to the configured bot.
2. `safeops-telegram` receives the update through Bot API long polling.
3. `safeops-telegram` rejects non-private chats and users outside `telegram.allowed_users`.
4. `safeops-telegram` rate-limits the verified Telegram user and rejects oversized messages.
5. `safeops-telegram` invokes the configured OpenClaw command with the message on stdin and trusted environment metadata: `SAFEOPS_CHANNEL=telegram`, `SAFEOPS_TELEGRAM_USER_ID`, and `SAFEOPS_PRINCIPAL`.
6. OpenClaw runs the SafeOps agent with only SafeOps MCP tools available.
7. `safeops-mcp` uses `identity.administrator_id`, which must be `telegram:<admin_id>` when Telegram is enabled.
8. SafeOps approvals and mutable audit events are bound to that administrator identity.
9. `safeops-telegram` redacts and splits the OpenClaw response before sending it to Telegram.

Telegram confirmation button flow:

1. OpenClaw asks SafeOps for a mutable action approval.
2. SafeOps creates a pending approval, hashes the generated confirmation code, and returns `approval_id` plus `confirmation_code`.
3. OpenClaw includes those fields in its response.
4. `safeops-telegram` attaches optional inline buttons with callback data bound to the approval ID and code.
5. A callback is translated into controlled confirmation or cancellation text and sent to OpenClaw.
6. SafeOps still verifies ownership, code hash, expiration, current configuration, current policy, and approval status in `confirm_action` or `cancel_action`.

Read flow:

1. The MCP client calls a typed tool.
2. `safeops-mcp` validates arguments and policy.
3. `safeops-mcp` calls the executor over `/run/safeops/safeops.sock`.
4. The executor resolves the alias from its own configuration.
5. The executor returns structured JSON.

Advanced diagnostics flow:

1. The MCP client calls one of the read-only diagnostic tools: `cpu_status`, `memory_status`, `disk_health`, `network_status`, `time_status`, `configured_process_status`, or `host_health_summary`.
2. `safeops-mcp` validates that no arbitrary path, interface, host, port, command, or process selector was supplied.
3. The read is audited as `diagnostic_read` without storing sensitive payloads.
4. The executor routes the closed operation to a subsystem-specific Linux adapter.
5. CPU and memory prefer `/proc` and `/sys`; disk health uses configured filesystem aliases; network uses local interface metadata and configured ping targets only; time uses local clock metadata and `timedatectl show` when enabled; process diagnostics only match configured service and container aliases.
6. `host_health_summary` evaluates configured thresholds inside SafeOps and returns objective findings with `severity`, `code`, `message`, and optional `resource`. The LLM explains these findings but must not invent unsupported diagnoses.

Diagnostic adapters are intentionally separate packages instead of a generic host-command adapter. This keeps each subsystem's input surface closed and testable.

Proactive alert flow:

1. `safeops-monitor` wakes on `alerts.interval` or an operator runs `safeopsctl alerts check`.
2. Enabled checks inspect configured service aliases, configured container aliases, executor availability, SQLite alert state, CPU, memory, disk, and repeated configured-resource log errors.
3. Each abnormal condition maps to a deterministic alert ID derived from resource kind, resource alias, and alert type.
4. SQLite stores the alert state as `new`, `active`, `acknowledged`, `resolved`, or `suppressed`, with first/last observation timestamps, notification timestamp, count, suppression, acknowledgement, resolution, and JSON metadata.
5. The monitor applies `persistence_threshold`, `cooldown`, temporary silences, and maintenance windows before notifying.
6. Eligible alerts are grouped into a single Telegram message. Resolution notifications are sent only when `alerts.notify_resolution` is true and the alert was previously notified.
7. MCP tools and `safeopsctl alerts` can list, acknowledge, silence, and manually resolve persisted alerts. These operations change alert state only.

The direct Telegram sender is intentionally isolated in `safeops-monitor` for this phase. A future OpenClaw event queue can replace that notifier without changing alert evaluation or persistence.

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

Maintenance flow:

1. MCP maintenance tools accept only configured aliases and normalized options such as `dry_run`, `max_age`, and `min_records`.
2. Non-dry-run maintenance requests create generic approvals with action types `restart_group`, `rotate_logs`, `cleanup_cache`, `remove_records`, `reset_failure`, or `reboot_host`.
3. `confirm_action` revalidates configuration, policy, owner, confirmation code, arguments hash, and current resource availability before acquiring a persistent operation lock.
4. The executor receives a closed operation over the Unix socket. It resolves group members, service units, container names, log paths, and cache paths from configuration again.
5. Group restart stops resources in `stop_order` and starts resources in `order`, with configured timeout and optional health checks.
6. Log rotation and cache cleanup operate only on configured paths. The executor uses filesystem APIs with controlled paths and does not invoke a shell.
7. SafeOps record cleanup deletes only old audit and approval rows while preserving the configured minimum record count.
8. Host reboot is disabled by default. When enabled, it uses a longer confirmation code, checks for active mutable locks, and schedules reboot through the configured restricted command. `cancel_action` can cancel a reboot approval before confirmation or call the executor cancellation operation for a reboot that has already been scheduled.
