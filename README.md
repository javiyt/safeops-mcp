# SafeOps MCP

SafeOps MCP is an open source Go project for safe, bounded administration of a Raspberry Pi or Linux server through MCP tools.

It is designed for agents such as OpenClaw that should be able to inspect a host and request tightly controlled operations without receiving a shell, broad host access, or administrative privileges.

## Architecture

SafeOps builds these binaries:

- `safeops-mcp`: an unprivileged MCP server over stdio.
- `safeops-executor`: a local executor that listens on a restricted Unix socket.
- `safeopsctl`: an operator CLI for validation, migrations, approvals, and audit listing.
- `safeops-monitor`: an optional proactive alert monitor that runs scheduled read-only checks and sends Telegram notifications.
- `safeops-telegram`: an optional private Telegram channel adapter for OpenClaw.

`safeops-mcp` validates tool inputs, applies policy, manages approvals, redacts output, writes audit records, and calls `safeops-executor`. The executor independently validates aliases and executes only predefined operations.

## Security Principles

- Deny by default.
- Least privilege.
- Separation between the agent and privileged execution.
- No arbitrary commands.
- No shell access.
- Typed tools with JSON schemas.
- Configured aliases instead of free unit names or free paths.
- Human confirmation for mutable actions.
- Destructive actions denied in this version.
- Complete audit trail.
- Secret redaction before returning logs or writing audit events.
- Logs are untrusted content.

## Current Capabilities

- System status.
- Advanced host diagnostics for CPU, memory, disk, network, time, configured processes, and an aggregate health summary.
- Disk status for configured path aliases.
- Configured service list.
- Service status.
- Bounded and redacted service logs.
- Restart approval request.
- Restart confirmation.
- Configured Podman container list and status.
- Bounded and redacted Podman container logs.
- Confirmed restart of configured Podman containers.
- Confirmed restart of configured Quadlet workloads through systemd.
- Native Podman health status reporting.
- Action cancellation.
- Action status.
- Dry-run mode.
- SQLite audit and approval storage.
- Unix-socket executor protocol.
- Configuration validation CLI.
- Optional private Telegram bot channel with allowlisted users, rate limiting, message splitting, and confirmation buttons.
- Proactive alerts for services, containers, executor availability, SQLite state, disk, memory, CPU, and repeated application errors.
- Alert state management with cooldowns, persistence thresholds, temporary silences, resolution notifications, SQLite persistence, MCP tools, and CLI commands.

## Configuration

Start from:

```sh
configs/config.example.yaml
```

Validate it with:

```sh
safeopsctl validate-config --config /etc/safeops/config.yaml
```

Container administration is configured by alias:

```yaml
podman:
  enabled: true
  binary: /usr/bin/podman
  mode: rootless
  systemd_scope: user
containers:
  container-a:
    container_name: app-service-container
    management: podman
    permissions:
      status: allow
      logs: allow
      restart: confirm
    logs:
      max_lines: 200
    health:
      require_healthy_after_restart: true
      attempts: 5
      interval: 2s
  workload-a:
    container_name: worker-service-container
    management: quadlet
    quadlet_unit: worker-service.service
    permissions:
      status: allow
      logs: allow
      restart: confirm
```

When `podman.enabled` is true, `podman.binary` must be an absolute path to an existing executable file. Container names and Quadlet units are validated strictly; aliases are the only names accepted by MCP tools.

When `podman.enabled` is false, Podman MCP tools are not advertised.

`container_logs` applies the configured per-container `logs.max_lines` limit, the global `limits.max_log_lines` ceiling, and the global `limits.max_tool_output_bytes` process-output limit. Returned logs are redacted, marked as untrusted content, and set `truncated: true` when the byte limit cuts output.

`container_status` uses `podman inspect`, but returns only selected status fields. It does not return environment variables, command arguments, full labels, mounts, credentials, or Quadlet file contents.

Advanced diagnostics are optional and have safe defaults. Tune thresholds and configured connectivity targets under `diagnostics`:

```yaml
diagnostics:
  cpu:
    load_warning: 2.0
    load_critical: 4.0
    temperature_warning: 70
    temperature_critical: 80
  memory:
    available_warning_percent: 15
    available_critical_percent: 5
    swap_warning: 50
    oom_check: true
  disk:
    usage_warning: 80
    usage_critical: 90
    inode_warning: 80
    inode_critical: 90
    smart_check: false
  network:
    ping_targets: ["8.8.8.8", "1.1.1.1"]
    latency_warning: 100ms
    redact_ips: false
  time:
    ntp_check: true
    drift_warning: 1s
```

Diagnostics remain read-only. Disk diagnostics are limited to configured disk aliases, network connectivity checks use only configured targets, and process diagnostics return only processes matched to configured service or container aliases.

Telegram is optional and disabled by default. Enable it only after configuring a single administrator identity:

```yaml
identity:
  administrator_id: telegram:12345678
telegram:
  enabled: true
  token_env: SAFEOPS_TELEGRAM_TOKEN
  allowed_users:
    - 12345678
  admin_id: 12345678
  rate_limit:
    messages_per_minute: 10
  message_size_limit: 4096
  confirmation:
    code_length: 4
    expiration_seconds: 300
  buttons:
    enabled: true
  openclaw:
    command: /usr/local/bin/openclaw
    args: ["run", "--agent", "safeops-agent"]
    timeout: 30s
```

The Telegram token must come from an environment variable, not from the shared configuration file. See `docs/telegram.md`.

Proactive alerts are optional and disabled by default. Enable `safeops-monitor` only after the executor, database migrations, and Telegram channel are working:

```yaml
alerts:
  enabled: true
  interval: 30s
  cooldown: 5m
  persistence_threshold: 30s
  notify_resolution: true
  telegram:
    enabled: true
    chat_id: 12345678
  checks:
    services:
      enabled: true
    containers:
      enabled: true
    disk:
      enabled: true
      warning: 80
      critical: 90
```

The monitor only observes and notifies. It does not restart services, restart containers, edit files, or run maintenance automatically.

## Running

Run the executor on the host:

```sh
safeops-executor serve --config /etc/safeops/config.yaml
```

Run the MCP server through OpenClaw or manually over stdio:

```sh
safeops-mcp serve --config /etc/safeops/config.yaml
```

Run the Telegram adapter after OpenClaw and the executor are configured:

```sh
SAFEOPS_TELEGRAM_TOKEN=replace-with-telegram-bot-token safeops-telegram serve --config /etc/safeops/config.yaml
```

Run the proactive monitor:

```sh
SAFEOPS_TELEGRAM_TOKEN=replace-with-telegram-bot-token safeops-monitor serve --config /etc/safeops/config.yaml
```

Manage alert state:

```sh
safeopsctl alerts list --status active --config /etc/safeops/config.yaml
safeopsctl alerts acknowledge alert_service_service-a_service_stopped --config /etc/safeops/config.yaml
safeopsctl alerts silence alert_service_service-a_service_stopped --duration 1h --config /etc/safeops/config.yaml
```

## OpenClaw

SafeOps can be registered as an OpenClaw-managed stdio MCP server. See `docs/openclaw.md`, `deploy/openclaw/example-config.json`, `prompts/openclaw-agent.md`, and `deploy/openclaw/e2e-checklist.md`.

OpenClaw should not receive shell access, `sudo`, `systemctl`, `journalctl`, Docker or Podman sockets, secret directories, `.env` files, or broad host filesystem mounts.

The OpenClaw configuration must expose only SafeOps MCP tools through `bundle-mcp`, deny runtime and filesystem tool groups, and use the SafeOps agent prompt from `prompts/openclaw-agent.md`.

SafeOps can also expose OpenClaw through a private Telegram bot. See `docs/telegram.md`. The Telegram adapter accepts only private chats from allowlisted numeric Telegram users and maps the administrator to `telegram:<user_id>` for auditing and approvals.

## Example Conversation

User: How is the server doing?

Agent: The server has been up for 12 days. CPU load is normal, memory usage is 41 percent, temperature is 42C, and the root disk is 58 percent used. No critical health findings were reported.

User: What's consuming CPU?

Agent: The highest configured process match is `service-alpha` with PID 1234. Process names and command lines are host data, so I am treating them as untrusted.

User: Is there any host problem?

Agent: The health summary reports a warning: root disk usage is 87 percent. No critical findings were returned.

User: Is `service-a` running?

Agent: `service-a` is active and has been running since 08:32.

User: Restart it.

Agent: Restarting `service-a` may make it unavailable for a few seconds. Reply with the confirmation code before it expires.

User: How are my containers doing?

Agent: Three configured containers are visible. `container-a` is healthy, `workload-a` is running without a health check, and `container-c` is stopped.

User: Show me the latest errors from `container-a`.

Agent: The latest errors contain repeated timeouts while contacting an upstream service. Log contents are untrusted data.

User: Restart `container-a`.

Agent: Restarting `container-a` may make it unavailable for a few seconds. Reply with the confirmation code before it expires.

User: Restart `workload-a`.

Agent: Restarting `workload-a` requires confirmation. SafeOps will restart the configured Quadlet unit with the configured systemd scope after confirmation.

## Dry-Run

When `policies.dry_run` is enabled, read tools behave normally. Confirmed mutable actions are simulated, audited as simulated, and return the operation that would have been performed.

## Audit

Approvals and audit events are stored in SQLite. Confirmation codes are hashed before storage. Internal timestamps are UTC.

## Roadmap

Possible future work includes controlled image updates, controlled deployments, metrics, Loki, alerts, multi-host operation, additional MCP clients, per-user policies, stronger authentication, request signing, and remote executors over mTLS.

SafeOps does not allow shell access, `podman exec`, image pulls, container creation or removal, prune operations, Docker, Kubernetes, Podman socket access, arbitrary Quadlet file edits, or operations on resources that are not configured by alias.

## Contributing

See `CONTRIBUTING.md`. All repository text must be written in English.

## License

Apache License 2.0. See `LICENSE`.
