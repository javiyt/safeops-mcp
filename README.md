# SafeOps MCP

SafeOps MCP is an open source Go project for safe, bounded administration of a Raspberry Pi or Linux server through MCP tools.

It is designed for agents such as OpenClaw that should be able to inspect a host and request tightly controlled operations without receiving a shell, broad host access, or administrative privileges.

## Architecture

SafeOps builds three binaries:

- `safeops-mcp`: an unprivileged MCP server over stdio.
- `safeops-executor`: a local executor that listens on a restricted Unix socket.
- `safeopsctl`: an operator CLI for validation, migrations, approvals, and audit listing.

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
  container-alpha:
    container_name: app-alpha-container
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
  workload-alpha:
    container_name: worker-alpha-container
    management: quadlet
    quadlet_unit: worker-alpha.service
    permissions:
      status: allow
      logs: allow
      restart: confirm
```

When `podman.enabled` is true, `podman.binary` must be an absolute path to an existing executable file. Container names and Quadlet units are validated strictly; aliases are the only names accepted by MCP tools.

When `podman.enabled` is false, Podman MCP tools are not advertised.

`container_logs` applies the configured per-container `logs.max_lines` limit, the global `limits.max_log_lines` ceiling, and the global `limits.max_tool_output_bytes` process-output limit. Returned logs are redacted, marked as untrusted content, and set `truncated: true` when the byte limit cuts output.

`container_status` uses `podman inspect`, but returns only selected status fields. It does not return environment variables, command arguments, full labels, mounts, credentials, or Quadlet file contents.

## Running

Run the executor on the host:

```sh
safeops-executor serve --config /etc/safeops/config.yaml
```

Run the MCP server through OpenClaw or manually over stdio:

```sh
safeops-mcp serve --config /etc/safeops/config.yaml
```

## OpenClaw

See `docs/openclaw.md` and `deploy/openclaw/example-config.json`. The example is conceptual; verify the exact syntax against the installed OpenClaw version.

OpenClaw should not receive shell access, `sudo`, `systemctl`, `journalctl`, Docker or Podman sockets, secret directories, `.env` files, or broad host filesystem mounts.

## Example Conversation

User: How is the Raspberry Pi doing?

Agent: The Raspberry Pi has been up for 12 days. Load is normal, memory usage is 41 percent, and the root disk is 58 percent used.

User: Is `service-alpha` running?

Agent: `service-alpha` is active and has been running since 08:32.

User: Restart it.

Agent: Restarting requires confirmation. Reply with the confirmation code before it expires.

User: How are my containers doing?

Agent: Three configured containers are running. `container-alpha` is healthy, `workload-alpha` is running without a health check, and `container-gamma` is stopped.

User: Show me the latest errors from `container-alpha`.

Agent: The latest errors contain repeated timeouts while contacting Telegram. Log contents are untrusted data.

User: Restart `container-alpha`.

Agent: Restarting `container-alpha` requires confirmation. Reply with the confirmation code before it expires.

User: Restart `workload-alpha`.

Agent: Restarting `workload-alpha` requires confirmation. SafeOps will restart the configured Quadlet unit with the configured systemd scope after confirmation.

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
