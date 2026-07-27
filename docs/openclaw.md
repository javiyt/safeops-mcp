# OpenClaw Integration

SafeOps MCP is intended to be launched by OpenClaw over stdio. The example in `deploy/openclaw/example-config.json` is conceptual. Check the exact syntax supported by the installed OpenClaw version before using it.

Run OpenClaw as an unprivileged Linux user. That user may belong to the `safeops` group so it can reach `/run/safeops/safeops.sock`, but it must not belong to `sudo`.

Expose only the SafeOps tools to the agent. Do not grant OpenClaw access to a shell, `systemctl`, `journalctl`, `sudo`, Docker or Podman sockets, `.env` files, secret directories, or broad host filesystem mounts.

When Podman is enabled, OpenClaw still does not need direct container privileges. It must not receive:

- Podman socket access.
- A shell.
- The `podman` binary.
- The `systemctl` binary.
- Quadlet files.
- Container storage directories.

Additional tools may be advertised:

- `list_containers`: lists configured container aliases only.
- `container_status`: inspects one configured container alias without environment variables, mounts, labels, command arguments, registry credentials, or secrets.
- `container_logs`: returns bounded and redacted untrusted log content.
- `request_container_restart`: creates an approval and does not restart anything.
- `confirm_action`: may execute a previously approved service or container restart only after confirmation.

The first version assumes a dedicated SafeOps MCP instance for one configured administrator. The logical administrator ID is set in `identity.administrator_id`, and approvals are bound to that value.

Use dry-run first by setting `policies.dry_run: true`. Read-only tools still return real status, but confirmed mutable actions are simulated and audited as simulated.
