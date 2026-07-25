# OpenClaw Integration

SafeOps MCP is intended to be launched by OpenClaw over stdio. The example in `deploy/openclaw/example-config.json` is conceptual. Check the exact syntax supported by the installed OpenClaw version before using it.

Run OpenClaw as an unprivileged Linux user. That user may belong to the `safeops` group so it can reach `/run/safeops/safeops.sock`, but it must not belong to `sudo`.

Expose only the SafeOps tools to the agent. Do not grant OpenClaw access to a shell, `systemctl`, `journalctl`, `sudo`, Docker or Podman sockets, `.env` files, secret directories, or broad host filesystem mounts.

The first version assumes a dedicated SafeOps MCP instance for one configured administrator. The logical administrator ID is set in `identity.administrator_id`, and approvals are bound to that value.

Use dry-run first by setting `policies.dry_run: true`. Read-only tools still return real status, but confirmed mutable actions are simulated and audited as simulated.
