# Operations

Install the three binaries under `/usr/local/bin`: `safeops-mcp`, `safeops-executor`, and `safeopsctl`.

Create a dedicated `safeops` group and a `safeops-executor` user. The OpenClaw user may join `safeops` to access the socket, but it must not join `sudo`.

Create `/etc/safeops/config.yaml` from `configs/config.example.yaml`. Create `/var/lib/safeops` owned by the executor user or by a restricted service account.

Run migrations with:

```sh
safeopsctl migrate --config /etc/safeops/config.yaml
```

Validate configuration with:

```sh
safeopsctl validate-config --config /etc/safeops/config.yaml
```

When Podman is enabled, validation requires `podman.binary` to be an absolute path to an existing file. Validate from the same host image or Raspberry Pi environment where the executor will run.

Install `deploy/systemd/safeops-executor.service` as a starting point and review hardening options for the target distribution.

For service restarts, choose one host privilege model:

1. A dedicated executor user with minimal sudoers entries for specific configured services.
2. A privileged executor service with stronger systemd hardening and the same closed API.

Do not install sudoers entries automatically. Avoid broad rules such as unrestricted root commands.

Back up `/var/lib/safeops/safeops.db` according to local retention policy. The database contains approval history and audit events, not plaintext confirmation codes.

## Rootless Podman

Rootless Podman is the recommended container mode.

Rootless containers are visible only to the Linux user that owns them. Run `safeops-executor` as that same user when it manages rootless containers. Do not use `sudo podman` for SafeOps-managed containers.

OpenClaw remains unprivileged. It communicates only with `safeops-mcp`, which communicates with `safeops-executor` through the restricted Unix socket. OpenClaw does not need Podman, systemctl, a shell, Quadlet files, container storage directories, or any Podman socket.

Configure:

```yaml
podman:
  enabled: true
  binary: /usr/bin/podman
  mode: rootless
  systemd_scope: user
```

Validate manually as the executor user:

```sh
/usr/bin/podman ps --filter name=app-alpha-container
/usr/bin/podman inspect --type container --format json app-alpha-container
systemctl --user status worker-alpha.service
safeopsctl podman check --config /etc/safeops/config.yaml
safeopsctl containers list --config /etc/safeops/config.yaml
safeopsctl containers status container-alpha --config /etc/safeops/config.yaml
```

`safeopsctl podman check` verifies the configured Podman binary, mode, configured container visibility, user-scoped systemd access when configured, `XDG_RUNTIME_DIR`, and linger when `loginctl` is available. It prints status metadata only; it must not print container environment variables, command arguments, mounts, or secrets from inspect output.

`XDG_RUNTIME_DIR` normally points to `/run/user/<uid>` for the logged-in user and is required for `systemctl --user` and rootless Podman integration. SafeOps diagnostics report whether it is set, but do not print the path. If the executor runs when the user is not logged in, enable linger for that user:

```sh
loginctl enable-linger safeops-executor
```

Review the target distribution's user service behavior before enabling linger.

Quadlet units for rootless workloads are normally under the owning user's systemd user configuration, such as `~/.config/containers/systemd/`. SafeOps reads status and restarts only the configured unit. It does not edit Quadlet files and does not run daemon reload in this iteration.

For `systemd_scope: system`, the executor must have only the minimum permission needed to inspect and restart the configured units. Prefer rootless `systemd_scope: user` unless there is a clear operational reason.

Common errors:

- Container not found: the executor is probably running as the wrong user or the alias resolves to the wrong configured container name.
- Missing `XDG_RUNTIME_DIR`: the user service environment is not available.
- `systemctl --user` cannot connect: enable linger or run the executor in the correct user session.
- Permission denied from Podman: check rootless ownership and avoid `sudo podman`.

Dry-run can be tested by setting `policies.dry_run: true`. Read tools still call Podman, but confirmed restarts are simulated and audited as simulated.
