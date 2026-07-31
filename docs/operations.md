# Operations

Install the binaries under `/usr/local/bin`: `safeops-mcp`, `safeops-executor`, `safeopsctl`, `safeops-monitor`, and optionally `safeops-telegram`.

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

## Host Diagnostics

SafeOps includes read-only diagnostics for administrator checks and OpenClaw-backed conversations:

```sh
safeopsctl diagnostics cpu --config /etc/safeops/config.yaml
safeopsctl diagnostics memory --config /etc/safeops/config.yaml
safeopsctl diagnostics disk --config /etc/safeops/config.yaml
safeopsctl diagnostics disk root --config /etc/safeops/config.yaml
safeopsctl diagnostics network --config /etc/safeops/config.yaml
safeopsctl diagnostics time --config /etc/safeops/config.yaml
safeopsctl diagnostics processes --config /etc/safeops/config.yaml
safeopsctl diagnostics health-summary --config /etc/safeops/config.yaml
```

Add `--json` to any diagnostic command for structured output.

The health summary status is:

- `healthy`: no warning or critical findings.
- `degraded`: at least one warning finding and no critical finding.
- `critical`: at least one critical finding.

Tune thresholds in `/etc/safeops/config.yaml`:

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
  disk:
    usage_warning: 80
    usage_critical: 90
    inode_warning: 80
    inode_critical: 90
  network:
    ping_targets: ["8.8.8.8", "1.1.1.1"]
    latency_warning: 100ms
    redact_ips: false
  time:
    ntp_check: true
    drift_warning: 1s
```

Disk diagnostics are limited to `filesystem.disk_paths`. Process diagnostics are limited to configured service and container aliases. Network connectivity checks use only configured targets and do not scan local networks or arbitrary ports.

When Podman is enabled, validation requires `podman.binary` to be an absolute path to an existing file. Validate from the same host image or Raspberry Pi environment where the executor will run.

Install `deploy/systemd/safeops-executor.service` as a starting point and review hardening options for the target distribution.

For service restarts, choose one host privilege model:

1. A dedicated executor user with minimal sudoers entries for specific configured services.
2. A privileged executor service with stronger systemd hardening and the same closed API.

Do not install sudoers entries automatically. Avoid broad rules such as unrestricted root commands.

Back up `/var/lib/safeops/safeops.db` according to local retention policy. The database contains approval history and audit events, not plaintext confirmation codes.

## Proactive Alerts

Run migrations before enabling the monitor:

```sh
safeopsctl migrate --config /etc/safeops/config.yaml
```

Enable alerts with explicit checks and Telegram delivery:

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
  silence_schedule:
    - start: "02:00"
      end: "06:00"
      timezone: "Europe/Madrid"
  checks:
    services:
      enabled: true
    containers:
      enabled: true
    disk:
      enabled: true
      warning: 80
      critical: 90
    memory:
      enabled: true
      pressure_warning: 0.5
      pressure_critical: 0.8
    cpu:
      enabled: true
      load_warning: 2.0
      load_critical: 4.0
      temperature_warning: 70
      temperature_critical: 80
    sqlite:
      enabled: true
    executor:
      enabled: true
    app_errors:
      enabled: true
      pattern: "ERROR|FATAL"
      threshold: 5
```

Start the monitor:

```sh
SAFEOPS_TELEGRAM_TOKEN=replace-with-telegram-bot-token safeops-monitor serve --config /etc/safeops/config.yaml
```

Run one check manually:

```sh
safeopsctl alerts check --config /etc/safeops/config.yaml
```

Manage alerts:

```sh
safeopsctl alerts list --status active --config /etc/safeops/config.yaml
safeopsctl alerts acknowledge alert_service_service-a_service_stopped --config /etc/safeops/config.yaml
safeopsctl alerts silence alert_service_service-a_service_stopped --duration 1h --config /etc/safeops/config.yaml
safeopsctl alerts resolve alert_service_service-a_service_stopped --config /etc/safeops/config.yaml
```

Example Telegram notification:

```text
Alert: Service service-a is failed.
Severity: critical
ID: alert_service_service-a_service_stopped
No action has been taken.
```

Install [safeops-monitor.service](../deploy/systemd/safeops-monitor.service) as a starting point and review the hardening paths for the target host. The monitor needs read access to `/etc/safeops/config.yaml`, write access to `/var/lib/safeops`, access to the executor Unix socket, and outbound HTTPS access to Telegram only when Telegram notifications are enabled.

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
/usr/bin/podman ps --filter name=app-service-container
/usr/bin/podman inspect --type container --format json app-service-container
systemctl --user status worker-service.service
safeopsctl podman check --config /etc/safeops/config.yaml
safeopsctl containers list --config /etc/safeops/config.yaml
safeopsctl containers status container-a --config /etc/safeops/config.yaml
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

## Telegram Channel

Telegram support is optional. Enable it only after the executor and OpenClaw are working locally.

Store the bot token outside the repository:

```sh
install -d -m 0750 /etc/safeops/secrets
printf '%s\n' 'SAFEOPS_TELEGRAM_TOKEN=replace-with-telegram-bot-token' > /etc/safeops/secrets/telegram.env
chmod 0600 /etc/safeops/secrets/telegram.env
```

Configure the single administrator by numeric Telegram ID:

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

Validate with the token loaded:

```sh
set -a
. /etc/safeops/secrets/telegram.env
set +a
safeopsctl validate-config --config /etc/safeops/config.yaml
```

Run the adapter:

```sh
set -a
. /etc/safeops/secrets/telegram.env
set +a
safeops-telegram serve --config /etc/safeops/config.yaml
```

Recommended service shape:

```ini
[Unit]
Description=SafeOps Telegram adapter
After=network-online.target safeops-executor.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/safeops/secrets/telegram.env
ExecStart=/usr/local/bin/safeops-telegram serve --config /etc/safeops/config.yaml
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadOnlyPaths=/etc/safeops/config.yaml
ReadWritePaths=/var/lib/safeops

[Install]
WantedBy=multi-user.target
```

To add or remove an authorized Telegram user in this phase, edit `telegram.allowed_users`, keep `telegram.admin_id` as the single administrator, validate config, and restart `safeops-telegram`. Multi-user roles are intentionally deferred.

Audit channel events:

```sh
safeopsctl audit list --limit 50 --config /etc/safeops/config.yaml
```

Telegram channel events use component `safeops-telegram` and user IDs such as `telegram:12345678`. Mutable SafeOps events are still produced by `safeops-mcp` and are tied to the configured administrator identity.

## Controlled Maintenance

Configure maintenance by alias. Do not configure broad filesystem locations; use dedicated application log and cache paths:

```yaml
groups:
  app-stack:
    resources: [service-alpha, container-gamma, workload-alpha]
    order: [container-gamma, service-alpha, workload-alpha]
    stop_order: [workload-alpha, service-alpha, container-gamma]
    timeout: 60s
    health_check: true
applications:
  app-worker:
    cache_path: /var/cache/app-worker
    cleanup:
      enabled: true
      max_age: 24h
      max_size: 1GB
audit_retention: 90d
audit_min_records: 1000
host_reboot:
  enabled: false
```

Dry-run maintenance from the CLI:

```sh
safeopsctl groups restart app-stack --dry-run --config /etc/safeops/config.yaml
safeopsctl logs rotate service-alpha --dry-run --config /etc/safeops/config.yaml
safeopsctl cache cleanup app-worker --dry-run --config /etc/safeops/config.yaml
safeopsctl records cleanup --max-age 90d --min-records 1000 --dry-run --config /etc/safeops/config.yaml
safeopsctl reset-failed service-alpha --dry-run --config /etc/safeops/config.yaml
```

Host reboot is disabled by default. If enabled, configure sudoers outside SafeOps so the executor user can run only the restricted shutdown command without a password. Do not grant broad sudo.

## Controlled Application Updates

Run migrations before using deployments:

```sh
safeopsctl migrate --config /etc/safeops/config.yaml
```

Configure each deployable application under `applications`. The application alias must point at an existing service or container alias:

```yaml
podman:
  registry_whitelist: [ghcr.io]
applications:
  app-service:
    kind: service
    service_name: service-alpha
    management: systemd
    repository:
      type: git
      url: https://example.invalid/org/app-service
      branch: main
      path: /opt/app-service
      whitelist: [https://example.invalid/org/app-service]
    version:
      file: /opt/app-service/VERSION
    rollback:
      enabled: true
      versions_to_keep: 5
    permissions:
      check: allow
      update: confirm
      rollback: confirm
  example-container:
    kind: container
    container_name: container-alpha
    management: podman
    repository:
      type: container-registry
    image:
      registry: ghcr.io
      repository: example/app-service
      channel: stable
      digest_required: true
    rollback:
      enabled: true
      versions_to_keep: 5
    permissions:
      check: allow
      update: confirm
      rollback: confirm
```

Check and operate from the CLI:

```sh
safeopsctl app version app-service --config /etc/safeops/config.yaml
safeopsctl app check-update app-service --config /etc/safeops/config.yaml
safeopsctl app update app-service --dry-run --config /etc/safeops/config.yaml
safeopsctl app rollback app-service --version 1.0.0 --dry-run --config /etc/safeops/config.yaml
safeopsctl app history app-service --config /etc/safeops/config.yaml
```

Telegram and OpenClaw should use the MCP tools instead of direct CLI execution: `application_version`, `check_application_update`, `request_application_update`, `request_application_rollback`, and `confirm_action`.

History rows use status `success`, `failed`, or the executor result status. `previous_version` and `next_version` describe the transition, while `image_digest` or `commit_hash` identify the deployed artifact. SafeOps prunes history per application according to `rollback.versions_to_keep`.

Install `git` for service applications. Container applications use the configured Podman binary; `skopeo` is not required by this implementation.
