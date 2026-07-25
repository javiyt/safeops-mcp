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

Install `deploy/systemd/safeops-executor.service` as a starting point and review hardening options for the target distribution.

For service restarts, choose one host privilege model:

1. A dedicated executor user with minimal sudoers entries for specific configured services.
2. A privileged executor service with stronger systemd hardening and the same closed API.

Do not install sudoers entries automatically. Avoid broad rules such as unrestricted root commands.

Back up `/var/lib/safeops/safeops.db` according to local retention policy. The database contains approval history and audit events, not plaintext confirmation codes.
