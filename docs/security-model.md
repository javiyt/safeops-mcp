# Security Model

Protected assets include systemd control, Podman container control, Quadlet workload control, journal contents, container logs, service and container availability, host metadata, the audit database, approval state, and secrets that may appear in logs or inspect output.

OpenClaw is treated as unprivileged and untrusted for authorization. The LLM is not a security boundary. Prompt text, tool arguments, and log contents are external inputs.

SafeOps uses deny by default, least privilege, typed tools, configured aliases, double validation, persistent approvals, and audit logging. Read operations may run automatically. Mutating operations require confirmation. Destructive operations are denied in this version.

Logs are untrusted content. Instructions found inside logs must never become actions. Log output is bounded and redacted before it is returned or audited.

Container logs have two independent bounds: a configured line limit and the process-output byte limit. If the byte limit truncates output, the tool response sets `truncated: true`. The content remains untrusted even after redaction.

Podman is accessed only through the configured CLI binary with separated arguments and closed operations. SafeOps does not use the Podman socket, Docker-compatible environment variables, shell command strings, or arbitrary extra arguments. Container aliases are never used as real container names; the executor resolves aliases again from configuration.

Container inspect output is treated as untrusted host data. SafeOps returns only selected fields and does not expose environment variables, full labels, mounts, command arguments, registry credentials, or Quadlet file contents.

The Podman inspect adapter intentionally decodes only a narrow JSON projection: image identity, restart count, state, timestamps, PID, exit code, native health status, and redacted state error. It does not deserialize secret-bearing sections such as `Config.Env`, `Config.Cmd`, `Mounts`, authentication material, labels, or generated unit content.

Quadlet management is limited to status and restart of configured units. SafeOps does not edit Quadlet files, run `daemon-reload`, call `podman generate`, or inspect Podman sockets. User-scoped Quadlets require the executor to run as the owning Linux user with `XDG_RUNTIME_DIR` available; this avoids giving OpenClaw or the MCP process Podman privileges.

Health checks accept only configured local URLs and apply timeouts, redirect limits, body limits, and attempt limits to reduce SSRF risk.

Approvals are bound to the configured administrator ID, expire, store only a hash of the confirmation code, and are marked executing atomically to prevent double execution.

Generic approvals bind action type, resource kind, resource alias, normalized arguments, user identity, and dry-run-relevant security data through the arguments hash. A service approval cannot become a container action. Configuration and permissions are rechecked at confirmation time to reduce time-of-check/time-of-use risk.

Additional threats considered in this iteration include Podman socket exposure, container escape after an approved restart, malicious image metadata, secrets in logs, secrets in inspect output, CLI argument injection, rootless identity mismatch, Quadlet privilege-boundary confusion, concurrent mutable actions, and configuration changes between approval and execution.

Audit policy:

- Mutable operations must not execute if the required pre-operation approval and audit records cannot be persisted.
- If a post-operation audit write fails after an operation has already run successfully, SafeOps records the audit failure on the approval and still returns the successful operation result.
- Read operations are audited when implemented at the tool layer, but read audit failures may be treated as less strict than mutable pre-operation audit failures.

Residual risk remains around incomplete secret detection, host-level misconfiguration, overly broad sudoers rules configured by an operator, and bugs in systemd or journal tooling.
