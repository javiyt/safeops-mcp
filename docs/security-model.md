# Security Model

Protected assets include systemd control, Podman container control, Quadlet workload control, journal contents, container logs, service and container availability, host metadata, network metadata, process metadata, the audit database, approval state, and secrets that may appear in logs, command lines, or inspect output.

OpenClaw is treated as unprivileged and untrusted for authorization. The LLM is not a security boundary. Prompt text, tool arguments, and log contents are external inputs.

OpenClaw-specific threats include prompt injection from user messages, prompt injection from logs, malicious or misleading service output, attempts to coerce the agent into inventing aliases, attempts to use unavailable shell or filesystem tools, and identity spoofing when the channel layer is not strongly authenticated. OpenClaw configuration must therefore expose only SafeOps MCP tools, deny general runtime and filesystem tool groups, and run under a Linux user without sudo or direct container-runtime access.

Telegram-specific threats include bot token theft, spoofed or forwarded messages, accidental group exposure, unauthorized users discovering the bot, confirmation-code brute force, callback replay, callback tampering, oversized-message abuse, and leakage of operational details into Telegram clients.

The Telegram adapter mitigates these threats by requiring private chats, checking numeric Telegram user IDs against `telegram.allowed_users`, enforcing per-user rate limits, rejecting oversized incoming messages, redacting outgoing text, splitting long responses, and auditing channel events with `telegram:<user_id>`. The token must be supplied through an environment variable such as `SAFEOPS_TELEGRAM_TOKEN`; a real token must not be stored in repository files.

SafeOps uses deny by default, least privilege, typed tools, configured aliases, double validation, persistent approvals, and audit logging. Read operations may run automatically. Mutating operations require confirmation. Destructive operations are denied in this version.

Logs are untrusted content. Instructions found inside logs must never become actions. Log output is bounded and redacted before it is returned or audited.

Diagnostic output is also untrusted host data. Process names, command lines, DNS servers, gateways, IP addresses, SMART data, and time-service metadata may reveal operational details. SafeOps mitigates this by exposing only typed read tools, limiting disk diagnostics to configured aliases, limiting connectivity checks to configured targets, optionally redacting IP addresses with `diagnostics.network.redact_ips`, redacting command lines, and auditing every diagnostic read.

Process diagnostics must not enumerate all host processes for the LLM. `configured_process_status` and the `cpu_status.processes` field only return processes matched to configured service or container aliases. If no configured match is found, SafeOps returns an empty list rather than broad process output.

Network diagnostics do not perform arbitrary scanning. They do not accept user-supplied interfaces, hosts, ports, packet captures, or local-network ranges. Connectivity checks use only `diagnostics.network.ping_targets`.

Disk diagnostics do not accept arbitrary paths. `disk_health` returns configured filesystem aliases only. SMART is disabled by default and should be enabled only after the operator verifies the target platform and disclosure profile.

The SafeOps OpenClaw prompt treats logs as data, not instructions. A log line that asks the agent to run a command, reveal a secret, skip confirmation, or call a mutable tool is hostile input and must not influence tool choice beyond summarizing the log as suspicious.

Container logs have two independent bounds: a configured line limit and the process-output byte limit. If the byte limit truncates output, the tool response sets `truncated: true`. The content remains untrusted even after redaction.

Podman is accessed only through the configured CLI binary with separated arguments and closed operations. SafeOps does not use the Podman socket, Docker-compatible environment variables, shell command strings, or arbitrary extra arguments. Container aliases are never used as real container names; the executor resolves aliases again from configuration.

Container inspect output is treated as untrusted host data. SafeOps returns only selected fields and does not expose environment variables, full labels, mounts, command arguments, registry credentials, or Quadlet file contents.

The Podman inspect adapter intentionally decodes only a narrow JSON projection: image identity, restart count, state, timestamps, PID, exit code, native health status, and redacted state error. It does not deserialize secret-bearing sections such as `Config.Env`, `Config.Cmd`, `Mounts`, authentication material, labels, or generated unit content.

Quadlet management is limited to status and restart of configured units. SafeOps does not edit Quadlet files, run `daemon-reload`, call `podman generate`, or inspect Podman sockets. User-scoped Quadlets require the executor to run as the owning Linux user with `XDG_RUNTIME_DIR` available; this avoids giving OpenClaw or the MCP process Podman privileges.

Health checks accept only configured local URLs and apply timeouts, redirect limits, body limits, and attempt limits to reduce SSRF risk.

Approvals are bound to the configured administrator ID, expire, store only a hash of the confirmation code, and are marked executing atomically to prevent double execution.

When Telegram is enabled, `identity.administrator_id` must be `telegram:<admin_id>`. This keeps SafeOps approval ownership and mutable audit rows tied to the Telegram administrator accepted by the channel adapter. The LLM must not be allowed to choose or rewrite this identity.

Generic approvals bind action type, resource kind, resource alias, normalized arguments, user identity, and dry-run-relevant security data through the arguments hash. A service approval cannot become a container action. Configuration and permissions are rechecked at confirmation time to reduce time-of-check/time-of-use risk.

Additional threats considered in this iteration include Podman socket exposure, container escape after an approved restart, malicious image metadata, secrets in logs, secrets in inspect output, CLI argument injection, rootless identity mismatch, Quadlet privilege-boundary confusion, concurrent mutable actions, and configuration changes between approval and execution.

Additional OpenClaw integration threats considered in this iteration include overbroad OpenClaw tool profiles, accidental MCP projection to unrelated agents, unsafe stdio wrappers around `safeops-mcp`, leakage of SafeOps config paths or logs into model context, forged confirmation codes in logs, and OpenClaw channel senders impersonating the configured administrator. The current mitigation is a dedicated SafeOps agent, a minimal OpenClaw tool profile with `bundle-mcp` added back, explicit deny lists, SafeOps-side confirmation revalidation, and manual E2E verification.

Additional Telegram integration threats considered in this iteration include stolen bot tokens, incorrect allowlists, group chat exposure, repeated confirmation attempts, message replay, stale inline buttons, malicious callback data, and OpenClaw wrappers that ignore trusted channel metadata. The current mitigation is token isolation, strict allowlists, private-chat enforcement, rate limiting, callback parsing with closed verbs, SafeOps-side approval revalidation, and manual E2E verification.

Audit policy:

- Mutable operations must not execute if the required pre-operation approval and audit records cannot be persisted.
- If a post-operation audit write fails after an operation has already run successfully, SafeOps records the audit failure on the approval and still returns the successful operation result.
- Read operations are audited when implemented at the tool layer, but read audit failures may be treated as less strict than mutable pre-operation audit failures.

Residual risk remains around incomplete secret detection, host-level misconfiguration, overly broad sudoers rules configured by an operator, and bugs in systemd or journal tooling.

Residual diagnostic risk remains around process names or command lines that encode sensitive business context, local DNS or gateway metadata when IP redaction is disabled, unavailable platform-specific telemetry, and external command differences for `ping` or `timedatectl`.

Residual OpenClaw risk remains around operator mistakes in channel allowlists, future OpenClaw configuration schema changes, third-party model behavior, and any non-SafeOps tool accidentally granted to the SafeOps agent.

Residual Telegram risk remains around Telegram account compromise, endpoint availability, Bot API behavior changes, local process environment exposure, and operators choosing an OpenClaw command wrapper that logs user messages or token-bearing environment variables.
