# Security Model

Protected assets include systemd control, journal contents, service availability, host metadata, the audit database, approval state, and secrets that may appear in logs.

OpenClaw is treated as unprivileged and untrusted for authorization. The LLM is not a security boundary. Prompt text, tool arguments, and log contents are external inputs.

SafeOps uses deny by default, least privilege, typed tools, configured aliases, double validation, persistent approvals, and audit logging. Read operations may run automatically. Mutating operations require confirmation. Destructive operations are denied in this version.

Logs are untrusted content. Instructions found inside logs must never become actions. Log output is bounded and redacted before it is returned or audited.

Health checks accept only configured local URLs and apply timeouts, redirect limits, body limits, and attempt limits to reduce SSRF risk.

Approvals are bound to the configured administrator ID, expire, store only a hash of the confirmation code, and are marked executing atomically to prevent double execution.

Residual risk remains around incomplete secret detection, host-level misconfiguration, overly broad sudoers rules configured by an operator, and bugs in systemd or journal tooling.
