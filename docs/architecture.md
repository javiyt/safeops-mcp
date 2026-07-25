# Architecture

SafeOps MCP has two separate binaries.

`safeops-mcp` runs without administrative privileges and speaks MCP over stdio. It validates tool inputs, applies policy, creates approvals, records audit events, redacts secrets, and calls the local executor through a Unix socket.

`safeops-executor` listens only on a local Unix socket. It resolves configured aliases to systemd units or filesystem paths, validates requests again, and performs only closed operations.

The trust boundary is the Unix socket. The MCP process never receives a free shell, never calls `sudo`, and never accepts arbitrary commands. The executor never talks to the LLM and never interprets natural language.

Read flow:

1. The MCP client calls a typed tool.
2. `safeops-mcp` validates arguments and policy.
3. `safeops-mcp` calls the executor over `/run/safeops/safeops.sock`.
4. The executor resolves the alias from its own configuration.
5. The executor returns structured JSON.

Restart flow:

1. `request_service_restart` creates a persistent approval and returns a short confirmation code.
2. `confirm_action` verifies the owner, state, expiration, code, policy, and current configuration.
3. The approval is atomically marked as executing.
4. The executor restarts the configured unit or simulates it in dry-run mode.
5. The final result is audited and the approval cannot be reused.

Add a tool by defining a use case in `internal/application`, adding a closed executor operation if needed, exposing it in `internal/adapters/inbound/mcpstdio`, and testing validation at both boundaries.
