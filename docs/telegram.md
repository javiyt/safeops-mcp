# Telegram Integration

SafeOps can run a private Telegram bot as the remote channel for an OpenClaw SafeOps agent.

The Telegram adapter is a separate binary, `safeops-telegram`. It receives private Telegram messages through long polling, validates the Telegram user, sends the text to OpenClaw, and returns the OpenClaw response to the same chat.

SafeOps remains the security boundary. Telegram is a channel. OpenClaw remains unprivileged. Mutable actions still require SafeOps approvals and `confirm_action`.

## Setup

Create a private bot with BotFather and store the token outside the repository:

```sh
install -d -m 0750 /etc/safeops/secrets
install -m 0600 /dev/null /etc/safeops/secrets/telegram.env
```

Put the token in the environment file:

```sh
SAFEOPS_TELEGRAM_TOKEN=replace-with-telegram-bot-token
```

Do not put a real token in `config.yaml`, documentation, shell history, logs, or issue reports.

Get the numeric Telegram user ID for the administrator with a user-info bot or a local Telegram API inspection tool. Configure a single administrator:

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

`safeops-telegram` requires `identity.administrator_id` to match `telegram:<admin_id>` when Telegram is enabled. In this phase only one administrator is supported.

Validate configuration with the token environment loaded:

```sh
set -a
. /etc/safeops/secrets/telegram.env
set +a
safeopsctl validate-config --config /etc/safeops/config.yaml
```

## Running

Run the executor and OpenClaw as documented in [operations.md](operations.md) and [openclaw.md](openclaw.md). Then start the Telegram adapter:

```sh
set -a
. /etc/safeops/secrets/telegram.env
set +a
safeops-telegram serve --config /etc/safeops/config.yaml
```

The adapter uses Telegram Bot API long polling. It does not require a public webhook endpoint or public TLS certificate.

## OpenClaw Contract

The adapter invokes the configured OpenClaw command once per Telegram message. The user message is sent on stdin. The adapter sets trusted environment metadata:

- `SAFEOPS_CHANNEL=telegram`
- `SAFEOPS_TELEGRAM_USER_ID=<numeric-id>`
- `SAFEOPS_PRINCIPAL=telegram:<numeric-id>`

OpenClaw must be configured so the SafeOps MCP server uses the same SafeOps configuration file. SafeOps binds approvals and audit rows to `identity.administrator_id`, which must be `telegram:<admin_id>` for Telegram deployments.

If the installed OpenClaw version provides a first-class HTTP or session API with trusted metadata, prefer that API and configure the adapter command as a small local wrapper around it. Do not let the model invent or modify `SAFEOPS_PRINCIPAL`.

## Confirmation Buttons

SafeOps returns pending approvals with an `approval_id` and a numeric `confirmation_code`. The adapter detects output fields in the form:

```text
approval_id=apr_example confirmation_code=4821
```

When buttons are enabled, the final Telegram reply includes:

- `Confirm`, encoded as `confirm:<approval_id>:<confirmation_code>`
- `Cancel`, encoded as `cancel:<approval_id>`

Button clicks are translated into controlled text sent to OpenClaw, such as:

```text
Confirm approval apr_example with code 4821.
```

SafeOps still performs the real verification in `confirm_action`: owner, status, expiration, code hash, action parameters, current policy, and current configuration are rechecked. Replayed buttons cannot execute an already completed approval.

## Daily Use

Example private chat:

```text
User:
How is the server?

Agent:
The server has been up for 12 days. CPU usage is low, memory usage is normal, and the root disk is within the configured limit.

User:
Are all services running?

Agent:
`service-alpha` is active. `service-beta` is active without a health check. `container-alpha` is stopped.

User:
Restart `container-alpha`.

Agent:
Restarting `container-alpha` requires confirmation. Reply with confirmation_code=4821 before it expires.

User:
Confirm approval apr_example with code 4821.

Agent:
`container-alpha` has been restarted and is healthy.
```

## Security Notes

- Only private chats are accepted.
- Only numeric user IDs in `telegram.allowed_users` are accepted.
- Telegram groups, channels, and unknown users are rejected before OpenClaw is called.
- Rate limiting is enforced per Telegram user.
- Incoming messages larger than `telegram.message_size_limit` are rejected.
- Outgoing messages are redacted and split to fit Telegram limits.
- Channel audit rows include `telegram:<user_id>`.
- SafeOps approval rows and mutable audit rows use the configured administrator identity.
- Confirmation codes are generated with `crypto/rand` and only hashes are stored.
- The Telegram token must stay outside the repository and outside logs.

## Manual Test Matrix

Run these checks with a test Telegram account before enabling the bot for daily use:

1. Send `/start` from the administrator and verify the welcome message.
2. Ask for host status.
3. Ask for a configured service status.
4. Ask for a configured container status.
5. Read bounded service logs.
6. Read bounded container logs.
7. Request a service restart and verify an approval code appears.
8. Confirm with the correct code.
9. Confirm with a wrong code.
10. Confirm after approval expiration.
11. Cancel a pending action.
12. Ask for an unknown alias and verify no fallback alias is invented.
13. Send a message from a non-allowed user and verify OpenClaw is not called.
14. Send a group message and verify OpenClaw is not called.
15. Ask for an unavailable command such as shell access and verify the agent refuses.
16. Click Confirm and Cancel buttons when buttons are enabled.

## Troubleshooting

- `SAFEOPS_TELEGRAM_TOKEN must contain the Telegram bot token`: load the environment file before running validation or the service.
- `telegram.admin_id must be listed`: add the administrator's numeric Telegram ID to `telegram.allowed_users`.
- `identity.administrator_id must be "telegram:<id>"`: update the SafeOps identity for Telegram deployments.
- No replies: verify the bot token, long polling connectivity, and the configured OpenClaw command.
- Repeated rate-limit replies: increase `telegram.rate_limit.messages_per_minute` cautiously or reduce automation that sends repeated messages.
