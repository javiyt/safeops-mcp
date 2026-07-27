#!/usr/bin/env sh
set -eu

OPENCLAW_USER="${OPENCLAW_USER:-openclaw}"
OPENCLAW_HOME="${OPENCLAW_HOME:-/var/lib/openclaw}"
OPENCLAW_CONFIG_DIR="${OPENCLAW_CONFIG_DIR:-$OPENCLAW_HOME/.openclaw}"
OPENCLAW_WORKSPACE="${OPENCLAW_WORKSPACE:-$OPENCLAW_HOME/safeops-agent-workspace}"
SAFEOPS_CONFIG="${SAFEOPS_CONFIG:-/etc/safeops/config.yaml}"
SAFEOPS_MCP_BIN="${SAFEOPS_MCP_BIN:-/usr/local/bin/safeops-mcp}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root" >&2
  exit 1
fi

if ! id "$OPENCLAW_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "$OPENCLAW_HOME" --shell /usr/sbin/nologin "$OPENCLAW_USER"
fi

if getent group safeops >/dev/null 2>&1; then
  usermod -a -G safeops "$OPENCLAW_USER"
fi

install -d -m 0750 -o "$OPENCLAW_USER" -g "$OPENCLAW_USER" "$OPENCLAW_CONFIG_DIR"
install -d -m 0750 -o "$OPENCLAW_USER" -g "$OPENCLAW_USER" "$OPENCLAW_WORKSPACE"

if [ ! -x "$SAFEOPS_MCP_BIN" ]; then
  echo "$SAFEOPS_MCP_BIN is missing or not executable" >&2
  exit 1
fi

if [ ! -r "$SAFEOPS_CONFIG" ]; then
  echo "$SAFEOPS_CONFIG is missing or not readable" >&2
  exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)

install -m 0640 -o "$OPENCLAW_USER" -g "$OPENCLAW_USER" "$REPO_ROOT/deploy/openclaw/example-config.json" "$OPENCLAW_CONFIG_DIR/openclaw.json"
install -m 0640 -o "$OPENCLAW_USER" -g "$OPENCLAW_USER" "$REPO_ROOT/prompts/openclaw-agent.md" "$OPENCLAW_WORKSPACE/AGENTS.md"

echo "OpenClaw SafeOps files installed."
echo "Review $OPENCLAW_CONFIG_DIR/openclaw.json before starting OpenClaw."
echo "Validate with: sudo -u $OPENCLAW_USER openclaw config validate"
