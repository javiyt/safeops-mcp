package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestRunSafeopsctlCommands(t *testing.T) {
	cfg := writeTestConfig(t)
	ctx := context.Background()
	if err := run(ctx, []string{"validate-config", "--config", cfg}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"migrate", "--config", cfg}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"approvals", "list", "--config", cfg}); err != nil {
		t.Fatal(err)
	}
	if err := run(ctx, []string{"audit", "list", "--limit", "5", "--config", cfg}); err != nil {
		t.Fatal(err)
	}
}

func TestRunSafeopsctlRejectsBadUsage(t *testing.T) {
	ctx := context.Background()
	for _, args := range [][]string{
		nil,
		{"unknown"},
		{"approvals"},
		{"audit"},
		{"validate-config", "--config", "/missing"},
		{"validate-config", "--bad"},
		{"migrate", "--bad"},
		{"approvals", "list", "--bad"},
		{"audit", "list", "--bad"},
	} {
		if err := run(ctx, args); err == nil {
			t.Fatalf("run(%v) error = nil, want error", args)
		}
	}
}

func writeTestConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := `server:
  name: host-alpha
identity:
  administrator_id: operator
database:
  path: ` + filepath.Join(dir, "safeops.db") + `
socket:
  path: ` + filepath.Join(dir, "safeops.sock") + `
  group: safeops
  mode: "0660"
policies:
  default: deny
  destructive_actions: deny
  approval_expiration: 5m
  dry_run: false
limits:
  operation_timeout: 15s
  max_log_lines: 200
  max_tool_output_bytes: 65536
  max_healthcheck_attempts: 5
filesystem:
  disk_paths:
    root:
      path: /
services:
  service-alpha:
    unit: app-alpha.service
    permissions:
      status: allow
      logs: allow
      restart: confirm
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
