package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunUsageAndServeEOF(t *testing.T) {
	oldArgs := os.Args
	oldStdin := os.Stdin
	defer func() {
		os.Args = oldArgs
		os.Stdin = oldStdin
	}()
	os.Args = []string{"safeops-mcp"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want usage error")
	}
	os.Args = []string{"safeops-mcp", "serve", "--bad"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want flag error")
	}
	cfg := writeMCPConfig(t)
	stdinPath := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(stdinPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stdin, err := os.Open(stdinPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
	}()
	os.Stdin = stdin
	os.Args = []string{"safeops-mcp", "serve", "--config", cfg}
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

func writeMCPConfig(t *testing.T) string {
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
