package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
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

func TestPodmanCheckUsesFakesAndDoesNotPrintSecrets(t *testing.T) {
	dir := t.TempDir()
	podmanPath := writeExecutable(t, dir, "podman", `#!/bin/sh
case "$1" in
version)
  printf '{"Version":"fake"}'
  ;;
inspect)
  printf '[{"Image":"sha256:abc","ImageName":"localhost/app:latest","Config":{"Env":["TOKEN=super-secret"]},"State":{"Status":"running","Healthcheck":{"Status":"healthy"}}}]'
  ;;
*)
  exit 1
  ;;
esac
`)
	systemctl := writeExecutable(t, dir, "systemctl", "#!/bin/sh\nexit 0\n")
	loginctl := writeExecutable(t, dir, "loginctl", "#!/bin/sh\nprintf 'yes\\n'\n")
	cfg := writePodmanConfig(t, dir, podmanPath)

	oldCurrentUser := currentUser
	oldLookPath := lookPath
	oldOutputf := outputf
	oldSystemctlPath := systemctlPath
	oldXDG := os.Getenv("XDG_RUNTIME_DIR")
	t.Cleanup(func() {
		currentUser = oldCurrentUser
		lookPath = oldLookPath
		outputf = oldOutputf
		systemctlPath = oldSystemctlPath
		_ = os.Setenv("XDG_RUNTIME_DIR", oldXDG)
	})
	currentUser = func() (*user.User, error) { return &user.User{Username: "operator"}, nil }
	lookPath = func(name string) (string, error) {
		if name == "loginctl" {
			return loginctl, nil
		}
		return "", os.ErrNotExist
	}
	systemctlPath = systemctl
	if err := os.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	outputf = func(format string, args ...any) (int, error) {
		return fmt.Fprintf(&buf, format, args...)
	}
	if err := run(context.Background(), []string{"podman", "check", "--config", cfg}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"binary\t" + podmanPath, "systemctl_user_access\tok", "linger\tyes", "container\tcontainer-alpha\texists=true\tstate=running\thealth=healthy"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "super-secret") || strings.Contains(out, "TOKEN=") || strings.Contains(out, "XDG_RUNTIME_DIR\t") {
		t.Fatalf("podman check output leaked sensitive data:\n%s", out)
	}
}

func TestPodmanCheckRequiresXDGForUserScope(t *testing.T) {
	dir := t.TempDir()
	podmanPath := writeExecutable(t, dir, "podman", "#!/bin/sh\nprintf '{}'\n")
	cfg := writePodmanConfig(t, dir, podmanPath)
	oldXDG := os.Getenv("XDG_RUNTIME_DIR")
	t.Cleanup(func() {
		_ = os.Setenv("XDG_RUNTIME_DIR", oldXDG)
	})
	if err := os.Unsetenv("XDG_RUNTIME_DIR"); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"podman", "check", "--config", cfg}); err == nil {
		t.Fatal("run() error = nil, want XDG_RUNTIME_DIR error")
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

func writeExecutable(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePodmanConfig(t *testing.T, dir, podmanBinary string) string {
	t.Helper()
	path := filepath.Join(dir, "podman-config.yaml")
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
podman:
  enabled: true
  binary: ` + podmanBinary + `
  mode: rootless
  systemd_scope: user
containers:
  container-alpha:
    container_name: app-alpha-container
    management: podman
    permissions:
      status: allow
      logs: allow
      restart: confirm
    logs:
      max_lines: 10
    health:
      attempts: 2
      interval: 1ms
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
