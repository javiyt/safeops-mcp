package podman

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
)

func TestInspectContainerMapsStructuredJSON(t *testing.T) {
	runner := &fakeRunner{stdout: `[{"Image":"sha256:abc","ImageName":"localhost/app-alpha:latest","RestartCount":2,"State":{"Status":"running","StatusString":"Up 1 hour","StartedAt":"2026-07-25T05:30:00Z","Pid":1234,"ExitCode":0,"Healthcheck":{"Status":"healthy"}}}]`}
	client := Client{Binary: "/usr/bin/podman", Runner: runner}
	out, err := client.InspectContainer(context.Background(), "container-alpha", "app-alpha-container", "podman")
	if err != nil {
		t.Fatal(err)
	}
	if out.State != "running" || out.Health != HealthHealthy || out.Image != "localhost/app-alpha:latest" || out.PID != 1234 {
		t.Fatalf("status = %+v", out)
	}
	wantArgs := []string{"inspect", "--type", "container", "--format", "json", "app-alpha-container"}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", runner.args, wantArgs)
	}
}

func TestInspectContainerHandlesErrors(t *testing.T) {
	client := Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{err: errors.New("podman failed: no such container token=abc")}}
	out, err := client.InspectContainer(context.Background(), "container-alpha", "missing", "podman")
	if err != nil {
		t.Fatal(err)
	}
	if out.Exists || out.Error != "podman failed: no such container token=[REDACTED]" {
		t.Fatalf("status = %+v", out)
	}
	client = Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{stdout: `{`}}
	if _, err := client.InspectContainer(context.Background(), "container-alpha", "bad-json", "podman"); err == nil {
		t.Fatal("InspectContainer() error = nil, want JSON error")
	}
}

func TestLogsAndRestartUseClosedArguments(t *testing.T) {
	runner := &fakeRunner{stdout: "token=abc\nservice started\n"}
	client := Client{Binary: "/usr/bin/podman", Runner: runner}
	logs, _, err := client.Logs(context.Background(), "app-alpha-container", 10, "2h")
	if err != nil {
		t.Fatal(err)
	}
	if logs[0].Message != "token=[REDACTED]" {
		t.Fatalf("logs = %+v", logs)
	}
	wantLogs := []string{"logs", "--tail", "10", "--since", "2h", "app-alpha-container"}
	if !reflect.DeepEqual(runner.args, wantLogs) {
		t.Fatalf("args = %#v, want %#v", runner.args, wantLogs)
	}
	if err := client.Restart(context.Background(), "app-alpha-container"); err != nil {
		t.Fatal(err)
	}
	wantRestart := []string{"restart", "app-alpha-container"}
	if !reflect.DeepEqual(runner.args, wantRestart) {
		t.Fatalf("args = %#v, want %#v", runner.args, wantRestart)
	}
	for _, arg := range runner.allArgs {
		switch arg {
		case "exec", "rm", "rmi", "prune", "pull", "run", "create", "generate", "kube":
			t.Fatalf("forbidden podman subcommand used: %s", arg)
		case "sh", "bash", "-c":
			t.Fatalf("shell argument used: %s", arg)
		}
	}
}

func TestWaitForHealthStates(t *testing.T) {
	runner := &fakeRunner{stdout: `[{"State":{"Status":"running","Healthcheck":{"Status":"starting"}}}]`}
	client := Client{Binary: "/usr/bin/podman", Runner: runner}
	if _, _, err := client.WaitForHealth(context.Background(), "container-alpha", "app-alpha-container", "podman", 1, time.Nanosecond); err == nil {
		t.Fatal("WaitForHealth() error = nil, want timeout")
	}
	runner.stdout = `[{"State":{"Status":"running"}}]`
	health, attempts, err := client.WaitForHealth(context.Background(), "container-alpha", "app-alpha-container", "podman", 1, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if health != HealthNotConfigured || attempts != 1 {
		t.Fatalf("health=%s attempts=%d", health, attempts)
	}
}

type fakeRunner struct {
	stdout  string
	err     error
	args    []string
	allArgs []string
}

func (r *fakeRunner) Run(_ context.Context, _ string, args ...string) (process.Result, error) {
	r.args = append([]string(nil), args...)
	r.allArgs = append(r.allArgs, args...)
	return process.Result{Stdout: r.stdout}, r.err
}
