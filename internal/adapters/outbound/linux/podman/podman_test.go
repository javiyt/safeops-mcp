package podman

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
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

func TestInspectContainerOmitsSecretBearingInspectFields(t *testing.T) {
	runner := &fakeRunner{stdout: `[{
		"Image":"sha256:abc",
		"ImageName":"localhost/app-alpha:latest",
		"Config":{"Env":["TOKEN=super-secret"],"Cmd":["--password=super-secret"]},
		"Mounts":[{"Source":"/srv/secrets","Destination":"/run/secrets"}],
		"State":{"Status":"running","StatusString":"Up 1 hour","Pid":1234,"ExitCode":0}
	}]`}
	client := Client{Binary: "/usr/bin/podman", Runner: runner}
	out, err := client.InspectContainer(context.Background(), "container-alpha", "app-alpha-container", "podman")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"super-secret", "TOKEN=", "--password", "/srv/secrets", "/run/secrets"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("inspect output leaked %q: %s", forbidden, data)
		}
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

func TestInspectContainerEmptyAndUnknownHealth(t *testing.T) {
	client := Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{stdout: `[]`}}
	out, err := client.InspectContainer(context.Background(), "container-alpha", "missing", "podman")
	if err != nil {
		t.Fatal(err)
	}
	if out.Exists || out.Health != HealthUnknown {
		t.Fatalf("status = %+v", out)
	}

	client = Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{stdout: `[{"State":{"Status":"running","FinishedAt":"0001-01-01T00:00:00Z","Healthcheck":{"Status":"mystery"}}}]`}}
	out, err = client.InspectContainer(context.Background(), "container-alpha", "app-alpha-container", "podman")
	if err != nil {
		t.Fatal(err)
	}
	if out.Health != HealthUnknown || out.FinishedAt != nil {
		t.Fatalf("status = %+v", out)
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

func TestLogsPropagatesGlobalByteTruncation(t *testing.T) {
	runner := &fakeRunner{stdout: "line one\nline two without newline", stdoutTruncated: true}
	client := Client{Binary: "/usr/bin/podman", Runner: runner}
	logs, truncated, err := client.Logs(context.Background(), "app-alpha-container", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("truncated = false, want true")
	}
	if len(logs) != 2 {
		t.Fatalf("logs length = %d, want 2", len(logs))
	}
}

func TestLogsEmptyAndError(t *testing.T) {
	client := Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{stdout: "\n"}}
	logs, truncated, err := client.Logs(context.Background(), "app-alpha-container", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) != 0 || truncated {
		t.Fatalf("logs=%+v truncated=%t", logs, truncated)
	}
	client = Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{err: errors.New("failed token=abc")}}
	if _, _, err := client.Logs(context.Background(), "app-alpha-container", 10, ""); err == nil || !strings.Contains(err.Error(), "token=[REDACTED]") {
		t.Fatalf("Logs() error = %v", err)
	}
}

func TestRestartRedactsErrors(t *testing.T) {
	client := Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{err: errors.New("failed password=abc")}}
	if err := client.Restart(context.Background(), "app-alpha-container"); err == nil || !strings.Contains(err.Error(), "password=[REDACTED]") {
		t.Fatalf("Restart() error = %v", err)
	}
}

func TestWaitForRunningStatesAndContext(t *testing.T) {
	client := Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{stdouts: []string{
		`[{"State":{"Status":"starting"}}]`,
		`[{"State":{"Status":"running"}}]`,
	}}}
	st, attempts, err := client.WaitForRunning(context.Background(), "container-alpha", "app-alpha-container", "podman", 2, time.Nanosecond)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != "running" || attempts != 2 {
		t.Fatalf("status=%+v attempts=%d", st, attempts)
	}

	client = Client{Binary: "/usr/bin/podman", Runner: &fakeRunner{stdout: `[{"State":{"Status":"starting"}}]`}}
	if _, _, err := client.WaitForRunning(context.Background(), "container-alpha", "app-alpha-container", "podman", 1, time.Nanosecond); err == nil {
		t.Fatal("WaitForRunning() error = nil, want timeout")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := client.WaitForRunning(ctx, "container-alpha", "app-alpha-container", "podman", 2, time.Hour); err == nil {
		t.Fatal("WaitForRunning() error = nil, want context error")
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
	runner.stdout = `[{"State":{"Status":"running","Healthcheck":{"Status":"unhealthy"}}}]`
	health, _, err = client.WaitForHealth(context.Background(), "container-alpha", "app-alpha-container", "podman", 1, time.Nanosecond)
	if err == nil || health != HealthUnhealthy {
		t.Fatalf("health=%s err=%v, want unhealthy error", health, err)
	}
	runner.stdout = `[{"State":{"Status":"exited","Healthcheck":{"Status":"healthy"}}}]`
	if _, _, err := client.WaitForHealth(context.Background(), "container-alpha", "app-alpha-container", "podman", 1, time.Nanosecond); err == nil {
		t.Fatal("WaitForHealth() error = nil, want not running error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner.stdout = `[{"State":{"Status":"running","Healthcheck":{"Status":"starting"}}}]`
	if _, _, err := client.WaitForHealth(ctx, "container-alpha", "app-alpha-container", "podman", 2, time.Hour); err == nil {
		t.Fatal("WaitForHealth() error = nil, want context error")
	}
}

type fakeRunner struct {
	stdout          string
	stdouts         []string
	stdoutTruncated bool
	err             error
	args            []string
	allArgs         []string
}

func (r *fakeRunner) Run(_ context.Context, _ string, args ...string) (process.Result, error) {
	r.args = append([]string(nil), args...)
	r.allArgs = append(r.allArgs, args...)
	if len(r.stdouts) > 0 {
		stdout := r.stdouts[0]
		r.stdouts = r.stdouts[1:]
		return process.Result{Stdout: stdout, StdoutTruncated: r.stdoutTruncated}, r.err
	}
	return process.Result{Stdout: r.stdout, StdoutTruncated: r.stdoutTruncated}, r.err
}
