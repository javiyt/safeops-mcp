package systemd

import (
	"context"
	"testing"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
)

func TestStatusUsesExplicitProperties(t *testing.T) {
	runner := &fakeRunner{stdout: "active\nrunning\n2026-07-24T10:00:00Z\n123\n"}
	client := Client{Runner: runner}
	status, err := client.Status(context.Background(), "service-alpha", "app-alpha.service")
	if err != nil {
		t.Fatal(err)
	}
	if status.ActiveState != "active" || status.MainPID != 123 {
		t.Fatalf("status = %+v", status)
	}
	want := []string{"show", "app-alpha.service", "--property=ActiveState", "--property=SubState", "--property=ExecMainStartTimestamp", "--property=MainPID", "--value"}
	if !equal(runner.args, want) {
		t.Fatalf("args = %#v", runner.args)
	}
}

func TestRestartUsesConfiguredUnitOnly(t *testing.T) {
	runner := &fakeRunner{}
	if err := (Client{Runner: runner}).Restart(context.Background(), "app-alpha.service"); err != nil {
		t.Fatal(err)
	}
	if !equal(runner.args, []string{"restart", "app-alpha.service"}) {
		t.Fatalf("args = %#v", runner.args)
	}
}

type fakeRunner struct {
	args   []string
	stdout string
}

func (r *fakeRunner) Run(_ context.Context, _ string, args ...string) (process.Result, error) {
	r.args = args
	return process.Result{Stdout: r.stdout}, nil
}

func equal(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
