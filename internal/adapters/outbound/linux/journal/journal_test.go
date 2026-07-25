package journal

import (
	"context"
	"testing"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
)

func TestLogsParsesJSONAndBuildsClosedArgs(t *testing.T) {
	runner := &fakeRunner{stdout: `{"__REALTIME_TIMESTAMP":"100","PRIORITY":"3","MESSAGE":"failed"}` + "\nnot-json\n"}
	entries, truncated, err := (Reader{Runner: runner}).Logs(context.Background(), "app-alpha.service", 10, "error", "2h")
	if err != nil {
		t.Fatal(err)
	}
	if truncated || len(entries) != 1 || entries[0].Message != "failed" {
		t.Fatalf("entries=%+v truncated=%v", entries, truncated)
	}
	want := []string{"-u", "app-alpha.service", "-n", "10", "--output=json", "--no-pager", "-p", "error", "--since", "2h"}
	if !equal(runner.args, want) {
		t.Fatalf("args = %#v", runner.args)
	}
}

func TestAsStringHandlesNumbersAndUnknownValues(t *testing.T) {
	if asString(float64(42)) != "42" {
		t.Fatal("float value was not formatted")
	}
	if asString(struct{}{}) != "" {
		t.Fatal("unknown value should return an empty string")
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
