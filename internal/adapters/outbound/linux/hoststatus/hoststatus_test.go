package hoststatus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemStatusReadsProcFiles(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "loadavg"), "0.10 0.20 0.30 1/100 42\n")
	mustWrite(t, filepath.Join(dir, "uptime"), "123.45 67.89\n")
	mustWrite(t, filepath.Join(dir, "meminfo"), "MemTotal:       1000 kB\nMemAvailable:    250 kB\n")
	out, err := (Reader{
		ProcRoot: dir,
		Hostname: func() (string, error) {
			return "host-alpha", nil
		},
		NumCPU: func() int {
			return 4
		},
		GOOS:   "linux",
		GOARCH: "arm64",
	}).SystemStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if out.Hostname != "host-alpha" || out.UptimeSeconds != 123 || out.LoadAverage.FifteenMinutes != 0.30 || out.Memory.UsedPercent != 75 || out.CPU.Cores != 4 {
		t.Fatalf("SystemStatus() = %+v", out)
	}
}

func TestSystemStatusHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (Reader{}).SystemStatus(ctx); err == nil {
		t.Fatal("SystemStatus() error = nil, want context error")
	}
}

func TestSystemStatusReturnsFileErrors(t *testing.T) {
	if _, err := (Reader{ProcRoot: t.TempDir()}).SystemStatus(context.Background()); err == nil {
		t.Fatal("SystemStatus() error = nil, want missing proc file error")
	}
}

func mustWrite(t *testing.T, path, value string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}
