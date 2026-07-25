package main

import (
	"os"
	"testing"
)

func TestRunUsageAndInvalidConfig(t *testing.T) {
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()
	os.Args = []string{"safeops-executor"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want usage error")
	}
	os.Args = []string{"safeops-executor", "serve", "--config", "/missing"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want config error")
	}
	os.Args = []string{"safeops-executor", "serve", "--bad"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want flag error")
	}
}
