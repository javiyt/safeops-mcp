package main

import (
	"os"
	"testing"
)

func TestRunUsage(t *testing.T) {
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()
	os.Args = []string{"safeops-telegram"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want usage error")
	}
	os.Args = []string{"safeops-telegram", "serve", "--bad"}
	if err := run(); err == nil {
		t.Fatal("run() error = nil, want flag error")
	}
}
