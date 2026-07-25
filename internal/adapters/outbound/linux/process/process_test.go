package process

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestCommandRunnerRunsWithoutShell(t *testing.T) {
	path := "/bin/echo"
	if runtime.GOOS == "windows" {
		t.Skip("test uses Unix process paths")
	}
	out, err := (CommandRunner{Timeout: time.Second, MaxBytes: 4}).Run(context.Background(), path, "abcdef")
	if err != nil {
		t.Fatal(err)
	}
	if out.Stdout != "abcd" {
		t.Fatalf("stdout = %q", out.Stdout)
	}
}

func TestCommandRunnerRejectsInvalidLimits(t *testing.T) {
	if _, err := (CommandRunner{}).Run(context.Background(), "/bin/echo"); err == nil {
		t.Fatal("Run() error = nil, want timeout error")
	}
	if _, err := (CommandRunner{Timeout: time.Second}).Run(context.Background(), "/bin/echo"); err == nil {
		t.Fatal("Run() error = nil, want max bytes error")
	}
}

func TestLimitedBufferBranches(t *testing.T) {
	var b limitedBuffer
	b.limit = 3
	if n, err := b.Write([]byte("ab")); err != nil || n != 2 {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if n, err := b.Write([]byte("cdef")); err != nil || n != 4 {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if n, err := b.Write([]byte("gh")); err != nil || n != 2 {
		t.Fatalf("Write() = %d, %v", n, err)
	}
	if b.String() != "abc" {
		t.Fatalf("String() = %q", b.String())
	}
}

func TestCommandRunnerReportsFailures(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses Unix process paths")
	}
	_, err := (CommandRunner{Timeout: time.Second, MaxBytes: 1024}).Run(context.Background(), "/usr/bin/false")
	if err == nil {
		t.Fatalf("err = %v", err)
	}
}
