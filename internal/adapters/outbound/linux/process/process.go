package process

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

type Runner interface {
	Run(ctx context.Context, path string, args ...string) (Result, error)
}

type Result struct {
	Stdout   string
	Stderr   string
	Duration time.Duration
}

type CommandRunner struct {
	Timeout  time.Duration
	MaxBytes int
}

func (r CommandRunner) Run(ctx context.Context, path string, args ...string) (Result, error) {
	if r.Timeout <= 0 {
		return Result{}, errors.New("process timeout must be positive")
	}
	if r.MaxBytes <= 0 {
		return Result{}, errors.New("process max bytes must be positive")
	}
	runCtx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	start := time.Now()
	cmd := exec.CommandContext(runCtx, path, args...)
	var stdout, stderr limitedBuffer
	stdout.limit = r.MaxBytes
	stderr.limit = r.MaxBytes
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{Stdout: stdout.String(), Stderr: stderr.String(), Duration: time.Since(start)}
	if runCtx.Err() != nil {
		return result, fmt.Errorf("%s timed out: %w", path, runCtx.Err())
	}
	if err != nil {
		return result, fmt.Errorf("%s failed: %w: %s", path, err, stderr.String())
	}
	return result, nil
}

type limitedBuffer struct {
	buf   []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - len(b.buf)
	if remaining <= 0 {
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf = append(b.buf, p[:remaining]...)
		return len(p), nil
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return string(b.buf)
}
