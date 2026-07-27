package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/javiyt/safeops-mcp/internal/adapters/inbound/executorhttp"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/configuredprocess"
	cpuadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/cpu"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/disk"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/diskhealth"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/healthcheck"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/hoststatus"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/journal"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/memory"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/network"
	podmanadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/podman"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/systemd"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/timestatus"
	"github.com/javiyt/safeops-mcp/internal/bootstrap"
	"github.com/javiyt/safeops-mcp/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		return fmt.Errorf("usage: safeops-executor serve --config /etc/safeops/config.yaml")
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	if err := fs.Parse(os.Args[2:]); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	runner := process.CommandRunner{Timeout: cfg.Limits.OperationTimeout.Std(), MaxBytes: cfg.Limits.MaxToolOutputBytes}
	cpuReader := cpuadapter.Reader{Config: cfg}
	backend := bootstrap.ExecutorBackend{
		Config:      cfg,
		Host:        hoststatus.Reader{},
		Disk:        disk.Reader{Config: cfg},
		CPU:         cpuReader,
		Memory:      memory.Reader{Config: cfg},
		DiskHealthR: diskhealth.Reader{Config: cfg},
		Network:     network.Reader{Config: cfg, Runner: runner},
		Time:        timestatus.Reader{Config: cfg, Runner: runner},
		Processes:   configuredprocess.Reader{CPU: cpuReader},
		Systemd:     systemd.Client{Runner: runner},
		Journal:     journal.Reader{Runner: runner},
		Healthcheck: healthcheck.Client{MaxBodyBytes: 4096},
		Podman:      podmanadapter.Client{Binary: cfg.Podman.Binary, Runner: runner},
	}
	return (&executorhttp.Server{Config: cfg, Backend: backend, Logger: logger}).ListenAndServe(ctx)
}
