package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/javiyt/safeops-mcp/internal/adapters/inbound/mcpstdio"
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
		return fmt.Errorf("usage: safeops-mcp serve --config /etc/safeops/config.yaml")
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
	service, closeStore, err := bootstrap.NewToolService(ctx, cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		_ = closeStore()
	}()
	return mcpstdio.Server{Tools: service, UserID: cfg.Identity.AdministratorID, In: os.Stdin, Out: os.Stdout, Logger: logger}.Serve(ctx)
}
