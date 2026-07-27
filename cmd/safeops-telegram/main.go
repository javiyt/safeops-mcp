package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	telegramadapter "github.com/javiyt/safeops-mcp/internal/adapters/inbound/telegram"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
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
		return fmt.Errorf("usage: safeops-telegram serve --config /etc/safeops/config.yaml")
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
	if !cfg.Telegram.Enabled {
		return fmt.Errorf("telegram.enabled must be true to run safeops-telegram")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	store, err := sqlite.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer func() {
		_ = store.Close()
	}()
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	bot := telegramadapter.Bot{
		Config: cfg,
		API: telegramadapter.HTTPAPI{
			Token:      cfg.TelegramToken(),
			HTTPClient: &http.Client{Timeout: 35 * time.Second},
		},
		Conversation: telegramadapter.NewOpenClawCLI(cfg.Telegram.OpenClaw),
		Audit:        store,
		IDs:          bootstrap.CryptoIDGenerator{},
		Clock:        bootstrap.SystemClock{},
		Limiter:      telegramadapter.NewRateLimiter(cfg.Telegram.RateLimit.MessagesPerMinute, time.Minute),
		Logger:       logger,
	}
	return bot.Serve(ctx)
}
