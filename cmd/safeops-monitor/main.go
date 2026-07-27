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

	"github.com/javiyt/safeops-mcp/internal/adapters/inbound/telegram"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/executorclient"
	sqlitestore "github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
	"github.com/javiyt/safeops-mcp/internal/application/alerts"
	"github.com/javiyt/safeops-mcp/internal/bootstrap"
	"github.com/javiyt/safeops-mcp/internal/config"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: safeops-monitor <serve|check> --config /etc/safeops/config.yaml")
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if !cfg.Alerts.Enabled {
		return fmt.Errorf("alerts are disabled")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	svc, closeFn, err := newAlertService(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		_ = closeFn()
	}()
	switch args[0] {
	case "check":
		return svc.RunOnce(ctx)
	case "serve":
		ticker := time.NewTicker(cfg.Alerts.Interval.Std())
		defer ticker.Stop()
		if err := svc.RunOnce(ctx); err != nil {
			svc.Logger.Error("alert check failed", "error", err)
		}
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
				if err := svc.RunOnce(ctx); err != nil {
					svc.Logger.Error("alert check failed", "error", err)
				}
			}
		}
	default:
		return fmt.Errorf("usage: safeops-monitor <serve|check> --config /etc/safeops/config.yaml")
	}
}

func newAlertService(ctx context.Context, cfg config.Config) (alerts.Service, func() error, error) {
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return alerts.Service{}, nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return alerts.Service{}, nil, err
	}
	var notifier alerts.Notifier
	if cfg.Alerts.Telegram.Enabled {
		notifier = telegramNotifier{
			api: telegram.HTTPAPI{
				Token:      cfg.TelegramToken(),
				HTTPClient: &http.Client{Timeout: 35 * time.Second},
			},
			chatID: cfg.Alerts.Telegram.ChatID,
		}
	}
	return alerts.Service{
		Config:   cfg,
		Executor: executorclient.New(cfg.Socket.Path),
		Alerts:   store,
		Audit:    store,
		Notifier: notifier,
		Clock:    bootstrap.SystemClock{},
		Logger:   slog.New(slog.NewJSONHandler(os.Stderr, nil)),
	}, store.Close, nil
}

type telegramNotifier struct {
	api    telegram.HTTPAPI
	chatID int64
}

func (n telegramNotifier) Notify(ctx context.Context, message string) error {
	return n.api.SendMessage(ctx, telegram.SendMessageRequest{ChatID: n.chatID, Text: message})
}
