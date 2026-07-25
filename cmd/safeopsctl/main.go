package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	sqlitestore "github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
	"github.com/javiyt/safeops-mcp/internal/config"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: safeopsctl <validate-config|migrate|approvals|audit> [args]")
	}
	switch args[0] {
	case "validate-config":
		fs := flag.NewFlagSet("validate-config", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		_, err := config.Load(*cfgPath)
		return err
	case "migrate":
		cfg, err := loadConfigFlag("migrate", args[1:])
		if err != nil {
			return err
		}
		store, err := sqlitestore.Open(cfg.Database.Path)
		if err != nil {
			return err
		}
		defer func() {
			_ = store.Close()
		}()
		return store.Migrate(ctx)
	case "approvals":
		return approvals(ctx, args[1:])
	case "audit":
		return audit(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func approvals(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: safeopsctl approvals list --config /etc/safeops/config.yaml")
	}
	cfg, err := loadConfigFlag("approvals list", args[1:])
	if err != nil {
		return err
	}
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer func() {
		_ = store.Close()
	}()
	items, err := store.List(ctx, 50)
	if err != nil {
		return err
	}
	for _, item := range items {
		fmt.Printf("%s\t%s\t%s\t%s\n", item.ID, item.UserID, item.Action, item.Status)
	}
	return nil
}

func audit(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: safeopsctl audit list --limit 20 --config /etc/safeops/config.yaml")
	}
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	limit := fs.Int("limit", 20, "Maximum number of audit events to print.")
	cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer func() {
		_ = store.Close()
	}()
	items, err := store.ListAudit(ctx, *limit)
	if err != nil {
		return err
	}
	for _, item := range items {
		fmt.Printf("%s\t%s\t%s\t%s\t%s\n", item.Timestamp.Format("2006-01-02T15:04:05Z07:00"), item.UserID, item.EventType, item.Action, item.Status)
	}
	return nil
}

func loadConfigFlag(name string, args []string) (config.Config, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, err
	}
	return config.Load(*cfgPath)
}
