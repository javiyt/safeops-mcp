package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sort"

	podmanadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/podman"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
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
		return fmt.Errorf("usage: safeopsctl <validate-config|migrate|approvals|audit|podman|containers> [args]")
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
	case "podman":
		return podman(ctx, args[1:])
	case "containers":
		return containers(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func podman(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return fmt.Errorf("usage: safeopsctl podman check --config /etc/safeops/config.yaml")
	}
	cfg, err := loadConfigFlag("podman check", args[1:])
	if err != nil {
		return err
	}
	if !cfg.Podman.Enabled {
		return fmt.Errorf("podman is not enabled")
	}
	if _, err := os.Stat(cfg.Podman.Binary); err != nil {
		return fmt.Errorf("podman binary: %w", err)
	}
	runner := process.CommandRunner{Timeout: cfg.Limits.OperationTimeout.Std(), MaxBytes: cfg.Limits.MaxToolOutputBytes}
	version, err := runner.Run(ctx, cfg.Podman.Binary, "version", "--format", "json")
	if err != nil {
		return err
	}
	current, _ := user.Current()
	fmt.Printf("binary\t%s\n", cfg.Podman.Binary)
	fmt.Printf("mode\t%s\n", cfg.Podman.Mode)
	fmt.Printf("systemd_scope\t%s\n", cfg.Podman.SystemdScope)
	if current != nil {
		fmt.Printf("user\t%s\n", current.Username)
	}
	if cfg.Podman.SystemdScope == "user" {
		fmt.Printf("XDG_RUNTIME_DIR\t%s\n", os.Getenv("XDG_RUNTIME_DIR"))
		if loginctl, err := exec.LookPath("loginctl"); err == nil && current != nil {
			if out, err := runner.Run(ctx, loginctl, "show-user", current.Username, "--property=Linger", "--value"); err == nil {
				fmt.Printf("linger\t%s\n", out.Stdout)
			}
		}
	}
	fmt.Printf("version_json_bytes\t%d\n", len(version.Stdout))
	client := podmanadapter.Client{Binary: cfg.Podman.Binary, Runner: runner}
	for alias, ctr := range cfg.Containers {
		st, err := client.InspectContainer(ctx, alias, ctr.ContainerName, ctr.Management)
		if err != nil {
			fmt.Printf("container\t%s\terror\t%s\n", alias, err)
			continue
		}
		fmt.Printf("container\t%s\texists=%t\tstate=%s\thealth=%s\n", alias, st.Exists, st.State, st.Health)
	}
	return nil
}

func containers(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: safeopsctl containers <list|status> [args]")
	}
	configArgs := args[1:]
	alias := ""
	if args[0] == "status" {
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl containers status <alias> --config /etc/safeops/config.yaml")
		}
		alias = args[1]
		configArgs = args[2:]
	}
	cfg, _, err := loadConfigFlagAfter("containers "+args[0], configArgs)
	if err != nil {
		return err
	}
	if !cfg.Podman.Enabled {
		return fmt.Errorf("podman is not enabled")
	}
	runner := process.CommandRunner{Timeout: cfg.Limits.OperationTimeout.Std(), MaxBytes: cfg.Limits.MaxToolOutputBytes}
	client := podmanadapter.Client{Binary: cfg.Podman.Binary, Runner: runner}
	switch args[0] {
	case "list":
		aliases := make([]string, 0, len(cfg.Containers))
		for alias := range cfg.Containers {
			aliases = append(aliases, alias)
		}
		sort.Strings(aliases)
		for _, alias := range aliases {
			ctr := cfg.Containers[alias]
			st, err := client.InspectContainer(ctx, alias, ctr.ContainerName, ctr.Management)
			if err != nil {
				fmt.Printf("%s\t%s\terror\t%s\n", alias, ctr.Management, err)
				continue
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", alias, ctr.Management, st.State, st.Health)
		}
		return nil
	case "status":
		ctr, ok := cfg.Containers[alias]
		if !ok {
			return fmt.Errorf("container alias %q is not configured", alias)
		}
		st, err := client.InspectContainer(ctx, alias, ctr.ContainerName, ctr.Management)
		if err != nil {
			return err
		}
		fmt.Printf("alias\t%s\nmanagement\t%s\nexists\t%t\nstate\t%s\nhealth\t%s\nimage\t%s\npid\t%d\n", st.Alias, st.Management, st.Exists, st.State, st.Health, st.Image, st.PID)
		return nil
	default:
		return fmt.Errorf("unknown containers command %q", args[0])
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
	cfg, _, err := loadConfigFlagAfter(name, args)
	return cfg, err
}

func loadConfigFlagAfter(name string, args []string) (config.Config, []string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	if err := fs.Parse(args); err != nil {
		return config.Config{}, nil, err
	}
	cfg, err := config.Load(*cfgPath)
	return cfg, fs.Args(), err
}
