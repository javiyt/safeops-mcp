package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/configuredprocess"
	cpuadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/cpu"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/diskhealth"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/memory"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/network"
	podmanadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/podman"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/timestatus"
	sqlitestore "github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
	"github.com/javiyt/safeops-mcp/internal/bootstrap"
	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

var (
	currentUser   = user.Current
	lookPath      = exec.LookPath
	outputf       = fmt.Printf
	systemctlPath = "/usr/bin/systemctl"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: safeopsctl <validate-config|migrate|approvals|audit|podman|containers|diagnostics> [args]")
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
	case "diagnostics":
		return diagnostics(ctx, args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func diagnostics(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: safeopsctl diagnostics <cpu|memory|disk|network|time|processes|health-summary> [disk-alias] [--json] --config /etc/safeops/config.yaml")
	}
	sub := args[0]
	configArgs := args[1:]
	diskAlias := ""
	if sub == "disk" && len(args) > 1 && !strings.HasPrefix(args[1], "-") {
		diskAlias = args[1]
		configArgs = args[2:]
	}
	fs := flag.NewFlagSet("diagnostics "+sub, flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "Print JSON output.")
	cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	if err := fs.Parse(configArgs); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	runner := process.CommandRunner{Timeout: cfg.Limits.OperationTimeout.Std(), MaxBytes: cfg.Limits.MaxToolOutputBytes}
	cpuReader := cpuadapter.Reader{Config: cfg}
	backend := bootstrap.ExecutorBackend{
		Config:      cfg,
		CPU:         cpuReader,
		Memory:      memory.Reader{Config: cfg},
		DiskHealthR: diskhealth.Reader{Config: cfg},
		Network:     network.Reader{Config: cfg, Runner: runner},
		Time:        timestatus.Reader{Config: cfg, Runner: runner},
		Processes:   configuredprocess.Reader{CPU: cpuReader},
	}
	var out any
	switch sub {
	case "cpu":
		out, err = backend.CPUStatus(ctx)
	case "memory":
		out, err = backend.MemoryStatus(ctx)
	case "disk":
		out, err = backend.DiskHealth(ctx, diskAlias)
	case "network":
		out, err = backend.NetworkStatus(ctx)
	case "time":
		out, err = backend.TimeStatus(ctx)
	case "processes":
		out, err = backend.ConfiguredProcessStatus(ctx)
	case "health-summary":
		out, err = backend.HostHealthSummary(ctx)
	default:
		return fmt.Errorf("unknown diagnostics command %q", sub)
	}
	if err != nil {
		return err
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	return printDiagnostic(sub, out)
}

func printDiagnostic(sub string, out any) error {
	switch v := out.(type) {
	case ports.CPUStatus:
		fmt.Printf("usage_percent\t%.1f\nload_average\t%v\nfrequency_mhz\t%d\n", v.UsagePercent, v.LoadAverage, v.FrequencyMHz)
	case ports.MemoryStatus:
		fmt.Printf("total_mb\t%d\navailable_mb\t%d\nused_mb\t%d\nswap_used_mb\t%d\npressure\t%.2f\n", v.TotalMB, v.AvailableMB, v.UsedMB, v.SwapUsedMB, v.MemoryPressure)
	case ports.DiskHealth:
		for _, d := range v.Disks {
			fmt.Printf("%s\t%s\tusage=%.1f%%\tinodes=%.1f%%\ttrend=%s\n", d.Name, d.Mount, d.UsagePercent, d.InodesPercent, d.Trend)
		}
	case ports.NetworkStatus:
		for _, iface := range v.Interfaces {
			fmt.Printf("%s\t%s\tip=%s\terrors=%d\tdropped=%d\n", iface.Name, iface.State, iface.IP, iface.Errors, iface.Dropped)
		}
		for _, conn := range v.Connectivity {
			fmt.Printf("connectivity\t%s\treachable=%t\n", conn.Target, conn.Reachable)
		}
	case ports.TimeStatus:
		fmt.Printf("current_time\t%s\ntimezone\t%s\tntp_synchronized\t%t\tservice_status\t%s\n", v.CurrentTime, v.Timezone, v.NTPSynchronized, v.ServiceStatus)
	case ports.ConfiguredProcessStatus:
		for _, p := range v.Processes {
			fmt.Printf("%s\tpid=%d\tstatus=%s\tname=%s\n", p.Alias, p.PID, p.Status, p.Name)
		}
	case ports.HostHealthSummary:
		fmt.Printf("status\t%s\ntimestamp\t%s\n", v.Status, v.Timestamp)
		for _, f := range v.Findings {
			fmt.Printf("%s\t%s\t%s\t%s\n", f.Severity, f.Code, f.Resource, f.Message)
		}
	default:
		return fmt.Errorf("unsupported diagnostic output for %s", sub)
	}
	return nil
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
	current, _ := currentUser()
	if err := podmanCheckPrintf("binary\t%s\n", cfg.Podman.Binary); err != nil {
		return err
	}
	if err := podmanCheckPrintf("mode\t%s\n", cfg.Podman.Mode); err != nil {
		return err
	}
	if err := podmanCheckPrintf("systemd_scope\t%s\n", cfg.Podman.SystemdScope); err != nil {
		return err
	}
	if current != nil {
		if err := podmanCheckPrintf("user\t%s\n", current.Username); err != nil {
			return err
		}
	}
	if cfg.Podman.SystemdScope == "user" {
		xdgSet := os.Getenv("XDG_RUNTIME_DIR") != ""
		if err := podmanCheckPrintf("xdg_runtime_dir_set\t%t\n", xdgSet); err != nil {
			return err
		}
		if !xdgSet {
			return fmt.Errorf("XDG_RUNTIME_DIR is required for user-scoped Quadlets")
		}
		if _, err := runner.Run(ctx, systemctlPath, "--user", "show-environment"); err != nil {
			return fmt.Errorf("systemctl --user access: %w", err)
		}
		if err := podmanCheckPrintf("systemctl_user_access\tok\n"); err != nil {
			return err
		}
		if loginctl, err := lookPath("loginctl"); err == nil && current != nil {
			if out, err := runner.Run(ctx, loginctl, "show-user", current.Username, "--property=Linger", "--value"); err == nil {
				if err := podmanCheckPrintf("linger\t%s\n", strings.TrimSpace(out.Stdout)); err != nil {
					return err
				}
			}
		}
	}
	if err := podmanCheckPrintf("version_json_bytes\t%d\n", len(version.Stdout)); err != nil {
		return err
	}
	client := podmanadapter.Client{Binary: cfg.Podman.Binary, Runner: runner}
	for alias, ctr := range cfg.Containers {
		st, err := client.InspectContainer(ctx, alias, ctr.ContainerName, ctr.Management)
		if err != nil {
			if err := podmanCheckPrintf("container\t%s\terror\t%s\n", alias, redaction.Redact(err.Error())); err != nil {
				return err
			}
			continue
		}
		if err := podmanCheckPrintf("container\t%s\texists=%t\tstate=%s\thealth=%s\n", alias, st.Exists, st.State, st.Health); err != nil {
			return err
		}
	}
	return nil
}

func podmanCheckPrintf(format string, args ...any) error {
	_, err := outputf(format, args...)
	return err
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
