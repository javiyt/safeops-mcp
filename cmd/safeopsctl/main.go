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
	"time"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/executorclient"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/configuredprocess"
	cpuadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/cpu"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/diskhealth"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/memory"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/network"
	podmanadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/podman"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/timestatus"
	sqlitestore "github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
	"github.com/javiyt/safeops-mcp/internal/application/alerts"
	"github.com/javiyt/safeops-mcp/internal/bootstrap"
	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/backup"
	"github.com/javiyt/safeops-mcp/internal/domain/deployment"
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
		return fmt.Errorf("usage: safeopsctl <validate-config|migrate|approvals|audit|alerts|podman|containers|diagnostics|app|backups|groups|logs|cache|records|reset-failed|reboot> [args]")
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
	case "alerts":
		return alertCommand(ctx, args[1:])
	case "podman":
		return podman(ctx, args[1:])
	case "containers":
		return containers(ctx, args[1:])
	case "diagnostics":
		return diagnostics(ctx, args[1:])
	case "app":
		return appCommand(ctx, args[1:])
	case "backups":
		return backupCommand(ctx, args[1:])
	case "groups", "logs", "cache", "records", "reset-failed", "reboot":
		return maintenance(ctx, args)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func backupCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: safeopsctl backups <list|status|history|create|restore-plan|verify> [args]")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("backups list", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		alias := fs.String("alias", "", "Backup alias.")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store, err := backupStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = store.Close() }()
		items, err := store.ListBackups(ctx, backup.ListFilter{BackupAlias: *alias}, 100)
		return printJSON(map[string]any{"backups": items, "total": len(items)}, err)
	case "status":
		fs := flag.NewFlagSet("backups status", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		alias := fs.String("alias", "", "Backup alias.")
		id := fs.String("id", "", "Backup ID.")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store, err := backupStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = store.Close() }()
		var record backup.Record
		if *id != "" {
			record, err = store.GetBackup(ctx, *id)
		} else {
			record, err = store.LatestBackup(ctx, *alias)
		}
		return printJSON(record, err)
	case "history":
		fs := flag.NewFlagSet("backups history", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		alias := fs.String("alias", "", "Backup alias.")
		limit := fs.Int("limit", 10, "Maximum records.")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store, err := backupStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = store.Close() }()
		items, err := store.ListBackups(ctx, backup.ListFilter{BackupAlias: *alias}, *limit)
		return printJSON(map[string]any{"history": items}, err)
	case "create":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl backups create <alias> [--reason text] [--dry-run] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("backups create", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		reason := fs.String("reason", "", "Reason for audit context.")
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		_ = reason
		out, err := executorClient(cfg).CreateBackup(ctx, ports.CreateBackupRequest{BackupAlias: args[1], OperationID: "safeopsctl", TriggeredBy: cfg.Identity.AdministratorID, DryRun: *dryRun})
		if err == nil && !*dryRun {
			err = appendCLIBackup(ctx, cfg, out)
		}
		return printJSON(out, err)
	case "restore-plan":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl backups restore-plan <alias> --id backup-001 [--target resource] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("backups restore-plan", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		id := fs.String("id", "", "Backup ID.")
		target := fs.String("target", "", "Optional target resource alias.")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *id == "" {
			return fmt.Errorf("--id is required")
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		store, err := backupStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() { _ = store.Close() }()
		record, err := store.GetBackup(ctx, *id)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).GenerateRestorePlan(ctx, ports.RestorePlanRequest{BackupAlias: args[1], BackupID: *id, SnapshotID: record.SnapshotID, Target: *target})
		return printJSON(out, err)
	case "verify":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl backups verify <alias> --id backup-001 --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("backups verify", flag.ContinueOnError)
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		id := fs.String("id", "", "Backup ID.")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).VerifyBackup(ctx, ports.VerifyBackupRequest{BackupAlias: args[1], BackupID: *id})
		return printJSON(out, err)
	default:
		return fmt.Errorf("unknown backups command %q", args[0])
	}
}

func appCommand(ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: safeopsctl app <version|check-update|update|rollback|history> <alias> [--config /etc/safeops/config.yaml]")
	}
	sub, alias := args[0], args[1]
	fs := flag.NewFlagSet("app "+sub, flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
	dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
	version := fs.String("version", "", "Target version from deployment history or configured source.")
	if err := fs.Parse(args[2:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	switch sub {
	case "version":
		out, err := executorClient(cfg).ApplicationVersion(ctx, ports.ApplicationVersionRequest{Application: alias})
		return printJSON(out, err)
	case "check-update":
		out, err := executorClient(cfg).CheckApplicationUpdate(ctx, ports.ApplicationVersionRequest{Application: alias})
		return printJSON(out, err)
	case "update":
		out, err := executorClient(cfg).UpdateApplication(ctx, ports.UpdateApplicationRequest{Application: alias, OperationID: "safeopsctl", TargetVersion: *version, TriggeredBy: cfg.Identity.AdministratorID, DryRun: *dryRun})
		if err == nil && !*dryRun {
			err = appendCLIHistory(ctx, cfg, alias, "update", out)
		}
		return printJSON(out, err)
	case "rollback":
		target := *version
		if target == "" {
			store, err := sqlitestore.Open(cfg.Database.Path)
			if err != nil {
				return err
			}
			defer func() { _ = store.Close() }()
			record, err := store.LatestSuccessfulDeployment(ctx, alias)
			if err != nil {
				return err
			}
			target = record.Version
		}
		out, err := executorClient(cfg).RollbackApplication(ctx, ports.RollbackApplicationRequest{Application: alias, OperationID: "safeopsctl", TargetVersion: target, TriggeredBy: cfg.Identity.AdministratorID, DryRun: *dryRun})
		if err == nil && !*dryRun {
			err = appendCLIHistory(ctx, cfg, alias, "rollback", out)
		}
		return printJSON(out, err)
	case "history":
		store, err := sqlitestore.Open(cfg.Database.Path)
		if err != nil {
			return err
		}
		defer func() { _ = store.Close() }()
		if err := store.Migrate(ctx); err != nil {
			return err
		}
		items, err := store.ListDeployments(ctx, alias, 20)
		return printJSON(map[string]any{"history": items}, err)
	default:
		return fmt.Errorf("unknown app command %q", sub)
	}
}

func appendCLIHistory(ctx context.Context, cfg config.Config, alias, deploymentType string, out ports.ApplicationDeploymentResponse) error {
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	record := deployment.HistoryRecord{
		ID:               fmt.Sprintf("dep_safeopsctl_%d", now.UnixNano()),
		ApplicationAlias: alias,
		Version:          firstNonEmptyCLI(out.CurrentVersion, out.TargetVersion),
		DeployedAt:       now,
		DeploymentType:   deploymentType,
		TriggeredBy:      cfg.Identity.AdministratorID,
		ImageDigest:      out.ImageDigest,
		CommitHash:       out.CommitHash,
		Status:           out.Status,
		PreviousVersion:  out.PreviousVersion,
		NextVersion:      out.TargetVersion,
		CreatedAt:        now,
	}
	if err := store.AppendDeployment(ctx, record); err != nil {
		return err
	}
	if app := cfg.Applications[alias]; app.Rollback.VersionsToKeep > 0 {
		return store.PruneDeployments(ctx, alias, app.Rollback.VersionsToKeep)
	}
	return nil
}

func backupStore(ctx context.Context, cfgPath string) (*sqlitestore.Store, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, err
	}
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func appendCLIBackup(ctx context.Context, cfg config.Config, out ports.BackupExecutionResponse) error {
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	if err := store.Migrate(ctx); err != nil {
		return err
	}
	now := time.Now().UTC()
	startTime, err := time.Parse(time.RFC3339, out.StartTime)
	if err != nil {
		startTime = now
	}
	var endTime *time.Time
	if out.EndTime != "" {
		parsed, err := time.Parse(time.RFC3339, out.EndTime)
		if err == nil {
			endTime = &parsed
		}
	}
	var checkedAt *time.Time
	if out.IntegrityCheckedAt != "" {
		parsed, err := time.Parse(time.RFC3339, out.IntegrityCheckedAt)
		if err == nil {
			checkedAt = &parsed
		}
	}
	status := backup.StatusCompleted
	if out.Status == "failed" {
		status = backup.StatusFailed
	}
	if out.IntegrityVerified {
		status = backup.StatusVerified
	}
	metadata, _ := json.Marshal(out.Metadata)
	return store.AppendBackup(ctx, backup.Record{
		ID:                 fmt.Sprintf("backup_safeopsctl_%d", now.UnixNano()),
		BackupAlias:        out.BackupAlias,
		SourceAlias:        out.SourceAlias,
		Backend:            out.Backend,
		SnapshotID:         out.SnapshotID,
		Status:             status,
		StartTime:          startTime,
		EndTime:            endTime,
		DurationSeconds:    out.DurationSeconds,
		SizeBytes:          out.SizeBytes,
		IntegrityVerified:  out.IntegrityVerified,
		IntegrityCheckedAt: checkedAt,
		ErrorMessage:       redaction.Redact(out.ErrorMessage),
		Metadata:           redaction.Redact(string(metadata)),
		CreatedAt:          now,
	})
}

func firstNonEmptyCLI(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func maintenance(ctx context.Context, args []string) error {
	switch args[0] {
	case "groups":
		if len(args) < 3 || args[1] != "restart" {
			return fmt.Errorf("usage: safeopsctl groups restart <group> [--dry-run] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("groups restart", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[3:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).RestartGroup(ctx, ports.RestartGroupRequest{Group: args[2], OperationID: "safeopsctl", DryRun: *dryRun})
		return printJSON(out, err)
	case "logs":
		if len(args) < 3 || args[1] != "rotate" {
			return fmt.Errorf("usage: safeopsctl logs rotate <resource> [--dry-run] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("logs rotate", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[3:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).RotateLogs(ctx, ports.RotateLogsRequest{Resource: args[2], OperationID: "safeopsctl", DryRun: *dryRun})
		return printJSON(out, err)
	case "cache":
		if len(args) < 3 || args[1] != "cleanup" {
			return fmt.Errorf("usage: safeopsctl cache cleanup <resource> [--dry-run] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("cache cleanup", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[3:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).CleanupCache(ctx, ports.CleanupCacheRequest{Resource: args[2], OperationID: "safeopsctl", DryRun: *dryRun})
		return printJSON(out, err)
	case "records":
		if len(args) < 2 || args[1] != "cleanup" {
			return fmt.Errorf("usage: safeopsctl records cleanup [--max-age 2160h] [--min-records 1000] [--dry-run] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("records cleanup", flag.ContinueOnError)
		maxAgeRaw := fs.String("max-age", "", "Maximum record age as a Go duration.")
		minRecords := fs.Int("min-records", 0, "Minimum records to keep.")
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		maxAge := cfg.AuditRetention.Std()
		if *maxAgeRaw != "" {
			maxAge, err = parseCLIDuration(*maxAgeRaw)
			if err != nil {
				return err
			}
		}
		keep := cfg.AuditMinRecords
		if *minRecords > 0 {
			keep = *minRecords
		}
		store, err := sqlitestore.Open(cfg.Database.Path)
		if err != nil {
			return err
		}
		defer func() { _ = store.Close() }()
		if err := store.Migrate(ctx); err != nil {
			return err
		}
		out, err := store.PruneRecords(ctx, time.Now().Add(-maxAge), keep, *dryRun)
		return printJSON(out, err)
	case "reset-failed":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl reset-failed <resource> [--dry-run] --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("reset-failed", flag.ContinueOnError)
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).ResetFailureState(ctx, ports.ResetFailureStateRequest{Resource: args[1], OperationID: "safeopsctl", DryRun: *dryRun})
		return printJSON(out, err)
	case "reboot":
		fs := flag.NewFlagSet("reboot", flag.ContinueOnError)
		delay := fs.String("delay", "5m", "Delay before reboot.")
		dryRun := fs.Bool("dry-run", false, "Simulate the operation.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		out, err := executorClient(cfg).RebootHost(ctx, ports.RebootHostRequest{Delay: *delay, OperationID: "safeopsctl", DryRun: *dryRun})
		return printJSON(out, err)
	default:
		return fmt.Errorf("unknown maintenance command %q", args[0])
	}
}

func printJSON(value any, err error) error {
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}

func parseCLIDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "d") {
		hours, err := time.ParseDuration(strings.TrimSuffix(raw, "d") + "h")
		if err != nil {
			return 0, err
		}
		return hours * 24, nil
	}
	return time.ParseDuration(raw)
}

func alertCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: safeopsctl alerts <list|acknowledge|silence|resolve|check> [args]")
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("alerts list", flag.ContinueOnError)
		status := fs.String("status", "", "Filter by alert status.")
		severity := fs.String("severity", "", "Filter by severity.")
		limit := fs.Int("limit", 50, "Maximum number of alerts to print.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		store, closeFn, err := openAlertStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() {
			_ = closeFn()
		}()
		items, err := store.ListAlerts(ctx, alert.ListFilter{Status: alert.Status(*status), Severity: alert.Severity(*severity)}, *limit)
		if err != nil {
			return err
		}
		for _, item := range items {
			fmt.Printf("%s\t%s\t%s\t%s\t%s\t%d\n", item.ID, item.Status, item.Severity, item.ResourceKind, item.ResourceAlias, item.Count)
		}
		return nil
	case "acknowledge":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl alerts acknowledge <alert-id> --config /etc/safeops/config.yaml")
		}
		cfg, store, closeFn, err := loadAlertCommand(ctx, "alerts acknowledge", args[2:])
		if err != nil {
			return err
		}
		defer func() {
			_ = closeFn()
		}()
		a, err := store.AcknowledgeAlert(ctx, args[1], cfg.Identity.AdministratorID, time.Now().UTC())
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\n", a.ID, a.Status)
		return nil
	case "silence":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl alerts silence <alert-id> --duration 1h --config /etc/safeops/config.yaml")
		}
		fs := flag.NewFlagSet("alerts silence", flag.ContinueOnError)
		duration := fs.String("duration", "", "Silence duration.")
		cfgPath := fs.String("config", "/etc/safeops/config.yaml", "Path to the SafeOps configuration file.")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *duration == "" {
			return fmt.Errorf("--duration is required")
		}
		d, err := time.ParseDuration(*duration)
		if err != nil || d <= 0 {
			return fmt.Errorf("--duration must be a positive Go duration such as 1h")
		}
		store, closeFn, err := openAlertStore(ctx, *cfgPath)
		if err != nil {
			return err
		}
		defer func() {
			_ = closeFn()
		}()
		now := time.Now().UTC()
		a, err := store.SilenceAlert(ctx, args[1], now.Add(d), now)
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\t%s\n", a.ID, a.Status, now.Add(d).Format(time.RFC3339))
		return nil
	case "resolve":
		if len(args) < 2 {
			return fmt.Errorf("usage: safeopsctl alerts resolve <alert-id> --config /etc/safeops/config.yaml")
		}
		_, store, closeFn, err := loadAlertCommand(ctx, "alerts resolve", args[2:])
		if err != nil {
			return err
		}
		defer func() {
			_ = closeFn()
		}()
		a, err := store.ResolveAlert(ctx, args[1], time.Now().UTC())
		if err != nil {
			return err
		}
		fmt.Printf("%s\t%s\n", a.ID, a.Status)
		return nil
	case "check":
		cfg, err := loadConfigFlag("alerts check", args[1:])
		if err != nil {
			return err
		}
		if !cfg.Alerts.Enabled {
			return fmt.Errorf("alerts are disabled")
		}
		store, err := sqlitestore.Open(cfg.Database.Path)
		if err != nil {
			return err
		}
		defer func() {
			_ = store.Close()
		}()
		if err := store.Migrate(ctx); err != nil {
			return err
		}
		svc := alerts.Service{
			Config:   cfg,
			Executor: executorClient(cfg),
			Alerts:   store,
			Audit:    store,
			Clock:    bootstrap.SystemClock{},
		}
		return svc.RunOnce(ctx)
	default:
		return fmt.Errorf("unknown alerts command %q", args[0])
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

func openAlertStore(ctx context.Context, cfgPath string) (*sqlitestore.Store, func() error, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return nil, nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return nil, nil, err
	}
	return store, store.Close, nil
}

func loadAlertCommand(ctx context.Context, name string, args []string) (config.Config, *sqlitestore.Store, func() error, error) {
	cfg, err := loadConfigFlag(name, args)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	store, err := sqlitestore.Open(cfg.Database.Path)
	if err != nil {
		return config.Config{}, nil, nil, err
	}
	if err := store.Migrate(ctx); err != nil {
		_ = store.Close()
		return config.Config{}, nil, nil, err
	}
	return cfg, store, store.Close, nil
}

func executorClient(cfg config.Config) executorclient.Client {
	return executorclient.New(cfg.Socket.Path)
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
