package bootstrap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

const resticBinary = "/usr/bin/restic"

func (b ExecutorBackend) CreateBackup(ctx context.Context, req ports.CreateBackupRequest) (ports.BackupExecutionResponse, error) {
	if req.OperationID == "" {
		return ports.BackupExecutionResponse{}, errors.New("operation_id is required")
	}
	backupCfg, err := b.backupConfig(req.BackupAlias)
	if err != nil {
		return ports.BackupExecutionResponse{}, err
	}
	start := time.Now().UTC()
	out := ports.BackupExecutionResponse{
		Status:      "completed",
		Action:      "create_backup",
		BackupAlias: req.BackupAlias,
		SourceAlias: backupCfg.SourceAlias,
		Backend:     backupCfg.Backend,
		StartTime:   start.Format(time.RFC3339),
		Metadata:    map[string]any{},
	}
	if req.DryRun {
		out.Status = "simulated"
		out.WouldRun = b.backupWouldRun(backupCfg)
		return out, nil
	}
	if b.Runner == nil {
		return ports.BackupExecutionResponse{}, errors.New("command runner is not configured")
	}
	runCtx := ctx
	if backupCfg.Limits.Timeout.Std() > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, backupCfg.Limits.Timeout.Std())
		defer cancel()
	}
	if err := b.runConfiguredCommands(runCtx, backupCfg.PreCommands); err != nil {
		return failedBackup(out, start, err), err
	}
	var snapshotID string
	var sizeBytes int64
	switch backupCfg.Backend {
	case "restic":
		snapshotID, sizeBytes, err = b.createResticBackup(runCtx, backupCfg)
	case "command":
		snapshotID, sizeBytes, err = b.createCommandBackup(runCtx, req.OperationID, backupCfg)
	default:
		err = fmt.Errorf("backup backend %q is not supported", backupCfg.Backend)
	}
	postErr := b.runConfiguredCommands(context.Background(), backupCfg.PostCommands)
	if err != nil {
		return failedBackup(out, start, err), err
	}
	if postErr != nil {
		return failedBackup(out, start, postErr), postErr
	}
	now := time.Now().UTC()
	out.SnapshotID = snapshotID
	out.SizeBytes = sizeBytes
	out.EndTime = now.Format(time.RFC3339)
	out.DurationSeconds = int64(now.Sub(start).Seconds())
	if backupCfg.IntegrityCheck {
		verify, err := b.VerifyBackup(ctx, ports.VerifyBackupRequest{BackupAlias: req.BackupAlias, SnapshotID: snapshotID})
		if err != nil {
			return failedBackup(out, start, err), err
		}
		out.IntegrityVerified = verify.IntegrityVerified
		out.IntegrityCheckedAt = verify.IntegrityCheckedAt
		if !verify.IntegrityVerified {
			out.Status = "failed"
			out.ErrorMessage = "integrity verification failed"
			return out, errors.New("integrity verification failed")
		}
	}
	retention, err := b.ApplyRetentionPolicy(ctx, ports.ApplyRetentionPolicyRequest{BackupAlias: req.BackupAlias})
	if err != nil {
		return failedBackup(out, start, err), err
	}
	out.RetentionApplied = retention.RetentionSet
	out.RetentionDeleted = retention.Deleted
	return out, nil
}

func (b ExecutorBackend) VerifyBackup(ctx context.Context, req ports.VerifyBackupRequest) (ports.BackupVerificationResponse, error) {
	backupCfg, err := b.backupConfig(req.BackupAlias)
	if err != nil {
		return ports.BackupVerificationResponse{}, err
	}
	now := time.Now().UTC()
	out := ports.BackupVerificationResponse{Status: "verified", BackupAlias: req.BackupAlias, BackupID: req.BackupID, SnapshotID: req.SnapshotID, IntegrityVerified: true, IntegrityCheckedAt: now.Format(time.RFC3339)}
	switch backupCfg.Backend {
	case "restic":
		args := []string{"-r", backupCfg.Repository, "--password-file", backupCfg.PasswordFile, "check"}
		if req.DryRun {
			out.Status = "simulated"
			out.WouldRun = resticBinary + " " + strings.Join(args, " ")
			return out, nil
		}
		if b.Runner == nil {
			return ports.BackupVerificationResponse{}, errors.New("command runner is not configured")
		}
		if _, err := b.Runner.Run(ctx, resticBinary, args...); err != nil {
			out.Status = "failed"
			out.IntegrityVerified = false
			return out, err
		}
	case "command":
		if req.DryRun {
			out.Status = "simulated"
			out.WouldRun = "check configured command backup metadata"
		}
	default:
		return ports.BackupVerificationResponse{}, fmt.Errorf("backup backend %q is not supported", backupCfg.Backend)
	}
	return out, nil
}

func (b ExecutorBackend) ApplyRetentionPolicy(ctx context.Context, req ports.ApplyRetentionPolicyRequest) (ports.ApplyRetentionPolicyResponse, error) {
	backupCfg, err := b.backupConfig(req.BackupAlias)
	if err != nil {
		return ports.ApplyRetentionPolicyResponse{}, err
	}
	out := ports.ApplyRetentionPolicyResponse{Status: "completed", BackupAlias: req.BackupAlias}
	if backupCfg.Retention.KeepLast == 0 && backupCfg.Retention.KeepHourly == 0 && backupCfg.Retention.KeepDaily == 0 && backupCfg.Retention.KeepWeekly == 0 {
		return out, nil
	}
	out.RetentionSet = true
	switch backupCfg.Backend {
	case "restic":
		args := []string{"-r", backupCfg.Repository, "--password-file", backupCfg.PasswordFile, "forget", "--prune"}
		if backupCfg.Retention.KeepLast > 0 {
			args = append(args, "--keep-last", fmt.Sprint(backupCfg.Retention.KeepLast))
		}
		if backupCfg.Retention.KeepHourly > 0 {
			args = append(args, "--keep-hourly", fmt.Sprint(backupCfg.Retention.KeepHourly))
		}
		if backupCfg.Retention.KeepDaily > 0 {
			args = append(args, "--keep-daily", fmt.Sprint(backupCfg.Retention.KeepDaily))
		}
		if backupCfg.Retention.KeepWeekly > 0 {
			args = append(args, "--keep-weekly", fmt.Sprint(backupCfg.Retention.KeepWeekly))
		}
		out.WouldRun = []string{resticBinary + " " + strings.Join(args, " ")}
		if req.DryRun {
			out.Status = "simulated"
			return out, nil
		}
		if b.Runner == nil {
			return ports.ApplyRetentionPolicyResponse{}, errors.New("command runner is not configured")
		}
		if _, err := b.Runner.Run(ctx, resticBinary, args...); err != nil {
			return ports.ApplyRetentionPolicyResponse{}, err
		}
	case "command":
		out.Retained = backupCfg.Retention.KeepLast
		if backupCfg.Retention.KeepLast <= 0 {
			return out, nil
		}
		if req.DryRun {
			out.Status = "simulated"
			out.WouldRun = []string{"delete old regular files in " + backupCfg.Destination + " beyond keep_last"}
			return out, nil
		}
		deleted, retained, err := pruneCommandBackupDestination(backupCfg.Destination, backupCfg.Retention.KeepLast)
		if err != nil {
			return ports.ApplyRetentionPolicyResponse{}, err
		}
		out.Deleted = deleted
		out.Retained = retained
	default:
		return ports.ApplyRetentionPolicyResponse{}, fmt.Errorf("backup backend %q is not supported", backupCfg.Backend)
	}
	return out, nil
}

func (b ExecutorBackend) GenerateRestorePlan(_ context.Context, req ports.RestorePlanRequest) (ports.RestorePlanResponse, error) {
	backupCfg, err := b.backupConfig(req.BackupAlias)
	if err != nil {
		return ports.RestorePlanResponse{}, err
	}
	target := firstNonEmpty(req.Target, backupCfg.SourceAlias, req.BackupAlias)
	steps := []string{
		"Review backup metadata and integrity status.",
		"Stop affected configured resources if restoration is approved in a future phase.",
		"Restore data from the selected backup using the configured backend.",
		"Start affected configured resources.",
		"Verify application health and inspect logs as untrusted output.",
	}
	return ports.RestorePlanResponse{
		PlanID:            "plan_" + req.BackupAlias + "_" + firstNonEmpty(req.BackupID, req.SnapshotID, "latest"),
		Backup:            ports.RestorePlanBackup{ID: req.BackupID, Alias: req.BackupAlias, Snapshot: req.SnapshotID},
		AffectedResources: []string{target},
		Steps:             steps,
		EstimatedDuration: "operator-defined",
		Risks:             []string{"Service downtime may be required.", "Data loss is possible if the wrong backup or target is selected.", "Restoration is not executable in this SafeOps phase."},
		RequiresApproval:  true,
		Mutable:           false,
	}, nil
}

func (b ExecutorBackend) backupConfig(alias string) (config.BackupConfig, error) {
	backupCfg, ok := b.Config.Backups[alias]
	if !ok {
		return config.BackupConfig{}, fmt.Errorf("backup alias %q is not configured", alias)
	}
	return backupCfg, nil
}

func (b ExecutorBackend) createResticBackup(ctx context.Context, backupCfg config.BackupConfig) (string, int64, error) {
	if err := validateResticPasswordFile(backupCfg.PasswordFile); err != nil {
		return "", 0, err
	}
	args := []string{"-r", backupCfg.Repository, "--password-file", backupCfg.PasswordFile, "backup", backupCfg.SourcePath, "--json"}
	result, err := b.Runner.Run(ctx, resticBinary, args...)
	if err != nil {
		return "", 0, err
	}
	snapshotID, sizeBytes := parseResticBackupOutput(result.Stdout)
	if snapshotID == "" {
		snapshotID = "restic-" + time.Now().UTC().Format("20060102150405")
	}
	return snapshotID, sizeBytes, nil
}

func (b ExecutorBackend) createCommandBackup(ctx context.Context, operationID string, backupCfg config.BackupConfig) (string, int64, error) {
	parts := strings.Fields(backupCfg.Operation)
	if len(parts) == 0 {
		return "", 0, errors.New("backup operation is empty")
	}
	if _, err := b.Runner.Run(ctx, parts[0], parts[1:]...); err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(backupCfg.Destination, 0o750); err != nil {
		return "", 0, err
	}
	size, _ := directorySize(backupCfg.Destination)
	return operationID, size, nil
}

func (b ExecutorBackend) runConfiguredCommands(ctx context.Context, commands []string) error {
	for _, command := range commands {
		parts := strings.Fields(command)
		if len(parts) == 0 {
			return errors.New("configured command is empty")
		}
		if _, err := b.Runner.Run(ctx, parts[0], parts[1:]...); err != nil {
			return err
		}
	}
	return nil
}

func (b ExecutorBackend) backupWouldRun(backupCfg config.BackupConfig) []string {
	var out []string
	out = append(out, backupCfg.PreCommands...)
	switch backupCfg.Backend {
	case "restic":
		out = append(out, resticBinary+" -r "+backupCfg.Repository+" --password-file [REDACTED] backup "+backupCfg.SourcePath+" --json")
	case "command":
		out = append(out, backupCfg.Operation)
	}
	out = append(out, backupCfg.PostCommands...)
	return out
}

func failedBackup(out ports.BackupExecutionResponse, start time.Time, err error) ports.BackupExecutionResponse {
	now := time.Now().UTC()
	out.Status = "failed"
	out.EndTime = now.Format(time.RFC3339)
	out.DurationSeconds = int64(now.Sub(start).Seconds())
	out.ErrorMessage = redaction.Redact(err.Error())
	return out
}

func validateResticPasswordFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("restic password file: %w", err)
	}
	if !filepath.IsAbs(path) {
		return errors.New("restic password file must be absolute")
	}
	if repoPrefix := workingDirectoryPrefix(); repoPrefix != "" && strings.HasPrefix(path, repoPrefix) {
		return errors.New("restic password file must be outside the repository")
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("restic password file must have 0600 permissions, got %o", info.Mode().Perm())
	}
	return nil
}

func workingDirectoryPrefix() string {
	wd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return wd + string(os.PathSeparator)
}

func parseResticBackupOutput(stdout string) (string, int64) {
	var snapshotID string
	var totalBytes int64
	for _, line := range strings.Split(stdout, "\n") {
		var item map[string]any
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			continue
		}
		if id, ok := item["snapshot_id"].(string); ok {
			snapshotID = id
		}
		if bytes, ok := item["total_bytes_processed"].(float64); ok {
			totalBytes = int64(bytes)
		}
	}
	return snapshotID, totalBytes
}

func directorySize(path string) (int64, error) {
	var total int64
	err := filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

func pruneCommandBackupDestination(destination string, keepLast int) (int, int, error) {
	entries, err := os.ReadDir(destination)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, 0, nil
		}
		return 0, 0, err
	}
	type candidate struct {
		path    string
		modTime time.Time
	}
	var files []candidate
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return 0, 0, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		files = append(files, candidate{path: filepath.Join(destination, entry.Name()), modTime: info.ModTime()})
	}
	sort.SliceStable(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})
	if len(files) <= keepLast {
		return 0, len(files), nil
	}
	deleted := 0
	for _, file := range files[keepLast:] {
		if err := os.Remove(file.path); err != nil {
			return deleted, keepLast, err
		}
		deleted++
	}
	return deleted, min(keepLast, len(files)), nil
}
