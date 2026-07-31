package tools

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/action"
	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/backup"
	"github.com/javiyt/safeops-mcp/internal/domain/deployment"
	"github.com/javiyt/safeops-mcp/internal/domain/policy"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

type Service struct {
	Config      config.Config
	Executor    ports.ExecutorClient
	Approvals   ports.ApprovalRepository
	Alerts      ports.AlertRepository
	Deployments ports.DeploymentRepository
	Backups     ports.BackupRepository
	Audit       ports.AuditRepository
	Clock       ports.Clock
	IDs         ports.IDGenerator
	Codes       ports.CodeGenerator
	Policy      policy.Engine
}

type RequestRestartInput struct {
	Service string `json:"service"`
	Reason  string `json:"reason"`
}

type RequestContainerRestartInput struct {
	Container string `json:"container"`
	Reason    string `json:"reason"`
}

type RequestGroupRestartInput struct {
	Group  string `json:"group"`
	Reason string `json:"reason"`
}

type RotateConfiguredLogsInput struct {
	Resource string `json:"resource"`
	DryRun   bool   `json:"dry_run"`
	Reason   string `json:"reason"`
}

type CleanupApplicationCacheInput struct {
	Resource string `json:"resource"`
	DryRun   bool   `json:"dry_run"`
	Reason   string `json:"reason"`
}

type RemoveExpiredSafeOpsRecordsInput struct {
	MaxAge     string `json:"max_age"`
	MinRecords int    `json:"min_records"`
	DryRun     bool   `json:"dry_run"`
	Reason     string `json:"reason"`
}

type ResetFailureStateInput struct {
	Resource string `json:"resource"`
	DryRun   bool   `json:"dry_run"`
	Reason   string `json:"reason"`
}

type RequestHostRebootInput struct {
	Reason string `json:"reason"`
	Delay  string `json:"delay"`
}

type ApplicationInput struct {
	Application string `json:"application"`
}

type RequestApplicationUpdateInput struct {
	Application string `json:"application"`
	Reason      string `json:"reason"`
	Version     string `json:"version"`
}

type RequestApplicationRollbackInput struct {
	Application string `json:"application"`
	Reason      string `json:"reason"`
	Version     string `json:"version"`
}

type BackupAliasInput struct {
	BackupAlias string `json:"backup_alias"`
}

type BackupStatusInput struct {
	BackupAlias string `json:"backup_alias"`
	BackupID    string `json:"backup_id"`
}

type BackupHistoryInput struct {
	BackupAlias string `json:"backup_alias"`
	Limit       int    `json:"limit"`
}

type RequestBackupInput struct {
	BackupAlias string `json:"backup_alias"`
	Reason      string `json:"reason"`
}

type RequestRestorePlanInput struct {
	BackupAlias string `json:"backup_alias"`
	BackupID    string `json:"backup_id"`
	Target      string `json:"target"`
}

type RequestRestartOutput struct {
	Status           string         `json:"status"`
	ApprovalID       string         `json:"approval_id"`
	ConfirmationCode string         `json:"confirmation_code"`
	ExpiresAt        string         `json:"expires_at"`
	Summary          string         `json:"summary"`
	ExpectedEffect   string         `json:"expected_effect"`
	CheckResults     map[string]any `json:"check_results,omitempty"`
}

type ConfirmInput struct {
	ApprovalID       string `json:"approval_id"`
	ConfirmationCode string `json:"confirmation_code"`
}

type ConfirmOutput struct {
	Status         string                       `json:"status"`
	Action         string                       `json:"action"`
	ResourceKind   string                       `json:"resource_kind,omitempty"`
	Resource       string                       `json:"resource,omitempty"`
	Service        string                       `json:"service,omitempty"`
	ServiceStatus  string                       `json:"service_status,omitempty"`
	ContainerState string                       `json:"container_state,omitempty"`
	Health         *ports.ContainerHealthResult `json:"health,omitempty"`
	Healthcheck    *ports.HealthcheckResult     `json:"healthcheck,omitempty"`
	WouldRun       string                       `json:"would_run,omitempty"`
	Result         any                          `json:"result,omitempty"`
}

type ListAlertsInput struct {
	Status   string `json:"status"`
	Severity string `json:"severity"`
	Limit    int    `json:"limit"`
}

type AcknowledgeAlertInput struct {
	AlertID string `json:"alert_id"`
}

type SilenceAlertInput struct {
	AlertID  string `json:"alert_id"`
	Duration string `json:"duration"`
}

func (s Service) SystemStatus(ctx context.Context) (ports.SystemStatus, error) {
	return s.Executor.SystemStatus(ctx)
}

func (s Service) DiskStatus(ctx context.Context, alias string) (ports.DiskStatus, error) {
	if _, ok := s.Config.Filesystem.DiskPaths[alias]; !ok {
		return ports.DiskStatus{}, fmt.Errorf("disk path alias %q is not configured", alias)
	}
	return s.Executor.DiskStatus(ctx, alias)
}

func (s Service) CPUStatus(ctx context.Context, userID string) (ports.CPUStatus, error) {
	out, err := s.Executor.CPUStatus(ctx)
	if err == nil {
		for i := range out.Processes {
			out.Processes[i].Name = redaction.Redact(out.Processes[i].Name)
			out.Processes[i].Command = redaction.Redact(out.Processes[i].Command)
		}
		err = s.auditRead(ctx, userID, "cpu_status", "{}")
	}
	return out, err
}

func (s Service) MemoryStatus(ctx context.Context, userID string) (ports.MemoryStatus, error) {
	out, err := s.Executor.MemoryStatus(ctx)
	if err == nil {
		for i := range out.OOMEvents {
			out.OOMEvents[i].Process = redaction.Redact(out.OOMEvents[i].Process)
		}
		err = s.auditRead(ctx, userID, "memory_status", "{}")
	}
	return out, err
}

func (s Service) DiskHealth(ctx context.Context, userID, alias string) (ports.DiskHealth, error) {
	if alias != "" {
		if _, ok := s.Config.Filesystem.DiskPaths[alias]; !ok {
			return ports.DiskHealth{}, fmt.Errorf("disk alias %q is not configured", alias)
		}
	}
	out, err := s.Executor.DiskHealth(ctx, alias)
	if err == nil {
		args, _ := json.Marshal(map[string]string{"disk": alias})
		err = s.auditRead(ctx, userID, "disk_health", string(args))
	}
	return out, err
}

func (s Service) NetworkStatus(ctx context.Context, userID string) (ports.NetworkStatus, error) {
	out, err := s.Executor.NetworkStatus(ctx)
	if err == nil {
		err = s.auditRead(ctx, userID, "network_status", "{}")
	}
	return out, err
}

func (s Service) TimeStatus(ctx context.Context, userID string) (ports.TimeStatus, error) {
	out, err := s.Executor.TimeStatus(ctx)
	if err == nil {
		err = s.auditRead(ctx, userID, "time_status", "{}")
	}
	return out, err
}

func (s Service) ConfiguredProcessStatus(ctx context.Context, userID string) (ports.ConfiguredProcessStatus, error) {
	out, err := s.Executor.ConfiguredProcessStatus(ctx)
	if err == nil {
		for i := range out.Processes {
			out.Processes[i].Name = redaction.Redact(out.Processes[i].Name)
			out.Processes[i].Command = redaction.Redact(out.Processes[i].Command)
		}
		err = s.auditRead(ctx, userID, "configured_process_status", "{}")
	}
	return out, err
}

func (s Service) HostHealthSummary(ctx context.Context, userID string) (ports.HostHealthSummary, error) {
	out, err := s.Executor.HostHealthSummary(ctx)
	if err == nil {
		err = s.auditRead(ctx, userID, "host_health_summary", "{}")
	}
	return out, err
}

func (s Service) ListAlerts(ctx context.Context, userID string, input ListAlertsInput) (map[string][]alert.Alert, error) {
	items, err := s.Alerts.ListAlerts(ctx, alert.ListFilter{Status: alert.Status(input.Status), Severity: alert.Severity(input.Severity)}, input.Limit)
	if err == nil {
		err = s.auditRead(ctx, userID, "list_alerts", "{}")
	}
	return map[string][]alert.Alert{"alerts": items}, err
}

func (s Service) AcknowledgeAlert(ctx context.Context, userID string, input AcknowledgeAlertInput) (map[string]string, error) {
	a, err := s.Alerts.AcknowledgeAlert(ctx, input.AlertID, userID, s.Clock.Now())
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "alert_acknowledged", "acknowledge_alert", "acknowledge_alert", fmt.Sprintf(`{"alert_id":%q}`, a.ID), "read", "allow", "acknowledged", "", ""); err != nil {
		return nil, err
	}
	return map[string]string{"status": string(a.Status), "message": "Alert " + a.ID + " acknowledged."}, nil
}

func (s Service) SilenceAlert(ctx context.Context, userID string, input SilenceAlertInput) (map[string]string, error) {
	d, err := time.ParseDuration(input.Duration)
	if err != nil || d <= 0 {
		return nil, errors.New("duration must be a positive Go duration such as 1h")
	}
	now := s.Clock.Now()
	until := now.Add(d)
	a, err := s.Alerts.SilenceAlert(ctx, input.AlertID, until, now)
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "alert_silenced", "silence_alert", "silence_alert", fmt.Sprintf(`{"alert_id":%q}`, a.ID), "read", "allow", "suppressed", "", ""); err != nil {
		return nil, err
	}
	return map[string]string{"status": string(a.Status), "message": fmt.Sprintf("Alert %s silenced until %s.", a.ID, until.UTC().Format(time.RFC3339))}, nil
}

func (s Service) ListServices(ctx context.Context) ([]ports.ServiceSummary, error) {
	return s.Executor.ListServices(ctx)
}

func (s Service) ApplicationVersion(ctx context.Context, userID string, input ApplicationInput) (ports.ApplicationVersionResponse, error) {
	if !s.applicationPermission(input.Application, "check", "allow") {
		return ports.ApplicationVersionResponse{}, fmt.Errorf("application %q is not allowed for version checks", input.Application)
	}
	out, err := s.Executor.ApplicationVersion(ctx, ports.ApplicationVersionRequest{Application: input.Application})
	if err == nil {
		err = s.audit(ctx, userID, "application_version_read", "application_version", "read_application_version", fmt.Sprintf(`{"application":%q}`, input.Application), "read", "allow", "completed", "", "")
	}
	return out, err
}

func (s Service) CheckApplicationUpdate(ctx context.Context, userID string, input ApplicationInput) (ports.ApplicationUpdateCheckResponse, error) {
	if !s.applicationPermission(input.Application, "check", "allow") {
		return ports.ApplicationUpdateCheckResponse{}, fmt.Errorf("application %q is not allowed for update checks", input.Application)
	}
	out, err := s.Executor.CheckApplicationUpdate(ctx, ports.ApplicationVersionRequest{Application: input.Application})
	if err == nil {
		err = s.audit(ctx, userID, "application_update_checked", "check_application_update", "check_application_update", fmt.Sprintf(`{"application":%q}`, input.Application), "read", "allow", "completed", "", "")
	}
	return out, err
}

func (s Service) RequestApplicationUpdate(ctx context.Context, userID string, input RequestApplicationUpdateInput) (RequestRestartOutput, error) {
	if !s.applicationPermission(input.Application, "update", "confirm") {
		return RequestRestartOutput{}, fmt.Errorf("application %q does not permit update requests", input.Application)
	}
	check, err := s.Executor.CheckApplicationUpdate(ctx, ports.ApplicationVersionRequest{Application: input.Application})
	if err != nil {
		return RequestRestartOutput{}, err
	}
	if input.Version != "" && input.Version != check.AvailableVersion {
		return RequestRestartOutput{}, fmt.Errorf("requested version %q is not the configured available version", input.Version)
	}
	extra := map[string]any{
		"current_version": check.CurrentVersion,
		"target_version":  firstNonEmpty(input.Version, check.AvailableVersion),
		"target_digest":   check.AvailableDigest,
		"target_commit":   check.AvailableCommit,
	}
	return s.requestApproval(ctx, userID, "request_application_update", action.TypeUpdateApplication, action.ResourceApplication, input.Application, input.Reason, extra, "high", "Update application "+input.Application, "The application workload will restart and may be unavailable for a few seconds.")
}

func (s Service) RequestApplicationRollback(ctx context.Context, userID string, input RequestApplicationRollbackInput) (RequestRestartOutput, error) {
	app, ok := s.Config.Applications[input.Application]
	if !ok || !app.Rollback.Enabled {
		return RequestRestartOutput{}, fmt.Errorf("application %q does not enable rollback", input.Application)
	}
	if !s.applicationPermission(input.Application, "rollback", "confirm") {
		return RequestRestartOutput{}, fmt.Errorf("application %q does not permit rollback requests", input.Application)
	}
	if s.Deployments == nil {
		return RequestRestartOutput{}, errors.New("deployment history repository is not configured")
	}
	target := deployment.HistoryRecord{}
	if input.Version != "" {
		history, err := s.Deployments.ListDeployments(ctx, input.Application, 50)
		if err != nil {
			return RequestRestartOutput{}, err
		}
		for _, record := range history {
			if record.Status == "success" && record.Version == input.Version {
				target = record
				break
			}
		}
		if target.ID == "" {
			return RequestRestartOutput{}, fmt.Errorf("version %q is not recorded for rollback", input.Version)
		}
	} else {
		record, err := s.Deployments.LatestSuccessfulDeployment(ctx, input.Application)
		if err != nil {
			return RequestRestartOutput{}, err
		}
		target = record
	}
	extra := map[string]any{"target_version": target.Version, "target_digest": target.ImageDigest, "target_commit": target.CommitHash}
	return s.requestApproval(ctx, userID, "request_application_rollback", action.TypeRollbackApplication, action.ResourceApplication, input.Application, input.Reason, extra, "high", "Rollback application "+input.Application, "The application workload will restart using a previously recorded version.")
}

func (s Service) ApplicationHistory(ctx context.Context, userID string, input ApplicationInput) (map[string][]deployment.HistoryRecord, error) {
	if !s.applicationPermission(input.Application, "check", "allow") {
		return nil, fmt.Errorf("application %q is not allowed for history checks", input.Application)
	}
	if s.Deployments == nil {
		return nil, errors.New("deployment history repository is not configured")
	}
	items, err := s.Deployments.ListDeployments(ctx, input.Application, 20)
	if err == nil {
		err = s.audit(ctx, userID, "application_history_read", "application_history", "read_application_history", fmt.Sprintf(`{"application":%q}`, input.Application), "read", "allow", "completed", "", "")
	}
	return map[string][]deployment.HistoryRecord{"history": items}, err
}

func (s Service) ListBackups(ctx context.Context, userID string, input BackupAliasInput) (map[string]any, error) {
	if err := s.validateBackupConfigured(input.BackupAlias, true); err != nil {
		return nil, err
	}
	if s.Backups == nil {
		return nil, errors.New("backup repository is not configured")
	}
	items, err := s.Backups.ListBackups(ctx, backup.ListFilter{BackupAlias: input.BackupAlias}, 100)
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "backups_listed", "list_backups", "list_backups", fmt.Sprintf(`{"backup_alias":%q}`, input.BackupAlias), "read", "allow", "completed", "", ""); err != nil {
		return nil, err
	}
	return map[string]any{"backups": backupSummaries(items), "total": len(items)}, nil
}

func (s Service) BackupStatus(ctx context.Context, userID string, input BackupStatusInput) (backup.Record, error) {
	if err := s.validateBackupConfigured(input.BackupAlias, input.BackupID == ""); err != nil {
		return backup.Record{}, err
	}
	if s.Backups == nil {
		return backup.Record{}, errors.New("backup repository is not configured")
	}
	var record backup.Record
	var err error
	if input.BackupID != "" {
		record, err = s.Backups.GetBackup(ctx, input.BackupID)
	} else {
		record, err = s.Backups.LatestBackup(ctx, input.BackupAlias)
	}
	if err != nil {
		return backup.Record{}, err
	}
	if input.BackupAlias != "" && record.BackupAlias != input.BackupAlias {
		return backup.Record{}, errors.New("backup_id does not belong to backup_alias")
	}
	if err := s.audit(ctx, userID, "backup_status_read", "backup_status", "backup_status", fmt.Sprintf(`{"backup_alias":%q,"backup_id":%q}`, input.BackupAlias, input.BackupID), "read", "allow", "completed", "", ""); err != nil {
		return backup.Record{}, err
	}
	return record, nil
}

func (s Service) BackupHistory(ctx context.Context, userID string, input BackupHistoryInput) (map[string]any, error) {
	if input.Limit <= 0 || input.Limit > 100 {
		input.Limit = 20
	}
	if err := s.validateBackupConfigured(input.BackupAlias, false); err != nil {
		return nil, err
	}
	if s.Backups == nil {
		return nil, errors.New("backup repository is not configured")
	}
	items, err := s.Backups.ListBackups(ctx, backup.ListFilter{BackupAlias: input.BackupAlias}, input.Limit)
	if err != nil {
		return nil, err
	}
	if err := s.audit(ctx, userID, "backup_history_read", "backup_history", "backup_history", fmt.Sprintf(`{"backup_alias":%q,"limit":%d}`, input.BackupAlias, input.Limit), "read", "allow", "completed", "", ""); err != nil {
		return nil, err
	}
	return map[string]any{"history": items, "total": len(items)}, nil
}

func (s Service) RequestBackup(ctx context.Context, userID string, input RequestBackupInput) (RequestRestartOutput, error) {
	if err := s.validateBackupConfigured(input.BackupAlias, false); err != nil {
		return RequestRestartOutput{}, err
	}
	if s.Backups != nil {
		running, err := s.Backups.BackupInProgress(ctx, input.BackupAlias)
		if err != nil {
			return RequestRestartOutput{}, err
		}
		if running {
			return RequestRestartOutput{}, fmt.Errorf("backup %q already has a running operation", input.BackupAlias)
		}
	}
	return s.requestApproval(ctx, userID, "request_backup", action.TypeCreateBackup, action.ResourceBackup, input.BackupAlias, input.Reason, nil, "high", "Create backup "+input.BackupAlias, "The backup may take a few minutes. Configured pre and post commands may briefly stop affected resources.")
}

func (s Service) RequestRestorePlan(ctx context.Context, userID string, input RequestRestorePlanInput) (ports.RestorePlanResponse, error) {
	if err := s.validateBackupConfigured(input.BackupAlias, false); err != nil {
		return ports.RestorePlanResponse{}, err
	}
	if s.Backups == nil {
		return ports.RestorePlanResponse{}, errors.New("backup repository is not configured")
	}
	record, err := s.Backups.GetBackup(ctx, input.BackupID)
	if err != nil {
		return ports.RestorePlanResponse{}, err
	}
	if record.BackupAlias != input.BackupAlias {
		return ports.RestorePlanResponse{}, errors.New("backup_id does not belong to backup_alias")
	}
	out, err := s.Executor.GenerateRestorePlan(ctx, ports.RestorePlanRequest{BackupAlias: input.BackupAlias, BackupID: input.BackupID, SnapshotID: record.SnapshotID, Target: input.Target})
	if err != nil {
		return ports.RestorePlanResponse{}, err
	}
	out.Backup = ports.RestorePlanBackup{
		ID:        record.ID,
		Alias:     record.BackupAlias,
		Snapshot:  record.SnapshotID,
		CreatedAt: record.StartTime.UTC().Format(time.RFC3339),
		SizeGB:    float64(record.SizeBytes) / 1_073_741_824,
		Integrity: record.IntegrityVerified,
	}
	if err := s.audit(ctx, userID, "backup_restore_plan_generated", "request_restore_plan", "generate_restore_plan", fmt.Sprintf(`{"backup_alias":%q,"backup_id":%q,"target":%q}`, input.BackupAlias, input.BackupID, input.Target), "read", "allow", "completed", "", ""); err != nil {
		return ports.RestorePlanResponse{}, err
	}
	return out, nil
}

func (s Service) ServiceStatus(ctx context.Context, alias string) (any, error) {
	if !s.permission(alias, "status", "allow") {
		return nil, fmt.Errorf("service %q is not allowed for status", alias)
	}
	return s.Executor.ServiceStatus(ctx, alias)
}

func (s Service) ServiceLogs(ctx context.Context, req ports.ServiceLogsRequest) (ports.ServiceLogsResponse, error) {
	if !s.permission(req.Service, "logs", "allow") {
		return ports.ServiceLogsResponse{}, fmt.Errorf("service %q is not allowed for logs", req.Service)
	}
	if req.Lines <= 0 || req.Lines > s.Config.Limits.MaxLogLines {
		return ports.ServiceLogsResponse{}, fmt.Errorf("lines must be between 1 and %d", s.Config.Limits.MaxLogLines)
	}
	if req.Priority != "" && !allowedPriority(req.Priority) {
		return ports.ServiceLogsResponse{}, fmt.Errorf("priority %q is not allowed", req.Priority)
	}
	if req.Since != "" && !allowedSince(req.Since) {
		return ports.ServiceLogsResponse{}, fmt.Errorf("since %q is not allowed", req.Since)
	}
	out, err := s.Executor.ServiceLogs(ctx, req)
	if err != nil {
		return ports.ServiceLogsResponse{}, err
	}
	for i := range out.Entries {
		out.Entries[i].Message = redaction.Redact(out.Entries[i].Message)
	}
	out.UntrustedContent = true
	return out, nil
}

func (s Service) RequestServiceRestart(ctx context.Context, userID string, input RequestRestartInput) (RequestRestartOutput, error) {
	return s.requestRestart(ctx, userID, "request_service_restart", action.TypeRestartService, action.ResourceService, input.Service, input.Reason)
}

func (s Service) RequestContainerRestart(ctx context.Context, userID string, input RequestContainerRestartInput) (RequestRestartOutput, error) {
	return s.requestRestart(ctx, userID, "request_container_restart", action.TypeRestartContainer, action.ResourceContainer, input.Container, input.Reason)
}

func (s Service) RequestGroupRestart(ctx context.Context, userID string, input RequestGroupRestartInput) (RequestRestartOutput, error) {
	group, ok := s.Config.Groups[input.Group]
	if !ok {
		return RequestRestartOutput{}, fmt.Errorf("group %q is not configured", input.Group)
	}
	order := group.Order
	if len(order) == 0 {
		order = group.Resources
	}
	return s.requestApproval(ctx, userID, "request_group_restart", action.TypeRestartGroup, action.ResourceGroup, input.Group, input.Reason, map[string]any{"order": order}, "high", "Restart group "+input.Group, fmt.Sprintf("Resources will be unavailable for about %s.", groupTimeout(s.Config, group)))
}

func (s Service) RotateConfiguredLogs(ctx context.Context, userID string, input RotateConfiguredLogsInput) (any, error) {
	if input.DryRun {
		out, err := s.Executor.RotateLogs(ctx, ports.RotateLogsRequest{Resource: input.Resource, DryRun: true})
		if err == nil {
			err = s.audit(ctx, userID, "maintenance_simulated", "rotate_configured_logs", string(action.TypeRotateLogs), fmt.Sprintf(`{"resource":%q,"dry_run":true}`, input.Resource), "mutating", "allow", "simulated", "", "")
		}
		return out, err
	}
	return s.requestApproval(ctx, userID, "rotate_configured_logs", action.TypeRotateLogs, action.ResourceLog, input.Resource, input.Reason, nil, "medium", "Rotate configured logs", "Configured logs may be rotated, compressed, and old rotations removed.")
}

func (s Service) CleanupApplicationCache(ctx context.Context, userID string, input CleanupApplicationCacheInput) (any, error) {
	if input.DryRun {
		out, err := s.Executor.CleanupCache(ctx, ports.CleanupCacheRequest{Resource: input.Resource, DryRun: true})
		if err == nil {
			err = s.audit(ctx, userID, "maintenance_simulated", "cleanup_application_cache", string(action.TypeCleanupCache), fmt.Sprintf(`{"resource":%q,"dry_run":true}`, input.Resource), "mutating", "allow", "simulated", "", "")
		}
		return out, err
	}
	return s.requestApproval(ctx, userID, "cleanup_application_cache", action.TypeCleanupCache, action.ResourceCache, input.Resource, input.Reason, nil, "medium", "Clean application cache "+input.Resource, "Configured cache files may be removed within age, size, and timeout limits.")
}

func (s Service) RemoveExpiredSafeOpsRecords(ctx context.Context, userID string, input RemoveExpiredSafeOpsRecordsInput) (any, error) {
	maxAge, minRecords, err := s.recordsLimits(input)
	if err != nil {
		return nil, err
	}
	if input.DryRun {
		out, err := s.Approvals.PruneRecords(ctx, s.Clock.Now().Add(-maxAge), minRecords, true)
		if err == nil {
			err = s.audit(ctx, userID, "maintenance_simulated", "remove_expired_safeops_records", string(action.TypeRemoveRecords), fmt.Sprintf(`{"max_age":%q,"min_records":%d,"dry_run":true}`, maxAge.String(), minRecords), "mutating", "allow", "simulated", "", "")
		}
		return out, err
	}
	return s.requestApproval(ctx, userID, "remove_expired_safeops_records", action.TypeRemoveRecords, action.ResourceRecord, "safeops-records", input.Reason, map[string]any{"max_age": maxAge.String(), "min_records": minRecords}, "medium", "Remove expired SafeOps records", "Old audit and approval records may be deleted while keeping the configured minimum.")
}

func (s Service) ResetResourceFailureState(ctx context.Context, userID string, input ResetFailureStateInput) (any, error) {
	if _, ok := s.Config.Containers[input.Resource]; ok {
		return ports.ResetFailureStateResponse{Status: "not_applicable", ResourceKind: "container", Resource: input.Resource, ResetOperation: "none", Result: "use request_container_restart for containers"}, nil
	}
	if _, ok := s.Config.Services[input.Resource]; !ok {
		return nil, fmt.Errorf("service %q is not configured", input.Resource)
	}
	if input.DryRun {
		out, err := s.Executor.ResetFailureState(ctx, ports.ResetFailureStateRequest{Resource: input.Resource, DryRun: true})
		if err == nil {
			err = s.audit(ctx, userID, "maintenance_simulated", "reset_resource_failure_state", string(action.TypeResetFailure), fmt.Sprintf(`{"resource":%q,"dry_run":true}`, input.Resource), "mutating", "allow", "simulated", "", "")
		}
		return out, err
	}
	return s.requestApproval(ctx, userID, "reset_resource_failure_state", action.TypeResetFailure, action.ResourceFailureState, input.Resource, input.Reason, nil, "low", "Reset failure state for "+input.Resource, "The systemd failed state will be cleared for the configured service.")
}

func (s Service) RequestHostReboot(ctx context.Context, userID string, input RequestHostRebootInput) (RequestRestartOutput, error) {
	if !s.Config.HostReboot.Enabled {
		return RequestRestartOutput{}, errors.New("host reboot is disabled")
	}
	if len(s.Config.HostReboot.AllowedUsers) > 0 && !containsString(s.Config.HostReboot.AllowedUsers, userID) {
		return RequestRestartOutput{}, errors.New("user is not allowed to request host reboot")
	}
	inProgress, err := s.Approvals.CountOperationsInProgress(ctx)
	if err != nil {
		return RequestRestartOutput{}, err
	}
	if inProgress > 0 {
		return RequestRestartOutput{}, errors.New("mutable operations are currently in progress")
	}
	out, err := s.requestApprovalWithCodeLength(ctx, userID, "request_host_reboot", action.TypeRebootHost, action.ResourceHost, "host", input.Reason, map[string]any{"delay": input.Delay}, "critical", "Reboot the host.", "All services will be stopped and the system will restart.", s.Config.HostReboot.ConfirmationCodeLength, s.Config.HostReboot.ConfirmationWindow.Std())
	if err == nil {
		out.CheckResults = map[string]any{"no_operations_in_progress": true, "recent_backup_exists": !s.Config.HostReboot.RequireBackup, "backup_age": ""}
	}
	return out, err
}

func (s Service) requestRestart(ctx context.Context, userID, tool string, act action.Type, kind action.ResourceKind, alias, reason string) (RequestRestartOutput, error) {
	noun := "service"
	effect := "The service may be unavailable for a few seconds."
	if kind == action.ResourceContainer {
		noun = "container"
		effect = "The container may be unavailable for a few seconds."
	}
	return s.requestApproval(ctx, userID, tool, act, kind, alias, reason, nil, "mutating", "Restart "+noun+" "+alias, effect)
}

func (s Service) requestApproval(ctx context.Context, userID, tool string, act action.Type, kind action.ResourceKind, alias, reason string, extra map[string]any, risk, summary, effect string) (RequestRestartOutput, error) {
	return s.requestApprovalWithCodeLength(ctx, userID, tool, act, kind, alias, reason, extra, risk, summary, effect, s.Config.ConfirmationCodeLength(), s.Config.ApprovalExpiration())
}

func (s Service) requestApprovalWithCodeLength(ctx context.Context, userID, tool string, act action.Type, kind action.ResourceKind, alias, reason string, extra map[string]any, risk, summary, effect string, codeLength int, expiration time.Duration) (RequestRestartOutput, error) {
	if s.Policy.Decide(action.RiskMutating) != policy.DecisionRequireApproval {
		return RequestRestartOutput{}, errors.New("mutable policy must require approval")
	}
	if err := s.validateActionAllowed(kind, alias); err != nil {
		return RequestRestartOutput{}, err
	}
	now := s.Clock.Now()
	approvalID, err := s.IDs.NewID("apr")
	if err != nil {
		return RequestRestartOutput{}, err
	}
	code, err := s.Codes.NewCode(codeLength)
	if err != nil {
		return RequestRestartOutput{}, err
	}
	normalized, err := normalizeAction(act, kind, alias, reason, userID, s.Config.Policies.DryRun, extra)
	if err != nil {
		return RequestRestartOutput{}, err
	}
	a := approval.Approval{
		ID:                   approvalID,
		UserID:               userID,
		Tool:                 tool,
		Action:               string(act),
		ResourceKind:         string(kind),
		ResourceAlias:        alias,
		NormalizedArguments:  string(normalized),
		ArgumentsHash:        hashString(string(normalized)),
		ConfirmationCodeHash: hashString(code),
		Status:               approval.StatusPending,
		CreatedAt:            now,
		ExpiresAt:            now.Add(expiration),
	}
	if err := s.Approvals.Create(ctx, a); err != nil {
		return RequestRestartOutput{}, err
	}
	eventType := "approval_requested"
	if kind == action.ResourceContainer {
		eventType = "container_restart_requested"
	}
	if err := s.audit(ctx, userID, eventType, tool, string(act), string(normalized), risk, "require_approval", "pending", approvalID, ""); err != nil {
		return RequestRestartOutput{}, err
	}
	return RequestRestartOutput{
		Status:           "approval_required",
		ApprovalID:       approvalID,
		ConfirmationCode: code,
		ExpiresAt:        a.ExpiresAt.Format(time.RFC3339),
		Summary:          summary,
		ExpectedEffect:   effect,
	}, nil
}

func (s Service) ConfirmAction(ctx context.Context, userID string, input ConfirmInput) (ConfirmOutput, error) {
	now := s.Clock.Now()
	a, err := s.Approvals.Get(ctx, input.ApprovalID)
	if err != nil {
		return ConfirmOutput{}, err
	}
	if a.UserID != userID {
		return ConfirmOutput{}, errors.New("approval belongs to a different user")
	}
	if a.Status != approval.StatusPending {
		return ConfirmOutput{}, fmt.Errorf("approval is %s", a.Status)
	}
	if !now.Before(a.ExpiresAt) {
		return ConfirmOutput{}, errors.New("approval has expired")
	}
	if !constantEqual(hashString(input.ConfirmationCode), a.ConfirmationCodeHash) {
		return ConfirmOutput{}, errors.New("confirmation code is incorrect")
	}
	if a.ResourceKind == "" {
		a.ResourceKind = string(action.ResourceService)
	}
	if a.ResourceAlias == "" {
		var legacy map[string]any
		if err := json.Unmarshal([]byte(a.NormalizedArguments), &legacy); err != nil {
			return ConfirmOutput{}, err
		}
		if v, ok := legacy["service"].(string); ok {
			a.ResourceAlias = v
		}
	}
	if err := s.validateActionAllowed(action.ResourceKind(a.ResourceKind), a.ResourceAlias); err != nil {
		return ConfirmOutput{}, err
	}
	if err := s.validateApplicationApprovalStillAllowed(a); err != nil {
		return ConfirmOutput{}, err
	}
	extra := argumentExtra(a.NormalizedArguments)
	normalized, err := normalizeAction(action.Type(a.Action), action.ResourceKind(a.ResourceKind), a.ResourceAlias, argumentReason(a.NormalizedArguments), userID, s.Config.Policies.DryRun, extra)
	if err != nil {
		return ConfirmOutput{}, err
	}
	if !constantEqual(hashString(string(normalized)), a.ArgumentsHash) {
		return ConfirmOutput{}, errors.New("approval arguments hash does not match current action")
	}
	if _, err := s.Approvals.MarkExecuting(ctx, a.ID, now); err != nil {
		return ConfirmOutput{}, err
	}
	opID, err := s.IDs.NewID("op")
	if err != nil {
		return ConfirmOutput{}, err
	}
	lockExpiresAt := now.Add(s.Config.Limits.OperationTimeout.Std() + time.Minute)
	if err := s.Approvals.AcquireOperationLock(ctx, a.ResourceKind, a.ResourceAlias, opID, lockExpiresAt); err != nil {
		_ = s.Approvals.MarkDone(ctx, a.ID, approval.StatusFailed, "", redaction.Redact(err.Error()), s.Clock.Now())
		return ConfirmOutput{}, err
	}
	defer func() {
		_ = s.Approvals.ReleaseOperationLock(context.Background(), a.ResourceKind, a.ResourceAlias, opID)
	}()
	out, err := s.executeApproved(ctx, a, opID)
	if err == nil {
		err = s.recordDeploymentResult(ctx, userID, a, out)
	}
	if backupErr := s.recordBackupResult(ctx, a, out); backupErr != nil && err == nil {
		err = backupErr
	}
	status := approval.StatusExecuted
	errorSummary := ""
	resultSummary := string(action.Type(a.Action)) + " executed"
	if s.Config.Policies.DryRun {
		status = approval.StatusSimulated
		resultSummary = "restart simulated"
	}
	if err != nil {
		status = approval.StatusFailed
		errorSummary = redaction.Redact(err.Error())
		resultSummary = ""
	}
	if markErr := s.Approvals.MarkDone(ctx, a.ID, status, resultSummary, errorSummary, s.Clock.Now()); markErr != nil && err == nil {
		err = markErr
	}
	eventType := "approval_completed"
	if a.Action == string(action.TypeRestartContainer) {
		eventType = "container_restart_executed"
		if status == approval.StatusFailed {
			eventType = "container_restart_failed"
		}
		if status == approval.StatusSimulated {
			eventType = "container_restart_simulated"
		}
	}
	if auditErr := s.audit(ctx, userID, eventType, "confirm_action", a.Action, a.NormalizedArguments, "mutating", "require_approval", string(status), a.ID, opID); auditErr != nil {
		if err != nil {
			return ConfirmOutput{}, err
		}
		_ = s.Approvals.MarkDone(ctx, a.ID, status, resultSummary, "post-operation audit failed: "+redaction.Redact(auditErr.Error()), s.Clock.Now())
	}
	if err != nil {
		return ConfirmOutput{}, err
	}
	return confirmOutput(out), nil
}

func (s Service) executeApproved(ctx context.Context, a approval.Approval, opID string) (any, error) {
	switch action.Type(a.Action) {
	case action.TypeRestartService:
		return s.Executor.RestartService(ctx, ports.RestartServiceRequest{Service: a.ResourceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeRestartContainer:
		return s.Executor.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: a.ResourceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeRestartGroup:
		return s.Executor.RestartGroup(ctx, ports.RestartGroupRequest{Group: a.ResourceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeRotateLogs:
		return s.Executor.RotateLogs(ctx, ports.RotateLogsRequest{Resource: a.ResourceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeCleanupCache:
		return s.Executor.CleanupCache(ctx, ports.CleanupCacheRequest{Resource: a.ResourceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeRemoveRecords:
		extra := argumentExtra(a.NormalizedArguments)
		maxAge, _ := time.ParseDuration(fmt.Sprint(extra["max_age"]))
		minRecords := s.Config.AuditMinRecords
		if v, ok := extra["min_records"].(float64); ok {
			minRecords = int(v)
		}
		return s.Approvals.PruneRecords(ctx, s.Clock.Now().Add(-maxAge), minRecords, s.Config.Policies.DryRun)
	case action.TypeResetFailure:
		return s.Executor.ResetFailureState(ctx, ports.ResetFailureStateRequest{Resource: a.ResourceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeRebootHost:
		delay := ""
		if v, ok := argumentExtra(a.NormalizedArguments)["delay"].(string); ok {
			delay = v
		}
		return s.Executor.RebootHost(ctx, ports.RebootHostRequest{Delay: delay, OperationID: opID, DryRun: s.Config.Policies.DryRun})
	case action.TypeUpdateApplication:
		extra := argumentExtra(a.NormalizedArguments)
		return s.Executor.UpdateApplication(ctx, ports.UpdateApplicationRequest{
			Application:   a.ResourceAlias,
			OperationID:   opID,
			TargetVersion: stringExtra(extra, "target_version"),
			TargetDigest:  stringExtra(extra, "target_digest"),
			TargetCommit:  stringExtra(extra, "target_commit"),
			TriggeredBy:   a.UserID,
			DryRun:        s.Config.Policies.DryRun,
		})
	case action.TypeRollbackApplication:
		extra := argumentExtra(a.NormalizedArguments)
		return s.Executor.RollbackApplication(ctx, ports.RollbackApplicationRequest{
			Application:   a.ResourceAlias,
			OperationID:   opID,
			TargetVersion: stringExtra(extra, "target_version"),
			TargetDigest:  stringExtra(extra, "target_digest"),
			TargetCommit:  stringExtra(extra, "target_commit"),
			TriggeredBy:   a.UserID,
			DryRun:        s.Config.Policies.DryRun,
		})
	case action.TypeCreateBackup:
		return s.Executor.CreateBackup(ctx, ports.CreateBackupRequest{
			BackupAlias: a.ResourceAlias,
			OperationID: opID,
			TriggeredBy: a.UserID,
			DryRun:      s.Config.Policies.DryRun,
		})
	default:
		return nil, fmt.Errorf("action %q is not supported", a.Action)
	}
}

func confirmOutput(out any) ConfirmOutput {
	switch v := out.(type) {
	case ports.RestartServiceResponse:
		return ConfirmOutput{Status: v.Status, Action: v.Action, ResourceKind: "service", Resource: v.Service, Service: v.Service, ServiceStatus: v.ServiceStatus, Healthcheck: v.Healthcheck, WouldRun: v.WouldRun}
	case ports.RestartContainerResponse:
		health := v.Health
		return ConfirmOutput{Status: v.Status, Action: v.Action, ResourceKind: v.ResourceKind, Resource: v.Resource, ContainerState: v.ContainerState, Health: &health, WouldRun: v.WouldRun}
	case ports.RestartGroupResponse:
		return ConfirmOutput{Status: v.Status, Action: v.Action, ResourceKind: "group", Resource: v.Group, Result: v, WouldRun: strings.Join(v.WouldRun, "\n")}
	case ports.RotateLogsResponse:
		return ConfirmOutput{Status: v.Status, Action: string(action.TypeRotateLogs), ResourceKind: "log", Result: v}
	case ports.CleanupCacheResponse:
		return ConfirmOutput{Status: v.Status, Action: string(action.TypeCleanupCache), ResourceKind: "cache", Result: v}
	case ports.PruneRecordsResponse:
		return ConfirmOutput{Status: v.Status, Action: string(action.TypeRemoveRecords), ResourceKind: "record", Resource: "safeops-records", Result: v}
	case ports.ResetFailureStateResponse:
		return ConfirmOutput{Status: v.Status, Action: string(action.TypeResetFailure), ResourceKind: v.ResourceKind, Resource: v.Resource, Result: v, WouldRun: v.WouldRun}
	case ports.RebootHostResponse:
		return ConfirmOutput{Status: v.Status, Action: v.Action, ResourceKind: "host", Resource: "host", Result: v, WouldRun: v.WouldRun}
	case ports.ApplicationDeploymentResponse:
		return ConfirmOutput{Status: v.Status, Action: v.Action, ResourceKind: "application", Resource: v.Application, Result: v, WouldRun: strings.Join(v.WouldRun, "\n")}
	case ports.BackupExecutionResponse:
		return ConfirmOutput{Status: v.Status, Action: v.Action, ResourceKind: "backup", Resource: v.BackupAlias, Result: v, WouldRun: strings.Join(v.WouldRun, "\n")}
	default:
		return ConfirmOutput{Status: "unknown"}
	}
}

func (s Service) ListContainers(ctx context.Context) ([]ports.ContainerSummary, error) {
	if !s.Config.Podman.Enabled {
		return nil, errors.New("podman is not enabled")
	}
	containers, err := s.Executor.ListContainers(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]ports.ContainerSummary, 0, len(containers))
	for _, container := range containers {
		if _, ok := s.Config.Containers[container.Alias]; ok {
			filtered = append(filtered, container)
		}
	}
	return filtered, nil
}

func (s Service) ContainerStatus(ctx context.Context, alias string) (ports.ContainerStatus, error) {
	if !s.permissionFor(action.ResourceContainer, alias, "status", "allow") {
		return ports.ContainerStatus{}, fmt.Errorf("container %q is not allowed for status", alias)
	}
	return s.Executor.ContainerStatus(ctx, alias)
}

func (s Service) ContainerLogs(ctx context.Context, req ports.ContainerLogsRequest) (ports.ContainerLogsResponse, error) {
	if !s.permissionFor(action.ResourceContainer, req.Container, "logs", "allow") {
		return ports.ContainerLogsResponse{}, fmt.Errorf("container %q is not allowed for logs", req.Container)
	}
	ctr := s.Config.Containers[req.Container]
	maxLines := ctr.Logs.MaxLines
	if maxLines == 0 {
		maxLines = s.Config.Limits.MaxLogLines
	}
	if req.Lines <= 0 || req.Lines > maxLines {
		return ports.ContainerLogsResponse{}, fmt.Errorf("lines must be between 1 and %d", maxLines)
	}
	if req.Since != "" && !allowedSince(req.Since) {
		return ports.ContainerLogsResponse{}, fmt.Errorf("since %q is not allowed", req.Since)
	}
	out, err := s.Executor.ContainerLogs(ctx, req)
	if err != nil {
		return ports.ContainerLogsResponse{}, err
	}
	for i := range out.Entries {
		out.Entries[i].Message = redaction.Redact(out.Entries[i].Message)
	}
	out.UntrustedContent = true
	return out, nil
}

func (s Service) CancelAction(ctx context.Context, userID string, approvalID string) error {
	a, getErr := s.Approvals.Get(ctx, approvalID)
	if getErr == nil && a.UserID == userID && a.Action == string(action.TypeRebootHost) && (a.Status == approval.StatusExecuted || a.Status == approval.StatusExecuting || a.Status == approval.StatusSimulated) {
		if _, err := s.Executor.CancelHostReboot(ctx, ports.RebootHostRequest{OperationID: a.OperationID, DryRun: s.Config.Policies.DryRun}); err != nil {
			return err
		}
		if err := s.Approvals.MarkDone(ctx, approvalID, approval.StatusRejected, "host reboot canceled", "", s.Clock.Now()); err != nil {
			return err
		}
		return s.audit(ctx, userID, "host_reboot_canceled", "cancel_action", string(action.TypeRebootHost), a.NormalizedArguments, "critical", "require_approval", "rejected", approvalID, a.OperationID)
	}
	if err := s.Approvals.Cancel(ctx, approvalID, userID, s.Clock.Now()); err != nil {
		return err
	}
	return s.audit(ctx, userID, "approval_canceled", "cancel_action", "", "{}", "mutating", "require_approval", "rejected", approvalID, "")
}

func (s Service) ActionStatus(ctx context.Context, userID, approvalID string) (approval.Approval, error) {
	a, err := s.Approvals.Get(ctx, approvalID)
	if err != nil {
		return approval.Approval{}, err
	}
	if a.UserID != userID {
		return approval.Approval{}, errors.New("approval belongs to a different user")
	}
	if a.Status == approval.StatusPending && !s.Clock.Now().Before(a.ExpiresAt) {
		a.Status = approval.StatusExpired
	}
	return a, nil
}

func (s Service) permission(alias, name, expected string) bool {
	svc, ok := s.Config.Services[alias]
	if !ok {
		return false
	}
	switch name {
	case "status":
		return svc.Permissions.Status == expected
	case "logs":
		return svc.Permissions.Logs == expected
	case "restart":
		return svc.Permissions.Restart == expected
	default:
		return false
	}
}

func (s Service) permissionFor(kind action.ResourceKind, alias, name, expected string) bool {
	if kind == action.ResourceService {
		return s.permission(alias, name, expected)
	}
	ctr, ok := s.Config.Containers[alias]
	if !ok {
		return false
	}
	switch name {
	case "status":
		return ctr.Permissions.Status == expected
	case "logs":
		return ctr.Permissions.Logs == expected
	case "restart":
		return ctr.Permissions.Restart == expected
	default:
		return false
	}
}

func normalizeAction(act action.Type, kind action.ResourceKind, alias, reason, userID string, dryRun bool, extra map[string]any) ([]byte, error) {
	args := map[string]any{
		"action_type":    act,
		"resource_kind":  kind,
		"resource_alias": alias,
		"reason":         reason,
		"user_id":        userID,
		"dry_run":        dryRun,
	}
	for k, v := range extra {
		args[k] = v
	}
	return json.Marshal(args)
}

func argumentReason(raw string) string {
	var args map[string]any
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return ""
	}
	if v, ok := args["reason"].(string); ok {
		return v
	}
	return ""
}

func argumentExtra(raw string) map[string]any {
	var args map[string]any
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		return nil
	}
	delete(args, "action_type")
	delete(args, "resource_kind")
	delete(args, "resource_alias")
	delete(args, "reason")
	delete(args, "user_id")
	delete(args, "dry_run")
	return args
}

func (s Service) validateActionAllowed(kind action.ResourceKind, alias string) error {
	switch kind {
	case action.ResourceService, action.ResourceContainer:
		if !s.permissionFor(kind, alias, "restart", "confirm") {
			return fmt.Errorf("%s %q does not permit restart requests", kind, alias)
		}
	case action.ResourceGroup:
		group, ok := s.Config.Groups[alias]
		if !ok {
			return fmt.Errorf("group %q is not configured", alias)
		}
		for _, resource := range group.Resources {
			if _, ok := s.Config.Services[resource]; ok {
				if !s.permissionFor(action.ResourceService, resource, "restart", "confirm") {
					return fmt.Errorf("group %q contains service %q without restart confirmation permission", alias, resource)
				}
				continue
			}
			if _, ok := s.Config.Containers[resource]; ok {
				if !s.permissionFor(action.ResourceContainer, resource, "restart", "confirm") {
					return fmt.Errorf("group %q contains container %q without restart confirmation permission", alias, resource)
				}
				continue
			}
			return fmt.Errorf("group %q contains unknown resource %q", alias, resource)
		}
	case action.ResourceLog:
		if alias == "" {
			return nil
		}
		if svc, ok := s.Config.Services[alias]; ok && svc.LogRotation.Enabled {
			return nil
		}
		if ctr, ok := s.Config.Containers[alias]; ok && ctr.LogRotation.Enabled {
			return nil
		}
		return fmt.Errorf("resource %q does not enable log rotation", alias)
	case action.ResourceCache:
		app, ok := s.Config.Applications[alias]
		if !ok || !app.Cleanup.Enabled {
			return fmt.Errorf("application %q does not enable cache cleanup", alias)
		}
	case action.ResourceRecord:
		if alias != "safeops-records" {
			return fmt.Errorf("record resource %q is not configured", alias)
		}
	case action.ResourceFailureState:
		if _, ok := s.Config.Services[alias]; !ok {
			return fmt.Errorf("service %q is not configured for reset-failed", alias)
		}
	case action.ResourceHost:
		if !s.Config.HostReboot.Enabled || alias != "host" {
			return errors.New("host reboot is disabled")
		}
	case action.ResourceApplication:
		app, ok := s.Config.Applications[alias]
		if !ok || app.Kind == "" {
			return fmt.Errorf("application %q is not configured for deployments", alias)
		}
	case action.ResourceBackup:
		if _, ok := s.Config.Backups[alias]; !ok {
			return fmt.Errorf("backup %q is not configured", alias)
		}
	default:
		return fmt.Errorf("resource kind %q is not supported", kind)
	}
	return nil
}

func (s Service) validateApplicationApprovalStillAllowed(a approval.Approval) error {
	if action.ResourceKind(a.ResourceKind) != action.ResourceApplication {
		return nil
	}
	switch action.Type(a.Action) {
	case action.TypeUpdateApplication:
		if !s.applicationPermission(a.ResourceAlias, "update", "confirm") {
			return fmt.Errorf("application %q no longer permits update requests", a.ResourceAlias)
		}
	case action.TypeRollbackApplication:
		if !s.applicationPermission(a.ResourceAlias, "rollback", "confirm") {
			return fmt.Errorf("application %q no longer permits rollback requests", a.ResourceAlias)
		}
	default:
		return fmt.Errorf("application action %q is not supported", a.Action)
	}
	return nil
}

func (s Service) applicationPermission(alias, name, expected string) bool {
	app, ok := s.Config.Applications[alias]
	if !ok || app.Kind == "" {
		return false
	}
	switch name {
	case "check":
		return app.Permissions.Check == expected
	case "update":
		return app.Permissions.Update == expected
	case "rollback":
		return app.Permissions.Rollback == expected
	default:
		return false
	}
}

func (s Service) recordDeploymentResult(ctx context.Context, userID string, a approval.Approval, out any) error {
	result, ok := out.(ports.ApplicationDeploymentResponse)
	if !ok || s.Deployments == nil || s.Config.Policies.DryRun {
		return nil
	}
	deploymentType := "update"
	if action.Type(a.Action) == action.TypeRollbackApplication {
		deploymentType = "rollback"
	}
	id, err := s.IDs.NewID("dep")
	if err != nil {
		return err
	}
	now := s.Clock.Now()
	status := "success"
	if result.Status != "success" {
		status = result.Status
	}
	record := deployment.HistoryRecord{
		ID:               id,
		ApplicationAlias: a.ResourceAlias,
		Version:          firstNonEmpty(result.CurrentVersion, result.TargetVersion),
		DeployedAt:       now,
		DeploymentType:   deploymentType,
		TriggeredBy:      userID,
		ImageDigest:      result.ImageDigest,
		CommitHash:       result.CommitHash,
		Status:           status,
		PreviousVersion:  result.PreviousVersion,
		NextVersion:      result.TargetVersion,
		CreatedAt:        now,
	}
	if err := s.Deployments.AppendDeployment(ctx, record); err != nil {
		return err
	}
	app := s.Config.Applications[a.ResourceAlias]
	if app.Rollback.VersionsToKeep > 0 {
		return s.Deployments.PruneDeployments(ctx, a.ResourceAlias, app.Rollback.VersionsToKeep)
	}
	return nil
}

func (s Service) recordBackupResult(ctx context.Context, a approval.Approval, out any) error {
	result, ok := out.(ports.BackupExecutionResponse)
	if !ok || s.Backups == nil || s.Config.Policies.DryRun {
		return nil
	}
	id, err := s.IDs.NewID("backup")
	if err != nil {
		return err
	}
	startTime, err := time.Parse(time.RFC3339, result.StartTime)
	if err != nil {
		startTime = s.Clock.Now()
	}
	var endTime *time.Time
	if result.EndTime != "" {
		parsed, err := time.Parse(time.RFC3339, result.EndTime)
		if err == nil {
			endTime = &parsed
		}
	}
	var checkedAt *time.Time
	if result.IntegrityCheckedAt != "" {
		parsed, err := time.Parse(time.RFC3339, result.IntegrityCheckedAt)
		if err == nil {
			checkedAt = &parsed
		}
	}
	metadata, _ := json.Marshal(result.Metadata)
	status := backup.StatusCompleted
	switch result.Status {
	case "failed":
		status = backup.StatusFailed
	case "verified":
		status = backup.StatusVerified
	case "running":
		status = backup.StatusRunning
	case "pending":
		status = backup.StatusPending
	}
	if result.IntegrityVerified {
		status = backup.StatusVerified
	}
	record := backup.Record{
		ID:                 id,
		BackupAlias:        a.ResourceAlias,
		SourceAlias:        result.SourceAlias,
		Backend:            result.Backend,
		SnapshotID:         result.SnapshotID,
		Status:             status,
		StartTime:          startTime,
		EndTime:            endTime,
		DurationSeconds:    result.DurationSeconds,
		SizeBytes:          result.SizeBytes,
		IntegrityVerified:  result.IntegrityVerified,
		IntegrityCheckedAt: checkedAt,
		ErrorMessage:       redaction.Redact(result.ErrorMessage),
		Metadata:           redaction.Redact(string(metadata)),
		CreatedAt:          s.Clock.Now(),
	}
	if err := s.Backups.AppendBackup(ctx, record); err != nil {
		return err
	}
	if s.Alerts != nil && (record.Status == backup.StatusFailed || (result.IntegrityCheckedAt != "" && !record.IntegrityVerified)) {
		finding := alert.Finding{
			ResourceKind:  "backup",
			ResourceAlias: record.BackupAlias,
			Type:          "backup_failed",
			Severity:      alert.SeverityCritical,
			Message:       "Backup " + record.BackupAlias + " failed or did not pass integrity verification.",
			Metadata:      redaction.Redact(record.Metadata),
		}
		_, _, err := s.Alerts.UpsertObserved(ctx, finding, s.Clock.Now())
		return err
	}
	return nil
}

func (s Service) recordsLimits(input RemoveExpiredSafeOpsRecordsInput) (time.Duration, int, error) {
	maxAge := s.Config.AuditRetention.Std()
	if strings.TrimSpace(input.MaxAge) != "" {
		parsed, err := parseMaintenanceDuration(input.MaxAge)
		if err != nil {
			return 0, 0, fmt.Errorf("max_age must be a duration such as 2160h or 90d")
		}
		maxAge = parsed
	}
	minRecords := s.Config.AuditMinRecords
	if input.MinRecords > 0 {
		minRecords = input.MinRecords
	}
	if maxAge <= 0 || minRecords < 0 {
		return 0, 0, errors.New("record cleanup limits are invalid")
	}
	return maxAge, minRecords, nil
}

func parseMaintenanceDuration(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasSuffix(raw, "d") {
		days, err := time.ParseDuration(strings.TrimSuffix(raw, "d") + "h")
		if err != nil {
			return 0, err
		}
		return days * 24, nil
	}
	return time.ParseDuration(raw)
}

func groupTimeout(cfg config.Config, group config.GroupConfig) time.Duration {
	if group.Timeout.Std() > 0 {
		return group.Timeout.Std()
	}
	return cfg.Limits.OperationTimeout.Std()
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func (s Service) validateBackupConfigured(alias string, allowEmpty bool) error {
	if alias == "" && allowEmpty {
		return nil
	}
	if _, ok := s.Config.Backups[alias]; !ok {
		return fmt.Errorf("backup %q is not configured", alias)
	}
	return nil
}

func backupSummaries(items []backup.Record) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		summary := map[string]any{
			"id":          item.ID,
			"alias":       item.BackupAlias,
			"snapshot_id": item.SnapshotID,
			"status":      item.Status,
			"start_time":  item.StartTime.UTC().Format(time.RFC3339),
			"size_gb":     float64(item.SizeBytes) / 1_073_741_824,
			"integrity":   item.IntegrityVerified,
		}
		if item.EndTime != nil {
			summary["end_time"] = item.EndTime.UTC().Format(time.RFC3339)
		}
		out = append(out, summary)
	}
	return out
}

func stringExtra(values map[string]any, key string) string {
	if v, ok := values[key].(string); ok {
		return v
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func allowedPriority(value string) bool {
	switch value {
	case "emerg", "alert", "crit", "err", "error", "warning", "notice", "info", "debug":
		return true
	default:
		return false
	}
}

func allowedSince(value string) bool {
	switch value {
	case "15m", "30m", "1h", "2h", "6h", "12h", "24h":
		return true
	default:
		return false
	}
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func constantEqual(left, right string) bool {
	return hmac.Equal([]byte(left), []byte(right))
}

func (s Service) audit(ctx context.Context, userID, eventType, tool, act, args, risk, decision, status, approvalID, operationID string) error {
	id, err := s.IDs.NewID("aud")
	if err != nil {
		return err
	}
	return s.Audit.Append(ctx, audit.Event{
		ID:             id,
		Timestamp:      s.Clock.Now(),
		UserID:         userID,
		Component:      "safeops-mcp",
		EventType:      eventType,
		Tool:           tool,
		Action:         act,
		Arguments:      redaction.Redact(args),
		Risk:           risk,
		PolicyDecision: decision,
		Status:         status,
		ApprovalID:     approvalID,
		OperationID:    operationID,
	})
}

func (s Service) auditRead(ctx context.Context, userID, tool, args string) error {
	return s.audit(ctx, userID, "diagnostic_read", tool, "read_diagnostics", args, "read", "allow", "completed", "", "")
}
