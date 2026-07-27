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
	"github.com/javiyt/safeops-mcp/internal/domain/policy"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

type Service struct {
	Config    config.Config
	Executor  ports.ExecutorClient
	Approvals ports.ApprovalRepository
	Alerts    ports.AlertRepository
	Audit     ports.AuditRepository
	Clock     ports.Clock
	IDs       ports.IDGenerator
	Codes     ports.CodeGenerator
	Policy    policy.Engine
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
	status := approval.StatusExecuted
	errorSummary := ""
	resultSummary := "restart executed"
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
	default:
		return fmt.Errorf("resource kind %q is not supported", kind)
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
