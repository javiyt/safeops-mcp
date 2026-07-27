package tools

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/action"
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

type RequestRestartOutput struct {
	Status           string `json:"status"`
	ApprovalID       string `json:"approval_id"`
	ConfirmationCode string `json:"confirmation_code"`
	ExpiresAt        string `json:"expires_at"`
	Summary          string `json:"summary"`
	ExpectedEffect   string `json:"expected_effect"`
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

func (s Service) requestRestart(ctx context.Context, userID, tool string, act action.Type, kind action.ResourceKind, alias, reason string) (RequestRestartOutput, error) {
	if s.Policy.Decide(action.RiskMutating) != policy.DecisionRequireApproval {
		return RequestRestartOutput{}, errors.New("restart policy must require approval")
	}
	if !s.permissionFor(kind, alias, "restart", "confirm") {
		return RequestRestartOutput{}, fmt.Errorf("%s %q does not permit restart requests", kind, alias)
	}
	now := s.Clock.Now()
	approvalID, err := s.IDs.NewID("apr")
	if err != nil {
		return RequestRestartOutput{}, err
	}
	code, err := s.Codes.NewCode(4)
	if err != nil {
		return RequestRestartOutput{}, err
	}
	normalized, err := normalizeAction(act, kind, alias, reason, userID, s.Config.Policies.DryRun)
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
		ExpiresAt:            now.Add(s.Config.Policies.ApprovalExpiration.Std()),
	}
	if err := s.Approvals.Create(ctx, a); err != nil {
		return RequestRestartOutput{}, err
	}
	eventType := "approval_requested"
	if kind == action.ResourceContainer {
		eventType = "container_restart_requested"
	}
	if err := s.audit(ctx, userID, eventType, tool, string(act), string(normalized), "mutating", "require_approval", "pending", approvalID, ""); err != nil {
		return RequestRestartOutput{}, err
	}
	noun := "service"
	effect := "The service may be unavailable for a few seconds."
	if kind == action.ResourceContainer {
		noun = "container"
		effect = "The container may be unavailable for a few seconds."
	}
	return RequestRestartOutput{
		Status:           "approval_required",
		ApprovalID:       approvalID,
		ConfirmationCode: code,
		ExpiresAt:        a.ExpiresAt.Format(time.RFC3339),
		Summary:          "Restart " + noun + " " + alias,
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
	if !s.permissionFor(action.ResourceKind(a.ResourceKind), a.ResourceAlias, "restart", "confirm") {
		return ConfirmOutput{}, errors.New("restart is no longer permitted by configuration")
	}
	normalized, err := normalizeAction(action.Type(a.Action), action.ResourceKind(a.ResourceKind), a.ResourceAlias, argumentReason(a.NormalizedArguments), userID, s.Config.Policies.DryRun)
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
	default:
		return ConfirmOutput{Status: "unknown"}
	}
}

func (s Service) ListContainers(ctx context.Context) ([]ports.ContainerSummary, error) {
	if !s.Config.Podman.Enabled {
		return nil, errors.New("podman is not enabled")
	}
	return s.Executor.ListContainers(ctx)
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

func normalizeAction(act action.Type, kind action.ResourceKind, alias, reason, userID string, dryRun bool) ([]byte, error) {
	return json.Marshal(map[string]any{
		"action_type":    act,
		"resource_kind":  kind,
		"resource_alias": alias,
		"reason":         reason,
		"user_id":        userID,
		"dry_run":        dryRun,
	})
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
