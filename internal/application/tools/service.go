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
	if s.Policy.Decide(action.RiskMutating) != policy.DecisionRequireApproval {
		return RequestRestartOutput{}, errors.New("restart policy must require approval")
	}
	if !s.permission(input.Service, "restart", "confirm") {
		return RequestRestartOutput{}, fmt.Errorf("service %q does not permit restart requests", input.Service)
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
	normalized, err := json.Marshal(map[string]string{"service": input.Service, "reason": input.Reason})
	if err != nil {
		return RequestRestartOutput{}, err
	}
	a := approval.Approval{
		ID:                   approvalID,
		UserID:               userID,
		Tool:                 "request_service_restart",
		Action:               string(action.TypeRestartService),
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
	_ = s.audit(ctx, userID, "approval_requested", "request_service_restart", string(action.TypeRestartService), string(normalized), "mutating", "require_approval", "pending", approvalID, "")
	return RequestRestartOutput{
		Status:           "approval_required",
		ApprovalID:       approvalID,
		ConfirmationCode: code,
		ExpiresAt:        a.ExpiresAt.Format(time.RFC3339),
		Summary:          "Restart " + input.Service,
		ExpectedEffect:   "The service may be unavailable for a few seconds.",
	}, nil
}

func (s Service) ConfirmAction(ctx context.Context, userID string, input ConfirmInput) (ports.RestartServiceResponse, error) {
	now := s.Clock.Now()
	a, err := s.Approvals.Get(ctx, input.ApprovalID)
	if err != nil {
		return ports.RestartServiceResponse{}, err
	}
	if a.UserID != userID {
		return ports.RestartServiceResponse{}, errors.New("approval belongs to a different user")
	}
	if a.Status != approval.StatusPending {
		return ports.RestartServiceResponse{}, fmt.Errorf("approval is %s", a.Status)
	}
	if !now.Before(a.ExpiresAt) {
		return ports.RestartServiceResponse{}, errors.New("approval has expired")
	}
	if !constantEqual(hashString(input.ConfirmationCode), a.ConfirmationCodeHash) {
		return ports.RestartServiceResponse{}, errors.New("confirmation code is incorrect")
	}
	var args map[string]string
	if err := json.Unmarshal([]byte(a.NormalizedArguments), &args); err != nil {
		return ports.RestartServiceResponse{}, err
	}
	serviceAlias := args["service"]
	if !s.permission(serviceAlias, "restart", "confirm") {
		return ports.RestartServiceResponse{}, errors.New("restart is no longer permitted by configuration")
	}
	if _, err := s.Approvals.MarkExecuting(ctx, a.ID, now); err != nil {
		return ports.RestartServiceResponse{}, err
	}
	opID, err := s.IDs.NewID("op")
	if err != nil {
		return ports.RestartServiceResponse{}, err
	}
	out, err := s.Executor.RestartService(ctx, ports.RestartServiceRequest{Service: serviceAlias, OperationID: opID, DryRun: s.Config.Policies.DryRun})
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
	_ = s.audit(ctx, userID, "approval_completed", "confirm_action", string(action.TypeRestartService), a.NormalizedArguments, "mutating", "require_approval", string(status), a.ID, opID)
	if err != nil {
		return ports.RestartServiceResponse{}, err
	}
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
