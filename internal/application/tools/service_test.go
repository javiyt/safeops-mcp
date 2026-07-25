package tools

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/policy"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

func TestRestartApprovalFlow(t *testing.T) {
	fakeApprovals := newApprovalRepo()
	svc := testService(fakeApprovals, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatalf("RequestServiceRestart() error = %v", err)
	}
	if out.ConfirmationCode == "" {
		t.Fatal("confirmation code is empty")
	}
	stored, _ := fakeApprovals.Get(context.Background(), out.ApprovalID)
	if stored.ConfirmationCodeHash == out.ConfirmationCode {
		t.Fatal("confirmation code was stored in plaintext")
	}
	result, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode})
	if err != nil {
		t.Fatalf("ConfirmAction() error = %v", err)
	}
	if result.Status != "executed" {
		t.Fatalf("status = %q, want executed", result.Status)
	}
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode}); err == nil {
		t.Fatal("second confirmation succeeded, want rejection")
	}
}

func TestWrongUserCannotConfirm(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmAction(context.Background(), "other", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want error")
	}
}

func TestServiceLogsAreMarkedUntrustedAndRedacted(t *testing.T) {
	svc := testService(newApprovalRepo(), fakeAudit{}, fakeExecutor{})
	out, err := svc.ServiceLogs(context.Background(), ports.ServiceLogsRequest{Service: "service-alpha", Lines: 10, Priority: "error", Since: "2h"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.UntrustedContent {
		t.Fatal("logs were not marked as untrusted")
	}
	if out.Entries[0].Message != "token=[REDACTED]" {
		t.Fatalf("message = %q", out.Entries[0].Message)
	}
}

func TestReadToolsAndValidation(t *testing.T) {
	svc := testService(newApprovalRepo(), fakeAudit{}, fakeExecutor{})
	if _, err := svc.SystemStatus(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ListServices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DiskStatus(context.Background(), "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DiskStatus(context.Background(), "free"); err == nil {
		t.Fatal("DiskStatus() error = nil, want error")
	}
	if _, err := svc.ServiceStatus(context.Background(), "service-alpha"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ServiceStatus(context.Background(), "missing"); err == nil {
		t.Fatal("ServiceStatus() error = nil, want error")
	}
	if _, err := svc.ServiceLogs(context.Background(), ports.ServiceLogsRequest{Service: "service-alpha", Lines: 201}); err == nil {
		t.Fatal("ServiceLogs() error = nil, want line limit error")
	}
	if _, err := svc.ServiceLogs(context.Background(), ports.ServiceLogsRequest{Service: "service-alpha", Lines: 1, Priority: "free"}); err == nil {
		t.Fatal("ServiceLogs() error = nil, want priority error")
	}
	if _, err := svc.ServiceLogs(context.Background(), ports.ServiceLogsRequest{Service: "service-alpha", Lines: 1, Since: "forever"}); err == nil {
		t.Fatal("ServiceLogs() error = nil, want since error")
	}
}

func TestCancelAndActionStatus(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CancelAction(context.Background(), "operator", out.ApprovalID); err != nil {
		t.Fatal(err)
	}
	status, err := svc.ActionStatus(context.Background(), "operator", out.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != approval.StatusRejected {
		t.Fatalf("status = %s", status.Status)
	}
}

func TestActionStatusExpiresPendingApproval(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	svc.Clock = fakeClock{now: time.Date(2026, 7, 24, 10, 10, 0, 0, time.UTC)}
	status, err := svc.ActionStatus(context.Background(), "operator", out.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Status != approval.StatusExpired {
		t.Fatalf("status = %s", status.Status)
	}
}

func TestConfirmRejectsBadCodeAndExpiredApproval(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: "0000"}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want bad code error")
	}
	svc.Clock = fakeClock{now: time.Date(2026, 7, 24, 10, 10, 0, 0, time.UTC)}
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want expired error")
	}
}

func TestConfirmDryRunAndExecutorFailure(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	svc.Config.Policies.DryRun = true
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "executed" {
		t.Fatalf("result = %+v", result)
	}
	repo = newApprovalRepo()
	svc = testService(repo, fakeAudit{}, fakeExecutor{restartErr: errors.New("failed token=abc")})
	out, err = svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want executor error")
	}
	stored, _ := repo.Get(context.Background(), out.ApprovalID)
	if stored.Status != approval.StatusFailed || stored.ErrorSummary != "failed token=[REDACTED]" {
		t.Fatalf("stored approval = %+v", stored)
	}
}

func TestRequestRestartRejectsDeniedServiceAndGeneratorErrors(t *testing.T) {
	svc := testService(newApprovalRepo(), fakeAudit{}, fakeExecutor{})
	if _, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "missing", Reason: "stopped"}); err == nil {
		t.Fatal("RequestServiceRestart() error = nil, want service error")
	}
	svc.IDs = failingIDs{}
	if _, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"}); err == nil {
		t.Fatal("RequestServiceRestart() error = nil, want ID error")
	}
	svc = testService(newApprovalRepo(), fakeAudit{}, fakeExecutor{})
	svc.Codes = failingCodes{}
	if _, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"}); err == nil {
		t.Fatal("RequestServiceRestart() error = nil, want code error")
	}
}

func TestActionStatusRejectsWrongUser(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ActionStatus(context.Background(), "other", out.ApprovalID); err == nil {
		t.Fatal("ActionStatus() error = nil, want user error")
	}
}

func testService(approvals ports.ApprovalRepository, audit ports.AuditRepository, executor ports.ExecutorClient) Service {
	return Service{
		Config:    ConfigForTest(),
		Executor:  executor,
		Approvals: approvals,
		Audit:     audit,
		Clock:     fakeClock{now: time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)},
		IDs:       fakeIDs{},
		Codes:     fakeCodes{},
		Policy:    policy.Engine{},
	}
}

func ConfigForTest() config.Config {
	return config.Config{
		Identity:   config.IdentityConfig{AdministratorID: "operator"},
		Policies:   config.PoliciesConfig{Default: "deny", DestructiveActions: "deny", ApprovalExpiration: config.Duration(5 * time.Minute)},
		Limits:     config.LimitsConfig{OperationTimeout: config.Duration(15 * time.Second), MaxLogLines: 200, MaxToolOutputBytes: 65536, MaxHealthcheckAttempts: 5},
		Filesystem: config.FilesystemConfig{DiskPaths: map[string]config.DiskPathConfig{"root": {Path: "/"}}},
		Services: map[string]config.ServiceConfig{
			"service-alpha": {
				Unit:        "app-alpha.service",
				Permissions: config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
			},
		},
	}
}

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time { return c.now }

type fakeIDs struct{}

func (fakeIDs) NewID(prefix string) (string, error) { return prefix + "_1", nil }

type failingIDs struct{}

func (failingIDs) NewID(string) (string, error) { return "", errors.New("id failed") }

type fakeCodes struct{}

func (fakeCodes) NewCode(int) (string, error) { return "4821", nil }

type failingCodes struct{}

func (failingCodes) NewCode(int) (string, error) { return "", errors.New("code failed") }

type fakeAudit struct{}

func (fakeAudit) Append(context.Context, audit.Event) error             { return nil }
func (fakeAudit) ListAudit(context.Context, int) ([]audit.Event, error) { return nil, nil }

type approvalRepo struct {
	items map[string]approval.Approval
}

func newApprovalRepo() *approvalRepo {
	return &approvalRepo{items: map[string]approval.Approval{}}
}

func (r *approvalRepo) Create(_ context.Context, a approval.Approval) error {
	r.items[a.ID] = a
	return nil
}

func (r *approvalRepo) Get(_ context.Context, id string) (approval.Approval, error) {
	a, ok := r.items[id]
	if !ok {
		return approval.Approval{}, errors.New("not found")
	}
	return a, nil
}

func (r *approvalRepo) MarkExecuting(_ context.Context, id string, _ time.Time) (approval.Approval, error) {
	a := r.items[id]
	if a.Status != approval.StatusPending {
		return approval.Approval{}, errors.New("not pending")
	}
	a.Status = approval.StatusExecuting
	a.Attempts++
	r.items[id] = a
	return a, nil
}

func (r *approvalRepo) MarkDone(_ context.Context, id string, status approval.Status, resultSummary, errorSummary string, executedAt time.Time) error {
	a := r.items[id]
	a.Status = status
	a.ResultSummary = resultSummary
	a.ErrorSummary = errorSummary
	a.ExecutedAt = &executedAt
	r.items[id] = a
	return nil
}

func (r *approvalRepo) Cancel(_ context.Context, id string, userID string, _ time.Time) error {
	a := r.items[id]
	if a.UserID != userID || a.Status != approval.StatusPending {
		return errors.New("cannot cancel")
	}
	a.Status = approval.StatusRejected
	r.items[id] = a
	return nil
}

func (r *approvalRepo) List(context.Context, int) ([]approval.Approval, error) { return nil, nil }

type fakeExecutor struct {
	restartErr error
}

func (fakeExecutor) SystemStatus(context.Context) (ports.SystemStatus, error) {
	return ports.SystemStatus{}, nil
}
func (fakeExecutor) DiskStatus(context.Context, string) (ports.DiskStatus, error) {
	return ports.DiskStatus{}, nil
}
func (fakeExecutor) ListServices(context.Context) ([]ports.ServiceSummary, error) { return nil, nil }
func (fakeExecutor) ServiceStatus(context.Context, string) (service.Status, error) {
	return service.Status{ActiveState: "active"}, nil
}
func (fakeExecutor) ServiceLogs(context.Context, ports.ServiceLogsRequest) (ports.ServiceLogsResponse, error) {
	return ports.ServiceLogsResponse{Entries: []service.LogEntry{{Message: "token=abc"}}}, nil
}
func (e fakeExecutor) RestartService(context.Context, ports.RestartServiceRequest) (ports.RestartServiceResponse, error) {
	if e.restartErr != nil {
		return ports.RestartServiceResponse{}, e.restartErr
	}
	return ports.RestartServiceResponse{Status: "executed", Action: "restart_service", Service: "service-alpha", ServiceStatus: "active"}, nil
}
