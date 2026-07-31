package tools

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/backup"
	"github.com/javiyt/safeops-mcp/internal/domain/deployment"
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

func TestDiagnosticReadToolsAuditAndRedact(t *testing.T) {
	auditRepo := &recordingAudit{}
	svc := testService(newApprovalRepo(), auditRepo, fakeExecutor{})
	cpu, err := svc.CPUStatus(context.Background(), "operator")
	if err != nil {
		t.Fatal(err)
	}
	if cpu.Processes[0].Command != "--token=[REDACTED]" {
		t.Fatalf("command = %q", cpu.Processes[0].Command)
	}
	if _, err := svc.MemoryStatus(context.Background(), "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DiskHealth(context.Background(), "operator", "root"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DiskHealth(context.Background(), "operator", "missing"); err == nil {
		t.Fatal("DiskHealth() error = nil, want missing alias error")
	}
	if _, err := svc.NetworkStatus(context.Background(), "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.TimeStatus(context.Background(), "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfiguredProcessStatus(context.Background(), "operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.HostHealthSummary(context.Background(), "operator"); err != nil {
		t.Fatal(err)
	}
	if len(auditRepo.events) != 7 {
		t.Fatalf("audit events = %d, want 7", len(auditRepo.events))
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

func TestContainerToolsAndRestartApproval(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	svc.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	svc.Config.Containers = map[string]config.ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
			Logs:          config.ContainerLogsConfig{MaxLines: 10},
			Health:        config.ContainerHealthConfig{Attempts: 2, Interval: config.Duration(time.Millisecond)},
		},
	}
	if _, err := svc.ListContainers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ContainerStatus(context.Background(), "container-alpha"); err != nil {
		t.Fatal(err)
	}
	logs, err := svc.ContainerLogs(context.Background(), ports.ContainerLogsRequest{Container: "container-alpha", Lines: 1, Since: "2h"})
	if err != nil {
		t.Fatal(err)
	}
	if !logs.UntrustedContent || logs.Entries[0].Message != "token=[REDACTED]" {
		t.Fatalf("logs = %+v", logs)
	}
	if _, err := svc.ContainerLogs(context.Background(), ports.ContainerLogsRequest{Container: "container-alpha", Lines: 11}); err == nil {
		t.Fatal("ContainerLogs() error = nil, want line limit error")
	}
	out, err := svc.RequestContainerRestart(context.Background(), "operator", RequestContainerRestartInput{Container: "container-alpha", Reason: "unhealthy"})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := repo.Get(context.Background(), out.ApprovalID)
	if stored.Action != "restart_container" || stored.ResourceKind != "container" || stored.ResourceAlias != "container-alpha" {
		t.Fatalf("stored approval = %+v", stored)
	}
	result, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode})
	if err != nil {
		t.Fatal(err)
	}
	if result.Action != "restart_container" || result.ContainerState != "running" {
		t.Fatalf("result = %+v", result)
	}
}

func TestListContainersReturnsOnlyConfiguredAliases(t *testing.T) {
	svc := testService(newApprovalRepo(), fakeAudit{}, fakeExecutorWithExtraContainer{})
	svc.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	svc.Config.Containers = map[string]config.ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
	}
	containers, err := svc.ListContainers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(containers) != 1 || containers[0].Alias != "container-alpha" {
		t.Fatalf("containers = %+v", containers)
	}
}

func TestPodmanDisabledRejectsContainerTools(t *testing.T) {
	svc := testService(newApprovalRepo(), fakeAudit{}, fakeExecutor{})
	if _, err := svc.ListContainers(context.Background()); err == nil {
		t.Fatal("ListContainers() error = nil, want disabled error")
	}
	if _, err := svc.RequestContainerRestart(context.Background(), "operator", RequestContainerRestartInput{Container: "container-alpha", Reason: "unhealthy"}); err == nil {
		t.Fatal("RequestContainerRestart() error = nil, want disabled error")
	}
}

func TestApplicationErrorBranches(t *testing.T) {
	svc := testService(newApprovalRepo(), fakeAudit{}, fakeExecutor{})
	svc.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	svc.Config.Containers = map[string]config.ContainerConfig{
		"denied": {
			ContainerName: "denied",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "deny", Logs: "deny", Restart: "deny"},
		},
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
			Logs:          config.ContainerLogsConfig{MaxLines: 10},
		},
	}
	if _, err := svc.ContainerStatus(context.Background(), "denied"); err == nil {
		t.Fatal("ContainerStatus() error = nil, want denied error")
	}
	if _, err := svc.ContainerLogs(context.Background(), ports.ContainerLogsRequest{Container: "container-alpha", Lines: 1, Since: "forever"}); err == nil {
		t.Fatal("ContainerLogs() error = nil, want since error")
	}
	if err := svc.CancelAction(context.Background(), "operator", "missing"); err == nil {
		t.Fatal("CancelAction() error = nil, want missing error")
	}
}

func TestApplicationUpdateApprovalRecordsDeploymentHistory(t *testing.T) {
	repo := newApprovalRepo()
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	version, err := svc.ApplicationVersion(context.Background(), "operator", ApplicationInput{Application: "app-service"})
	if err != nil {
		t.Fatal(err)
	}
	if version.CurrentVersion != "1.0.0" {
		t.Fatalf("version = %+v", version)
	}
	check, err := svc.CheckApplicationUpdate(context.Background(), "operator", ApplicationInput{Application: "app-service"})
	if err != nil {
		t.Fatal(err)
	}
	if !check.UpdateAvailable {
		t.Fatalf("check = %+v", check)
	}
	out, err := svc.RequestApplicationUpdate(context.Background(), "operator", RequestApplicationUpdateInput{Application: "app-service", Reason: "controlled update"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "success" || result.ResourceKind != "application" {
		t.Fatalf("result = %+v", result)
	}
	history, err := svc.ApplicationHistory(context.Background(), "operator", ApplicationInput{Application: "app-service"})
	if err != nil {
		t.Fatal(err)
	}
	if len(history["history"]) != 1 || history["history"][0].Version != "1.0.1" {
		t.Fatalf("history = %+v", history)
	}
}

func TestApplicationRollbackUsesRecordedVersionOnly(t *testing.T) {
	repo := newApprovalRepo()
	repo.deployments = []deployment.HistoryRecord{{ID: "dep_0", ApplicationAlias: "app-service", Version: "1.0.0", CommitHash: "commit-prev", Status: "success"}}
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	if _, err := svc.RequestApplicationRollback(context.Background(), "operator", RequestApplicationRollbackInput{Application: "app-service", Reason: "rollback", Version: "9.9.9"}); err == nil {
		t.Fatal("RequestApplicationRollback() error = nil, want unknown version error")
	}
	out, err := svc.RequestApplicationRollback(context.Background(), "operator", RequestApplicationRollbackInput{Application: "app-service", Reason: "rollback", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "success" {
		t.Fatalf("result = %+v", result)
	}
}

func TestRequestRestartRequiresAuditPersistence(t *testing.T) {
	svc := testService(newApprovalRepo(), failingAudit{}, fakeExecutor{})
	if _, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"}); err == nil {
		t.Fatal("RequestServiceRestart() error = nil, want audit error")
	}
}

func TestConfirmRejectsUnsupportedAction(t *testing.T) {
	repo := newApprovalRepo()
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	normalized, err := normalizeAction("restart_host", "service", "service-alpha", "bad", "operator", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(context.Background(), approval.Approval{
		ID:                   "apr_bad",
		UserID:               "operator",
		Tool:                 "request_service_restart",
		Action:               "restart_host",
		ResourceKind:         "service",
		ResourceAlias:        "service-alpha",
		NormalizedArguments:  string(normalized),
		ArgumentsHash:        hashString(string(normalized)),
		ConfirmationCodeHash: hashString("4821"),
		Status:               approval.StatusPending,
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: "apr_bad", ConfirmationCode: "4821"}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want unsupported action error")
	}
}

func TestConfirmRejectsTamperedApprovalArguments(t *testing.T) {
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	repo := newApprovalRepo()
	if err := repo.Create(context.Background(), approval.Approval{
		ID:                   "apr_tampered",
		UserID:               "operator",
		Tool:                 "request_service_restart",
		Action:               "restart_service",
		ResourceKind:         "service",
		ResourceAlias:        "service-alpha",
		NormalizedArguments:  `{"reason":"changed"}`,
		ArgumentsHash:        hashString(`{"reason":"original"}`),
		ConfirmationCodeHash: hashString("4821"),
		Status:               approval.StatusPending,
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: "apr_tampered", ConfirmationCode: "4821"}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want hash mismatch")
	}

	repo = newApprovalRepo()
	if err := repo.Create(context.Background(), approval.Approval{
		ID:                   "apr_bad_json",
		UserID:               "operator",
		Tool:                 "request_service_restart",
		Action:               "restart_service",
		NormalizedArguments:  `{`,
		ArgumentsHash:        hashString(`{`),
		ConfirmationCodeHash: hashString("4821"),
		Status:               approval.StatusPending,
		CreatedAt:            now,
		ExpiresAt:            now.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	svc = testService(repo, fakeAudit{}, fakeExecutor{})
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: "apr_bad_json", ConfirmationCode: "4821"}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want bad JSON")
	}
}

func TestConfirmRejectsConcurrentResourceLock(t *testing.T) {
	repo := newApprovalRepo()
	repo.locked = true
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want lock error")
	}
	stored, _ := repo.Get(context.Background(), out.ApprovalID)
	if stored.Status != approval.StatusFailed {
		t.Fatalf("status = %s, want failed", stored.Status)
	}
}

func TestConfirmRevalidatesConfigurationBeforeExecution(t *testing.T) {
	repo := newApprovalRepo()
	executor := &recordingExecutor{}
	svc := testService(repo, fakeAudit{}, executor)
	out, err := svc.RequestServiceRestart(context.Background(), "operator", RequestRestartInput{Service: "service-alpha", Reason: "stopped"})
	if err != nil {
		t.Fatal(err)
	}
	cfg := svc.Config.Services["service-alpha"]
	cfg.Permissions.Restart = "deny"
	svc.Config.Services["service-alpha"] = cfg
	if _, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode}); err == nil {
		t.Fatal("ConfirmAction() error = nil, want configuration revalidation error")
	}
	if executor.restartServiceCalls != 0 {
		t.Fatalf("restartServiceCalls = %d, want 0", executor.restartServiceCalls)
	}
}

func TestConfirmSuccessfulOperationSurvivesPostAuditFailure(t *testing.T) {
	repo := newApprovalRepo()
	audit := &failAfterAudit{failAfter: 1}
	svc := testService(repo, audit, fakeExecutor{})
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
	stored, err := repo.Get(context.Background(), out.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != approval.StatusExecuted || stored.ErrorSummary == "" {
		t.Fatalf("stored approval = %+v", stored)
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

func TestBackupApprovalPersistsMetadataAndRestorePlan(t *testing.T) {
	repo := newApprovalRepo()
	auditRepo := &recordingAudit{}
	svc := testService(repo, auditRepo, fakeExecutor{})
	out, err := svc.RequestBackup(context.Background(), "operator", RequestBackupInput{BackupAlias: "backup-alpha", Reason: "before maintenance"})
	if err != nil {
		t.Fatalf("RequestBackup() error = %v", err)
	}
	if out.Status != "approval_required" || out.ConfirmationCode == "" {
		t.Fatalf("approval output = %+v", out)
	}
	result, err := svc.ConfirmAction(context.Background(), "operator", ConfirmInput{ApprovalID: out.ApprovalID, ConfirmationCode: out.ConfirmationCode})
	if err != nil {
		t.Fatalf("ConfirmAction() error = %v", err)
	}
	if result.ResourceKind != "backup" || result.Resource != "backup-alpha" {
		t.Fatalf("result = %+v", result)
	}
	if len(repo.backups) != 1 {
		t.Fatalf("persisted backups = %d, want 1", len(repo.backups))
	}
	if repo.backups[0].Status != backup.StatusVerified || repo.backups[0].SnapshotID != "snapshot-alpha" {
		t.Fatalf("backup record = %+v", repo.backups[0])
	}
	listed, err := svc.ListBackups(context.Background(), "operator", BackupAliasInput{BackupAlias: "backup-alpha"})
	if err != nil {
		t.Fatalf("ListBackups() error = %v", err)
	}
	if listed["total"].(int) != 1 {
		t.Fatalf("listed = %+v", listed)
	}
	plan, err := svc.RequestRestorePlan(context.Background(), "operator", RequestRestorePlanInput{BackupAlias: "backup-alpha", BackupID: repo.backups[0].ID})
	if err != nil {
		t.Fatalf("RequestRestorePlan() error = %v", err)
	}
	if plan.Mutable || !plan.RequiresApproval || plan.Backup.ID != repo.backups[0].ID {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestRequestBackupRejectsConcurrentBackup(t *testing.T) {
	repo := newApprovalRepo()
	repo.backups = append(repo.backups, backup.Record{ID: "backup_running", BackupAlias: "backup-alpha", Status: backup.StatusRunning})
	svc := testService(repo, fakeAudit{}, fakeExecutor{})
	if _, err := svc.RequestBackup(context.Background(), "operator", RequestBackupInput{BackupAlias: "backup-alpha", Reason: "manual"}); err == nil {
		t.Fatal("RequestBackup() error = nil, want concurrent backup error")
	}
}

func testService(approvals ports.ApprovalRepository, audit ports.AuditRepository, executor ports.ExecutorClient) Service {
	deployments, _ := approvals.(ports.DeploymentRepository)
	backups, _ := approvals.(ports.BackupRepository)
	return Service{
		Config:      ConfigForTest(),
		Executor:    executor,
		Approvals:   approvals,
		Deployments: deployments,
		Backups:     backups,
		Audit:       audit,
		Clock:       fakeClock{now: time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)},
		IDs:         fakeIDs{},
		Codes:       fakeCodes{},
		Policy:      policy.Engine{},
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
		Applications: map[string]config.ApplicationConfig{
			"app-service": {
				Kind:        "service",
				ServiceName: "service-alpha",
				Management:  "systemd",
				Repository:  config.ApplicationRepositoryConfig{Type: "git", URL: "https://example.invalid/app-service", Branch: "main", Path: "/opt/app-service"},
				Permissions: config.ApplicationPermissionsConfig{Check: "allow", Update: "confirm", Rollback: "confirm"},
				Rollback:    config.ApplicationRollbackConfig{Enabled: true, VersionsToKeep: 5},
			},
		},
		Backups: map[string]config.BackupConfig{
			"backup-alpha": {
				SourceAlias:    "service-alpha",
				Description:    "Configured backup",
				Backend:        "command",
				Operation:      "/usr/bin/true",
				Destination:    "/tmp/safeops-backup-alpha",
				Retention:      config.BackupRetention{KeepLast: 7},
				IntegrityCheck: true,
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

type recordingAudit struct {
	events []audit.Event
}

func (a *recordingAudit) Append(_ context.Context, event audit.Event) error {
	a.events = append(a.events, event)
	return nil
}

func (a *recordingAudit) ListAudit(context.Context, int) ([]audit.Event, error) { return nil, nil }

type failingAudit struct{}

func (failingAudit) Append(context.Context, audit.Event) error {
	return errors.New("audit failed")
}
func (failingAudit) ListAudit(context.Context, int) ([]audit.Event, error) { return nil, nil }

type failAfterAudit struct {
	calls     int
	failAfter int
}

func (a *failAfterAudit) Append(context.Context, audit.Event) error {
	a.calls++
	if a.calls > a.failAfter {
		return errors.New("audit failed")
	}
	return nil
}

func (a *failAfterAudit) ListAudit(context.Context, int) ([]audit.Event, error) { return nil, nil }

type approvalRepo struct {
	items       map[string]approval.Approval
	deployments []deployment.HistoryRecord
	backups     []backup.Record
	locked      bool
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
func (r *approvalRepo) CountOperationsInProgress(context.Context) (int, error) { return 0, nil }
func (r *approvalRepo) PruneRecords(context.Context, time.Time, int, bool) (ports.PruneRecordsResponse, error) {
	return ports.PruneRecordsResponse{Status: "simulated", RecordsToDelete: 1, RecordsRemaining: 1000, DryRun: true}, nil
}
func (r *approvalRepo) AcquireOperationLock(context.Context, string, string, string, time.Time) error {
	if r.locked {
		return errors.New("resource already has an executing operation")
	}
	r.locked = true
	return nil
}
func (r *approvalRepo) ReleaseOperationLock(context.Context, string, string, string) error {
	r.locked = false
	return nil
}
func (r *approvalRepo) AppendDeployment(_ context.Context, record deployment.HistoryRecord) error {
	r.deployments = append(r.deployments, record)
	return nil
}
func (r *approvalRepo) ListDeployments(_ context.Context, applicationAlias string, limit int) ([]deployment.HistoryRecord, error) {
	var out []deployment.HistoryRecord
	for _, record := range r.deployments {
		if record.ApplicationAlias == applicationAlias {
			out = append(out, record)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
func (r *approvalRepo) LatestSuccessfulDeployment(_ context.Context, applicationAlias string) (deployment.HistoryRecord, error) {
	for i := len(r.deployments) - 1; i >= 0; i-- {
		record := r.deployments[i]
		if record.ApplicationAlias == applicationAlias && record.Status == "success" {
			return record, nil
		}
	}
	return deployment.HistoryRecord{}, errors.New("not found")
}
func (r *approvalRepo) PruneDeployments(_ context.Context, applicationAlias string, keep int) error {
	if keep <= 0 {
		return nil
	}
	var kept []deployment.HistoryRecord
	count := 0
	for i := len(r.deployments) - 1; i >= 0; i-- {
		record := r.deployments[i]
		if record.ApplicationAlias == applicationAlias {
			count++
			if count > keep {
				continue
			}
		}
		kept = append([]deployment.HistoryRecord{record}, kept...)
	}
	r.deployments = kept
	return nil
}

func (r *approvalRepo) AppendBackup(_ context.Context, record backup.Record) error {
	r.backups = append(r.backups, record)
	return nil
}

func (r *approvalRepo) ListBackups(_ context.Context, filter backup.ListFilter, limit int) ([]backup.Record, error) {
	var out []backup.Record
	for _, record := range r.backups {
		if filter.BackupAlias != "" && record.BackupAlias != filter.BackupAlias {
			continue
		}
		if filter.BackupID != "" && record.ID != filter.BackupID {
			continue
		}
		out = append(out, record)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *approvalRepo) LatestBackup(_ context.Context, backupAlias string) (backup.Record, error) {
	for i := len(r.backups) - 1; i >= 0; i-- {
		record := r.backups[i]
		if backupAlias == "" || record.BackupAlias == backupAlias {
			return record, nil
		}
	}
	return backup.Record{}, errors.New("not found")
}

func (r *approvalRepo) GetBackup(_ context.Context, id string) (backup.Record, error) {
	for _, record := range r.backups {
		if record.ID == id {
			return record, nil
		}
	}
	return backup.Record{}, errors.New("not found")
}

func (r *approvalRepo) BackupInProgress(_ context.Context, backupAlias string) (bool, error) {
	for _, record := range r.backups {
		if record.BackupAlias == backupAlias && (record.Status == backup.StatusPending || record.Status == backup.StatusRunning) {
			return true, nil
		}
	}
	return false, nil
}

type fakeExecutor struct {
	restartErr error
}

func (fakeExecutor) SystemStatus(context.Context) (ports.SystemStatus, error) {
	return ports.SystemStatus{}, nil
}
func (fakeExecutor) DiskStatus(context.Context, string) (ports.DiskStatus, error) {
	return ports.DiskStatus{}, nil
}
func (fakeExecutor) CPUStatus(context.Context) (ports.CPUStatus, error) {
	return ports.CPUStatus{UsagePercent: 10, LoadAverage: []float64{0.1, 0.2, 0.3}, Processes: []ports.ProcessUsage{{PID: 123, Name: "worker", Command: "--token=abc"}}}, nil
}
func (fakeExecutor) MemoryStatus(context.Context) (ports.MemoryStatus, error) {
	return ports.MemoryStatus{TotalMB: 1024, AvailableMB: 512}, nil
}
func (fakeExecutor) DiskHealth(context.Context, string) (ports.DiskHealth, error) {
	return ports.DiskHealth{Disks: []ports.DiskHealthItem{{Name: "root", UsagePercent: 50, InodesPercent: 10}}}, nil
}
func (fakeExecutor) NetworkStatus(context.Context) (ports.NetworkStatus, error) {
	return ports.NetworkStatus{}, nil
}
func (fakeExecutor) TimeStatus(context.Context) (ports.TimeStatus, error) {
	return ports.TimeStatus{CurrentTime: "2026-07-24T10:00:00Z", Timezone: "UTC"}, nil
}
func (fakeExecutor) ConfiguredProcessStatus(context.Context) (ports.ConfiguredProcessStatus, error) {
	return ports.ConfiguredProcessStatus{Processes: []ports.ProcessUsage{{PID: 123, Name: "worker", Command: "--token=abc"}}}, nil
}
func (fakeExecutor) HostHealthSummary(context.Context) (ports.HostHealthSummary, error) {
	return ports.HostHealthSummary{Status: "healthy", Timestamp: "2026-07-24T10:00:00Z"}, nil
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
func (fakeExecutor) ListContainers(context.Context) ([]ports.ContainerSummary, error) {
	return nil, nil
}

type fakeExecutorWithExtraContainer struct {
	fakeExecutor
}

func (fakeExecutorWithExtraContainer) ListContainers(context.Context) ([]ports.ContainerSummary, error) {
	return []ports.ContainerSummary{
		{Alias: "container-alpha", Management: "podman", State: "running", Health: "healthy"},
		{Alias: "unknown-container", Management: "podman", State: "running", Health: "healthy"},
	}, nil
}

func (fakeExecutor) ContainerStatus(context.Context, string) (ports.ContainerStatus, error) {
	return ports.ContainerStatus{Alias: "container-alpha", State: "running", Health: "healthy"}, nil
}
func (fakeExecutor) ContainerLogs(context.Context, ports.ContainerLogsRequest) (ports.ContainerLogsResponse, error) {
	return ports.ContainerLogsResponse{Entries: []ports.ContainerLogEntry{{Message: "token=abc"}}, UntrustedContent: true}, nil
}
func (fakeExecutor) RestartContainer(context.Context, ports.RestartContainerRequest) (ports.RestartContainerResponse, error) {
	return ports.RestartContainerResponse{Status: "executed", Action: "restart_container", ResourceKind: "container", Resource: "container-alpha", ContainerState: "running", Health: ports.ContainerHealthResult{Configured: true, Status: "healthy", Attempts: 1}}, nil
}
func (fakeExecutor) RestartGroup(context.Context, ports.RestartGroupRequest) (ports.RestartGroupResponse, error) {
	return ports.RestartGroupResponse{Status: "executed", Action: "restart_group", Group: "app-stack"}, nil
}
func (fakeExecutor) RotateLogs(context.Context, ports.RotateLogsRequest) (ports.RotateLogsResponse, error) {
	return ports.RotateLogsResponse{Status: "simulated", DryRun: true}, nil
}
func (fakeExecutor) CleanupCache(context.Context, ports.CleanupCacheRequest) (ports.CleanupCacheResponse, error) {
	return ports.CleanupCacheResponse{Status: "simulated", DryRun: true}, nil
}
func (fakeExecutor) ResetFailureState(context.Context, ports.ResetFailureStateRequest) (ports.ResetFailureStateResponse, error) {
	return ports.ResetFailureStateResponse{Status: "simulated", ResourceKind: "service", Resource: "service-alpha", ResetOperation: "reset-failed", Result: "simulated"}, nil
}
func (fakeExecutor) RebootHost(context.Context, ports.RebootHostRequest) (ports.RebootHostResponse, error) {
	return ports.RebootHostResponse{Status: "simulated", Action: "reboot_host"}, nil
}
func (fakeExecutor) CancelHostReboot(context.Context, ports.RebootHostRequest) (ports.RebootHostResponse, error) {
	return ports.RebootHostResponse{Status: "executed", Action: "cancel_reboot_host"}, nil
}
func (fakeExecutor) ApplicationVersion(context.Context, ports.ApplicationVersionRequest) (ports.ApplicationVersionResponse, error) {
	return ports.ApplicationVersionResponse{Application: "app-service", Kind: "service", CurrentVersion: "1.0.0", AvailableVersion: "1.0.1", AvailableCommit: "commit-next"}, nil
}
func (fakeExecutor) CheckApplicationUpdate(context.Context, ports.ApplicationVersionRequest) (ports.ApplicationUpdateCheckResponse, error) {
	return ports.ApplicationUpdateCheckResponse{Application: "app-service", CurrentVersion: "1.0.0", AvailableVersion: "1.0.1", AvailableCommit: "commit-next", UpdateAvailable: true}, nil
}
func (fakeExecutor) UpdateApplication(context.Context, ports.UpdateApplicationRequest) (ports.ApplicationDeploymentResponse, error) {
	return ports.ApplicationDeploymentResponse{Status: "success", Action: "update_application", Application: "app-service", PreviousVersion: "1.0.0", CurrentVersion: "1.0.1", TargetVersion: "1.0.1", CommitHash: "commit-next"}, nil
}
func (fakeExecutor) RollbackApplication(context.Context, ports.RollbackApplicationRequest) (ports.ApplicationDeploymentResponse, error) {
	return ports.ApplicationDeploymentResponse{Status: "success", Action: "rollback_application", Application: "app-service", PreviousVersion: "1.0.1", CurrentVersion: "1.0.0", TargetVersion: "1.0.0", CommitHash: "commit-prev"}, nil
}
func (fakeExecutor) CreateBackup(context.Context, ports.CreateBackupRequest) (ports.BackupExecutionResponse, error) {
	return ports.BackupExecutionResponse{Status: "completed", Action: "create_backup", BackupAlias: "backup-alpha", SourceAlias: "service-alpha", Backend: "command", SnapshotID: "snapshot-alpha", StartTime: "2026-07-24T10:00:00Z", EndTime: "2026-07-24T10:01:00Z", DurationSeconds: 60, SizeBytes: 1024, IntegrityVerified: true}, nil
}
func (fakeExecutor) VerifyBackup(context.Context, ports.VerifyBackupRequest) (ports.BackupVerificationResponse, error) {
	return ports.BackupVerificationResponse{Status: "verified", BackupAlias: "backup-alpha", IntegrityVerified: true, IntegrityCheckedAt: "2026-07-24T10:01:00Z"}, nil
}
func (fakeExecutor) ApplyRetentionPolicy(context.Context, ports.ApplyRetentionPolicyRequest) (ports.ApplyRetentionPolicyResponse, error) {
	return ports.ApplyRetentionPolicyResponse{Status: "completed", BackupAlias: "backup-alpha", RetentionSet: true}, nil
}
func (fakeExecutor) GenerateRestorePlan(context.Context, ports.RestorePlanRequest) (ports.RestorePlanResponse, error) {
	return ports.RestorePlanResponse{PlanID: "plan_1", Steps: []string{"Review backup metadata."}, RequiresApproval: true}, nil
}

type recordingExecutor struct {
	fakeExecutor
	restartServiceCalls int
}

func (e *recordingExecutor) RestartService(ctx context.Context, req ports.RestartServiceRequest) (ports.RestartServiceResponse, error) {
	e.restartServiceCalls++
	return e.fakeExecutor.RestartService(ctx, req)
}
