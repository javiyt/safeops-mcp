package sqlite

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/backup"
	"github.com/javiyt/safeops-mcp/internal/domain/deployment"
)

func TestMigrationsAreIdempotentAndApprovalCannotExecuteTwice(t *testing.T) {
	store, err := Open(t.TempDir() + "/safeops.db")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = store.Close()
	}()
	ctx := context.Background()
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	a := approval.Approval{
		ID: "apr_1", UserID: "operator", Tool: "request_service_restart", Action: "restart_service",
		NormalizedArguments: "{}", ArgumentsHash: "hash", ConfirmationCodeHash: "codehash",
		Status: approval.StatusPending, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := store.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkExecuting(ctx, "apr_1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkExecuting(ctx, "apr_1", now); err == nil {
		t.Fatal("second MarkExecuting succeeded, want rejection")
	}
}

func TestApprovalRepositoryLifecycle(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	a := approval.Approval{
		ID: "apr_2", UserID: "operator", Tool: "request_service_restart", Action: "restart_service",
		NormalizedArguments: `{"service":"service-alpha"}`, ArgumentsHash: "hash", ConfirmationCodeHash: "codehash",
		Status: approval.StatusPending, CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	if err := store.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "apr_2")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != "operator" || got.Status != approval.StatusPending {
		t.Fatalf("Get() = %+v", got)
	}
	if err := store.Cancel(ctx, "apr_2", "operator", now); err != nil {
		t.Fatal(err)
	}
	got, err = store.Get(ctx, "apr_2")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != approval.StatusRejected {
		t.Fatalf("status = %s", got.Status)
	}
	items, err := store.List(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("List() length = %d", len(items))
	}
}

func TestBackupRepositoryLifecycle(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	end := now.Add(time.Minute)
	checked := end.Add(10 * time.Second)
	record := backup.Record{
		ID:                 "backup_1",
		BackupAlias:        "backup-alpha",
		SourceAlias:        "service-alpha",
		Backend:            "command",
		SnapshotID:         "snapshot-alpha",
		Status:             backup.StatusVerified,
		StartTime:          now,
		EndTime:            &end,
		DurationSeconds:    60,
		SizeBytes:          1024,
		IntegrityVerified:  true,
		IntegrityCheckedAt: &checked,
		Metadata:           `{"backend":"command"}`,
		CreatedAt:          now,
	}
	if err := store.AppendBackup(ctx, record); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetBackup(ctx, "backup_1")
	if err != nil {
		t.Fatal(err)
	}
	if got.BackupAlias != "backup-alpha" || !got.IntegrityVerified || got.EndTime == nil {
		t.Fatalf("GetBackup() = %+v", got)
	}
	latest, err := store.LatestBackup(ctx, "backup-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if latest.ID != "backup_1" {
		t.Fatalf("LatestBackup() = %+v", latest)
	}
	items, err := store.ListBackups(ctx, backup.ListFilter{BackupAlias: "backup-alpha"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("ListBackups() length = %d", len(items))
	}
	running, err := store.BackupInProgress(ctx, "backup-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if running {
		t.Fatal("BackupInProgress() = true, want false")
	}
}

func TestApprovalMarkDoneAndExpiredMarkExecuting(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	a := approval.Approval{
		ID: "apr_3", UserID: "operator", Tool: "request_service_restart", Action: "restart_service",
		NormalizedArguments: `{}`, ArgumentsHash: "hash", ConfirmationCodeHash: "codehash",
		Status: approval.StatusPending, CreatedAt: now, ExpiresAt: now.Add(-time.Minute),
	}
	if err := store.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkExecuting(ctx, "apr_3", now); err == nil {
		t.Fatal("MarkExecuting() error = nil, want expired error")
	}
	a.ID = "apr_4"
	a.ExpiresAt = now.Add(time.Minute)
	if err := store.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := store.MarkExecuting(ctx, "apr_4", now); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkDone(ctx, "apr_4", approval.StatusExecuted, "done", "", now); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "apr_4")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != approval.StatusExecuted || got.ExecutedAt == nil {
		t.Fatalf("Get() = %+v", got)
	}
}

func TestDeploymentHistoryRepository(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	records := []deployment.HistoryRecord{
		{ID: "dep_1", ApplicationAlias: "app-service", Version: "1.0.0", DeployedAt: now, DeploymentType: "update", TriggeredBy: "operator", Status: "success", CreatedAt: now},
		{ID: "dep_2", ApplicationAlias: "app-service", Version: "1.0.1", DeployedAt: now.Add(time.Minute), DeploymentType: "update", TriggeredBy: "operator", Status: "success", PreviousVersion: "1.0.0", CommitHash: "commit-next", CreatedAt: now.Add(time.Minute)},
	}
	for _, record := range records {
		if err := store.AppendDeployment(ctx, record); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := store.LatestSuccessfulDeployment(ctx, "app-service")
	if err != nil {
		t.Fatal(err)
	}
	if latest.Version != "1.0.1" || latest.CommitHash != "commit-next" {
		t.Fatalf("latest = %+v", latest)
	}
	if err := store.PruneDeployments(ctx, "app-service", 1); err != nil {
		t.Fatal(err)
	}
	items, err := store.ListDeployments(ctx, "app-service", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != "dep_2" {
		t.Fatalf("items = %+v", items)
	}
}

func TestAuditRepository(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	event := audit.Event{
		ID: "aud_1", Timestamp: time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC), UserID: "operator",
		Component: "safeops-mcp", EventType: "approval_requested", Tool: "request_service_restart",
		Action: "restart_service", Arguments: `{}`, Risk: "mutating", PolicyDecision: "require_approval",
		Status: "pending", ResultSummary: "", ErrorSummary: "", ApprovalID: "apr_1", OperationID: "op_1",
	}
	if err := store.Append(ctx, event); err != nil {
		t.Fatal(err)
	}
	events, err := store.ListAudit(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != "aud_1" {
		t.Fatalf("ListAudit() = %+v", events)
	}
}

func TestOperationLocks(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	if err := store.AcquireOperationLock(ctx, "container", "container-alpha", "op_1", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AcquireOperationLock(ctx, "container", "container-alpha", "op_2", time.Now().Add(time.Minute)); err == nil {
		t.Fatal("AcquireOperationLock() error = nil, want conflict")
	}
	if err := store.ReleaseOperationLock(ctx, "container", "container-alpha", "op_1"); err != nil {
		t.Fatal(err)
	}
	if err := store.AcquireOperationLock(ctx, "container", "container-alpha", "op_2", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.AcquireOperationLock(ctx, "container", "container-alpha", "op_3", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestOperationLocksRejectConcurrentMutableActions(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	var acquired int32
	var conflicted int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(operationID string) {
			defer wg.Done()
			<-start
			err := store.AcquireOperationLock(ctx, "container", "container-alpha", operationID, time.Now().Add(time.Minute))
			if err != nil {
				atomic.AddInt32(&conflicted, 1)
				return
			}
			atomic.AddInt32(&acquired, 1)
			time.Sleep(10 * time.Millisecond)
			if err := store.ReleaseOperationLock(ctx, "container", "container-alpha", operationID); err != nil {
				t.Errorf("ReleaseOperationLock() error = %v", err)
			}
		}(approvalIDForIndex(i))
	}
	close(start)
	wg.Wait()
	if acquired != 1 || conflicted != 1 {
		t.Fatalf("acquired=%d conflicted=%d, want 1/1", acquired, conflicted)
	}
	if err := store.AcquireOperationLock(ctx, "container", "container-alpha", "op_after", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("lock was not released after operation: %v", err)
	}
}

func TestAlertRepositoryLifecycle(t *testing.T) {
	store := migratedStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)
	finding := alert.Finding{
		ResourceKind:  "service",
		ResourceAlias: "service-a",
		Type:          "service_stopped",
		Severity:      alert.SeverityCritical,
		Message:       "Service service-a is inactive.",
		Metadata:      `{"active_state":"failed"}`,
	}
	created, isNew, err := store.UpsertObserved(ctx, finding, now)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew || created.Status != alert.StatusNew || created.Count != 1 {
		t.Fatalf("created alert = %+v, isNew=%t", created, isNew)
	}
	updated, isNew, err := store.UpsertObserved(ctx, finding, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if isNew || updated.Status != alert.StatusActive || updated.Count != 2 {
		t.Fatalf("updated alert = %+v, isNew=%t", updated, isNew)
	}
	ack, err := store.AcknowledgeAlert(ctx, updated.ID, "operator", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != alert.StatusAcknowledged || ack.AcknowledgedBy != "operator" {
		t.Fatalf("acknowledged alert = %+v", ack)
	}
	suppressed, err := store.SilenceAlert(ctx, updated.ID, now.Add(time.Hour), now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if suppressed.Status != alert.StatusSuppressed || suppressed.SuppressedUntil == nil {
		t.Fatalf("suppressed alert = %+v", suppressed)
	}
	resolved, err := store.ResolveAlert(ctx, updated.ID, now.Add(4*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Status != alert.StatusResolved || resolved.ResolvedAt == nil {
		t.Fatalf("resolved alert = %+v", resolved)
	}
	items, err := store.ListAlerts(ctx, alert.ListFilter{Status: alert.StatusResolved}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != updated.ID {
		t.Fatalf("ListAlerts() = %+v", items)
	}
	pruned, err := store.PruneResolvedAlerts(ctx, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 1 {
		t.Fatalf("PruneResolvedAlerts() = %d, want 1", pruned)
	}
}

func approvalIDForIndex(i int) string {
	if i == 0 {
		return "op_1"
	}
	return "op_2"
}

func migratedStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(t.TempDir() + "/safeops.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	return store
}
