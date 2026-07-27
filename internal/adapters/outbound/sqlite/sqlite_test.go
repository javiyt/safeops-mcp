package sqlite

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
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
