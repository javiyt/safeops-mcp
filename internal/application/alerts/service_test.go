package alerts

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlitestore "github.com/javiyt/safeops-mcp/internal/adapters/outbound/sqlite"
	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

func TestRunOnceAppliesPersistenceCooldownAndResolution(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	clock := &testClock{now: time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)}
	notifier := &recordingNotifier{}
	exec := &fakeExecutor{service: service.Status{Alias: "service-a", ActiveState: "failed", SubState: "failed"}}
	svc := Service{
		Config: config.Config{
			Identity: config.IdentityConfig{AdministratorID: "telegram:12345678"},
			Limits:   config.LimitsConfig{MaxLogLines: 20},
			Alerts: config.AlertsConfig{
				Enabled:              true,
				Cooldown:             config.Duration(5 * time.Minute),
				PersistenceThreshold: config.Duration(30 * time.Second),
				NotifyResolution:     true,
				Checks: config.AlertChecksConfig{
					Services: config.AlertCheckConfig{Enabled: true, Interval: config.Duration(30 * time.Second)},
				},
			},
			Services: map[string]config.ServiceConfig{"service-a": {Permissions: config.PermissionsConfig{Status: "allow"}}},
		},
		Executor: exec,
		Alerts:   store,
		Audit:    store,
		Notifier: notifier,
		Clock:    clock,
	}
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(notifier.messages) != 0 {
		t.Fatalf("messages before persistence threshold = %d", len(notifier.messages))
	}
	clock.now = clock.now.Add(31 * time.Second)
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(notifier.messages) != 1 {
		t.Fatalf("messages after threshold = %d", len(notifier.messages))
	}
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(notifier.messages) != 1 {
		t.Fatalf("messages during cooldown = %d", len(notifier.messages))
	}
	exec.service.ActiveState = "active"
	clock.now = clock.now.Add(6 * time.Minute)
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(notifier.messages) != 2 {
		t.Fatalf("messages after resolution = %d", len(notifier.messages))
	}
	items, err := store.ListAlerts(ctx, alert.ListFilter{Status: alert.StatusResolved}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("resolved alerts = %d", len(items))
	}
}

func TestRunOnceGroupsMultipleAlerts(t *testing.T) {
	ctx := context.Background()
	store := testStore(t)
	clock := &testClock{now: time.Date(2026, 7, 27, 10, 0, 0, 0, time.UTC)}
	notifier := &recordingNotifier{}
	svc := Service{
		Config: config.Config{
			Limits: config.LimitsConfig{MaxLogLines: 20},
			Alerts: config.AlertsConfig{
				Enabled:              true,
				Cooldown:             config.Duration(5 * time.Minute),
				PersistenceThreshold: 0,
				Checks: config.AlertChecksConfig{
					Services: config.AlertCheckConfig{Enabled: true, Interval: config.Duration(30 * time.Second)},
				},
			},
			Services: map[string]config.ServiceConfig{
				"service-a": {Permissions: config.PermissionsConfig{Status: "allow"}},
				"service-b": {Permissions: config.PermissionsConfig{Status: "allow"}},
			},
		},
		Executor: &fakeExecutor{service: service.Status{ActiveState: "failed"}},
		Alerts:   store,
		Audit:    store,
		Notifier: notifier,
		Clock:    clock,
	}
	if err := svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(notifier.messages) != 1 {
		t.Fatalf("messages = %d", len(notifier.messages))
	}
	if got := notifier.messages[0]; got[:9] != "Alerts: 2" {
		t.Fatalf("grouped message = %q", got)
	}
}

func testStore(t *testing.T) *sqlitestore.Store {
	t.Helper()
	store, err := sqlitestore.Open(t.TempDir() + "/safeops.db")
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

type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time {
	return c.now
}

type recordingNotifier struct {
	messages []string
}

func (n *recordingNotifier) Notify(_ context.Context, message string) error {
	n.messages = append(n.messages, message)
	return nil
}

type fakeExecutor struct {
	service service.Status
}

func (f *fakeExecutor) SystemStatus(context.Context) (ports.SystemStatus, error) {
	return ports.SystemStatus{}, nil
}

func (f *fakeExecutor) DiskStatus(context.Context, string) (ports.DiskStatus, error) {
	return ports.DiskStatus{}, nil
}

func (f *fakeExecutor) CPUStatus(context.Context) (ports.CPUStatus, error) {
	return ports.CPUStatus{}, nil
}

func (f *fakeExecutor) MemoryStatus(context.Context) (ports.MemoryStatus, error) {
	return ports.MemoryStatus{}, nil
}

func (f *fakeExecutor) DiskHealth(context.Context, string) (ports.DiskHealth, error) {
	return ports.DiskHealth{}, nil
}

func (f *fakeExecutor) NetworkStatus(context.Context) (ports.NetworkStatus, error) {
	return ports.NetworkStatus{}, nil
}

func (f *fakeExecutor) TimeStatus(context.Context) (ports.TimeStatus, error) {
	return ports.TimeStatus{}, nil
}

func (f *fakeExecutor) ConfiguredProcessStatus(context.Context) (ports.ConfiguredProcessStatus, error) {
	return ports.ConfiguredProcessStatus{}, nil
}

func (f *fakeExecutor) HostHealthSummary(context.Context) (ports.HostHealthSummary, error) {
	return ports.HostHealthSummary{}, nil
}

func (f *fakeExecutor) ListServices(context.Context) ([]ports.ServiceSummary, error) {
	return nil, nil
}

func (f *fakeExecutor) ServiceStatus(_ context.Context, alias string) (service.Status, error) {
	if alias == "" {
		return service.Status{}, errors.New("missing alias")
	}
	out := f.service
	out.Alias = alias
	return out, nil
}

func (f *fakeExecutor) ServiceLogs(context.Context, ports.ServiceLogsRequest) (ports.ServiceLogsResponse, error) {
	return ports.ServiceLogsResponse{}, nil
}

func (f *fakeExecutor) RestartService(context.Context, ports.RestartServiceRequest) (ports.RestartServiceResponse, error) {
	return ports.RestartServiceResponse{}, nil
}

func (f *fakeExecutor) ListContainers(context.Context) ([]ports.ContainerSummary, error) {
	return nil, nil
}

func (f *fakeExecutor) ContainerStatus(context.Context, string) (ports.ContainerStatus, error) {
	return ports.ContainerStatus{}, nil
}

func (f *fakeExecutor) ContainerLogs(context.Context, ports.ContainerLogsRequest) (ports.ContainerLogsResponse, error) {
	return ports.ContainerLogsResponse{}, nil
}

func (f *fakeExecutor) RestartContainer(context.Context, ports.RestartContainerRequest) (ports.RestartContainerResponse, error) {
	return ports.RestartContainerResponse{}, nil
}

var _ ports.ExecutorClient = (*fakeExecutor)(nil)
var _ ports.AuditRepository = (*sqlitestore.Store)(nil)
var _ ports.AlertRepository = (*sqlitestore.Store)(nil)
var _ ports.Clock = (*testClock)(nil)
var _ Notifier = (*recordingNotifier)(nil)
var _ = audit.Event{}
