package bootstrap

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

func TestExecutorBackendReadOperations(t *testing.T) {
	backend := testBackend()
	ctx := context.Background()
	if out, err := backend.SystemStatus(ctx); err != nil || out.Hostname != "host-alpha" {
		t.Fatalf("SystemStatus() = %+v, %v", out, err)
	}
	if out, err := backend.DiskStatus(ctx, "root"); err != nil || out.PathAlias != "root" {
		t.Fatalf("DiskStatus() = %+v, %v", out, err)
	}
	if out, err := backend.ServiceStatus(ctx, "service-alpha"); err != nil || out.Unit != "app-alpha.service" {
		t.Fatalf("ServiceStatus() = %+v, %v", out, err)
	}
	if out, err := backend.ServiceLogs(ctx, ports.ServiceLogsRequest{Service: "service-alpha", Lines: 10}); err != nil || !out.UntrustedContent {
		t.Fatalf("ServiceLogs() = %+v, %v", out, err)
	}
	if out, err := backend.ListServices(ctx); err != nil || len(out) != 2 || out[0].Alias != "service-alpha" {
		t.Fatalf("ListServices() = %+v, %v", out, err)
	}
}

func TestExecutorBackendRejectsUnknownOrDeniedAliases(t *testing.T) {
	backend := testBackend()
	ctx := context.Background()
	if _, err := backend.DiskStatus(ctx, "free-path"); err == nil {
		t.Fatal("DiskStatus() error = nil, want error")
	}
	if _, err := backend.ServiceStatus(ctx, "missing"); err == nil {
		t.Fatal("ServiceStatus() error = nil, want error")
	}
	if _, err := backend.ServiceLogs(ctx, ports.ServiceLogsRequest{Service: "service-denied"}); err == nil {
		t.Fatal("ServiceLogs() error = nil, want error")
	}
	if _, err := backend.RestartService(ctx, ports.RestartServiceRequest{Service: "service-denied", OperationID: "op_1"}); err == nil {
		t.Fatal("RestartService() error = nil, want error")
	}
}

func TestExecutorBackendRestartDryRunAndExecute(t *testing.T) {
	backend := testBackend()
	ctx := context.Background()
	if _, err := backend.RestartService(ctx, ports.RestartServiceRequest{Service: "service-alpha"}); err == nil {
		t.Fatal("RestartService() error = nil, want missing operation_id error")
	}
	dry, err := backend.RestartService(ctx, ports.RestartServiceRequest{Service: "service-alpha", OperationID: "op_1", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if dry.Status != "simulated" || dry.WouldRun == "" {
		t.Fatalf("dry-run result = %+v", dry)
	}
	executed, err := backend.RestartService(ctx, ports.RestartServiceRequest{Service: "service-alpha", OperationID: "op_2"})
	if err != nil {
		t.Fatal(err)
	}
	if executed.Status != "executed" || executed.Healthcheck == nil || !executed.Healthcheck.Healthy {
		t.Fatalf("executed result = %+v", executed)
	}
}

func TestExecutorBackendRestartPropagatesErrors(t *testing.T) {
	backend := testBackend()
	sys := backend.Systemd.(*fakeSystemd)
	sys.err = errors.New("restart failed")
	if _, err := backend.RestartService(context.Background(), ports.RestartServiceRequest{Service: "service-alpha", OperationID: "op_1"}); err == nil {
		t.Fatal("RestartService() error = nil, want error")
	}
}

func TestExecutorBackendServiceLogsPropagatesErrors(t *testing.T) {
	backend := testBackend()
	backend.Journal = fakeJournal{err: errors.New("journal failed")}
	if _, err := backend.ServiceLogs(context.Background(), ports.ServiceLogsRequest{Service: "service-alpha", Lines: 1}); err == nil {
		t.Fatal("ServiceLogs() error = nil, want journal error")
	}
}

func testBackend() ExecutorBackend {
	cfg := config.Config{
		Filesystem: config.FilesystemConfig{DiskPaths: map[string]config.DiskPathConfig{"root": {Path: "/"}}},
		Services: map[string]config.ServiceConfig{
			"service-alpha": {
				Unit:        "app-alpha.service",
				Permissions: config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
				Healthcheck: &config.HealthcheckConfig{URL: "http://127.0.0.1/health", Timeout: config.Duration(time.Second), Attempts: 2, Interval: config.Duration(time.Millisecond)},
			},
			"service-denied": {
				Unit:        "app-denied.service",
				Permissions: config.PermissionsConfig{Status: "deny", Logs: "deny", Restart: "deny"},
			},
		},
	}
	return ExecutorBackend{
		Config:      cfg,
		Host:        fakeHost{},
		Disk:        fakeDisk{},
		Systemd:     &fakeSystemd{},
		Journal:     fakeJournal{},
		Healthcheck: fakeHealthcheck{},
	}
}

type fakeHost struct{}

func (fakeHost) SystemStatus(context.Context) (ports.SystemStatus, error) {
	return ports.SystemStatus{Hostname: "host-alpha"}, nil
}

type fakeDisk struct{}

func (fakeDisk) DiskStatus(_ context.Context, alias string) (ports.DiskStatus, error) {
	return ports.DiskStatus{PathAlias: alias}, nil
}

type fakeSystemd struct {
	err error
}

func (s *fakeSystemd) Status(_ context.Context, alias, unit string) (service.Status, error) {
	return service.Status{Alias: alias, Unit: unit, ActiveState: "active"}, s.err
}

func (s *fakeSystemd) Restart(context.Context, string) error {
	return s.err
}

type fakeJournal struct {
	err error
}

func (j fakeJournal) Logs(context.Context, string, int, string, string) ([]service.LogEntry, bool, error) {
	if j.err != nil {
		return nil, false, j.err
	}
	return []service.LogEntry{{Message: "ok"}}, false, nil
}

type fakeHealthcheck struct{}

func (fakeHealthcheck) Check(context.Context, string, time.Duration, int, time.Duration) (bool, int) {
	return true, 1
}
