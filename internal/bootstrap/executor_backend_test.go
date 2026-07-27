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

func TestExecutorBackendContainerReadOperationsAndErrors(t *testing.T) {
	backend := testBackend()
	backend.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "system"}
	backend.Config.Containers = map[string]config.ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
		"denied": {
			ContainerName: "denied-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "deny", Logs: "deny", Restart: "deny"},
		},
	}
	ctx := context.Background()
	if out, err := backend.ListContainers(ctx); err != nil || len(out) != 2 || out[0].Alias != "container-alpha" {
		t.Fatalf("ListContainers() = %+v, %v", out, err)
	}
	if out, err := backend.ContainerStatus(ctx, "container-alpha"); err != nil || out.State != "running" {
		t.Fatalf("ContainerStatus() = %+v, %v", out, err)
	}
	if out, err := backend.ContainerLogs(ctx, ports.ContainerLogsRequest{Container: "container-alpha", Lines: 1}); err != nil || !out.UntrustedContent {
		t.Fatalf("ContainerLogs() = %+v, %v", out, err)
	}
	disabled := backend
	disabled.Config.Podman.Enabled = false
	if _, err := disabled.ListContainers(ctx); err == nil {
		t.Fatal("ListContainers() error = nil, want disabled error")
	}
	if _, err := disabled.ContainerStatus(ctx, "container-alpha"); err == nil {
		t.Fatal("ContainerStatus() error = nil, want disabled error")
	}
	if _, err := disabled.ContainerLogs(ctx, ports.ContainerLogsRequest{Container: "container-alpha"}); err == nil {
		t.Fatal("ContainerLogs() error = nil, want disabled error")
	}
	if _, err := backend.ContainerStatus(ctx, "missing"); err == nil {
		t.Fatal("ContainerStatus() error = nil, want missing error")
	}
	if _, err := backend.ContainerStatus(ctx, "denied"); err == nil {
		t.Fatal("ContainerStatus() error = nil, want denied error")
	}
	if _, err := backend.ContainerLogs(ctx, ports.ContainerLogsRequest{Container: "missing"}); err == nil {
		t.Fatal("ContainerLogs() error = nil, want missing error")
	}
	if _, err := backend.ContainerLogs(ctx, ports.ContainerLogsRequest{Container: "denied"}); err == nil {
		t.Fatal("ContainerLogs() error = nil, want denied error")
	}
}

func TestExecutorBackendContainerRestartValidationDryRunAndErrors(t *testing.T) {
	backend := testBackend()
	backend.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	backend.Config.Limits = config.LimitsConfig{MaxHealthcheckAttempts: 3}
	backend.Config.Containers = map[string]config.ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
		"workload-alpha": {
			ContainerName: "worker-alpha-container",
			Management:    "quadlet",
			QuadletUnit:   "worker-alpha.service",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
		"denied": {
			ContainerName: "denied-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "deny"},
		},
	}
	ctx := context.Background()
	if _, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "missing", OperationID: "op_1"}); err == nil {
		t.Fatal("RestartContainer() error = nil, want missing error")
	}
	if _, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "denied", OperationID: "op_1"}); err == nil {
		t.Fatal("RestartContainer() error = nil, want denied error")
	}
	if _, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "container-alpha"}); err == nil {
		t.Fatal("RestartContainer() error = nil, want operation_id error")
	}
	if out, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "container-alpha", OperationID: "op_1", DryRun: true}); err != nil || out.WouldRun != "/usr/bin/podman restart app-alpha-container" {
		t.Fatalf("podman dry-run = %+v, %v", out, err)
	}
	if out, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "workload-alpha", OperationID: "op_2", DryRun: true}); err != nil || out.WouldRun != "/usr/bin/systemctl --user restart worker-alpha.service" {
		t.Fatalf("quadlet dry-run = %+v, %v", out, err)
	}
	backend.Podman = &fakePodman{restartErr: errors.New("restart failed")}
	if _, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "container-alpha", OperationID: "op_3"}); err == nil {
		t.Fatal("RestartContainer() error = nil, want restart error")
	}
	backend.Podman = &fakePodman{runningErr: errors.New("not running")}
	if _, err := backend.RestartContainer(ctx, ports.RestartContainerRequest{ContainerAlias: "container-alpha", OperationID: "op_4"}); err == nil {
		t.Fatal("RestartContainer() error = nil, want running error")
	}
}

func TestExecutorBackendContainerRestartSkipsHealthPollingWhenNotConfigured(t *testing.T) {
	backend := testBackend()
	backend.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless"}
	backend.Config.Limits = config.LimitsConfig{MaxHealthcheckAttempts: 3}
	backend.Config.Containers = map[string]config.ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
	}
	podman := &fakePodman{status: ports.ContainerStatus{Exists: true, State: "running", Health: "not_configured"}}
	backend.Podman = podman
	out, err := backend.RestartContainer(context.Background(), ports.RestartContainerRequest{ContainerAlias: "container-alpha", OperationID: "op_1"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Health.Configured || out.Health.Status != "not_configured" || podman.waitHealthCalls != 0 {
		t.Fatalf("restart result = %+v, waitHealthCalls=%d", out, podman.waitHealthCalls)
	}
}

func TestExecutorBackendContainerRestartHealthFailures(t *testing.T) {
	backend := testBackend()
	backend.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless"}
	backend.Config.Limits = config.LimitsConfig{MaxHealthcheckAttempts: 3}
	backend.Config.Containers = map[string]config.ContainerConfig{
		"container-alpha": {
			ContainerName: "app-alpha-container",
			Management:    "podman",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
			Health:        config.ContainerHealthConfig{RequireHealthyAfterRestart: true},
		},
	}
	backend.Podman = &fakePodman{
		status:        ports.ContainerStatus{Exists: true, State: "running", Health: "starting"},
		health:        "unhealthy",
		waitHealthErr: errors.New("container unhealthy"),
	}
	if _, err := backend.RestartContainer(context.Background(), ports.RestartContainerRequest{ContainerAlias: "container-alpha", OperationID: "op_1"}); err == nil {
		t.Fatal("RestartContainer() error = nil, want unhealthy error")
	}

	backend.Config.Containers["container-alpha"] = config.ContainerConfig{
		ContainerName: "app-alpha-container",
		Management:    "podman",
		Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
	}
	backend.Podman = &fakePodman{
		status:        ports.ContainerStatus{Exists: true, State: "running", Health: "starting"},
		health:        "starting",
		waitHealthErr: errors.New("health still starting"),
	}
	out, err := backend.RestartContainer(context.Background(), ports.RestartContainerRequest{ContainerAlias: "container-alpha", OperationID: "op_2"})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Health.Configured || out.Health.Status != "starting" {
		t.Fatalf("restart result = %+v", out)
	}
}

func TestExecutorBackendQuadletUsesConfiguredSystemdScope(t *testing.T) {
	backend := testBackend()
	backend.Config.Podman = config.PodmanConfig{Enabled: true, Binary: "/usr/bin/podman", Mode: "rootless", SystemdScope: "user"}
	backend.Config.Limits = config.LimitsConfig{MaxHealthcheckAttempts: 3}
	backend.Config.Containers = map[string]config.ContainerConfig{
		"workload-alpha": {
			ContainerName: "worker-alpha-container",
			Management:    "quadlet",
			QuadletUnit:   "worker-alpha.service",
			Permissions:   config.PermissionsConfig{Status: "allow", Logs: "allow", Restart: "confirm"},
		},
	}
	sys := backend.Systemd.(*fakeSystemd)
	backend.Podman = &fakePodman{status: ports.ContainerStatus{Exists: true, State: "running", Health: "not_configured"}}
	if _, err := backend.ContainerStatus(context.Background(), "workload-alpha"); err != nil {
		t.Fatal(err)
	}
	if sys.statusScope != "user" {
		t.Fatalf("status scope = %q, want user", sys.statusScope)
	}
	if _, err := backend.RestartContainer(context.Background(), ports.RestartContainerRequest{ContainerAlias: "workload-alpha", OperationID: "op_1"}); err != nil {
		t.Fatal(err)
	}
	if sys.restartScope != "user" || sys.restartUnit != "worker-alpha.service" {
		t.Fatalf("restart scope/unit = %q/%q", sys.restartScope, sys.restartUnit)
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
		Podman:      &fakePodman{},
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
	err          error
	restartUnit  string
	restartScope string
	statusScope  string
}

func (s *fakeSystemd) Status(_ context.Context, alias, unit string) (service.Status, error) {
	return service.Status{Alias: alias, Unit: unit, ActiveState: "active"}, s.err
}

func (s *fakeSystemd) Restart(context.Context, string) error {
	return s.err
}

func (s *fakeSystemd) StatusWithScope(ctx context.Context, alias, unit, scope string) (service.Status, error) {
	s.statusScope = scope
	return s.Status(ctx, alias, unit)
}

func (s *fakeSystemd) RestartWithScope(ctx context.Context, unit, scope string) error {
	s.restartUnit = unit
	s.restartScope = scope
	return s.Restart(ctx, unit)
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

type fakePodman struct {
	status          ports.ContainerStatus
	health          string
	waitHealthErr   error
	restartErr      error
	runningErr      error
	restarted       string
	waitHealthCalls int
}

func (p *fakePodman) InspectContainer(context.Context, string, string, string) (ports.ContainerStatus, error) {
	if p.status.Exists {
		return p.status, nil
	}
	return ports.ContainerStatus{Exists: true, State: "running", Health: "healthy"}, nil
}
func (p *fakePodman) Logs(context.Context, string, int, string) ([]ports.ContainerLogEntry, bool, error) {
	return []ports.ContainerLogEntry{{Message: "ok"}}, false, nil
}
func (p *fakePodman) Restart(_ context.Context, name string) error {
	p.restarted = name
	return p.restartErr
}
func (p *fakePodman) WaitForRunning(context.Context, string, string, string, int, time.Duration) (ports.ContainerStatus, int, error) {
	if p.runningErr != nil {
		return ports.ContainerStatus{}, 1, p.runningErr
	}
	if p.status.Exists {
		return p.status, 1, nil
	}
	return ports.ContainerStatus{Exists: true, State: "running", Health: "healthy"}, 1, nil
}
func (p *fakePodman) WaitForHealth(context.Context, string, string, string, int, time.Duration) (string, int, error) {
	p.waitHealthCalls++
	if p.health != "" || p.waitHealthErr != nil {
		return p.health, 1, p.waitHealthErr
	}
	return "healthy", 1, nil
}
