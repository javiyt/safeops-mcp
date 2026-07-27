package bootstrap

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type ExecutorBackend struct {
	Config      config.Config
	Host        HostStatusReader
	Disk        DiskReader
	Systemd     SystemdClient
	Journal     JournalReader
	Healthcheck HealthcheckClient
	Podman      PodmanClient
}

type HostStatusReader interface {
	SystemStatus(ctx context.Context) (ports.SystemStatus, error)
}

type DiskReader interface {
	DiskStatus(ctx context.Context, alias string) (ports.DiskStatus, error)
}

type SystemdClient interface {
	Status(ctx context.Context, alias, unit string) (service.Status, error)
	Restart(ctx context.Context, unit string) error
	StatusWithScope(ctx context.Context, alias, unit, scope string) (service.Status, error)
	RestartWithScope(ctx context.Context, unit, scope string) error
}

type JournalReader interface {
	Logs(ctx context.Context, unit string, lines int, priority, since string) ([]service.LogEntry, bool, error)
}

type HealthcheckClient interface {
	Check(ctx context.Context, url string, timeout time.Duration, attempts int, interval time.Duration) (bool, int)
}

type PodmanClient interface {
	InspectContainer(ctx context.Context, alias, name, management string) (ports.ContainerStatus, error)
	Logs(ctx context.Context, name string, lines int, since string) ([]ports.ContainerLogEntry, bool, error)
	Restart(ctx context.Context, name string) error
	WaitForRunning(ctx context.Context, alias, name, management string, attempts int, interval time.Duration) (ports.ContainerStatus, int, error)
	WaitForHealth(ctx context.Context, alias, name, management string, attempts int, interval time.Duration) (string, int, error)
}

func (b ExecutorBackend) SystemStatus(ctx context.Context) (ports.SystemStatus, error) {
	return b.Host.SystemStatus(ctx)
}

func (b ExecutorBackend) DiskStatus(ctx context.Context, alias string) (ports.DiskStatus, error) {
	if _, ok := b.Config.Filesystem.DiskPaths[alias]; !ok {
		return ports.DiskStatus{}, fmt.Errorf("disk path alias %q is not configured", alias)
	}
	return b.Disk.DiskStatus(ctx, alias)
}

func (b ExecutorBackend) ListServices(ctx context.Context) ([]ports.ServiceSummary, error) {
	aliases := make([]string, 0, len(b.Config.Services))
	for alias := range b.Config.Services {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	out := make([]ports.ServiceSummary, 0, len(aliases))
	for _, alias := range aliases {
		st, err := b.ServiceStatus(ctx, alias)
		status := "unknown"
		if err == nil {
			status = st.ActiveState
		}
		out = append(out, ports.ServiceSummary{Alias: alias, Status: status})
	}
	return out, nil
}

func (b ExecutorBackend) ServiceStatus(ctx context.Context, alias string) (service.Status, error) {
	svc, ok := b.Config.Services[alias]
	if !ok {
		return service.Status{}, fmt.Errorf("service alias %q is not configured", alias)
	}
	if svc.Permissions.Status != "allow" {
		return service.Status{}, fmt.Errorf("service alias %q does not allow status", alias)
	}
	return b.Systemd.Status(ctx, alias, svc.Unit)
}

func (b ExecutorBackend) ServiceLogs(ctx context.Context, req ports.ServiceLogsRequest) (ports.ServiceLogsResponse, error) {
	svc, ok := b.Config.Services[req.Service]
	if !ok {
		return ports.ServiceLogsResponse{}, fmt.Errorf("service alias %q is not configured", req.Service)
	}
	if svc.Permissions.Logs != "allow" {
		return ports.ServiceLogsResponse{}, fmt.Errorf("service alias %q does not allow logs", req.Service)
	}
	entries, truncated, err := b.Journal.Logs(ctx, svc.Unit, req.Lines, req.Priority, req.Since)
	if err != nil {
		return ports.ServiceLogsResponse{}, err
	}
	return ports.ServiceLogsResponse{Service: req.Service, Entries: entries, Truncated: truncated, UntrustedContent: true}, nil
}

func (b ExecutorBackend) RestartService(ctx context.Context, req ports.RestartServiceRequest) (ports.RestartServiceResponse, error) {
	svc, ok := b.Config.Services[req.Service]
	if !ok {
		return ports.RestartServiceResponse{}, fmt.Errorf("service alias %q is not configured", req.Service)
	}
	if svc.Permissions.Restart != "confirm" {
		return ports.RestartServiceResponse{}, fmt.Errorf("service alias %q does not allow confirmed restarts", req.Service)
	}
	if req.OperationID == "" {
		return ports.RestartServiceResponse{}, fmt.Errorf("operation_id is required")
	}
	if req.DryRun {
		return ports.RestartServiceResponse{
			Status:        "simulated",
			Action:        "restart_service",
			Service:       req.Service,
			ServiceStatus: "unchanged",
			WouldRun:      "/usr/bin/systemctl restart " + svc.Unit,
		}, nil
	}
	if err := b.Systemd.Restart(ctx, svc.Unit); err != nil {
		return ports.RestartServiceResponse{}, err
	}
	status, err := b.Systemd.Status(ctx, req.Service, svc.Unit)
	if err != nil {
		return ports.RestartServiceResponse{}, err
	}
	var hc *ports.HealthcheckResult
	if svc.Healthcheck != nil {
		healthy, attempts := b.Healthcheck.Check(ctx, svc.Healthcheck.URL, svc.Healthcheck.Timeout.Std(), svc.Healthcheck.Attempts, svc.Healthcheck.Interval.Std())
		hc = &ports.HealthcheckResult{Configured: true, Healthy: healthy, Attempts: attempts}
	}
	return ports.RestartServiceResponse{
		Status:        "executed",
		Action:        "restart_service",
		Service:       req.Service,
		ServiceStatus: status.ActiveState,
		Healthcheck:   hc,
	}, nil
}

func (b ExecutorBackend) ListContainers(ctx context.Context) ([]ports.ContainerSummary, error) {
	if !b.Config.Podman.Enabled {
		return nil, fmt.Errorf("podman is not enabled")
	}
	aliases := make([]string, 0, len(b.Config.Containers))
	for alias := range b.Config.Containers {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	out := make([]ports.ContainerSummary, 0, len(aliases))
	for _, alias := range aliases {
		ctr := b.Config.Containers[alias]
		st, err := b.ContainerStatus(ctx, alias)
		state, health := "unknown", "unknown"
		if err == nil {
			state = st.State
			health = st.Health
		}
		out = append(out, ports.ContainerSummary{Alias: alias, Management: ctr.Management, State: state, Health: health})
	}
	return out, nil
}

func (b ExecutorBackend) ContainerStatus(ctx context.Context, alias string) (ports.ContainerStatus, error) {
	if !b.Config.Podman.Enabled {
		return ports.ContainerStatus{}, fmt.Errorf("podman is not enabled")
	}
	ctr, ok := b.Config.Containers[alias]
	if !ok {
		return ports.ContainerStatus{}, fmt.Errorf("container alias %q is not configured", alias)
	}
	if ctr.Permissions.Status != "allow" {
		return ports.ContainerStatus{}, fmt.Errorf("container alias %q does not allow status", alias)
	}
	st, err := b.Podman.InspectContainer(ctx, alias, ctr.ContainerName, ctr.Management)
	if err != nil {
		return ports.ContainerStatus{}, err
	}
	if ctr.Management == "quadlet" {
		scope := b.Config.Podman.SystemdScope
		if scope == "" {
			scope = "system"
		}
		unit, err := b.Systemd.StatusWithScope(ctx, alias, ctr.QuadletUnit, scope)
		if err == nil {
			st.Quadlet = &ports.QuadletStatus{Unit: ctr.QuadletUnit, ActiveState: unit.ActiveState, SubState: unit.SubState}
		}
	}
	return st, nil
}

func (b ExecutorBackend) ContainerLogs(ctx context.Context, req ports.ContainerLogsRequest) (ports.ContainerLogsResponse, error) {
	if !b.Config.Podman.Enabled {
		return ports.ContainerLogsResponse{}, fmt.Errorf("podman is not enabled")
	}
	ctr, ok := b.Config.Containers[req.Container]
	if !ok {
		return ports.ContainerLogsResponse{}, fmt.Errorf("container alias %q is not configured", req.Container)
	}
	if ctr.Permissions.Logs != "allow" {
		return ports.ContainerLogsResponse{}, fmt.Errorf("container alias %q does not allow logs", req.Container)
	}
	entries, truncated, err := b.Podman.Logs(ctx, ctr.ContainerName, req.Lines, req.Since)
	if err != nil {
		return ports.ContainerLogsResponse{}, err
	}
	return ports.ContainerLogsResponse{Container: req.Container, Entries: entries, Truncated: truncated, UntrustedContent: true}, nil
}

func (b ExecutorBackend) RestartContainer(ctx context.Context, req ports.RestartContainerRequest) (ports.RestartContainerResponse, error) {
	if !b.Config.Podman.Enabled {
		return ports.RestartContainerResponse{}, fmt.Errorf("podman is not enabled")
	}
	ctr, ok := b.Config.Containers[req.ContainerAlias]
	if !ok {
		return ports.RestartContainerResponse{}, fmt.Errorf("container alias %q is not configured", req.ContainerAlias)
	}
	if ctr.Permissions.Restart != "confirm" {
		return ports.RestartContainerResponse{}, fmt.Errorf("container alias %q does not allow confirmed restarts", req.ContainerAlias)
	}
	if req.OperationID == "" {
		return ports.RestartContainerResponse{}, fmt.Errorf("operation_id is required")
	}
	attempts := ctr.Health.Attempts
	if attempts == 0 {
		attempts = b.Config.Limits.MaxHealthcheckAttempts
	}
	interval := ctr.Health.Interval.Std()
	if interval <= 0 {
		interval = 2 * time.Second
	}
	if req.DryRun {
		would := b.Config.Podman.Binary + " restart " + ctr.ContainerName
		if ctr.Management == "quadlet" {
			scope := b.Config.Podman.SystemdScope
			if scope == "user" {
				would = "/usr/bin/systemctl --user restart " + ctr.QuadletUnit
			} else {
				would = "/usr/bin/systemctl restart " + ctr.QuadletUnit
			}
		}
		return ports.RestartContainerResponse{Status: "simulated", Action: "restart_container", ResourceKind: "container", Resource: req.ContainerAlias, ContainerState: "unchanged", Health: ports.ContainerHealthResult{Configured: false, Status: "unknown"}, WouldRun: would}, nil
	}
	if ctr.Management == "quadlet" {
		scope := b.Config.Podman.SystemdScope
		if scope == "" {
			scope = "system"
		}
		if err := b.Systemd.RestartWithScope(ctx, ctr.QuadletUnit, scope); err != nil {
			return ports.RestartContainerResponse{}, err
		}
	} else if err := b.Podman.Restart(ctx, ctr.ContainerName); err != nil {
		return ports.RestartContainerResponse{}, err
	}
	st, runningAttempts, err := b.Podman.WaitForRunning(ctx, req.ContainerAlias, ctr.ContainerName, ctr.Management, attempts, interval)
	if err != nil {
		return ports.RestartContainerResponse{}, err
	}
	healthStatus, healthAttempts, err := b.Podman.WaitForHealth(ctx, req.ContainerAlias, ctr.ContainerName, ctr.Management, attempts, interval)
	configured := healthStatus != "not_configured"
	if err != nil && (ctr.Health.RequireHealthyAfterRestart || healthStatus != "not_configured") {
		return ports.RestartContainerResponse{}, err
	}
	return ports.RestartContainerResponse{
		Status:         "executed",
		Action:         "restart_container",
		ResourceKind:   "container",
		Resource:       req.ContainerAlias,
		ContainerState: st.State,
		Health:         ports.ContainerHealthResult{Configured: configured, Status: healthStatus, Attempts: max(runningAttempts, healthAttempts)},
	}, nil
}
