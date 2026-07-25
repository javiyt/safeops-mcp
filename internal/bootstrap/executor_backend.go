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
}

type JournalReader interface {
	Logs(ctx context.Context, unit string, lines int, priority, since string) ([]service.LogEntry, bool, error)
}

type HealthcheckClient interface {
	Check(ctx context.Context, url string, timeout time.Duration, attempts int, interval time.Duration) (bool, int)
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
