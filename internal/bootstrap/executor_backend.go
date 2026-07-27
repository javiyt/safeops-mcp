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
	CPU         CPUReader
	Memory      MemoryReader
	DiskHealthR DiskHealthReader
	Network     NetworkReader
	Time        TimeReader
	Processes   ConfiguredProcessReader
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

type CPUReader interface {
	CPUStatus(ctx context.Context) (ports.CPUStatus, error)
}

type MemoryReader interface {
	MemoryStatus(ctx context.Context) (ports.MemoryStatus, error)
}

type DiskHealthReader interface {
	DiskHealth(ctx context.Context, alias string) (ports.DiskHealth, error)
}

type NetworkReader interface {
	NetworkStatus(ctx context.Context) (ports.NetworkStatus, error)
}

type TimeReader interface {
	TimeStatus(ctx context.Context) (ports.TimeStatus, error)
}

type ConfiguredProcessReader interface {
	ConfiguredProcessStatus(ctx context.Context) (ports.ConfiguredProcessStatus, error)
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

func (b ExecutorBackend) CPUStatus(ctx context.Context) (ports.CPUStatus, error) {
	return b.CPU.CPUStatus(ctx)
}

func (b ExecutorBackend) MemoryStatus(ctx context.Context) (ports.MemoryStatus, error) {
	return b.Memory.MemoryStatus(ctx)
}

func (b ExecutorBackend) DiskHealth(ctx context.Context, alias string) (ports.DiskHealth, error) {
	if alias != "" {
		if _, ok := b.Config.Filesystem.DiskPaths[alias]; !ok {
			return ports.DiskHealth{}, fmt.Errorf("disk alias %q is not configured", alias)
		}
	}
	return b.DiskHealthR.DiskHealth(ctx, alias)
}

func (b ExecutorBackend) NetworkStatus(ctx context.Context) (ports.NetworkStatus, error) {
	return b.Network.NetworkStatus(ctx)
}

func (b ExecutorBackend) TimeStatus(ctx context.Context) (ports.TimeStatus, error) {
	return b.Time.TimeStatus(ctx)
}

func (b ExecutorBackend) ConfiguredProcessStatus(ctx context.Context) (ports.ConfiguredProcessStatus, error) {
	return b.Processes.ConfiguredProcessStatus(ctx)
}

func (b ExecutorBackend) HostHealthSummary(ctx context.Context) (ports.HostHealthSummary, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var findings []ports.HealthFinding
	if cpuStatus, err := b.CPUStatus(ctx); err == nil {
		findings = append(findings, b.cpuFindings(cpuStatus)...)
	}
	if memoryStatus, err := b.MemoryStatus(ctx); err == nil {
		findings = append(findings, b.memoryFindings(memoryStatus)...)
	}
	if disks, err := b.DiskHealth(ctx, ""); err == nil {
		findings = append(findings, b.diskFindings(disks)...)
	}
	if networkStatus, err := b.NetworkStatus(ctx); err == nil {
		findings = append(findings, b.networkFindings(networkStatus)...)
	}
	if timeStatus, err := b.TimeStatus(ctx); err == nil {
		findings = append(findings, b.timeFindings(timeStatus)...)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
	status := "healthy"
	for _, finding := range findings {
		if finding.Severity == "critical" {
			status = "critical"
			break
		}
		if finding.Severity == "warning" {
			status = "degraded"
		}
	}
	return ports.HostHealthSummary{Status: status, Findings: findings, Timestamp: time.Now().UTC().Format(time.RFC3339)}, nil
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
	if st.Health == "not_configured" {
		return ports.RestartContainerResponse{
			Status:         "executed",
			Action:         "restart_container",
			ResourceKind:   "container",
			Resource:       req.ContainerAlias,
			ContainerState: st.State,
			Health:         ports.ContainerHealthResult{Configured: false, Status: "not_configured", Attempts: runningAttempts},
		}, nil
	}
	healthStatus, healthAttempts, err := b.Podman.WaitForHealth(ctx, req.ContainerAlias, ctr.ContainerName, ctr.Management, attempts, interval)
	configured := healthStatus != "not_configured"
	if err != nil && (ctr.Health.RequireHealthyAfterRestart || healthStatus == "unhealthy") {
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

func (b ExecutorBackend) cpuFindings(st ports.CPUStatus) []ports.HealthFinding {
	var out []ports.HealthFinding
	if len(st.LoadAverage) > 0 {
		load := st.LoadAverage[0]
		if load >= b.Config.Diagnostics.CPU.LoadCritical {
			out = append(out, finding("critical", "cpu_high_load", fmt.Sprintf("CPU one-minute load is %.2f.", load), "cpu"))
		} else if load >= b.Config.Diagnostics.CPU.LoadWarning {
			out = append(out, finding("warning", "cpu_high_load", fmt.Sprintf("CPU one-minute load is %.2f.", load), "cpu"))
		}
	}
	if st.Temperature != nil {
		temp := *st.Temperature
		if temp >= b.Config.Diagnostics.CPU.TemperatureCritical {
			out = append(out, finding("critical", "cpu_temperature_high", fmt.Sprintf("CPU temperature is %.1fC.", temp), "cpu"))
		} else if temp >= b.Config.Diagnostics.CPU.TemperatureWarning {
			out = append(out, finding("warning", "cpu_temperature_high", fmt.Sprintf("CPU temperature is %.1fC.", temp), "cpu"))
		}
	}
	if st.Throttling.Throttled {
		out = append(out, finding("warning", "cpu_throttled", "CPU throttling is currently reported by the host.", "cpu"))
	}
	return out
}

func (b ExecutorBackend) memoryFindings(st ports.MemoryStatus) []ports.HealthFinding {
	var out []ports.HealthFinding
	availablePercent := 100.0
	if st.TotalMB > 0 {
		availablePercent = float64(st.AvailableMB) / float64(st.TotalMB) * 100
	}
	if availablePercent <= b.Config.Diagnostics.Memory.AvailableCriticalPercent {
		out = append(out, finding("critical", "memory_available_low", fmt.Sprintf("Available memory is %.1f%%.", availablePercent), "memory"))
	} else if availablePercent <= b.Config.Diagnostics.Memory.AvailableWarningPercent {
		out = append(out, finding("warning", "memory_available_low", fmt.Sprintf("Available memory is %.1f%%.", availablePercent), "memory"))
	}
	if st.SwapTotalMB > 0 {
		swapPercent := float64(st.SwapUsedMB) / float64(st.SwapTotalMB) * 100
		if swapPercent >= b.Config.Diagnostics.Memory.SwapWarning {
			out = append(out, finding("warning", "swap_usage_high", fmt.Sprintf("Swap usage is %.1f%%.", swapPercent), "swap"))
		}
	}
	if len(st.OOMEvents) > 0 {
		out = append(out, finding("warning", "oom_events_recent", "Recent OOM events were reported.", "memory"))
	}
	return out
}

func (b ExecutorBackend) diskFindings(st ports.DiskHealth) []ports.HealthFinding {
	var out []ports.HealthFinding
	for _, disk := range st.Disks {
		if disk.UsagePercent >= b.Config.Diagnostics.Disk.UsageCritical {
			out = append(out, finding("critical", "disk_usage_high", fmt.Sprintf("%s usage is %.1f%%.", disk.Name, disk.UsagePercent), disk.Name))
		} else if disk.UsagePercent >= b.Config.Diagnostics.Disk.UsageWarning {
			out = append(out, finding("warning", "disk_usage_high", fmt.Sprintf("%s usage is %.1f%%.", disk.Name, disk.UsagePercent), disk.Name))
		}
		if disk.InodesPercent >= b.Config.Diagnostics.Disk.InodeCritical {
			out = append(out, finding("critical", "disk_inodes_high", fmt.Sprintf("%s inode usage is %.1f%%.", disk.Name, disk.InodesPercent), disk.Name))
		} else if disk.InodesPercent >= b.Config.Diagnostics.Disk.InodeWarning {
			out = append(out, finding("warning", "disk_inodes_high", fmt.Sprintf("%s inode usage is %.1f%%.", disk.Name, disk.InodesPercent), disk.Name))
		}
		if disk.FilesystemErrors {
			out = append(out, finding("critical", "filesystem_errors", "Filesystem errors are reported.", disk.Name))
		}
		if disk.SMART.Available && disk.SMART.Status != "" && disk.SMART.Status != "PASSED" {
			out = append(out, finding("critical", "smart_status_failed", "SMART status is not passing.", disk.Name))
		}
	}
	return out
}

func (b ExecutorBackend) networkFindings(st ports.NetworkStatus) []ports.HealthFinding {
	var out []ports.HealthFinding
	for _, iface := range st.Interfaces {
		if iface.State == "up" && (iface.Errors > 0 || iface.Dropped > 0) {
			out = append(out, finding("warning", "network_interface_errors", fmt.Sprintf("Interface %s reports packet errors or drops.", iface.Name), iface.Name))
		}
	}
	for _, conn := range st.Connectivity {
		if !conn.Reachable {
			out = append(out, finding("warning", "network_connectivity_failed", "Configured connectivity target is unreachable.", conn.Target))
			continue
		}
		if conn.LatencyMS != nil && *conn.LatencyMS >= float64(b.Config.Diagnostics.Network.LatencyWarning.Std().Milliseconds()) {
			out = append(out, finding("warning", "network_latency_high", fmt.Sprintf("Latency to %s is %.1f ms.", conn.Target, *conn.LatencyMS), conn.Target))
		}
	}
	return out
}

func (b ExecutorBackend) timeFindings(st ports.TimeStatus) []ports.HealthFinding {
	if b.Config.Diagnostics.Time.NTPCheck && !st.NTPSynchronized {
		return []ports.HealthFinding{finding("warning", "time_not_synchronized", "NTP synchronization is not reported as active.", "time")}
	}
	if st.DriftSeconds != nil && *st.DriftSeconds >= b.Config.Diagnostics.Time.DriftWarning.Std().Seconds() {
		return []ports.HealthFinding{finding("warning", "time_drift_high", fmt.Sprintf("Clock drift is %.3f seconds.", *st.DriftSeconds), "time")}
	}
	return nil
}

func finding(severity, code, message, resource string) ports.HealthFinding {
	return ports.HealthFinding{Severity: severity, Code: code, Message: message, Resource: resource}
}

func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 3
	case "warning":
		return 2
	default:
		return 1
	}
}
