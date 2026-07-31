package bootstrap

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
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
	Git         GitClient
	Runner      process.Runner
	Rebooter    HostRebooter
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
	Start(ctx context.Context, unit string) error
	Stop(ctx context.Context, unit string) error
	ResetFailed(ctx context.Context, unit string) error
	StatusWithScope(ctx context.Context, alias, unit, scope string) (service.Status, error)
	RestartWithScope(ctx context.Context, unit, scope string) error
	StartWithScope(ctx context.Context, unit, scope string) error
	StopWithScope(ctx context.Context, unit, scope string) error
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
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	WaitForRunning(ctx context.Context, alias, name, management string, attempts int, interval time.Duration) (ports.ContainerStatus, int, error)
	WaitForHealth(ctx context.Context, alias, name, management string, attempts int, interval time.Duration) (string, int, error)
	RemoteImageDigest(ctx context.Context, image string) (string, error)
	PullImage(ctx context.Context, image string) (string, error)
}

type GitClient interface {
	RemoteCommit(ctx context.Context, repositoryURL, branch string) (string, error)
	CurrentCommit(ctx context.Context, repositoryPath string) (string, error)
	Fetch(ctx context.Context, repositoryPath, branch string) error
	CheckoutCommit(ctx context.Context, repositoryPath, commit string) error
}

type HostRebooter interface {
	ScheduleReboot(ctx context.Context, delayMinutes int) error
	CancelReboot(ctx context.Context) error
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

func (b ExecutorBackend) RestartGroup(ctx context.Context, req ports.RestartGroupRequest) (ports.RestartGroupResponse, error) {
	group, ok := b.Config.Groups[req.Group]
	if !ok {
		return ports.RestartGroupResponse{}, fmt.Errorf("group alias %q is not configured", req.Group)
	}
	if req.OperationID == "" {
		return ports.RestartGroupResponse{}, fmt.Errorf("operation_id is required")
	}
	startOrder := group.Order
	if len(startOrder) == 0 {
		startOrder = group.Resources
	}
	stopOrder := group.StopOrder
	if len(stopOrder) == 0 {
		stopOrder = reverseStrings(startOrder)
	}
	timeout := group.Timeout.Std()
	if timeout <= 0 {
		timeout = b.Config.Limits.OperationTimeout.Std()
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var steps []ports.MaintenanceStep
	var would []string
	for _, alias := range stopOrder {
		cmd, err := b.groupResourceCommand(alias, "stop")
		if err != nil {
			return ports.RestartGroupResponse{}, err
		}
		would = append(would, cmd)
		if req.DryRun {
			steps = append(steps, ports.MaintenanceStep{ResourceKind: b.resourceKind(alias), Resource: alias, Operation: "stop", Status: "simulated"})
			continue
		}
		if err := b.stopResource(runCtx, alias); err != nil {
			return ports.RestartGroupResponse{}, err
		}
		steps = append(steps, ports.MaintenanceStep{ResourceKind: b.resourceKind(alias), Resource: alias, Operation: "stop", Status: "executed"})
	}
	for _, alias := range startOrder {
		cmd, err := b.groupResourceCommand(alias, "start")
		if err != nil {
			return ports.RestartGroupResponse{}, err
		}
		would = append(would, cmd)
		if req.DryRun {
			steps = append(steps, ports.MaintenanceStep{ResourceKind: b.resourceKind(alias), Resource: alias, Operation: "start", Status: "simulated"})
			continue
		}
		if err := b.startResource(runCtx, alias, group.HealthCheck); err != nil {
			return ports.RestartGroupResponse{}, err
		}
		steps = append(steps, ports.MaintenanceStep{ResourceKind: b.resourceKind(alias), Resource: alias, Operation: "start", Status: "executed"})
	}
	status := "executed"
	if req.DryRun {
		status = "simulated"
	}
	return ports.RestartGroupResponse{Status: status, Action: "restart_group", Group: req.Group, Steps: steps, WouldRun: would}, nil
}

func (b ExecutorBackend) RotateLogs(ctx context.Context, req ports.RotateLogsRequest) (ports.RotateLogsResponse, error) {
	targets, err := b.logTargets(req.Resource)
	if err != nil {
		return ports.RotateLogsResponse{}, err
	}
	var out ports.RotateLogsResponse
	out.Status = "executed"
	out.DryRun = req.DryRun
	if req.DryRun {
		out.Status = "simulated"
	}
	var total int64
	for _, target := range targets {
		info, err := os.Stat(target.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return ports.RotateLogsResponse{}, err
		}
		if info.IsDir() {
			return ports.RotateLogsResponse{}, fmt.Errorf("configured log path %q is a directory", target.path)
		}
		total += info.Size()
		if total > b.Config.LogRotation.MaxTotalSize.Int64() {
			return ports.RotateLogsResponse{}, fmt.Errorf("configured log rotation exceeds max_total_size")
		}
		if info.Size() < target.rotation.MaxSize.Int64() && time.Since(info.ModTime()) < target.rotation.MaxAge.Std() {
			continue
		}
		out.Rotated = true
		out.FilesRotated = append(out.FilesRotated, target.path)
		out.Compressed = out.Compressed || target.rotation.Compress
		out.SpaceFreedMB += info.Size() / 1024 / 1024
		if req.DryRun {
			continue
		}
		deleted, err := rotateOneLog(target.path, target.rotation)
		if err != nil {
			return ports.RotateLogsResponse{}, err
		}
		out.Deleted = append(out.Deleted, deleted...)
	}
	return out, nil
}

func (b ExecutorBackend) CleanupCache(ctx context.Context, req ports.CleanupCacheRequest) (ports.CleanupCacheResponse, error) {
	app, ok := b.Config.Applications[req.Resource]
	if !ok {
		return ports.CleanupCacheResponse{}, fmt.Errorf("application alias %q is not configured", req.Resource)
	}
	cleanup := configCleanup(app.Cleanup, b.Config.CacheCleanup.Default)
	if !cleanup.Enabled {
		return ports.CleanupCacheResponse{}, fmt.Errorf("application alias %q does not enable cache cleanup", req.Resource)
	}
	ctx, cancel := context.WithTimeout(ctx, cleanup.Timeout.Std())
	defer cancel()
	cutoff := time.Now().Add(-cleanup.MaxAge.Std())
	var files []cacheFile
	var total int64
	err := filepath.WalkDir(app.CachePath, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		if info.ModTime().Before(cutoff) {
			files = append(files, cacheFile{path: path, size: info.Size(), modTime: info.ModTime()})
		}
		return nil
	})
	if err != nil {
		return ports.CleanupCacheResponse{}, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].modTime.Before(files[j].modTime) })
	for total > cleanup.MaxSize.Int64() && len(files) > 0 {
		total -= files[0].size
		files = files[1:]
	}
	var bytes int64
	var oldest time.Duration
	for _, file := range files {
		bytes += file.size
		age := time.Since(file.modTime)
		if age > oldest {
			oldest = age
		}
	}
	out := ports.CleanupCacheResponse{Status: "executed", FilesDeleted: len(files), SpaceFreedMB: bytes / 1024 / 1024, OldestFileAge: oldest.Round(time.Second).String(), DryRun: req.DryRun}
	if req.DryRun {
		out.Status = "simulated"
		out.FilesToDelete = len(files)
		out.SpaceToFreeMB = bytes / 1024 / 1024
		out.FilesDeleted = 0
		out.SpaceFreedMB = 0
		return out, nil
	}
	for _, file := range files {
		if err := os.Remove(file.path); err != nil {
			return ports.CleanupCacheResponse{}, err
		}
	}
	return out, nil
}

func (b ExecutorBackend) ResetFailureState(ctx context.Context, req ports.ResetFailureStateRequest) (ports.ResetFailureStateResponse, error) {
	svc, ok := b.Config.Services[req.Resource]
	if !ok {
		if _, container := b.Config.Containers[req.Resource]; container {
			return ports.ResetFailureStateResponse{Status: "not_applicable", ResourceKind: "container", Resource: req.Resource, ResetOperation: "none", Result: "containers do not support reset-failed"}, nil
		}
		return ports.ResetFailureStateResponse{}, fmt.Errorf("service alias %q is not configured", req.Resource)
	}
	if req.OperationID == "" {
		return ports.ResetFailureStateResponse{}, fmt.Errorf("operation_id is required")
	}
	if req.DryRun {
		return ports.ResetFailureStateResponse{Status: "simulated", ResourceKind: "service", Resource: req.Resource, ResetOperation: "reset-failed", Result: "simulated", WouldRun: "/usr/bin/systemctl reset-failed " + svc.Unit}, nil
	}
	if err := b.Systemd.ResetFailed(ctx, svc.Unit); err != nil {
		return ports.ResetFailureStateResponse{}, err
	}
	return ports.ResetFailureStateResponse{Status: "executed", ResourceKind: "service", Resource: req.Resource, ResetOperation: "reset-failed", Result: "success"}, nil
}

func (b ExecutorBackend) RebootHost(ctx context.Context, req ports.RebootHostRequest) (ports.RebootHostResponse, error) {
	if !b.Config.HostReboot.Enabled {
		return ports.RebootHostResponse{}, fmt.Errorf("host reboot is disabled")
	}
	delay := strings.TrimSpace(req.Delay)
	if delay == "" {
		delay = "5m"
	}
	d, err := time.ParseDuration(delay)
	if err != nil || d < 0 || d > b.Config.HostReboot.ConfirmationWindow.Std() {
		return ports.RebootHostResponse{}, fmt.Errorf("delay must be between 0 and host_reboot.confirmation_window")
	}
	minutes := int(d.Round(time.Minute).Minutes())
	if d > 0 && minutes == 0 {
		minutes = 1
	}
	checks := map[string]any{"recent_backup_exists": !b.Config.HostReboot.RequireBackup, "backup_age": "", "no_operations_in_progress": true}
	args := []string{"shutdown", "-r", "+" + strconv.Itoa(minutes)}
	would := b.Config.HostReboot.RebootCommand + " " + strings.Join(args, " ")
	if req.DryRun {
		return ports.RebootHostResponse{Status: "simulated", Action: "reboot_host", Delay: delay, ExpectedEffect: "All services will stop and the host will restart.", CheckResults: checks, WouldRun: would}, nil
	}
	if b.Rebooter == nil {
		return ports.RebootHostResponse{}, fmt.Errorf("host reboot execution requires a configured executor reboot runner")
	}
	if err := b.Rebooter.ScheduleReboot(ctx, minutes); err != nil {
		return ports.RebootHostResponse{}, err
	}
	return ports.RebootHostResponse{Status: "executed", Action: "reboot_host", Delay: delay, ExpectedEffect: "All services will stop and the host will restart.", CheckResults: checks}, nil
}

func (b ExecutorBackend) CancelHostReboot(ctx context.Context, req ports.RebootHostRequest) (ports.RebootHostResponse, error) {
	if !b.Config.HostReboot.Enabled {
		return ports.RebootHostResponse{}, fmt.Errorf("host reboot is disabled")
	}
	if req.DryRun {
		return ports.RebootHostResponse{Status: "simulated", Action: "cancel_reboot_host", ExpectedEffect: "A scheduled host reboot would be canceled.", WouldRun: b.Config.HostReboot.CancelCommand + " shutdown -c"}, nil
	}
	if b.Rebooter == nil {
		return ports.RebootHostResponse{}, fmt.Errorf("host reboot cancellation requires a configured executor reboot runner")
	}
	if err := b.Rebooter.CancelReboot(ctx); err != nil {
		return ports.RebootHostResponse{}, err
	}
	return ports.RebootHostResponse{Status: "executed", Action: "cancel_reboot_host", ExpectedEffect: "Scheduled host reboot was canceled."}, nil
}

type logTarget struct {
	path     string
	rotation config.ResourceLogRotationConfig
}

type cacheFile struct {
	path    string
	size    int64
	modTime time.Time
}

func (b ExecutorBackend) logTargets(resource string) ([]logTarget, error) {
	var targets []logTarget
	addService := func(alias string, svc config.ServiceConfig) {
		if svc.LogRotation.Enabled {
			targets = append(targets, logTarget{path: svc.LogPath, rotation: configLogRotation(svc.LogRotation, b.Config.LogRotation.Default)})
		}
	}
	addContainer := func(alias string, ctr config.ContainerConfig) {
		if ctr.LogRotation.Enabled {
			targets = append(targets, logTarget{path: ctr.LogPath, rotation: configLogRotation(ctr.LogRotation, b.Config.LogRotation.Default)})
		}
	}
	if resource != "" {
		if svc, ok := b.Config.Services[resource]; ok {
			addService(resource, svc)
			return targets, nil
		}
		if ctr, ok := b.Config.Containers[resource]; ok {
			addContainer(resource, ctr)
			return targets, nil
		}
		return nil, fmt.Errorf("resource alias %q is not configured", resource)
	}
	for alias, svc := range b.Config.Services {
		addService(alias, svc)
	}
	for alias, ctr := range b.Config.Containers {
		addContainer(alias, ctr)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no configured logs enable rotation")
	}
	return targets, nil
}

func configLogRotation(local, def config.ResourceLogRotationConfig) config.ResourceLogRotationConfig {
	if local.MaxSize.Int64() == 0 {
		local.MaxSize = def.MaxSize
	}
	if local.MaxAge.Std() == 0 {
		local.MaxAge = def.MaxAge
	}
	if local.Keep == 0 {
		local.Keep = def.Keep
	}
	return local
}

func configCleanup(local, def config.ResourceCleanupConfig) config.ResourceCleanupConfig {
	if local.MaxAge.Std() == 0 {
		local.MaxAge = def.MaxAge
	}
	if local.MaxSize.Int64() == 0 {
		local.MaxSize = def.MaxSize
	}
	if local.Timeout.Std() == 0 {
		local.Timeout = def.Timeout
	}
	return local
}

func rotateOneLog(path string, rotation config.ResourceLogRotationConfig) ([]string, error) {
	var deleted []string
	for i := rotation.Keep; i >= 1; i-- {
		old := path + "." + strconv.Itoa(i)
		if rotation.Compress {
			old += ".gz"
		}
		if i == rotation.Keep {
			if err := os.Remove(old); err == nil {
				deleted = append(deleted, old)
			} else if !os.IsNotExist(err) {
				return deleted, err
			}
			continue
		}
		next := path + "." + strconv.Itoa(i+1)
		if rotation.Compress {
			next += ".gz"
		}
		if err := os.Rename(old, next); err != nil && !os.IsNotExist(err) {
			return deleted, err
		}
	}
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		return deleted, err
	}
	if rotation.Compress {
		gzPath := rotated + ".gz"
		if err := gzipFile(rotated, gzPath); err != nil {
			return deleted, err
		}
		if err := os.Remove(rotated); err != nil {
			return deleted, err
		}
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return deleted, err
	}
	return deleted, file.Close()
}

func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	writer := gzip.NewWriter(out)
	if _, err := io.Copy(writer, in); err != nil {
		_ = writer.Close()
		return err
	}
	return writer.Close()
}

func reverseStrings(values []string) []string {
	out := make([]string, len(values))
	for i := range values {
		out[len(values)-1-i] = values[i]
	}
	return out
}

func (b ExecutorBackend) resourceKind(alias string) string {
	if _, ok := b.Config.Services[alias]; ok {
		return "service"
	}
	return "container"
}

func (b ExecutorBackend) groupResourceCommand(alias, op string) (string, error) {
	if svc, ok := b.Config.Services[alias]; ok {
		return "/usr/bin/systemctl " + op + " " + svc.Unit, nil
	}
	if ctr, ok := b.Config.Containers[alias]; ok {
		if ctr.Management == "quadlet" {
			scope := b.Config.Podman.SystemdScope
			if scope == "user" {
				return "/usr/bin/systemctl --user " + op + " " + ctr.QuadletUnit, nil
			}
			return "/usr/bin/systemctl " + op + " " + ctr.QuadletUnit, nil
		}
		return b.Config.Podman.Binary + " " + op + " " + ctr.ContainerName, nil
	}
	return "", fmt.Errorf("resource alias %q is not configured", alias)
}

func (b ExecutorBackend) stopResource(ctx context.Context, alias string) error {
	if svc, ok := b.Config.Services[alias]; ok {
		return b.Systemd.Stop(ctx, svc.Unit)
	}
	ctr, ok := b.Config.Containers[alias]
	if !ok {
		return fmt.Errorf("resource alias %q is not configured", alias)
	}
	if ctr.Management == "quadlet" {
		scope := b.Config.Podman.SystemdScope
		if scope == "" {
			scope = "system"
		}
		return b.Systemd.StopWithScope(ctx, ctr.QuadletUnit, scope)
	}
	return b.Podman.Stop(ctx, ctr.ContainerName)
}

func (b ExecutorBackend) startResource(ctx context.Context, alias string, healthCheck bool) error {
	if svc, ok := b.Config.Services[alias]; ok {
		if err := b.Systemd.Start(ctx, svc.Unit); err != nil {
			return err
		}
		if healthCheck && svc.Healthcheck != nil {
			healthy, _ := b.Healthcheck.Check(ctx, svc.Healthcheck.URL, svc.Healthcheck.Timeout.Std(), svc.Healthcheck.Attempts, svc.Healthcheck.Interval.Std())
			if !healthy {
				return fmt.Errorf("service alias %q failed health check", alias)
			}
		}
		return nil
	}
	ctr, ok := b.Config.Containers[alias]
	if !ok {
		return fmt.Errorf("resource alias %q is not configured", alias)
	}
	if ctr.Management == "quadlet" {
		scope := b.Config.Podman.SystemdScope
		if scope == "" {
			scope = "system"
		}
		if err := b.Systemd.StartWithScope(ctx, ctr.QuadletUnit, scope); err != nil {
			return err
		}
	} else if err := b.Podman.Start(ctx, ctr.ContainerName); err != nil {
		return err
	}
	if healthCheck {
		attempts := ctr.Health.Attempts
		if attempts == 0 {
			attempts = b.Config.Limits.MaxHealthcheckAttempts
		}
		interval := ctr.Health.Interval.Std()
		if interval <= 0 {
			interval = 2 * time.Second
		}
		if _, _, err := b.Podman.WaitForRunning(ctx, alias, ctr.ContainerName, ctr.Management, attempts, interval); err != nil {
			return err
		}
	}
	return nil
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
