package ports

import (
	"context"
	"time"

	"github.com/javiyt/safeops-mcp/internal/domain/alert"
	"github.com/javiyt/safeops-mcp/internal/domain/approval"
	"github.com/javiyt/safeops-mcp/internal/domain/audit"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
)

type Clock interface {
	Now() time.Time
}

type IDGenerator interface {
	NewID(prefix string) (string, error)
}

type CodeGenerator interface {
	NewCode(digits int) (string, error)
}

type ApprovalRepository interface {
	Create(ctx context.Context, approval approval.Approval) error
	Get(ctx context.Context, id string) (approval.Approval, error)
	MarkExecuting(ctx context.Context, id string, now time.Time) (approval.Approval, error)
	MarkDone(ctx context.Context, id string, status approval.Status, resultSummary, errorSummary string, executedAt time.Time) error
	Cancel(ctx context.Context, id string, userID string, now time.Time) error
	List(ctx context.Context, limit int) ([]approval.Approval, error)
	AcquireOperationLock(ctx context.Context, resourceKind, resourceAlias, operationID string, expiresAt time.Time) error
	ReleaseOperationLock(ctx context.Context, resourceKind, resourceAlias, operationID string) error
	CountOperationsInProgress(ctx context.Context) (int, error)
	PruneRecords(ctx context.Context, before time.Time, minRecords int, dryRun bool) (PruneRecordsResponse, error)
}

type AuditRepository interface {
	Append(ctx context.Context, event audit.Event) error
	ListAudit(ctx context.Context, limit int) ([]audit.Event, error)
}

type AlertRepository interface {
	UpsertObserved(ctx context.Context, finding alert.Finding, now time.Time) (alert.Alert, bool, error)
	ResolveMissing(ctx context.Context, observedIDs map[string]bool, now time.Time) ([]alert.Alert, error)
	ListAlerts(ctx context.Context, filter alert.ListFilter, limit int) ([]alert.Alert, error)
	GetAlert(ctx context.Context, id string) (alert.Alert, error)
	CheckAlertStorage(ctx context.Context, now time.Time) error
	MarkAlertNotified(ctx context.Context, id string, now time.Time) error
	AcknowledgeAlert(ctx context.Context, id, userID string, now time.Time) (alert.Alert, error)
	SilenceAlert(ctx context.Context, id string, until time.Time, now time.Time) (alert.Alert, error)
	ResolveAlert(ctx context.Context, id string, now time.Time) (alert.Alert, error)
	PruneResolvedAlerts(ctx context.Context, before time.Time) (int64, error)
}

type ExecutorClient interface {
	SystemStatus(ctx context.Context) (SystemStatus, error)
	DiskStatus(ctx context.Context, alias string) (DiskStatus, error)
	CPUStatus(ctx context.Context) (CPUStatus, error)
	MemoryStatus(ctx context.Context) (MemoryStatus, error)
	DiskHealth(ctx context.Context, alias string) (DiskHealth, error)
	NetworkStatus(ctx context.Context) (NetworkStatus, error)
	TimeStatus(ctx context.Context) (TimeStatus, error)
	ConfiguredProcessStatus(ctx context.Context) (ConfiguredProcessStatus, error)
	HostHealthSummary(ctx context.Context) (HostHealthSummary, error)
	ListServices(ctx context.Context) ([]ServiceSummary, error)
	ServiceStatus(ctx context.Context, alias string) (service.Status, error)
	ServiceLogs(ctx context.Context, req ServiceLogsRequest) (ServiceLogsResponse, error)
	RestartService(ctx context.Context, req RestartServiceRequest) (RestartServiceResponse, error)
	ListContainers(ctx context.Context) ([]ContainerSummary, error)
	ContainerStatus(ctx context.Context, alias string) (ContainerStatus, error)
	ContainerLogs(ctx context.Context, req ContainerLogsRequest) (ContainerLogsResponse, error)
	RestartContainer(ctx context.Context, req RestartContainerRequest) (RestartContainerResponse, error)
	RestartGroup(ctx context.Context, req RestartGroupRequest) (RestartGroupResponse, error)
	RotateLogs(ctx context.Context, req RotateLogsRequest) (RotateLogsResponse, error)
	CleanupCache(ctx context.Context, req CleanupCacheRequest) (CleanupCacheResponse, error)
	ResetFailureState(ctx context.Context, req ResetFailureStateRequest) (ResetFailureStateResponse, error)
	RebootHost(ctx context.Context, req RebootHostRequest) (RebootHostResponse, error)
	CancelHostReboot(ctx context.Context, req RebootHostRequest) (RebootHostResponse, error)
}

type ExecutorServer interface {
	SystemStatus(ctx context.Context) (SystemStatus, error)
	DiskStatus(ctx context.Context, alias string) (DiskStatus, error)
	CPUStatus(ctx context.Context) (CPUStatus, error)
	MemoryStatus(ctx context.Context) (MemoryStatus, error)
	DiskHealth(ctx context.Context, alias string) (DiskHealth, error)
	NetworkStatus(ctx context.Context) (NetworkStatus, error)
	TimeStatus(ctx context.Context) (TimeStatus, error)
	ConfiguredProcessStatus(ctx context.Context) (ConfiguredProcessStatus, error)
	HostHealthSummary(ctx context.Context) (HostHealthSummary, error)
	ListServices(ctx context.Context) ([]ServiceSummary, error)
	ServiceStatus(ctx context.Context, alias string) (service.Status, error)
	ServiceLogs(ctx context.Context, req ServiceLogsRequest) (ServiceLogsResponse, error)
	RestartService(ctx context.Context, req RestartServiceRequest) (RestartServiceResponse, error)
	ListContainers(ctx context.Context) ([]ContainerSummary, error)
	ContainerStatus(ctx context.Context, alias string) (ContainerStatus, error)
	ContainerLogs(ctx context.Context, req ContainerLogsRequest) (ContainerLogsResponse, error)
	RestartContainer(ctx context.Context, req RestartContainerRequest) (RestartContainerResponse, error)
	RestartGroup(ctx context.Context, req RestartGroupRequest) (RestartGroupResponse, error)
	RotateLogs(ctx context.Context, req RotateLogsRequest) (RotateLogsResponse, error)
	CleanupCache(ctx context.Context, req CleanupCacheRequest) (CleanupCacheResponse, error)
	ResetFailureState(ctx context.Context, req ResetFailureStateRequest) (ResetFailureStateResponse, error)
	RebootHost(ctx context.Context, req RebootHostRequest) (RebootHostResponse, error)
	CancelHostReboot(ctx context.Context, req RebootHostRequest) (RebootHostResponse, error)
}

type SystemStatus struct {
	Hostname      string      `json:"hostname"`
	UptimeSeconds uint64      `json:"uptime_seconds"`
	LoadAverage   LoadAverage `json:"load_average"`
	Memory        Memory      `json:"memory"`
	CPU           CPU         `json:"cpu"`
	Kernel        string      `json:"kernel"`
}

type LoadAverage struct {
	OneMinute      float64 `json:"one_minute"`
	FiveMinutes    float64 `json:"five_minutes"`
	FifteenMinutes float64 `json:"fifteen_minutes"`
}

type Memory struct {
	TotalBytes     uint64  `json:"total_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type CPU struct {
	Cores              int      `json:"cores"`
	Architecture       string   `json:"architecture"`
	TemperatureCelsius *float64 `json:"temperature_celsius,omitempty"`
}

type DiskStatus struct {
	PathAlias      string  `json:"path_alias"`
	Path           string  `json:"path"`
	TotalBytes     uint64  `json:"total_bytes"`
	UsedBytes      uint64  `json:"used_bytes"`
	AvailableBytes uint64  `json:"available_bytes"`
	UsedPercent    float64 `json:"used_percent"`
}

type CPUStatus struct {
	UsagePercent float64        `json:"usage_percent"`
	Cores        []CoreUsage    `json:"cores"`
	LoadAverage  []float64      `json:"load_average"`
	Processes    []ProcessUsage `json:"processes"`
	FrequencyMHz uint64         `json:"frequency"`
	Throttling   Throttling     `json:"throttling"`
	Temperature  *float64       `json:"temperature,omitempty"`
}

type CoreUsage struct {
	Core  int     `json:"core"`
	Usage float64 `json:"usage"`
}

type ProcessUsage struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Command string  `json:"command,omitempty"`
	Alias   string  `json:"alias,omitempty"`
	Status  string  `json:"status,omitempty"`
}

type Throttling struct {
	FrequencyCapped bool `json:"frequency_capped"`
	Throttled       bool `json:"throttled"`
}

type MemoryStatus struct {
	TotalMB        uint64     `json:"total_mb"`
	AvailableMB    uint64     `json:"available_mb"`
	UsedMB         uint64     `json:"used_mb"`
	CacheMB        uint64     `json:"cache_mb"`
	SwapTotalMB    uint64     `json:"swap_total_mb"`
	SwapUsedMB     uint64     `json:"swap_used_mb"`
	MemoryPressure float64    `json:"memory_pressure"`
	OOMEvents      []OOMEvent `json:"oom_events"`
}

type OOMEvent struct {
	Timestamp string `json:"timestamp"`
	Process   string `json:"process"`
	Killed    bool   `json:"killed"`
}

type DiskHealth struct {
	Disks []DiskHealthItem `json:"disks"`
}

type DiskHealthItem struct {
	Name             string      `json:"name"`
	Mount            string      `json:"mount"`
	TotalGB          float64     `json:"total_gb"`
	UsedGB           float64     `json:"used_gb"`
	AvailableGB      float64     `json:"available_gb"`
	UsagePercent     float64     `json:"usage_percent"`
	InodesTotal      uint64      `json:"inodes_total"`
	InodesUsed       uint64      `json:"inodes_used"`
	InodesPercent    float64     `json:"inodes_percent"`
	Trend            string      `json:"trend"`
	FilesystemErrors bool        `json:"filesystem_errors"`
	SMART            SMARTStatus `json:"smart"`
}

type SMARTStatus struct {
	Available          bool     `json:"available"`
	Status             string   `json:"status,omitempty"`
	Temperature        *float64 `json:"temperature,omitempty"`
	ReallocatedSectors *uint64  `json:"reallocated_sectors,omitempty"`
}

type NetworkStatus struct {
	Interfaces   []NetworkInterface   `json:"interfaces"`
	Connectivity []ConnectivityResult `json:"connectivity"`
}

type NetworkInterface struct {
	Name    string   `json:"name"`
	State   string   `json:"state"`
	IP      string   `json:"ip,omitempty"`
	Gateway string   `json:"gateway,omitempty"`
	DNS     []string `json:"dns,omitempty"`
	Errors  uint64   `json:"errors"`
	Dropped uint64   `json:"dropped"`
}

type ConnectivityResult struct {
	Target    string   `json:"target"`
	Reachable bool     `json:"reachable"`
	LatencyMS *float64 `json:"latency_ms,omitempty"`
}

type TimeStatus struct {
	CurrentTime     string   `json:"current_time"`
	Timezone        string   `json:"timezone"`
	NTPSynchronized bool     `json:"ntp_synchronized"`
	NTPServer       string   `json:"ntp_server,omitempty"`
	DriftSeconds    *float64 `json:"drift_seconds,omitempty"`
	ServiceStatus   string   `json:"service_status"`
}

type ConfiguredProcessStatus struct {
	Processes []ProcessUsage `json:"processes"`
}

type HostHealthSummary struct {
	Status    string          `json:"status"`
	Findings  []HealthFinding `json:"findings"`
	Timestamp string          `json:"timestamp"`
}

type HealthFinding struct {
	Severity string `json:"severity"`
	Code     string `json:"code"`
	Message  string `json:"message"`
	Resource string `json:"resource,omitempty"`
}

type ServiceSummary struct {
	Alias  string `json:"alias"`
	Status string `json:"status"`
}

type ServiceLogsRequest struct {
	Service  string `json:"service"`
	Lines    int    `json:"lines"`
	Priority string `json:"priority,omitempty"`
	Since    string `json:"since,omitempty"`
}

type ServiceLogsResponse struct {
	Service          string             `json:"service"`
	Entries          []service.LogEntry `json:"entries"`
	Truncated        bool               `json:"truncated"`
	UntrustedContent bool               `json:"untrusted_content"`
}

type RestartServiceRequest struct {
	Service     string `json:"service"`
	OperationID string `json:"operation_id"`
	DryRun      bool   `json:"dry_run"`
}

type RestartServiceResponse struct {
	Status        string             `json:"status"`
	Action        string             `json:"action"`
	Service       string             `json:"service"`
	ServiceStatus string             `json:"service_status"`
	WouldRun      string             `json:"would_run,omitempty"`
	Healthcheck   *HealthcheckResult `json:"healthcheck,omitempty"`
}

type HealthcheckResult struct {
	Configured bool `json:"configured"`
	Healthy    bool `json:"healthy"`
	Attempts   int  `json:"attempts"`
}

type ContainerSummary struct {
	Alias      string `json:"alias"`
	Management string `json:"management"`
	State      string `json:"state"`
	Health     string `json:"health"`
}

type ContainerStatus struct {
	Alias         string         `json:"alias"`
	ContainerName string         `json:"container_name"`
	Management    string         `json:"management"`
	Exists        bool           `json:"exists"`
	State         string         `json:"state"`
	Status        string         `json:"status"`
	Health        string         `json:"health"`
	StartedAt     string         `json:"started_at,omitempty"`
	FinishedAt    *string        `json:"finished_at"`
	RestartCount  int            `json:"restart_count"`
	Image         string         `json:"image"`
	ImageID       string         `json:"image_id"`
	PID           int            `json:"pid"`
	ExitCode      int            `json:"exit_code"`
	Error         string         `json:"error"`
	Quadlet       *QuadletStatus `json:"quadlet,omitempty"`
}

type QuadletStatus struct {
	Unit        string `json:"unit"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
}

type ContainerLogsRequest struct {
	Container string `json:"container"`
	Lines     int    `json:"lines"`
	Since     string `json:"since,omitempty"`
}

type ContainerLogEntry struct {
	Timestamp string `json:"timestamp"`
	Stream    string `json:"stream"`
	Message   string `json:"message"`
}

type ContainerLogsResponse struct {
	Container        string              `json:"container"`
	Entries          []ContainerLogEntry `json:"entries"`
	Truncated        bool                `json:"truncated"`
	UntrustedContent bool                `json:"untrusted_content"`
}

type RestartContainerRequest struct {
	ContainerAlias string `json:"container_alias"`
	OperationID    string `json:"operation_id"`
	DryRun         bool   `json:"dry_run"`
}

type RestartContainerResponse struct {
	Status         string                `json:"status"`
	Action         string                `json:"action"`
	ResourceKind   string                `json:"resource_kind"`
	Resource       string                `json:"resource"`
	ContainerState string                `json:"container_state"`
	Health         ContainerHealthResult `json:"health"`
	WouldRun       string                `json:"would_run,omitempty"`
}

type ContainerHealthResult struct {
	Configured bool   `json:"configured"`
	Status     string `json:"status"`
	Attempts   int    `json:"attempts"`
}

type RestartGroupRequest struct {
	Group       string `json:"group"`
	OperationID string `json:"operation_id"`
	DryRun      bool   `json:"dry_run"`
}

type RestartGroupResponse struct {
	Status   string            `json:"status"`
	Action   string            `json:"action"`
	Group    string            `json:"group"`
	Steps    []MaintenanceStep `json:"steps"`
	WouldRun []string          `json:"would_run,omitempty"`
}

type MaintenanceStep struct {
	ResourceKind string `json:"resource_kind"`
	Resource     string `json:"resource"`
	Operation    string `json:"operation"`
	Status       string `json:"status"`
}

type RotateLogsRequest struct {
	Resource    string `json:"resource,omitempty"`
	OperationID string `json:"operation_id"`
	DryRun      bool   `json:"dry_run"`
}

type RotateLogsResponse struct {
	Status       string   `json:"status"`
	Rotated      bool     `json:"rotated"`
	FilesRotated []string `json:"files_rotated"`
	Compressed   bool     `json:"compressed"`
	Deleted      []string `json:"deleted"`
	SpaceFreedMB int64    `json:"space_freed_mb"`
	DryRun       bool     `json:"dry_run"`
}

type CleanupCacheRequest struct {
	Resource    string `json:"resource"`
	OperationID string `json:"operation_id"`
	DryRun      bool   `json:"dry_run"`
}

type CleanupCacheResponse struct {
	Status        string `json:"status"`
	FilesDeleted  int    `json:"files_deleted,omitempty"`
	FilesToDelete int    `json:"files_to_delete,omitempty"`
	SpaceFreedMB  int64  `json:"space_freed_mb,omitempty"`
	SpaceToFreeMB int64  `json:"space_to_free_mb,omitempty"`
	OldestFileAge string `json:"oldest_file_age,omitempty"`
	DryRun        bool   `json:"dry_run"`
}

type PruneRecordsResponse struct {
	Status           string `json:"status"`
	RecordsToDelete  int64  `json:"records_to_delete"`
	RecordsDeleted   int64  `json:"records_deleted,omitempty"`
	RecordsRemaining int64  `json:"records_remaining"`
	DryRun           bool   `json:"dry_run"`
}

type ResetFailureStateRequest struct {
	Resource    string `json:"resource"`
	OperationID string `json:"operation_id"`
	DryRun      bool   `json:"dry_run"`
}

type ResetFailureStateResponse struct {
	Status         string `json:"status"`
	ResourceKind   string `json:"resource_kind"`
	Resource       string `json:"resource"`
	ResetOperation string `json:"reset_operation"`
	Result         string `json:"result"`
	WouldRun       string `json:"would_run,omitempty"`
}

type RebootHostRequest struct {
	Delay       string `json:"delay,omitempty"`
	OperationID string `json:"operation_id"`
	DryRun      bool   `json:"dry_run"`
}

type RebootHostResponse struct {
	Status         string         `json:"status"`
	Action         string         `json:"action"`
	Delay          string         `json:"delay"`
	ExpectedEffect string         `json:"expected_effect"`
	CheckResults   map[string]any `json:"check_results"`
	WouldRun       string         `json:"would_run,omitempty"`
}
