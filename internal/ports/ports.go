package ports

import (
	"context"
	"time"

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
}

type AuditRepository interface {
	Append(ctx context.Context, event audit.Event) error
	ListAudit(ctx context.Context, limit int) ([]audit.Event, error)
}

type ExecutorClient interface {
	SystemStatus(ctx context.Context) (SystemStatus, error)
	DiskStatus(ctx context.Context, alias string) (DiskStatus, error)
	ListServices(ctx context.Context) ([]ServiceSummary, error)
	ServiceStatus(ctx context.Context, alias string) (service.Status, error)
	ServiceLogs(ctx context.Context, req ServiceLogsRequest) (ServiceLogsResponse, error)
	RestartService(ctx context.Context, req RestartServiceRequest) (RestartServiceResponse, error)
	ListContainers(ctx context.Context) ([]ContainerSummary, error)
	ContainerStatus(ctx context.Context, alias string) (ContainerStatus, error)
	ContainerLogs(ctx context.Context, req ContainerLogsRequest) (ContainerLogsResponse, error)
	RestartContainer(ctx context.Context, req RestartContainerRequest) (RestartContainerResponse, error)
}

type ExecutorServer interface {
	SystemStatus(ctx context.Context) (SystemStatus, error)
	DiskStatus(ctx context.Context, alias string) (DiskStatus, error)
	ListServices(ctx context.Context) ([]ServiceSummary, error)
	ServiceStatus(ctx context.Context, alias string) (service.Status, error)
	ServiceLogs(ctx context.Context, req ServiceLogsRequest) (ServiceLogsResponse, error)
	RestartService(ctx context.Context, req RestartServiceRequest) (RestartServiceResponse, error)
	ListContainers(ctx context.Context) ([]ContainerSummary, error)
	ContainerStatus(ctx context.Context, alias string) (ContainerStatus, error)
	ContainerLogs(ctx context.Context, req ContainerLogsRequest) (ContainerLogsResponse, error)
	RestartContainer(ctx context.Context, req RestartContainerRequest) (RestartContainerResponse, error)
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
