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
}

type ExecutorServer interface {
	SystemStatus(ctx context.Context) (SystemStatus, error)
	DiskStatus(ctx context.Context, alias string) (DiskStatus, error)
	ListServices(ctx context.Context) ([]ServiceSummary, error)
	ServiceStatus(ctx context.Context, alias string) (service.Status, error)
	ServiceLogs(ctx context.Context, req ServiceLogsRequest) (ServiceLogsResponse, error)
	RestartService(ctx context.Context, req RestartServiceRequest) (RestartServiceResponse, error)
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
