package alert

import "time"

type Status string

const (
	StatusNew          Status = "new"
	StatusActive       Status = "active"
	StatusAcknowledged Status = "acknowledged"
	StatusResolved     Status = "resolved"
	StatusSuppressed   Status = "suppressed"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

type Alert struct {
	ID              string     `json:"id"`
	ResourceKind    string     `json:"resource_kind"`
	ResourceAlias   string     `json:"resource_alias"`
	Type            string     `json:"alert_type"`
	Severity        Severity   `json:"severity"`
	Status          Status     `json:"status"`
	Message         string     `json:"message"`
	FirstObserved   time.Time  `json:"first_observed"`
	LastObserved    time.Time  `json:"last_observed"`
	LastNotified    *time.Time `json:"last_notified,omitempty"`
	Count           int        `json:"count"`
	AcknowledgedBy  string     `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at,omitempty"`
	SuppressedUntil *time.Time `json:"suppressed_until,omitempty"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	Metadata        string     `json:"metadata,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Finding struct {
	ResourceKind  string
	ResourceAlias string
	Type          string
	Severity      Severity
	Message       string
	Metadata      string
}

type ListFilter struct {
	Status   Status
	Severity Severity
}
