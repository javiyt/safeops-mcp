package service

import "time"

type Permission string

const (
	PermissionAllow   Permission = "allow"
	PermissionDeny    Permission = "deny"
	PermissionConfirm Permission = "confirm"
)

type Service struct {
	Alias       string
	Unit        string
	Permissions Permissions
	Healthcheck *Healthcheck
}

type Permissions struct {
	Status  Permission
	Logs    Permission
	Restart Permission
}

type Healthcheck struct {
	URL      string
	Timeout  time.Duration
	Attempts int
	Interval time.Duration
}

type Status struct {
	Alias       string `json:"alias"`
	Unit        string `json:"unit"`
	ActiveState string `json:"active_state"`
	SubState    string `json:"sub_state"`
	StartedAt   string `json:"started_at,omitempty"`
	MainPID     int    `json:"main_pid,omitempty"`
}

type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Priority  string `json:"priority"`
	Message   string `json:"message"`
}
