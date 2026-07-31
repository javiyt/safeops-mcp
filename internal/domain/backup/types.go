package backup

import "time"

type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusVerified  Status = "verified"
)

type Record struct {
	ID                 string
	BackupAlias        string
	SourceAlias        string
	Backend            string
	SnapshotID         string
	Status             Status
	StartTime          time.Time
	EndTime            *time.Time
	DurationSeconds    int64
	SizeBytes          int64
	IntegrityVerified  bool
	IntegrityCheckedAt *time.Time
	ErrorMessage       string
	Metadata           string
	CreatedAt          time.Time
}

type ListFilter struct {
	BackupAlias string
	BackupID    string
}
