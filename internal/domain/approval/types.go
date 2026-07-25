package approval

import "time"

type Status string

const (
	StatusPending   Status = "pending"
	StatusExecuting Status = "executing"
	StatusExecuted  Status = "executed"
	StatusRejected  Status = "rejected"
	StatusExpired   Status = "expired"
	StatusFailed    Status = "failed"
	StatusSimulated Status = "simulated"
)

type Approval struct {
	ID                   string
	UserID               string
	Tool                 string
	Action               string
	NormalizedArguments  string
	ArgumentsHash        string
	ConfirmationCodeHash string
	Status               Status
	CreatedAt            time.Time
	ExpiresAt            time.Time
	ExecutedAt           *time.Time
	ErrorSummary         string
	ResultSummary        string
	Attempts             int
}
