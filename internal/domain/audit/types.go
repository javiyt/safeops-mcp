package audit

import "time"

type Event struct {
	ID             string
	Timestamp      time.Time
	UserID         string
	Component      string
	EventType      string
	Tool           string
	Action         string
	Arguments      string
	Risk           string
	PolicyDecision string
	Status         string
	DurationMillis int64
	ResultSummary  string
	ErrorSummary   string
	ApprovalID     string
	OperationID    string
}
