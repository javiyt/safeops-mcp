package deployment

import "time"

type HistoryRecord struct {
	ID               string    `json:"id"`
	ApplicationAlias string    `json:"application_alias"`
	Version          string    `json:"version"`
	DeployedAt       time.Time `json:"deployed_at"`
	DeploymentType   string    `json:"deployment_type"`
	TriggeredBy      string    `json:"triggered_by"`
	ImageDigest      string    `json:"image_digest,omitempty"`
	CommitHash       string    `json:"commit_hash,omitempty"`
	Status           string    `json:"status"`
	PreviousVersion  string    `json:"previous_version,omitempty"`
	NextVersion      string    `json:"next_version,omitempty"`
	Metadata         string    `json:"metadata,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}
