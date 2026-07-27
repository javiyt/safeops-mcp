package podman

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/ports"
	"github.com/javiyt/safeops-mcp/internal/redaction"
)

const (
	HealthHealthy       = "healthy"
	HealthUnhealthy     = "unhealthy"
	HealthStarting      = "starting"
	HealthNotConfigured = "not_configured"
	HealthUnknown       = "unknown"
)

type Client struct {
	Binary string
	Runner process.Runner
}

func (c Client) InspectContainer(ctx context.Context, alias, name, management string) (ports.ContainerStatus, error) {
	res, err := c.Runner.Run(ctx, c.Binary, "inspect", "--type", "container", "--format", "json", name)
	if err != nil {
		msg := redaction.Redact(err.Error())
		if strings.Contains(strings.ToLower(msg), "no such container") || strings.Contains(strings.ToLower(msg), "does not exist") {
			return ports.ContainerStatus{Alias: alias, ContainerName: name, Management: management, Exists: false, Health: HealthUnknown, FinishedAt: nil, Error: msg}, nil
		}
		return ports.ContainerStatus{}, errors.New(msg)
	}
	var items []inspectContainer
	if err := json.Unmarshal([]byte(res.Stdout), &items); err != nil {
		return ports.ContainerStatus{}, fmt.Errorf("decode podman inspect json: %w", err)
	}
	if len(items) == 0 {
		return ports.ContainerStatus{Alias: alias, ContainerName: name, Management: management, Exists: false, Health: HealthUnknown, FinishedAt: nil}, nil
	}
	item := items[0]
	health := HealthNotConfigured
	if item.State.Healthcheck != nil {
		health = normalizeHealth(item.State.Healthcheck.Status)
	}
	finished := emptyToNil(item.State.FinishedAt)
	return ports.ContainerStatus{
		Alias:         alias,
		ContainerName: name,
		Management:    management,
		Exists:        true,
		State:         item.State.Status,
		Status:        item.State.StatusString,
		Health:        health,
		StartedAt:     item.State.StartedAt,
		FinishedAt:    finished,
		RestartCount:  item.RestartCount,
		Image:         item.ImageName,
		ImageID:       item.Image,
		PID:           item.State.PID,
		ExitCode:      item.State.ExitCode,
		Error:         redaction.Redact(item.State.Error),
	}, nil
}

func (c Client) Logs(ctx context.Context, name string, lines int, since string) ([]ports.ContainerLogEntry, bool, error) {
	args := []string{"logs", "--tail", fmt.Sprintf("%d", lines)}
	if since != "" {
		args = append(args, "--since", since)
	}
	args = append(args, name)
	res, err := c.Runner.Run(ctx, c.Binary, args...)
	if err != nil {
		return nil, false, errors.New(redaction.Redact(err.Error()))
	}
	rawLines := strings.Split(strings.TrimRight(res.Stdout, "\n"), "\n")
	if len(rawLines) == 1 && rawLines[0] == "" {
		rawLines = nil
	}
	entries := make([]ports.ContainerLogEntry, 0, len(rawLines))
	for _, line := range rawLines {
		entries = append(entries, ports.ContainerLogEntry{Stream: "stdout", Message: redaction.Redact(line)})
	}
	return entries, false, nil
}

func (c Client) Restart(ctx context.Context, name string) error {
	_, err := c.Runner.Run(ctx, c.Binary, "restart", name)
	if err != nil {
		return errors.New(redaction.Redact(err.Error()))
	}
	return nil
}

func (c Client) WaitForRunning(ctx context.Context, alias, name, management string, attempts int, interval time.Duration) (ports.ContainerStatus, int, error) {
	if attempts <= 0 {
		attempts = 1
	}
	if interval <= 0 {
		interval = time.Second
	}
	var last ports.ContainerStatus
	for i := 1; i <= attempts; i++ {
		st, err := c.InspectContainer(ctx, alias, name, management)
		if err != nil {
			return ports.ContainerStatus{}, i, err
		}
		last = st
		if st.Exists && st.State == "running" {
			return st, i, nil
		}
		select {
		case <-ctx.Done():
			return ports.ContainerStatus{}, i, ctx.Err()
		case <-time.After(interval):
		}
	}
	return last, attempts, fmt.Errorf("container %q did not reach running state", alias)
}

func (c Client) WaitForHealth(ctx context.Context, alias, name, management string, attempts int, interval time.Duration) (string, int, error) {
	if attempts <= 0 {
		attempts = 1
	}
	if interval <= 0 {
		interval = time.Second
	}
	last := HealthUnknown
	for i := 1; i <= attempts; i++ {
		st, err := c.InspectContainer(ctx, alias, name, management)
		if err != nil {
			return HealthUnknown, i, err
		}
		if !st.Exists || st.State != "running" {
			return st.Health, i, fmt.Errorf("container %q is not running", alias)
		}
		last = st.Health
		switch st.Health {
		case HealthHealthy, HealthNotConfigured:
			return st.Health, i, nil
		case HealthUnhealthy:
			return st.Health, i, fmt.Errorf("container %q is unhealthy", alias)
		}
		select {
		case <-ctx.Done():
			return last, i, ctx.Err()
		case <-time.After(interval):
		}
	}
	return last, attempts, fmt.Errorf("container %q health did not settle", alias)
}

type inspectContainer struct {
	Image        string `json:"Image"`
	ImageName    string `json:"ImageName"`
	RestartCount int    `json:"RestartCount"`
	State        struct {
		Status       string `json:"Status"`
		StatusString string `json:"StatusString"`
		StartedAt    string `json:"StartedAt"`
		FinishedAt   string `json:"FinishedAt"`
		PID          int    `json:"Pid"`
		ExitCode     int    `json:"ExitCode"`
		Error        string `json:"Error"`
		Healthcheck  *struct {
			Status string `json:"Status"`
		} `json:"Healthcheck"`
	} `json:"State"`
}

func normalizeHealth(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "healthy":
		return HealthHealthy
	case "unhealthy":
		return HealthUnhealthy
	case "starting":
		return HealthStarting
	case "":
		return HealthNotConfigured
	default:
		return HealthUnknown
	}
}

func emptyToNil(value string) *string {
	if value == "" || strings.HasPrefix(value, "0001-") {
		return nil
	}
	return &value
}
