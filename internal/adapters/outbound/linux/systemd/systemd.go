package systemd

import (
	"context"
	"strconv"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/domain/service"
)

type Client struct {
	Runner process.Runner
}

func (c Client) Status(ctx context.Context, alias, unit string) (service.Status, error) {
	return c.StatusWithScope(ctx, alias, unit, "system")
}

func (c Client) StatusWithScope(ctx context.Context, alias, unit, scope string) (service.Status, error) {
	args := []string{"show", unit, "--property=ActiveState", "--property=SubState", "--property=ExecMainStartTimestamp", "--property=MainPID", "--value"}
	if scope == "user" {
		args = append([]string{"--user"}, args...)
	}
	res, err := c.Runner.Run(ctx, "/usr/bin/systemctl", args...)
	if err != nil {
		return service.Status{}, err
	}
	lines := strings.Split(strings.TrimSpace(res.Stdout), "\n")
	st := service.Status{Alias: alias, Unit: unit}
	if len(lines) > 0 {
		st.ActiveState = lines[0]
	}
	if len(lines) > 1 {
		st.SubState = lines[1]
	}
	if len(lines) > 2 {
		st.StartedAt = lines[2]
	}
	if len(lines) > 3 {
		pid, _ := strconv.Atoi(strings.TrimSpace(lines[3]))
		st.MainPID = pid
	}
	return st, nil
}

func (c Client) Restart(ctx context.Context, unit string) error {
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", "restart", unit)
	return err
}

func (c Client) Start(ctx context.Context, unit string) error {
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", "start", unit)
	return err
}

func (c Client) Stop(ctx context.Context, unit string) error {
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", "stop", unit)
	return err
}

func (c Client) ResetFailed(ctx context.Context, unit string) error {
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", "reset-failed", unit)
	return err
}

func (c Client) RestartWithScope(ctx context.Context, unit, scope string) error {
	args := []string{"restart", unit}
	if scope == "user" {
		args = append([]string{"--user"}, args...)
	}
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", args...)
	return err
}

func (c Client) StartWithScope(ctx context.Context, unit, scope string) error {
	args := []string{"start", unit}
	if scope == "user" {
		args = append([]string{"--user"}, args...)
	}
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", args...)
	return err
}

func (c Client) StopWithScope(ctx context.Context, unit, scope string) error {
	args := []string{"stop", unit}
	if scope == "user" {
		args = append([]string{"--user"}, args...)
	}
	_, err := c.Runner.Run(ctx, "/usr/bin/systemctl", args...)
	return err
}
