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
	res, err := c.Runner.Run(ctx, "/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--property=SubState", "--property=ExecMainStartTimestamp", "--property=MainPID", "--value")
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
