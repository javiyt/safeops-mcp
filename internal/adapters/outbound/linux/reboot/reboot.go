package reboot

import (
	"context"
	"strconv"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
)

type Client struct {
	Command       string
	CancelCommand string
	Runner        process.Runner
}

func (c Client) ScheduleReboot(ctx context.Context, delayMinutes int) error {
	if delayMinutes < 0 {
		delayMinutes = 0
	}
	_, err := c.Runner.Run(ctx, c.Command, "shutdown", "-r", "+"+strconv.Itoa(delayMinutes))
	return err
}

func (c Client) CancelReboot(ctx context.Context) error {
	command := c.CancelCommand
	if command == "" {
		command = c.Command
	}
	_, err := c.Runner.Run(ctx, command, "shutdown", "-c")
	return err
}
