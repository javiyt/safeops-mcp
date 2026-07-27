package timestatus

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/process"
	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	Config          config.Config
	Runner          process.Runner
	TimedatectlPath string
	Now             func() time.Time
}

func (r Reader) TimeStatus(ctx context.Context) (ports.TimeStatus, error) {
	select {
	case <-ctx.Done():
		return ports.TimeStatus{}, ctx.Err()
	default:
	}
	now := time.Now().UTC()
	if r.Now != nil {
		now = r.Now().UTC()
	}
	out := ports.TimeStatus{
		CurrentTime:   now.Format(time.RFC3339),
		Timezone:      timezone(),
		ServiceStatus: "unknown",
	}
	path := r.TimedatectlPath
	if path == "" {
		path = "/usr/bin/timedatectl"
	}
	if r.Runner == nil || !r.Config.Diagnostics.Time.NTPCheck {
		return out, nil
	}
	res, err := r.Runner.Run(ctx, path, "show", "--property=Timezone", "--property=NTPSynchronized", "--property=SystemClockSynchronized")
	if err != nil {
		return out, nil
	}
	out.ServiceStatus = "active"
	for _, line := range strings.Split(res.Stdout, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch key {
		case "Timezone":
			if strings.TrimSpace(value) != "" {
				out.Timezone = strings.TrimSpace(value)
			}
		case "NTPSynchronized", "SystemClockSynchronized":
			out.NTPSynchronized = strings.TrimSpace(value) == "yes"
		}
	}
	return out, nil
}

func timezone() string {
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		if value := strings.TrimSpace(string(data)); value != "" {
			return value
		}
	}
	return time.Local.String()
}
