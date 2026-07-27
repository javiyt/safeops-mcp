package configuredprocess

import (
	"context"

	cpuadapter "github.com/javiyt/safeops-mcp/internal/adapters/outbound/linux/cpu"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	CPU cpuadapter.Reader
}

func (r Reader) ConfiguredProcessStatus(ctx context.Context) (ports.ConfiguredProcessStatus, error) {
	out, err := r.CPU.CPUStatus(ctx)
	if err != nil {
		return ports.ConfiguredProcessStatus{}, err
	}
	return ports.ConfiguredProcessStatus{Processes: out.Processes}, nil
}
