package memory

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	ProcRoot string
	Config   config.Config
}

func (r Reader) MemoryStatus(ctx context.Context) (ports.MemoryStatus, error) {
	select {
	case <-ctx.Done():
		return ports.MemoryStatus{}, ctx.Err()
	default:
	}
	procRoot := r.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	values, err := readMeminfo(filepath.Join(procRoot, "meminfo"))
	if err != nil {
		return ports.MemoryStatus{}, err
	}
	total := values["MemTotal"]
	available := values["MemAvailable"]
	cache := values["Cached"] + values["SReclaimable"]
	swapTotal := values["SwapTotal"]
	swapFree := values["SwapFree"]
	used := uint64(0)
	if total > available {
		used = total - available
	}
	pressure := 0.0
	if total > 0 {
		pressure = float64(used) / float64(total)
	}
	return ports.MemoryStatus{
		TotalMB:        kbToMB(total),
		AvailableMB:    kbToMB(available),
		UsedMB:         kbToMB(used),
		CacheMB:        kbToMB(cache),
		SwapTotalMB:    kbToMB(swapTotal),
		SwapUsedMB:     kbToMB(swapTotal - swapFree),
		MemoryPressure: pressure,
		OOMEvents:      nil,
	}, nil
}

func readMeminfo(path string) (map[string]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	values := map[string]uint64{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(fields[1], 10, 64)
		values[strings.TrimSuffix(fields[0], ":")] = v
	}
	return values, scanner.Err()
}

func kbToMB(value uint64) uint64 {
	return value / 1024
}
