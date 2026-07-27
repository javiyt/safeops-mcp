package diskhealth

import (
	"context"
	"fmt"
	"sort"
	"syscall"

	"github.com/javiyt/safeops-mcp/internal/config"
	"github.com/javiyt/safeops-mcp/internal/ports"
)

type Reader struct {
	Config config.Config
}

func (r Reader) DiskHealth(ctx context.Context, alias string) (ports.DiskHealth, error) {
	select {
	case <-ctx.Done():
		return ports.DiskHealth{}, ctx.Err()
	default:
	}
	if alias != "" {
		item, err := r.disk(alias)
		if err != nil {
			return ports.DiskHealth{}, err
		}
		return ports.DiskHealth{Disks: []ports.DiskHealthItem{item}}, nil
	}
	aliases := make([]string, 0, len(r.Config.Filesystem.DiskPaths))
	for name := range r.Config.Filesystem.DiskPaths {
		aliases = append(aliases, name)
	}
	sort.Strings(aliases)
	out := make([]ports.DiskHealthItem, 0, len(aliases))
	for _, name := range aliases {
		item, err := r.disk(name)
		if err != nil {
			return ports.DiskHealth{}, err
		}
		out = append(out, item)
	}
	return ports.DiskHealth{Disks: out}, nil
}

func (r Reader) disk(alias string) (ports.DiskHealthItem, error) {
	cfg, ok := r.Config.Filesystem.DiskPaths[alias]
	if !ok {
		return ports.DiskHealthItem{}, fmt.Errorf("disk alias %q is not configured", alias)
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(cfg.Path, &stat); err != nil {
		return ports.DiskHealthItem{}, err
	}
	total := stat.Blocks * uint64(stat.Bsize)
	available := stat.Bavail * uint64(stat.Bsize)
	used := total - available
	usage := percent(used, total)
	inodesUsed := stat.Files - stat.Ffree
	return ports.DiskHealthItem{
		Name:             alias,
		Mount:            cfg.Path,
		TotalGB:          bytesToGB(total),
		UsedGB:           bytesToGB(used),
		AvailableGB:      bytesToGB(available),
		UsagePercent:     usage,
		InodesTotal:      stat.Files,
		InodesUsed:       inodesUsed,
		InodesPercent:    percent(inodesUsed, stat.Files),
		Trend:            "unknown",
		FilesystemErrors: false,
		SMART:            ports.SMARTStatus{Available: false},
	}, nil
}

func bytesToGB(value uint64) float64 {
	return float64(value) / 1024 / 1024 / 1024
}

func percent(value, total uint64) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) / float64(total) * 100
}
